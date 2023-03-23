use futures::{FutureExt, SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};
use std::process::Stdio;
use std::rc::Rc;
use std::str::FromStr;
use futures::future::err;
use structopt::StructOpt;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tokio::task::spawn_local;
use tun::TunPacket;
use url::Url;

use crate::iptables::{
    create_vpn_config, generate_interface_subnet_and_name, iptables_cleanup,
    iptables_route_to_interface, IpTablesRule, SubnetIpv4Info,
};
use crate::packet_conv::{packet_ether_to_ip_slice, packet_ip_wrap_to_ether};
use ya_runtime_sdk::error::Error;
use ya_runtime_sdk::server::ContainerEndpoint;
use ya_runtime_sdk::*;

use crate::routing::{Network, RoutingTable};

#[derive(StructOpt)]
#[structopt(rename_all = "kebab-case")]
pub struct GatewayCli {
    /// VPN endpoint address
    #[structopt(long)]
    vpn_endpoint: Option<Url>,
}

#[derive(Default, Deserialize, Serialize)]
pub struct GatewayConf {}

#[derive(Default, RuntimeDef, Clone)]
#[cli(GatewayCli)]
#[conf(GatewayConf)]
pub struct OutboundGatewayRuntime {
    pub vpn: Option<ContainerEndpoint>,
    pub routing: RoutingTable,
    pub vpn_subnet_info: Option<SubnetIpv4Info>,
    pub rules_to_remove: Rc<Mutex<Vec<IpTablesRule>>>,

    pub yagna_net_ip: Option<Ipv4Addr>,
    pub yagna_net_addr: Option<Ipv4Addr>,
    pub yagna_net_mask: Option<Ipv4Addr>,
}

impl Runtime for OutboundGatewayRuntime {
    fn deploy<'a>(&mut self, ctx: &mut Context<Self>) -> OutputResponse<'a> {
        log::info!("Running `Deploy` command. Vpn endpoint: {:?}", ctx.cli.runtime.vpn_endpoint);

        // SDK will auto-generate the following code:
        //
        // async move {
        //     Ok(Some(serialize::json::json!({
        //         "startMode": "blocking",
        //         "valid": {"Ok": ""},
        //         "vols": []
        //     })))
        // }
        // .boxed_local()

        async move { Ok(None) }.boxed_local()
    }

    fn start<'a>(&mut self, ctx: &mut Context<Self>) -> OutputResponse<'a> {
        log::info!("Running `Start` command");

        let _emitter = ctx
            .emitter
            .clone()
            .expect("Service not running in Server mode");

        let _workdir = ctx.cli.workdir.clone().expect("Workdir not provided");

        log::debug!("VPN endpoint: {:?}", ctx.cli.runtime.vpn_endpoint);

        let endpoint = ctx.cli.runtime.vpn_endpoint.clone();
        let endpoint = match endpoint.map(ContainerEndpoint::try_from) {
            Some(Ok(endpoint)) => endpoint,
            Some(Err(e)) => return Error::response(format!("Failed to parse VPN endpoint: {e}")),
            None => {
                return Error::response("Start command expects VPN endpoint, but None was found.")
            }
        };


        async move {


            //endpoint.connect(cep).await?;
            Ok(Some(serde_json::json!({

            })))
        }
        .boxed_local()
    }

    fn stop<'a>(&mut self, _: &mut Context<Self>) -> EmptyResponse<'a> {
        // Gracefully shutdown the service
        log::info!("Running `Stop` command");
        let ip_rules_to_remove_ext = self.rules_to_remove.clone();
        async move {
            // Remove IP rules
            let ip_rules_to_remove = { ip_rules_to_remove_ext.lock().await.clone() };
            log::info!("Cleaning iptables rules: {ip_rules_to_remove:?}");
            iptables_cleanup(ip_rules_to_remove)?;
            Ok(())
        }
        .boxed_local()
    }

    fn run_command<'a>(
        &mut self,
        command: RunProcess,
        mode: RuntimeMode,
        ctx: &mut Context<Self>,
    ) -> ProcessIdResponse<'a> {
        log::info!("Running `Run` command with params: {command:?} mode: {mode:?}");

        if let RuntimeMode::Command = mode {
            return Error::response("Command mode is not supported");
        }

        if command.bin != "test" {
            return Error::response(format!(
                "Only `test` command supported. Provided: command: `{}`, args: `{:?}`",
                command.bin, command.args
            ));
        }

        // Echo the executed command and its arguments
        let started = tokio::process::Command::new("echo")
            .args(["Test: Executing echo command on Provider machine - passed"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null())
            .spawn();

        // Wraps command's lifecycle. The handler is executed in background.
        // Result of `started` is handled prior to emitting command lifecycle events.
        futures::future::ready(started).as_command(ctx, |child, mut run_ctx| async move {
            let output = child.wait_with_output().await?;
            run_ctx.stdout(output.stdout).await;
            run_ctx.stderr(output.stderr).await;
            Ok(())
        })
    }

    fn offer<'a>(&mut self, _ctx: &mut Context<Self>) -> OutputResponse<'a> {
        log::info!("Creating Offer template.");
        async move {
            Ok(Some(serde_json::json!({
                "properties": {
                    "golem.runtime.capabilities": ["vpn", "gateway"]
                },
                "constraints": ""
            })))
        }
        .boxed_local()
    }

    /// Join a VPN network
    fn join_network<'a>(
        &mut self,
        network: CreateNetwork,
        _ctx: &mut Context<Self>,
    ) -> EndpointResponse<'a> {
        log::info!("Running `join_network` with: {network:?}");

        if network.networks.len() != 1 {
            return Error::response("Only one network is supported");
        }
        {
            let network = network.networks.iter().next().unwrap();
            //network.if_addr;
            self.yagna_net_ip = match Ipv4Addr::from_str(network.if_addr.as_str()) {
                Ok(ip) => Some(ip),
                Err(err) => return Error::response(format!("Error when parsing network ipaddr {err:?}")),
            };
            self.yagna_net_mask = match Ipv4Addr::from_str(network.mask.as_str()) {
                Ok(mask) => Some(mask),
                Err(err) => return Error::response(format!("Error when parsing network mask {err:?}")),
            };
            self.yagna_net_addr = match Ipv4Addr::from_str(network.addr.as_str()) {
                Ok(addr) => Some(addr),
                Err(err) => return Error::response(format!("Error when parsing network addr {err:?}")),
            };
        }



        //log::info!("VPN endpoint: {endpoint}");
        let socket_addr = SocketAddr::from(([127, 0, 0, 1], 52001));
        let new_endpoint = ContainerEndpoint::UdpDatagram(socket_addr);
        self.vpn = Some(new_endpoint.clone());

        let vpn_subnet_info = generate_interface_subnet_and_name(7).unwrap();
        self.vpn_subnet_info = Some(vpn_subnet_info.clone());

        log::info!("VPN subnet: {vpn_subnet_info:?}");

        let tun_config = create_vpn_config(&vpn_subnet_info);
        let _echo_server = false;

        let ip_rules_to_remove_ext = self.rules_to_remove.clone();
        let yagna_subnet = Ipv4Addr::from_str("192.168.8.0").unwrap();

        // TODO: I'm returning here the same endpoint, that I got from ExeUnit.
        //       In reality I should start listening on the same protocol as ExeUnit
        //       Requested and return my endpoint address here.
        let routing = self.routing.clone();
        let endpoint = self.vpn.clone();


        async move {
            //let tun =
            let socket = Rc::new(UdpSocket::bind(socket_addr).await.unwrap());

            log::info!("Listening on: {}", socket.local_addr().unwrap());
            let dev = tun::create_as_async(&tun_config).unwrap();

            let ip_rules_to_remove =
                iptables_route_to_interface("enX0", &vpn_subnet_info.interface_name).unwrap();
            {
                //use this method due to runtime issues
                *ip_rules_to_remove_ext.lock().await = ip_rules_to_remove;
            }

            let (mut tun_write, mut tun_read) = dev.into_framed().split();
            //let r = Arc::new(socket);
            //let s = r.clone();
            let (udp_socket_write_, mut rx_forward_to_socket) = mpsc::channel::<Vec<u8>>(1);
            let (set_addr, mut rx_get_addr) = mpsc::channel::<SocketAddr>(1);

            let socket_ = socket.clone();
            spawn_local(async move {
                let addr = rx_get_addr.recv().await.unwrap();
                while let Some(bytes) = rx_forward_to_socket.recv().await {
                    log::trace!("Sending {:?} bytes to {:?}", bytes, addr);
                    let _len = socket_.send_to(&bytes, &addr).await.unwrap();
                }
            });
            let _socket_ = socket.clone();
            let udp_socket_write = udp_socket_write_.clone();
            spawn_local(async move {
                loop {
                    if let Some(Ok(packet)) = tun_read.next().await {
                        //todo: add mac addresses
                        match packet_ip_wrap_to_ether(
                            &packet.get_bytes(),
                            None,
                            None,
                            Some(&vpn_subnet_info.subnet.octets()),
                            Some(&yagna_subnet.octets()),
                        ) {
                            Ok(ether_packet) => {
                                if let Err(err) = udp_socket_write.send(ether_packet).await {
                                    log::error!("Error sending packet: {:?}", err);
                                }
                            }
                            Err(e) => {
                                log::error!("Error wrapping packet: {:?}", e);
                            }
                        }
                    }
                }
            });
            let _udp_socket_write = udp_socket_write_;

            spawn_local(async move {
                let mut buf_box = Box::new([0; 70000]); //sufficient to hold max UDP packet
                let buf = &mut *buf_box;
                let mut is_addr_sent = false;
                loop {
                    let (len, addr) = socket.recv_from(buf).await.unwrap();
                    log::trace!("{len:?} bytes received from {addr:?}");
                    log::trace!("Packet content {:?}", &buf[..len]);
                    if !is_addr_sent {
                        set_addr.send(addr).await.unwrap();
                        is_addr_sent = true;
                    }
                    match packet_ether_to_ip_slice(
                        &mut buf[..len],
                        Some(&yagna_subnet.octets()),
                        Some(&vpn_subnet_info.subnet.octets()),
                    ) {
                        Ok(ip_slice) => {
                            log::trace!("IP packet: {:?}", ip_slice);
                            if let Err(err) =
                                tun_write.send(TunPacket::new(ip_slice.to_vec())).await
                            {
                                log::error!("Error sending packet: {:?}", err);
                            }
                        }
                        Err(e) => {
                            log::error!("Error unwrapping packet: {:?}", e);
                        }
                    }
                }
            });
            routing.update_network(network).await?;
            endpoint.ok_or_else(|| {
                Error::from_string("VPN ExeUnit - Runtime communication endpoint not set")
            })

            //endpoint.connect(cep).await?;
            /*Ok(Some(serde_json::json!({
                "endpoint": new_endpoint,
                "vpn-subnet-info": vpn_subnet_info,
            })))*/
        }
            .boxed_local()
    }
}
