use std::net::{Ipv4Addr, SocketAddr};
use futures::FutureExt;
use serde::{Deserialize, Serialize};
use std::process::Stdio;
use arp_parse::ARPSliceBuilder;
use structopt::StructOpt;
use tokio::net::UdpSocket;
use url::Url;

use ya_runtime_sdk::error::Error;
use ya_runtime_sdk::server::ContainerEndpoint;
use ya_runtime_sdk::*;
use etherparse::{EtherType, PacketHeaders};

use crate::routing::RoutingTable;

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
}

impl Runtime for OutboundGatewayRuntime {
    fn deploy<'a>(&mut self, _: &mut Context<Self>) -> OutputResponse<'a> {
        log::info!("Running `Deploy` command");

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
        let endpoint = match endpoint.map(ContainerEndpoint::try_from)
        {
            Some(Ok(endpoint)) => endpoint,
            Some(Err(e)) => return Error::response(format!("Failed to parse VPN endpoint: {e}")),
            None => {
                return Error::response("Start command expects VPN endpoint, but None was found.")
            }
        };

        log::info!("VPN endpoint: {endpoint}");
        let socket_addr = SocketAddr::from(([127, 0, 0, 1], 52001));
        let new_endpoint = ContainerEndpoint::UdpDatagram(socket_addr);
        self.vpn = Some(new_endpoint.clone());

        // TODO: Here we should start listening on the same protocol as ExeUnit.
        async move {

            tokio::spawn( async move {
                let sock = UdpSocket::bind(socket_addr).await.unwrap();
                log::info!("Listening on: {}", sock.local_addr().unwrap());
                let mut buf_box = Box::new([0; 70000]); //sufficient to hold max UDP packet
                let mut buf = &mut *buf_box;
                loop {
                    let (len, addr) = sock.recv_from(buf).await.unwrap();
                    log::info!("{len:?} bytes received from {addr:?}");
                    log::info!("Packet content {:?}", &buf[..len]);
                    match PacketHeaders::from_ethernet_slice(buf) {
                        Err(value) => log::info!("Err {:?}", value),
                        Ok(value) => {
                            if let Some(link) = value.link.clone().map(|link| link.ether_type == EtherType::Arp as u16) {

                                let slice = arp_parse::parse(value.payload).unwrap();
                                let op_code = slice.op_code();
                                if op_code == arp_parse::OPCODE_REQUEST {
                                    let target_ip_addr = Ipv4Addr::new(
                                        slice.target_protocol_addr()[0],
                                        slice.target_protocol_addr()[1],
                                        slice.target_protocol_addr()[2],
                                        slice.target_protocol_addr()[3]);
                                    log::info!("ARP request for IP {}", target_ip_addr);
                                    //let arp_response_builder = ARPSliceBuilder::new(buf) {

//                                    }
                                }

                            }
                            //    let slice = arp_parse::parse(&buff).unwrap();
                            //    let op_code = slice.op_code();
                            //}
                            log::info!("link: {:?}", value.link);
                            log::info!("vlan: {:?}", value.vlan);
                            log::info!("ip: {:?}", value.ip);
                            log::info!("transport: {:?}", value.transport);
                        }
                    }

                    //let len = sock.send_to(&buf[..len], addr).await.unwrap();
                    //ddprintln!("{:?} bytes sent", len);
                }
            });

            //endpoint.connect(cep).await?;
            Ok(Some(serde_json::json!({
                "endpoint": new_endpoint,
            })))
        }
        .boxed_local()
    }

    fn stop<'a>(&mut self, _: &mut Context<Self>) -> EmptyResponse<'a> {
        // Gracefully shutdown the service
        log::info!("Running `Stop` command");
        async move { Ok(()) }.boxed_local()
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

        // TODO: I'm returning here the same endpoint, that I got from ExeUnit.
        //       In reality I should start listening on the same protocol as ExeUnit
        //       Requested and return my endpoint address here.
        let routing = self.routing.clone();
        let endpoint = self.vpn.clone();
        async move {
            routing.update_network(network).await?;
            endpoint.ok_or_else(|| {
                Error::from_string("VPN ExeUnit - Runtime communication endpoint not set")
            })
        }
        .boxed_local()
    }
}
