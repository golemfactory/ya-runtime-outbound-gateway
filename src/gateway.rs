use anyhow::bail;
use arp_parse::ARPSliceBuilder;
use futures::{FutureExt, SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::io::Bytes;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Stdio;
use std::sync::Arc;
use structopt::StructOpt;
use tokio::net::UdpSocket;
use url::Url;

use etherparse::IpHeader::{Version4, Version6};
use etherparse::{EtherType, PacketBuilder, PacketHeaders, TransportHeader};
use tokio::sync::mpsc;
use tun::TunPacket;
use ya_relay_stack::packet::{IpPacket, IpV4Field, PeekPacket, UdpField, UdpPacket};
use ya_relay_stack::Protocol;

use ya_runtime_sdk::error::Error;
use ya_runtime_sdk::server::ContainerEndpoint;
use ya_runtime_sdk::*;

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

fn _reverse_udp(frame: &Vec<u8>) -> anyhow::Result<Vec<u8>> {
    let ip_packet = match IpPacket::peek(frame) {
        Ok(_) => IpPacket::packet(frame),
        _ => bail!("Error peeking IP packet"),
    };

    if ip_packet.protocol() != Protocol::Udp as u8 {
        return Ok(frame.to_vec());
    }

    let src = ip_packet.src_address();
    let dst = ip_packet.dst_address();

    println!("Src: {:?}, Dst: {:?}", src, dst);

    let udp_data = ip_packet.payload();
    let _udp_data_len = udp_data.len();

    let udp_packet = match UdpPacket::peek(udp_data) {
        Ok(_) => UdpPacket::packet(udp_data),
        _ => bail!("Error peeking UDP packet"),
    };

    let src_port = udp_packet.src_port();
    let dst_port = udp_packet.dst_port();
    println!("Src port: {:?}, Dst port: {:?}", src_port, dst_port);

    let content = &udp_data[UdpField::PAYLOAD];

    match std::str::from_utf8(content) {
        Ok(content_str) => println!("Content (string): {content_str:?}"),
        Err(_e) => println!("Content (binary): {:?}", content),
    };

    let mut reversed = frame.clone();
    reversed[IpV4Field::SRC_ADDR].copy_from_slice(&dst);
    reversed[IpV4Field::DST_ADDR].copy_from_slice(&src);

    let reversed_udp_data = &mut reversed[ip_packet.payload_off()..];

    reversed_udp_data[UdpField::SRC_PORT].copy_from_slice(&udp_data[UdpField::DST_PORT]);
    reversed_udp_data[UdpField::DST_PORT].copy_from_slice(&udp_data[UdpField::SRC_PORT]);

    Ok(reversed)
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
        let endpoint = match endpoint.map(ContainerEndpoint::try_from) {
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

        let vpn_network_addr = "192.168.8.7";
        let vpn_network_mask = "255.255.255.0";
        let vpn_layer = "tun".to_string();

        let addr = vpn_network_addr.parse::<IpAddr>().unwrap();
        let mask = vpn_network_mask.parse::<IpAddr>().unwrap();
        let vpn_interface_name = "vpn0";
        let mut config = tun::Configuration::default();
        let vpn_layer = match vpn_layer.as_str() {
            "tun" => tun::Layer::L3,
            "tap" => tun::Layer::L2,
            _ => panic!("Invalid vpn layer"),
        };
        config
            .layer(vpn_layer)
            .address(addr)
            .netmask(mask)
            .name(vpn_interface_name)
            .up();

        let echo_server = false;
        // TODO: Here we should start listening on the same protocol as ExeUnit.
        async move {
            //let tun =
            let socket = Arc::new(UdpSocket::bind(socket_addr).await.unwrap());

            log::info!("Listening on: {}", socket.local_addr().unwrap());
            let dev = tun::create_as_async(&config).unwrap();
            let (mut tun_write, mut tun_read) = dev.into_framed().split();
            //let r = Arc::new(socket);
            //let s = r.clone();
            let (udp_socket_write, mut rx_forward_to_socket) =
                mpsc::channel::<(Vec<u8>, SocketAddr)>(1);
            let socket_ = socket.clone();
            tokio::spawn(async move {
                while let Some((bytes, addr)) = rx_forward_to_socket.recv().await {
                    let len = socket_.send_to(&bytes, &addr).await.unwrap();
                    println!("{:?} bytes sent", len);
                }
            });
            let socket_ = socket.clone();
            tokio::spawn(async move {
                let mut buf_box = Box::new([0; 70000]); //sufficient to hold max UDP packet
                let buf = &mut *buf_box;
                loop {
                    if let Some(Ok(packet)) = tun_read.next().await {
                        if let Ok(packet) =
                            etherparse::PacketHeaders::from_ip_slice(&packet.get_bytes())
                        {
                            match &packet.ip {
                                None => {
                                    log::error!("No IP header found");
                                }
                                Some(Version4(ip, _ipv4_extensions)) => {
                                    match packet.transport {
                                        Some(TransportHeader::Udp(udp_header)) => {
                                            let builder = PacketBuilder::ethernet2(
                                                [1, 1, 1, 1, 1, 1],
                                                [2, 2, 2, 2, 2, 2],
                                            )
                                            .ipv4(ip.source, ip.destination, ip.time_to_live)
                                            .udp(
                                                udp_header.source_port,
                                                udp_header.destination_port,
                                            ); //desitnation port

                                            log::info!(
                                                "Source ip: {:?}, dest ip: {:?}",
                                                ip.source,
                                                ip.destination
                                            ); // payload of the udp packet
                                            let payload = packet.payload;
                                            // get some memory to store the serialized data
                                            let mut complete_packet = Vec::<u8>::with_capacity(
                                                builder.size(payload.len()),
                                            );
                                            builder.write(&mut complete_packet, &payload).unwrap();

                                            log::info!(
                                                "Sending wrapped eth packet: {:?}",
                                                complete_packet
                                            );
                                            if let Err(err) = socket_
                                                .send_to(
                                                    &complete_packet,
                                                    SocketAddr::from(([127, 0, 0, 1], 52001)),
                                                )
                                                .await
                                            {
                                                log::error!(
                                                    "Error sending packet to websocket: {:?}",
                                                    err
                                                );
                                            }
                                            log::info!("udp: {:?}", udp_header);
                                        }
                                        Some(TransportHeader::Tcp(tcp_header)) => {
                                            log::info!("tcp: {:?}", tcp_header);
                                        }
                                        Some(TransportHeader::Icmpv4(icmp_header)) => {
                                            log::info!("icmp: {:?}", icmp_header);
                                        }
                                        Some(TransportHeader::Icmpv6(icmp_header)) => {
                                            log::info!("icmp: {:?}", icmp_header);
                                        }
                                        None => {
                                            log::info!("No transport header");
                                        }
                                    }
                                }
                                Some(Version6(_ipv6_header, _ipv6_ext)) => {
                                    log::info!("IpV6");
                                }
                            }
                        }
                    }
                }
            });

            tokio::spawn(async move {
                let mut buf_box = Box::new([0; 70000]); //sufficient to hold max UDP packet
                let buf = &mut *buf_box;
                loop {
                    let (len, addr) = socket.recv_from(buf).await.unwrap();
                    log::info!("{len:?} bytes received from {addr:?}");
                    log::info!("Packet content {:?}", &buf[..len]);

                    let value = match PacketHeaders::from_ethernet_slice(&buf[..len]) {
                        Err(value) => {
                            log::warn!("Failed to parse/read packet {:?}", value);
                            continue;
                        }
                        Ok(value) => value,
                    };

                    log::info!("link: {:?}", value.link);
                    log::info!("vlan: {:?}", value.vlan);
                    log::info!("ip: {:?}", value.ip);
                    log::info!("transport: {:?}", value.transport);

                    let link = if let Some(link) = value.link {
                        link
                    } else {
                        log::warn!("No ethernet header found {:?}", value);
                        continue;
                    };

                    let ether_type = EtherType::from_u16(link.ether_type);
                    match ether_type {
                        Some(EtherType::Ipv4 | EtherType::Ipv6) => {
                            match &value.ip {
                                None => {
                                    log::error!("No IP header found {:?}", link);
                                    continue;
                                }
                                Some(Version4(ip, _ipv4_extensions)) => {
                                    match value.transport {
                                        Some(TransportHeader::Udp(udp_header)) => {
                                            if echo_server {
                                                let builder = PacketBuilder::ethernet2(
                                                    link.source,
                                                    link.destination,
                                                )
                                                .ipv4(ip.destination, ip.source, ip.time_to_live)
                                                .udp(
                                                    udp_header.destination_port,
                                                    udp_header.source_port,
                                                ); //destination port
                                                   // payload of the udp packet
                                                let payload = value.payload;
                                                // get some memory to store the serialized data
                                                let mut complete_packet = Vec::<u8>::with_capacity(
                                                    builder.size(payload.len()),
                                                );
                                                builder
                                                    .write(&mut complete_packet, &payload)
                                                    .unwrap();
                                                log::info!("Sending packet: {:?}", complete_packet);
                                                let _ = udp_socket_write
                                                    .send((complete_packet, addr))
                                                    .await;
                                                log::info!("udp: {:?}", udp_header);
                                            } else {
                                                let builder = PacketBuilder::ipv4(
                                                    ip.source,
                                                    ip.destination,
                                                    ip.time_to_live,
                                                )
                                                .udp(
                                                    udp_header.source_port,
                                                    udp_header.destination_port,
                                                ); //destination port
                                                   // payload of the udp packet
                                                let payload = value.payload;
                                                // get some memory to store the serialized data
                                                let mut complete_packet = Vec::<u8>::with_capacity(
                                                    builder.size(payload.len()),
                                                );
                                                builder
                                                    .write(&mut complete_packet, &payload)
                                                    .unwrap();
                                                log::info!("Sending packet: {:?}", complete_packet);
                                                let _ = tun_write
                                                    .send(TunPacket::new(complete_packet))
                                                    .await;
                                                //se((complete_packet, addr)).await;
                                                log::info!("udp: {:?}", udp_header);
                                            }
                                        }
                                        Some(TransportHeader::Tcp(tcp_header)) => {
                                            log::info!("tcp: {:?}", tcp_header);
                                        }
                                        Some(TransportHeader::Icmpv4(icmp_header)) => {
                                            log::info!("icmp: {:?}", icmp_header);
                                        }
                                        Some(TransportHeader::Icmpv6(icmp_header)) => {
                                            log::info!("icmp: {:?}", icmp_header);
                                        }
                                        None => {
                                            log::info!("No transport header");
                                        }
                                    }
                                }
                                Some(Version6(_ipv6_header, _ipv6_ext)) => {
                                    log::info!("IpV6");
                                }
                            }
                        }
                        Some(EtherType::Arp) => {
                            let slice = arp_parse::parse(value.payload).unwrap();
                            let op_code = slice.op_code();
                            if op_code == arp_parse::OPCODE_REQUEST {
                                let target_ip_addr = Ipv4Addr::new(
                                    slice.target_protocol_addr()[0],
                                    slice.target_protocol_addr()[1],
                                    slice.target_protocol_addr()[2],
                                    slice.target_protocol_addr()[3],
                                );
                                log::info!("ARP request for IP {}", target_ip_addr);

                                let mut buf_resp = [0u8; 14 + arp_parse::ARP_SIZE as usize];
                                let yagna_mac = [0u8; arp_parse::HARDWARE_SIZE_ETHERNET as usize];
                                let _arp_response_builder =
                                    ARPSliceBuilder::new(&mut buf_resp[14..])
                                        .unwrap()
                                        .op_code(arp_parse::OPCODE_REPLY)
                                        .unwrap()
                                        .sender_hardware_addr(&yagna_mac)
                                        .unwrap()
                                        .sender_protocol_addr(slice.target_protocol_addr())
                                        .unwrap()
                                        .target_protocol_addr(slice.sender_protocol_addr())
                                        .unwrap()
                                        .target_hardware_addr(slice.sender_hardware_addr())
                                        .unwrap();

                                buf_resp[0..6].copy_from_slice(&link.destination);
                                buf_resp[6..12].copy_from_slice(&link.source);
                                buf_resp[12..14]
                                    .copy_from_slice(&(EtherType::Arp as u16).to_be_bytes());

                                log::info!("Sending ARP response to {} {:?}", addr, buf_resp);

                                let _len = udp_socket_write
                                    .send((buf_resp.to_vec(), addr))
                                    .await
                                    .unwrap();
                            }
                        }
                        Some(_) => log::info!("Unknown link type {:?}", ether_type),
                        None => log::info!("Unknown link type"),
                    };
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
