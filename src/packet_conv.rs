use ya_relay_stack::packet::{EtherField, IpPacket, IpV4Field, PeekPacket};
use ya_relay_stack::Error;


//todo implement proper subnet translation, not only 255.255.255.0
fn translate_address(addr: &mut[u8], src_subnet: &[u8; 4], dst_subnet: &[u8; 4]) {
    if addr[0] == src_subnet[0] && addr[1] == src_subnet[1] && addr[2] == src_subnet[2] {
        addr[0] = dst_subnet[0];
        addr[1] = dst_subnet[1];
        addr[2] = dst_subnet[2];
    }
}

pub fn packet_ip_wrap_to_ether(
    frame: &[u8],
    src_mac: Option<&[u8; 6]>,
    dst_mac: Option<&[u8; 6]>,
    src_subnet: Option<&[u8; 4]>,
    dst_subnet: Option<&[u8; 4]>,
) -> Result<Vec<u8>, Error> {
    if frame.is_empty() {
        return Err(Error::Other(
            "Error when wrapping IP packet: Empty packet".into(),
        ));
    }
    if let Err(err) = IpPacket::peek(frame) {
        return Err(Error::PacketMalformed(format!(
            "Error when wrapping IP packet {err}"
        )));
    }

    let mut eth_packet = vec![0u8; frame.len() + 14];
    if let Some(dst_mac) = dst_mac {
        eth_packet[EtherField::DST_MAC].copy_from_slice(dst_mac);
    } else {
        const DEFAULT_DST_MAC: &[u8; 6] = &[0x02, 0x02, 0x02, 0x02, 0x02, 0x02];
        eth_packet[EtherField::DST_MAC].copy_from_slice(DEFAULT_DST_MAC);
    }
    if let Some(src_mac) = src_mac {
        eth_packet[EtherField::SRC_MAC].copy_from_slice(src_mac);
    } else {
        const DEFAULT_SRC_MAC: &[u8; 6] = &[0x01, 0x01, 0x01, 0x01, 0x01, 0x01];
        eth_packet[EtherField::SRC_MAC].copy_from_slice(DEFAULT_SRC_MAC);
    }
    eth_packet[EtherField::PAYLOAD].copy_from_slice(&frame[0..]);
    match IpPacket::packet(frame) {
        IpPacket::V4(pkt) => {
            const ETHER_TYPE_IPV4: &[u8; 2] = &[0x08, 0x00];
            eth_packet[EtherField::ETHER_TYPE].copy_from_slice(ETHER_TYPE_IPV4);
            if let (Some(src_subnet), Some(dst_subnet)) = (src_subnet, dst_subnet) {
                const ETHER_IP_SRC_ADDR: std::ops::Range<usize> = (14+12)..(14+16);
                const ETHER_IP_DST_ADDR: std::ops::Range<usize> = (14+16)..(14+20);
                translate_address(&mut eth_packet[ETHER_IP_SRC_ADDR], src_subnet, dst_subnet);
                translate_address(&mut eth_packet[ETHER_IP_DST_ADDR], src_subnet, dst_subnet);
            }
        }
        IpPacket::V6(_pkt) => {
            const ETHER_TYPE_IPV6: &[u8; 2] = &[0x86, 0xdd];
            eth_packet[EtherField::ETHER_TYPE].copy_from_slice(ETHER_TYPE_IPV6);
        }
    };
    Ok(eth_packet)
}

pub fn packet_ether_to_ip_slice<'a, 'b>(eth_packet: &'a mut[u8], src_subnet: Option<&'b [u8; 4]>, dst_subnet: Option<&'b [u8; 4]>) -> Result<&'a [u8], Error> {
    const MIN_IP_HEADER_LENGTH: usize = 20;
    if eth_packet.len() <= 14 + MIN_IP_HEADER_LENGTH {
        return Err(Error::Other(format!(
            "Error when creating IP packet from ether packet: Packet too short. Packet length {}",
            eth_packet.len()
        )));
    }

    let ip_frame = &mut eth_packet[EtherField::PAYLOAD];
    if let Err(err) = IpPacket::peek(ip_frame) {
        return Err(Error::PacketMalformed(format!(
            "Error when creating IP packet from ether packet {err}"
        )));
    } else {
        match IpPacket::packet(ip_frame) {
            IpPacket::V4(pkt) => {
                if let (Some(src_subnet), Some(dst_subnet)) = (src_subnet, dst_subnet) {
                    translate_address(&mut ip_frame[IpV4Field::SRC_ADDR], src_subnet, dst_subnet);
                    translate_address(&mut ip_frame[IpV4Field::DST_ADDR], src_subnet, dst_subnet);
                }
            }
            IpPacket::V6(_pkt) => {
                //todo handle ipv6
            }
        };
    }
    Ok(ip_frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_ether_to_ip() {
        let valid_ether_packet = hex::decode("51bd2c1e5c202423d4418ef108004500002800010000401175ba0d0f1112717375765b941a850014476f48656c6c6f205061636b6574").unwrap();
        let valid_ip_packet = hex::decode(
            "4500002800010000401175ba0d0f1112717375765b941a850014476f48656c6c6f205061636b6574",
        )
            .unwrap();

        assert_eq!(
            hex::encode(valid_ip_packet),
            hex::encode(packet_ether_to_ip_slice(&valid_ether_packet, None, None).unwrap())
        );
    }

    #[test]
    fn test_packet_ip_to_ether() {
        let valid_ip_packet = hex::decode(
            "4500002800010000401175ba0d0f1112717375765b941a850014476f48656c6c6f205061636b6574",
        )
            .unwrap();
        let valid_ether_packet = hex::decode("02020202020201010101010108004500002800010000401175ba0d0f1112717375765b941a850014476f48656c6c6f205061636b6574").unwrap();

        assert_eq!(
            hex::encode(&valid_ether_packet),
            hex::encode(packet_ip_wrap_to_ether(&valid_ip_packet, None, None).unwrap())
        );

        let valid_ether_packet2 = hex::decode("51bd2c1e5c202423d4418ef108004500002800010000401175ba0d0f1112717375765b941a850014476f48656c6c6f205061636b6574").unwrap();

        const SRC_MAC: &[u8; 6] = &[0x24, 0x23, 0xd4, 0x41, 0x8e, 0xf1];
        const DST_MAC: &[u8; 6] = &[0x51, 0xbd, 0x2c, 0x1e, 0x5c, 0x20];
        assert_eq!(
            hex::encode(&valid_ether_packet2),
            hex::encode(
                packet_ip_wrap_to_ether(&valid_ip_packet, Some(SRC_MAC), Some(DST_MAC), None, None).unwrap()
            )
        );
    }
}
