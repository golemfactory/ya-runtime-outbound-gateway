use ya_relay_stack::packet::{EtherField, IpPacket, IpV4Field, IpV4Packet, PeekPacket};
use ya_relay_stack::Error;


//todo implement proper subnet translation, not only 255.255.255.0
//returns true if translation was performed
fn translate_address(addr: &mut[u8], src_subnet: &[u8; 4], dst_subnet: &[u8; 4]) -> bool {
    let before_translation = u32::from_be_bytes([addr[0], addr[1], addr[2], addr[3]]);
    if addr[0] == src_subnet[0] && addr[1] == src_subnet[1] && addr[2] == src_subnet[2] {
        addr[0] = dst_subnet[0];
        addr[1] = dst_subnet[1];
        addr[2] = dst_subnet[2];
    }
    let after_translation = u32::from_be_bytes([addr[0], addr[1], addr[2], addr[3]]);
    //returns true if translation was done
    before_translation != after_translation
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
        IpPacket::V4(_pkt) => {
            const ETHER_TYPE_IPV4: &[u8; 2] = &[0x08, 0x00];
            eth_packet[EtherField::ETHER_TYPE].copy_from_slice(ETHER_TYPE_IPV4);
            if let (Some(src_subnet), Some(dst_subnet)) = (src_subnet, dst_subnet) {
                const ETHER_IP_SRC_ADDR: std::ops::Range<usize> = (14+12)..(14+16);
                const ETHER_IP_DST_ADDR: std::ops::Range<usize> = (14+16)..(14+20);
                let mut translated = false;
                translated |= translate_address(&mut eth_packet[ETHER_IP_SRC_ADDR], src_subnet, dst_subnet);
                translated |= translate_address(&mut eth_packet[ETHER_IP_DST_ADDR], src_subnet, dst_subnet);
                if translated {
                    compute_ipv4_checksum_in_place(&mut eth_packet[14..]);
                }
                const ETHER_IP_CHECKSUM: std::ops::Range<usize> = (14+10)..(14+12);
                eth_packet[ETHER_IP_CHECKSUM].copy_from_slice(&[0, 0]);
            }
        }
        IpPacket::V6(_pkt) => {
            const ETHER_TYPE_IPV6: &[u8; 2] = &[0x86, 0xdd];
            eth_packet[EtherField::ETHER_TYPE].copy_from_slice(ETHER_TYPE_IPV6);
        }
    };
    Ok(eth_packet)
}

pub fn compute_ipv4_checksum_in_place(bytes: &mut [u8]) {
    let packet_len = IpV4Packet::read_header_len(bytes);
    if bytes.len() < packet_len {
        log::warn!("Error when computing IPv4 checksum: Packet too short. Packet length {}", bytes.len());
        return;
    }

    let mut sum_f: u32 = 0;
    for i in 0..(packet_len/2) {
        let byte_no = i * 2;
        if byte_no == 10 {
            //do not add checksum field
            continue;
        }
        let u16val = u16::from_be_bytes([bytes[byte_no], bytes[byte_no + 1]]);
        sum_f += u16val as u32;
    }
    while sum_f >> 16 != 0 {
        sum_f = (sum_f >> 16) + (sum_f & 0xffff);
    }
    let sum_f = (sum_f ^ 0xffff) as u16;
    bytes[IpV4Field::CHECKSUM].copy_from_slice( &u16::to_be_bytes(sum_f));


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
            IpPacket::V4(_pkt) => {
                if let (Some(src_subnet), Some(dst_subnet)) = (src_subnet, dst_subnet) {
                    let mut translated = false;
                    translated |= translate_address(&mut ip_frame[IpV4Field::SRC_ADDR], src_subnet, dst_subnet);
                    translated |= translate_address(&mut ip_frame[IpV4Field::DST_ADDR], src_subnet, dst_subnet);
                    if translated {
                        compute_ipv4_checksum_in_place(ip_frame);
                    }
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
    use etherparse::packet_filter::ElementFilter::No;
    use super::*;

    #[test]
    fn test_packet_ether_to_ip() {
        let mut valid_ether_packet = hex::decode("51bd2c1e5c202423d4418ef108004500002800010000401175ba0d0f1112717375765b941a850014476f48656c6c6f205061636b6574").unwrap();
        let valid_ip_packet = hex::decode(
            "4500002800010000401175ba0d0f1112717375765b941a850014476f48656c6c6f205061636b6574",
        )
            .unwrap();

        assert_eq!(
            hex::encode(valid_ip_packet),
            hex::encode(packet_ether_to_ip_slice(valid_ether_packet.as_mut_slice(), None, None).unwrap())
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
            hex::encode(packet_ip_wrap_to_ether(&valid_ip_packet, None, None, None, None).unwrap())
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

    #[test]
    fn test_packet_translation() {
        {
            let packet_ether = hex::decode("a09fde7187fea09fde7187fe08004500002800010000401175ba0d0f1112717375765b941a850014476f48656c6c6f205061636b6574").unwrap();
            let packet_ip_after_translation = hex::decode("450000280001000040116fb511121314717375765b941a850014416a48656c6c6f205061636b6574").unwrap();

        }

    }
}
