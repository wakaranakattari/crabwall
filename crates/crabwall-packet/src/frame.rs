//! IP frame dissection for the passive sniffer and the NFQUEUE path.
//!
//! Two entry points serve two consumers. [`parse_frame`] strips Ethernet
//! framing (including up to two 802.1Q/QinQ VLAN tags) and dispatches to
//! IPv4 (RFC 791) or IPv6 (RFC 8200); it feeds the AF_PACKET sniffer,
//! which observes full link-layer frames. [`parse_ip_packet`] handles a
//! bare L3 packet with no Ethernet header, which is exactly what NFQUEUE
//! delivers as `NFQA_PAYLOAD`; it feeds the verdict path, which needs the
//! 5-tuple ([`IpFlow`]) rather than names.
//!
//! From either form only two facts are extracted, because only two facts
//! are learnable passively: DNS response payloads (UDP with source port
//! 53 - responses bind names to addresses, queries do not) and TLS
//! ClientHello payloads (TCP with destination port 443, handed to the
//! SNI extractor together with the packet destination). Everything else -
//! non-TCP/UDP protocols, unconnected UDP, fragmented packets without an
//! L4 header, unknown IPv6 extension chains - returns None. The IPv6
//! extension walk is bounded to 8 headers; fragments are skipped outright
//! rather than reassembled, since a firewall must decide on first sight
//! and reassembly would be both slow and spoofable.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// What a dissected packet teaches us.
#[derive(Debug, PartialEq, Eq)]
pub enum Captured {
    /// Raw DNS message (UDP source port 53).
    DnsMessage(Vec<u8>),
    /// TLS payload heading to 443, with the packet's destination.
    TlsHello {
        /// Destination IP of the packet.
        dst_ip: String,
        /// TCP payload starting at the TLS record.
        payload: Vec<u8>,
    },
}

/// A bare L3 packet's 5-tuple. Used by the NFQUEUE verdict path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IpFlow {
    /// 6 for TCP, 17 for UDP.
    pub proto: u8,
    /// Source address.
    pub src: IpAddr,
    /// Destination address.
    pub dst: IpAddr,
    /// Source port.
    pub sport: u16,
    /// Destination port.
    pub dport: u16,
}

/// Parse one Ethernet frame; extract DNS payloads and TLS hellos.
pub fn parse_frame(frame: &[u8]) -> Option<Captured> {
    if frame.len() < 14 {
        return None;
    }
    let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let mut off = 14usize;
    // Up to two VLAN tags (802.1Q / QinQ).
    for _ in 0..2 {
        if ethertype == 0x8100 || ethertype == 0x88A8 {
            let tag = frame.get(off..off + 4)?;
            ethertype = u16::from_be_bytes([tag[2], tag[3]]);
            off += 4;
        } else {
            break;
        }
    }
    match ethertype {
        0x0800 => parse_ipv4(frame.get(off..)?),
        0x86DD => parse_ipv6(frame.get(off..)?),
        _ => None,
    }
}

/// Parse a bare IPv4/IPv6 packet (no Ethernet header).
/// Returns the 5-tuple for TCP/UDP, `None` otherwise.
pub fn parse_ip_packet(packet: &[u8]) -> Option<IpFlow> {
    if packet.is_empty() {
        return None;
    }
    match packet[0] >> 4 {
        4 => flow_ipv4(packet),
        6 => flow_ipv6(packet),
        _ => None,
    }
}

fn parse_ipv4(ip: &[u8]) -> Option<Captured> {
    if ip.len() < 20 {
        return None;
    }
    let ihl = (ip[0] & 0x0F) as usize * 4;
    if ihl < 20 || ip.len() < ihl {
        return None;
    }
    // Non-first fragments carry no L4 header.
    if u16::from_be_bytes([ip[6], ip[7]]) & 0x1FFF != 0 {
        return None;
    }
    let dst = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]).to_string();
    parse_transport(ip[9], dst, ip.get(ihl..)?)
}

fn parse_ipv6(ip: &[u8]) -> Option<Captured> {
    let (proto, dst, l4) = split_ipv6(ip)?;
    parse_transport(proto, dst.to_string(), l4)
}

/// Split an IPv6 packet into (protocol, dst, L4 payload),
/// walking extension headers with a bounded loop.
fn split_ipv6(ip: &[u8]) -> Option<(u8, Ipv6Addr, &[u8])> {
    if ip.len() < 40 || ip[0] >> 4 != 6 {
        return None;
    }
    let dst = Ipv6Addr::from(u16_array(&ip[24..40]));
    let mut next = ip[6];
    let mut off = 40usize;
    for _ in 0..8 {
        match next {
            6 | 17 => return Some((next, dst, ip.get(off..)?)),
            // Hop-by-hop, routing, dest-opts: len unit is 8 bytes.
            0 | 43 | 60 => {
                let hdr = ip.get(off..off + 8)?;
                next = hdr[0];
                off += (hdr[1] as usize + 1) * 8;
            }
            // Fragments (and anything unknown): no L4 header to read.
            _ => return None,
        }
    }
    None
}

fn u16_array(b: &[u8]) -> [u16; 8] {
    let mut out = [0u16; 8];
    for (i, s) in out.iter_mut().enumerate() {
        *s = u16::from_be_bytes([b[2 * i], b[2 * i + 1]]);
    }
    out
}

/// Shared TCP/UDP dispatch for both families.
fn parse_transport(proto: u8, dst: String, l4: &[u8]) -> Option<Captured> {
    match proto {
        // UDP: only DNS *responses* teach us ip -> domain.
        17 => {
            if l4.len() < 8 {
                return None;
            }
            if u16::from_be_bytes([l4[0], l4[1]]) != 53 {
                return None;
            }
            Some(Captured::DnsMessage(l4.get(8..)?.to_vec()))
        }
        // TCP: ClientHello heading to 443 carries SNI.
        6 => {
            if l4.len() < 20 {
                return None;
            }
            if u16::from_be_bytes([l4[2], l4[3]]) != 443 {
                return None;
            }
            let data_off = ((l4[12] >> 4) as usize) * 4;
            if data_off < 20 {
                return None;
            }
            let payload = l4.get(data_off..)?.to_vec();
            if payload.is_empty() {
                return None;
            }
            Some(Captured::TlsHello {
                dst_ip: dst,
                payload,
            })
        }
        _ => None,
    }
}

fn flow_ipv4(packet: &[u8]) -> Option<IpFlow> {
    if packet.len() < 20 {
        return None;
    }
    let ihl = (packet[0] & 0x0F) as usize * 4;
    if ihl < 20 || packet.len() < ihl {
        return None;
    }
    if u16::from_be_bytes([packet[6], packet[7]]) & 0x1FFF != 0 {
        return None;
    }
    flow_transport(
        packet[9],
        IpAddr::V4(Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        )),
        IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        )),
        packet.get(ihl..)?,
    )
}

fn flow_ipv6(packet: &[u8]) -> Option<IpFlow> {
    let (proto, dst, l4) = split_ipv6(packet)?;
    let src = Ipv6Addr::from(u16_array(&packet[8..24]));
    flow_transport(proto, IpAddr::V6(src), IpAddr::V6(dst), l4)
}

fn flow_transport(proto: u8, src: IpAddr, dst: IpAddr, l4: &[u8]) -> Option<IpFlow> {
    let (sport, dport) = match proto {
        6 | 17 => {
            if l4.len() < 4 {
                return None;
            }
            (
                u16::from_be_bytes([l4[0], l4[1]]),
                u16::from_be_bytes([l4[2], l4[3]]),
            )
        }
        _ => return None,
    };
    Some(IpFlow {
        proto,
        src,
        dst,
        sport,
        dport,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{build_client_hello, test_dns_response};

    fn eth_ipv4_udp(dns: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&[0x08, 0x00]); // IPv4
        let total = (20 + 8 + dns.len()) as u16;
        let mut ip = vec![
            0x45, 0x00, 0, 0, 0x00, 0x00, 0x00, 0x00, 64, 17, 0x00, 0x00, 8, 8, 8, 8, 1, 2, 3, 4,
        ];
        ip[2..4].copy_from_slice(&total.to_be_bytes());
        f.extend_from_slice(&ip);
        let ulen = (8 + dns.len()) as u16;
        let mut udp = vec![0x00, 0x35, 0x00, 0x35]; // sport = dport = 53
        udp.extend_from_slice(&ulen.to_be_bytes());
        udp.extend_from_slice(&[0x00, 0x00]);
        f.extend_from_slice(&udp);
        f.extend_from_slice(dns);
        f
    }

    fn eth_ipv4_tcp(payload: &[u8], dst: [u8; 4], dport: u16) -> Vec<u8> {
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&[0x08, 0x00]);
        let total = (20 + 20 + payload.len()) as u16;
        let mut ip = vec![0x45, 0x00, 0, 0, 0x00, 0x00, 0x00, 0x00, 64, 6, 0x00, 0x00];
        ip.extend_from_slice(&[192, 168, 1, 5]);
        ip.extend_from_slice(&dst);
        ip[2..4].copy_from_slice(&total.to_be_bytes());
        f.extend_from_slice(&ip);
        let mut tcp = vec![
            0x12, 0x34, 0, 0, // dport filled below
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x18, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        tcp[2..4].copy_from_slice(&dport.to_be_bytes());
        f.extend_from_slice(&tcp);
        f.extend_from_slice(payload);
        f
    }

    fn eth_ipv6_udp(dns: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&[0x86, 0xDD]); // IPv6
        let mut ip = vec![0x60, 0x00, 0x00, 0x00];
        let plen = (8 + dns.len()) as u16;
        ip.extend_from_slice(&plen.to_be_bytes());
        ip.extend_from_slice(&[17, 64]); // UDP, hop limit
        ip.extend_from_slice(&[
            0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88,
        ]); // src 2001:4860:4860::8888
        ip.extend_from_slice(&[
            0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ]); // dst 2001:db8::1
        f.extend_from_slice(&ip);
        let mut udp = vec![0x00, 0x35, 0x00, 0x35];
        udp.extend_from_slice(&plen.to_be_bytes());
        udp.extend_from_slice(&[0x00, 0x00]);
        f.extend_from_slice(&udp);
        f.extend_from_slice(dns);
        f
    }

    #[test]
    fn captures_dns_response() {
        let dns = test_dns_response();
        match parse_frame(&eth_ipv4_udp(&dns)) {
            Some(Captured::DnsMessage(m)) => assert_eq!(m, dns),
            other => panic!("expected dns, got {other:?}"),
        }
    }

    #[test]
    fn captures_dns_over_ipv6() {
        let dns = test_dns_response();
        match parse_frame(&eth_ipv6_udp(&dns)) {
            Some(Captured::DnsMessage(m)) => assert_eq!(m, dns),
            other => panic!("expected dns, got {other:?}"),
        }
    }

    #[test]
    fn dns_request_direction_ignored() {
        // dport 53 but sport != 53: a query, teaches nothing.
        let mut f = eth_ipv4_udp(&test_dns_response());
        f[14 + 20] = 0x04; // sport 1234
        f[14 + 21] = 0xD2;
        assert_eq!(parse_frame(&f), None);
    }

    #[test]
    fn captures_tls_hello_with_dst() {
        let hello = build_client_hello("tracker.example.com");
        match parse_frame(&eth_ipv4_tcp(&hello, [93, 184, 216, 34], 443)) {
            Some(Captured::TlsHello { dst_ip, payload }) => {
                assert_eq!(dst_ip, "93.184.216.34");
                assert_eq!(payload, hello);
            }
            other => panic!("expected tls hello, got {other:?}"),
        }
    }

    #[test]
    fn non_443_tls_ignored() {
        let hello = build_client_hello("a.com");
        assert_eq!(parse_frame(&eth_ipv4_tcp(&hello, [1, 1, 1, 1], 8443)), None);
    }

    #[test]
    fn vlan_tagged_dns_parses() {
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&[0x81, 0x00, 0x00, 0x01, 0x08, 0x00]);
        f.extend_from_slice(&eth_ipv4_udp(&test_dns_response())[14..]);
        assert!(matches!(parse_frame(&f), Some(Captured::DnsMessage(_))));
    }

    #[test]
    fn fragments_and_truncation_rejected() {
        let mut f = eth_ipv4_udp(&test_dns_response());
        f[14 + 7] = 0x01; // fragment offset != 0: no L4 header here
        assert_eq!(parse_frame(&f), None);
        assert_eq!(parse_frame(&[0u8; 10]), None);
        assert_eq!(parse_frame(&[0u8; 14]), None);
        assert_eq!(parse_ip_packet(&[]), None);
    }

    #[test]
    fn flow_parses_v4_and_v6() {
        let dns = test_dns_response();
        let v4 = eth_ipv4_udp(&dns);
        let flow = parse_ip_packet(&v4[14..]).expect("v4 flow");
        assert_eq!(flow.proto, 17);
        assert_eq!(flow.sport, 53);
        assert_eq!(flow.dport, 53);
        assert_eq!(flow.dst.to_string(), "1.2.3.4");
        let v6 = eth_ipv6_udp(&dns);
        let flow = parse_ip_packet(&v6[14..]).expect("v6 flow");
        assert_eq!(flow.proto, 17);
        assert_eq!(flow.dst.to_string(), "2001:db8::1");
        let tls = build_client_hello("a.com");
        let frame = eth_ipv4_tcp(&tls, [9, 9, 9, 9], 443);
        let flow = parse_ip_packet(&frame[14..]).expect("tcp flow");
        assert_eq!((flow.proto, flow.dport), (6, 443));
    }
}
