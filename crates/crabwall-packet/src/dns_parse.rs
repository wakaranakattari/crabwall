//! DNS response parser (RFC 1035, section 4.1).
//!
//! Extracts (ip, domain) pairs from A and AAAA answer records so the
//! daemon can learn address-to-name mappings passively, without issuing
//! any query of its own. Only responses are interesting: queries name a
//! domain without binding it to an address. Name decoding handles label
//! compression pointers (section 4.1.4) with a hard bound of 10 jumps,
//! which provably terminates even on malicious pointer cycles, and
//! rejects names longer than the 253-octet protocol maximum (such length
//! can only arise from compression abuse, never from legitimate traffic).

/// Parse a DNS message, return (ip_string, domain) for each A/AAAA answer.
pub fn parse_dns_response(msg: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if msg.len() < 12 {
        return out;
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    if an > 64 {
        return out;
    }
    let mut off = 12usize;
    // Skip questions.
    for _ in 0..qd {
        if skip_name(msg, &mut off).is_err() {
            return out;
        }
        off = match off.checked_add(4) {
            Some(o) if o <= msg.len() => o,
            _ => return out,
        };
    }
    for _ in 0..an {
        let name = match read_name(msg, &mut off) {
            Ok(n) => n,
            Err(_) => break,
        };
        if off + 10 > msg.len() {
            break;
        }
        let rtype = u16::from_be_bytes([msg[off], msg[off + 1]]);
        let rdlen = u16::from_be_bytes([msg[off + 8], msg[off + 9]]) as usize;
        off += 10;
        let rdata = match msg.get(off..off + rdlen) {
            Some(r) => r,
            None => break,
        };
        off += rdlen;
        match (rtype, rdlen) {
            (1, 4) => {
                let ip = format!("{}.{}.{}.{}", rdata[0], rdata[1], rdata[2], rdata[3]);
                out.push((ip, name));
            }
            (28, 16) => {
                let mut segs = [0u16; 8];
                for (i, s) in segs.iter_mut().enumerate() {
                    *s = u16::from_be_bytes([rdata[2 * i], rdata[2 * i + 1]]);
                }
                let ip = segs
                    .iter()
                    .map(|s| format!("{s:x}"))
                    .collect::<Vec<_>>()
                    .join(":");
                out.push((ip, name));
            }
            _ => {}
        }
    }
    out
}

fn skip_name(msg: &[u8], off: &mut usize) -> Result<(), ()> {
    let mut jumps = 0;
    loop {
        let b = *msg.get(*off).ok_or(())?;
        if b & 0xC0 == 0xC0 {
            // Compressed pointer: two bytes, terminates the name here.
            if *off + 2 > msg.len() {
                return Err(());
            }
            *off += 2;
            jumps += 1;
            if jumps > 10 {
                return Err(());
            }
            // Pointer terminates this name in question section.
            return Ok(());
        } else if b == 0 {
            *off += 1;
            return Ok(());
        } else {
            let len = b as usize;
            if len > 63 || *off + 1 + len > msg.len() {
                return Err(());
            }
            *off += 1 + len;
        }
        if jumps > 10 {
            return Err(());
        }
    }
}

fn read_name(msg: &[u8], off: &mut usize) -> Result<String, ()> {
    let mut labels = Vec::new();
    let mut cur = *off;
    let mut jumped = false;
    let mut jumps = 0;
    loop {
        let b = *msg.get(cur).ok_or(())?;
        if b & 0xC0 == 0xC0 {
            let p1 = *msg.get(cur + 1).ok_or(())? as usize;
            let target = ((b as usize & 0x3F) << 8) | p1;
            if target >= msg.len() {
                return Err(());
            }
            if !jumped {
                *off = cur + 2;
                jumped = true;
            }
            cur = target;
            jumps += 1;
            if jumps > 10 {
                return Err(());
            }
        } else if b == 0 {
            if !jumped {
                *off = cur + 1;
            }
            break;
        } else {
            let len = b as usize;
            if len > 63 {
                return Err(());
            }
            let end = cur + 1 + len;
            if end > msg.len() {
                return Err(());
            }
            let label = std::str::from_utf8(&msg[cur + 1..end]).map_err(|_| ())?;
            labels.push(label.to_string());
            cur = end;
            if !jumped {
                *off = cur;
            }
        }
    }
    let name = labels.join(".");
    // DNS names cap at 253 octets; longer only arises from compression
    // abuse. Refuse rather than feeding giants downstream.
    if name.len() > 253 {
        return Err(());
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::test_dns_response;

    #[test]
    fn parses_a_answer() {
        let out = parse_dns_response(&test_dns_response());
        assert_eq!(
            out,
            vec![("93.184.216.34".to_string(), "example.com".to_string())]
        );
    }

    #[test]
    fn oversized_name_rejected() {
        // Five 60-char labels = 304 chars: over the 253 DNS maximum.
        let mut m = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        m.extend_from_slice(&[0xC0, 0x0C]);
        for _ in 0..5 {
            m.push(60);
            m.extend_from_slice(&[b'x'; 60]);
        }
        m.push(0);
        m.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04]);
        m.extend_from_slice(&[1, 2, 3, 4]);
        assert!(parse_dns_response(&m).is_empty());
    }

    #[test]
    fn rejects_truncated() {
        assert!(parse_dns_response(&[]).is_empty());
        assert!(parse_dns_response(&[0u8; 11]).is_empty());
        let mut pkt = test_dns_response();
        pkt.truncate(pkt.len() - 2);
        assert!(parse_dns_response(&pkt).is_empty());
    }
}
