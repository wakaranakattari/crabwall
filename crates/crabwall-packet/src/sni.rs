//! TLS ClientHello SNI extractor.
//!
//! The Server Name Indication (RFC 6066, carried in the ClientHello
//! extensions of TLS 1.0-1.3 per RFC 5246 and successors) names the
//! domain a client wants to talk to before encryption starts. For a
//! passive firewall this is the single most valuable cleartext signal
//! on port 443: it attributes HTTPS connections to domains even when
//! DNS itself is encrypted (DoH/DoT) and therefore invisible to the
//! packet sniffer. Known blind spot, documented honestly: Encrypted
//! Client Hello (ECH) encrypts the SNI as well, and there is no passive
//! countermeasure - see `docs/LIMITS.md`.
//!
//! The parser handles exactly one leading handshake record containing
//! one ClientHello, walking record header, handshake header, session id,
//! cipher suites, compression methods, and the extension list down to
//! the `server_name` extension (type 0x0000), returning its first
//! `host_name` entry. Anything else - wrong record type, truncation,
//! ServerHello, missing or empty extensions, non-UTF8 or overlong names -
//! yields None. The 255-octet cap mirrors the DNS name maximum; longer
//! inputs are malformed by construction and are refused rather than
//! passed into rules, logs, or the database.

/// Extract SNI hostname from bytes starting at a TLS record.
/// Only handles a single leading handshake record; anything else -> None.
pub fn extract_sni(payload: &[u8]) -> Option<String> {
    // TLS record header: type(1) version(2) length(2)
    if payload.len() < 5 || payload[0] != 0x16 {
        return None;
    }
    let rec_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    if payload.len() < 5 + rec_len {
        return None;
    }
    let body = &payload[5..5 + rec_len];
    // Handshake header: type(1) length(3)
    if body.len() < 4 || body[0] != 0x01 {
        return None;
    }
    let hs_len = ((body[1] as usize) << 16) | ((body[2] as usize) << 8) | body[3] as usize;
    if body.len() < 4 + hs_len {
        return None;
    }
    let mut cur = &body[4..4 + hs_len];
    // client_version(2) + random(32)
    cur = cur.get(2 + 32..)?;
    // session_id
    let sid_len = *cur.first()? as usize;
    cur = cur.get(1 + sid_len..)?;
    // cipher_suites
    if cur.len() < 2 {
        return None;
    }
    let cs_len = u16::from_be_bytes([cur[0], cur[1]]) as usize;
    cur = cur.get(2 + cs_len..)?;
    // compression_methods
    let cm_len = *cur.first()? as usize;
    cur = cur.get(1 + cm_len..)?;
    // extensions
    if cur.len() < 2 {
        return None;
    }
    let ext_total = u16::from_be_bytes([cur[0], cur[1]]) as usize;
    cur = cur.get(2..)?;
    cur = cur.get(..ext_total.min(cur.len()))?;
    while cur.len() >= 4 {
        let ext_type = u16::from_be_bytes([cur[0], cur[1]]);
        let ext_len = u16::from_be_bytes([cur[2], cur[3]]) as usize;
        cur = cur.get(4..)?;
        let data = cur.get(..ext_len.min(cur.len()))?;
        if ext_type == 0x0000 {
            // server_name_list: len(2) + entries(type(1) len(2) name)
            if data.len() >= 2 {
                let mut names = data.get(2..)?;
                while names.len() >= 3 {
                    let name_type = names[0];
                    let name_len = u16::from_be_bytes([names[1], names[2]]) as usize;
                    names = names.get(3..)?;
                    let name = names.get(..name_len.min(names.len()))?;
                    if name_type == 0 {
                        if let Ok(s) = std::str::from_utf8(name) {
                            // SNI is a DNS name: 255 octets max. Longer is
                            // malformed; refuse it rather than passing a
                            // giant string into rules and logs.
                            if !s.is_empty() && s.len() <= 255 {
                                return Some(s.to_string());
                            }
                        }
                        return None;
                    }
                    names = names.get(name_len.min(names.len())..)?;
                }
            }
            return None;
        }
        cur = cur.get(ext_len.min(cur.len())..)?;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::build_client_hello;

    #[test]
    fn extracts_sni() {
        let pkt = build_client_hello("tracker.example.com");
        assert_eq!(extract_sni(&pkt).as_deref(), Some("tracker.example.com"));
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(extract_sni(&[]), None);
        assert_eq!(extract_sni(&[0x15, 0x03, 0x01, 0x00, 0x00]), None); // alert record
        assert_eq!(extract_sni(&[0x16, 0x03]), None); // truncated
                                                      // ServerHello type 0x02 must not parse as SNI.
        let mut pkt = build_client_hello("a.com");
        pkt[5] = 0x02;
        assert_eq!(extract_sni(&pkt), None);
    }

    #[test]
    fn oversized_sni_rejected() {
        let long = "a".repeat(300) + ".com";
        let pkt = build_client_hello(&long);
        assert_eq!(extract_sni(&pkt), None);
    }

    #[test]
    fn no_extensions_means_none() {
        // Minimal hello without extensions block.
        let mut hello = vec![0x03, 0x03];
        hello.extend_from_slice(&[0xBB; 32]);
        hello.push(0x00);
        hello.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        hello.push(0x01);
        hello.push(0x00);
        hello.extend_from_slice(&[0x00, 0x00]); // ext len 0
        let mut hs = vec![0x01, 0x00, 0x00, hello.len() as u8];
        hs.extend_from_slice(&hello);
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        assert_eq!(extract_sni(&rec), None);
    }
}
