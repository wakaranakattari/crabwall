//! Test packet builders. Available to this crate's own tests and,
//! via the `test-util` feature, to downstream test, fuzz-seed and
//! benchmark code. Not part of the runtime API.
//!
//! Each builder constructs a minimal but fully well-formed packet and
//! therefore doubles as executable documentation of the exact layout
//! the corresponding parser expects. Fuzz seeds in `fuzz/seeds/` are
//! derived from these same shapes.

/// Build a minimal TLS ClientHello carrying `sni`.
/// Also documents the exact layout [`crate::sni::extract_sni`] expects.
pub fn build_client_hello(sni: &str) -> Vec<u8> {
    let mut hello = Vec::new();
    hello.extend_from_slice(&[0x03, 0x03]); // client_version TLS1.2
    hello.extend_from_slice(&[0xAA; 32]); // random
    hello.push(0x00); // session_id empty
    hello.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // 1 cipher suite
    hello.push(0x01); // compression_methods len
    hello.push(0x00); // null compression
                      // extensions
    let mut exts = Vec::new();
    let name = sni.as_bytes();
    let mut sn = Vec::new();
    let entry_len = 1 + 2 + name.len();
    sn.extend_from_slice(&(entry_len as u16).to_be_bytes());
    sn.push(0x00); // host_name
    sn.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sn.extend_from_slice(name);
    exts.extend_from_slice(&[0x00, 0x00]); // extension_type server_name
    exts.extend_from_slice(&(sn.len() as u16).to_be_bytes());
    exts.extend_from_slice(&sn);
    hello.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    hello.extend_from_slice(&exts);
    // handshake header
    let mut hs = vec![0x01];
    let l = hello.len();
    hs.push((l >> 16) as u8);
    hs.push((l >> 8) as u8);
    hs.push(l as u8);
    hs.extend_from_slice(&hello);
    // record header
    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

/// Build a minimal DNS response: `example.com -> 93.184.216.34`.
pub fn test_dns_response() -> Vec<u8> {
    fn encode_name(buf: &mut Vec<u8>, name: &str) {
        for part in name.split('.') {
            buf.push(part.len() as u8);
            buf.extend_from_slice(part.as_bytes());
        }
        buf.push(0);
    }
    let mut m = Vec::new();
    m.extend_from_slice(&[
        0x12, 0x34, // id
        0x81, 0x80, // flags: response, no error
        0x00, 0x01, // qdcount
        0x00, 0x01, // ancount
        0x00, 0x00, // nscount
        0x00, 0x00, // arcount
    ]);
    encode_name(&mut m, "example.com");
    m.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A IN
                                                    // Answer: pointer to offset 12 (the qname), A, 60s ttl, 4 bytes.
    m.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01]);
    m.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C, 0x00, 0x04]);
    m.extend_from_slice(&[93, 184, 216, 34]);
    m
}
