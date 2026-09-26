#![no_main]
use crabwall_packet::sni::extract_sni;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Parser enforces the 255-octet SNI maximum itself.
    if let Some(name) = extract_sni(data) {
        assert!(name.len() <= 255);
    }
});
