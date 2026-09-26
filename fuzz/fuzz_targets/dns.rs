#![no_main]
use crabwall_packet::dns_parse::parse_dns_response;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Must never panic or OOM on adversarial input; results are advisory.
    let pairs = parse_dns_response(data);
    // Parser guarantees protocol bounds (253-char names max).
    for (ip, domain) in &pairs {
        assert!(ip.len() < 64 && domain.len() <= 253);
    }
});
