#![no_main]
use crabwall_packet::frame::{parse_frame, parse_ip_packet};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_frame(data);
    let _ = parse_ip_packet(data);
});
