//! Packet parsing primitives: DNS, TLS SNI, IP frame dissection.
//!
//! This crate is deliberately pure: every function takes bytes and returns
//! plain data, with no I/O, no threads, and no global state. Purity serves
//! three goals. First, testability: every parser is covered by unit tests
//! with hand-built packets plus property-style fuzzing (see `fuzz/`).
//! Second, reuse: the same code feeds the AF_PACKET sniffer, the NFQUEUE
//! verdict path, and the `cargo xtask bench` smoke benchmarks. Third,
//! safety: untrusted network bytes are dissected here and nowhere else,
//! so the audit surface for malformed input is exactly these modules.
//!
//! Shared defensive rules across all parsers: bounds-check every read
//! (indexing untrusted slices never panics - `Option` propagation
//! instead), cap all outputs at protocol maxima (DNS names at 253 octets
//! per RFC 1035 section 2.3.4, SNI hostnames at 255 octets), bound every
//! loop that follows compression pointers or extension headers, and
//! reject rather than guess on any malformation.

#![warn(missing_docs)]

pub mod dns_parse;
pub mod frame;
pub mod sni;

#[cfg(any(test, feature = "test-util"))]
pub mod test_util;
