//! Passive packet sniffer: learns `ip -> domain` from DNS responses
//! (UDP sport 53) and TLS ClientHello SNI (TCP dport 443) via AF_PACKET.
//!
//! A raw packet socket observes copies of real traffic without
//! intercepting it: the sniffer can never block, delay, or alter a
//! packet, which makes it the safest sensor in the system to reason
//! about. Each captured frame goes through [`crabwall_packet::frame`]
//! dissection (fuzzed, no I/O in that crate) and any learned mapping is
//! inserted into the shared [`DnsCache`], where the poll path, the queue
//! fast path, and the SNI learner all benefit from everyone else's
//! observations.
//!
//! Best-effort by design: opening the socket needs `CAP_NET_RAW` (root
//! normally has it). Failure disables the sniffer with one warning while
//! the daemon keeps working on hosts-file and PTR data. The capture loop
//! runs on a dedicated blocking thread (raw `recv` has no async form
//! worth the wrapper), sleeps briefly on persistent errors instead of
//! busy-spinning, and only ever touches the cache through its mutex.

use crate::dns::DnsCache;
use crabwall_packet::frame::{parse_frame, Captured};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::time::Duration;
use tracing::warn;

/// Owned AF_PACKET capture handle. Ownership is the safety argument:
/// the fd closes itself on drop, can never leak across restarts, and
/// `spawn` moves it into exactly one thread, so no sharing discipline
/// is needed at all.
pub struct Sniffer {
    fd: OwnedFd,
}

impl Sniffer {
    /// Open an `AF_PACKET/SOCK_RAW` capture socket. Returns `None`
    /// (with a warning) when unavailable instead of failing the daemon.
    pub fn try_open() -> Option<Self> {
        // SAFETY: socket() with constant domain/type/protocol; the fd is
        // checked for errors and immediately wrapped in OwnedFd.
        let raw = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                (libc::ETH_P_ALL as u16).to_be() as libc::c_int,
            )
        };
        if raw < 0 {
            warn!(
                "packet sniffer disabled: {}",
                std::io::Error::last_os_error()
            );
            return None;
        }
        // SAFETY: raw is a valid, newly owned fd (socket succeeded).
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        Some(Self { fd })
    }

    /// Run the capture loop on a blocking thread; feeds the DNS cache.
    pub fn spawn(self, dns: Arc<DnsCache>) {
        std::thread::Builder::new()
            .name("crabwall-sniff".into())
            .spawn(move || self.run(dns))
            .ok();
    }

    fn run(self, dns: Arc<DnsCache>) {
        let mut buf = vec![0u8; 65535];
        loop {
            // SAFETY: buf is valid for its length; fd stays open for
            // the lifetime of self.
            let n =
                unsafe { libc::recv(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                // Persistent errors (e.g. device down) must not busy-spin.
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            let frame = &buf[..n as usize];
            match parse_frame(frame) {
                Some(Captured::DnsMessage(msg)) => dns.learn_from_packet(&msg),
                Some(Captured::TlsHello { dst_ip, payload }) => {
                    dns.learn_from_tls(&dst_ip, &payload);
                }
                None => {}
            }
        }
    }
}
