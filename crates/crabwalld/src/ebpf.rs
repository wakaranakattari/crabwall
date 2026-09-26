//! eBPF connect-event stream.
//!
//! A tracepoint program (`tracepoint/syscalls/sys_enter_connect`, built
//! by `cargo xtask build-ebpf` from `crates/crabwall-ebpf`) reports every
//! `connect()` syscall with PID, family, port, and address through a
//! perf-event array, and [`EbpfReader`] streams those records into the
//! [`Correlator`]. The program is strictly observe-only - it returns 0
//! unconditionally and never touches verdicts; blocking stays with
//! NFQUEUE, attribution speed is the only job here. The tracepoint hook
//! was chosen over `cgroup_sock_addr` for two principled reasons:
//! sockaddr byte order is POSIX-defined (ports and addresses are network
//! order, no guessing), and attaching needs no cgroupfs layout, so it
//! works identically in containers.
//!
//! Every failure mode degrades to the poll sensor: missing object, no
//! privileges (map creation fails with EPERM after successful parsing,
//! which still proves the object well-formed), no tracefs, perf setup
//! errors. The loader state (maps, program, link) is intentionally
//! leaked, because all three must outlive the daemon and there is no
//! meaningful shutdown order for them.
//!
//! Wire layout, mirrored by `ConnectEvent` in the eBPF crate and pinned
//! by unit tests on both sides: pid LE32, family u8, pad u8, dport LE16
//! in host order (converted in-BPF from network order), address 16 bytes
//! with IPv4 occupying the first 4 octets in network order. 24 bytes total.

use crate::correlator::{Correlator, FlowKey};
use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::Bpf;
use bytes::BytesMut;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// A decoded connect event: pid, destination, destination port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectEvent {
    /// Connecting process id.
    pub pid: u32,
    /// Destination address.
    pub dst: IpAddr,
    /// Destination port, host order.
    pub dport: u16,
}

/// Decode one 24-byte perf record. `None` on any malformation.
pub fn decode_event(buf: &[u8]) -> Option<ConnectEvent> {
    if buf.len() < 24 {
        return None;
    }
    let pid = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let family = buf[4];
    let dport = u16::from_le_bytes([buf[6], buf[7]]);
    let dst = match family {
        2 => IpAddr::V4(Ipv4Addr::new(buf[8], buf[9], buf[10], buf[11])),
        10 => {
            let mut b = [0u8; 16];
            b.copy_from_slice(&buf[8..24]);
            IpAddr::V6(Ipv6Addr::from(b))
        }
        _ => return None,
    };
    if pid == 0 || dport == 0 {
        return None;
    }
    Some(ConnectEvent { pid, dst, dport })
}

/// Probe result for the eBPF program object. `Available` means parsed
/// and loadable here; anything else carries the human reason and selects
/// the poll sensor. Note the unprivileged subtlety: parsing succeeds and
/// map creation fails with EPERM, which still proves the object is
/// well-formed - the two failure classes are deliberately not distinguished.
#[derive(Debug)]
pub enum EbpfSensor {
    Available,
    Unavailable(String),
}

impl EbpfSensor {
    pub fn probe() -> Self {
        let obj = object_path();
        if !std::path::Path::new(&obj).exists() {
            return EbpfSensor::Unavailable(format!("no ebpf object at {obj}"));
        }
        // Parse-check without privileges: aya-obj parsing runs before any
        // bpf() syscall, so EPERM here still means "well-formed object".
        match aya::Bpf::load_file(&obj) {
            Ok(_) => EbpfSensor::Available,
            Err(e) => {
                let s = format!("{e:#}");
                // Unprivileged parse probes fail at map creation, not at
                // parsing; both mean "not loadable here", with a hint.
                EbpfSensor::Unavailable(s)
            }
        }
    }
}

/// Path to the compiled program object.
pub fn object_path() -> String {
    std::env::var("CRABWALL_EBPF_OBJ")
        .unwrap_or_else(|_| "target/bpfel-unknown-none/release/crabwall-ebpf".to_string())
}

/// Streaming reader: attaches the tracepoint and feeds the correlator.
/// See module docs for lifetime reasoning (intentional leak).
pub struct EbpfReader;

impl EbpfReader {
    pub fn start(correlator: Arc<Correlator>) -> anyhow::Result<()> {
        let obj = object_path();
        let mut bpf = Bpf::load_file(&obj)?;
        let prog: &mut TracePoint = bpf
            .program_mut("crabwall_connect")
            .ok_or_else(|| anyhow::anyhow!("program crabwall_connect not found"))?
            .try_into()?;
        prog.load()?;
        // The link is owned by the program data inside `bpf`;
        // leaking `bpf` below keeps the attach alive.
        let _id = prog.attach("syscalls", "sys_enter_connect")?;
        let map = bpf
            .take_map("EVENTS")
            .ok_or_else(|| anyhow::anyhow!("map EVENTS not found"))?;
        let mut perf = AsyncPerfEventArray::try_from(map)?;
        for cpu in online_cpus()? {
            let mut buf = perf.open(cpu, None)?;
            let correlator = Arc::clone(&correlator);
            tokio::spawn(async move {
                let mut buffers = (0..8)
                    .map(|_| BytesMut::with_capacity(1024))
                    .collect::<Vec<_>>();
                loop {
                    let events = match buf.read_events(&mut buffers).await {
                        Ok(e) => e,
                        Err(e) => {
                            warn!("ebpf perf read failed: {e:#}");
                            return;
                        }
                    };
                    if events.lost > 0 {
                        debug!("ebpf perf lost {} events (reader too slow)", events.lost);
                    }
                    for buf in buffers.iter().take(events.read) {
                        if let Some(ev) = decode_event(buf) {
                            // No source port at connect-enter time; the
                            // queue path resolves sport-0 keys fuzzily.
                            correlator.insert(FlowKey::of(6, ev.dst, ev.dport, 0), ev.pid);
                        }
                    }
                }
            });
        }
        Box::leak(Box::new(bpf));
        info!("ebpf events: streaming connect feed into correlator");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(pid: u32, family: u8, dport: u16, addr: &[u8]) -> Vec<u8> {
        let mut b = Vec::with_capacity(24);
        b.extend_from_slice(&pid.to_le_bytes());
        b.push(family);
        b.push(0);
        b.extend_from_slice(&dport.to_le_bytes());
        let mut a = [0u8; 16];
        a[..addr.len().min(16)].copy_from_slice(&addr[..addr.len().min(16)]);
        b.extend_from_slice(&a);
        b
    }

    #[test]
    fn decodes_v4_and_v6() {
        let ev = decode_event(&record(4242, 2, 443, &[93, 184, 216, 34])).expect("v4");
        assert_eq!(ev.pid, 4242);
        assert_eq!(ev.dst.to_string(), "93.184.216.34");
        assert_eq!(ev.dport, 443);
        let ev = decode_event(&record(
            7,
            10,
            80,
            &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        ))
        .expect("v6");
        assert_eq!(ev.dst.to_string(), "2001:db8::1");
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(decode_event(&[]), None);
        assert_eq!(decode_event(&[0u8; 23]), None);
        assert_eq!(decode_event(&record(0, 2, 443, &[1, 2, 3, 4])), None); // pid 0
        assert_eq!(decode_event(&record(1, 2, 0, &[1, 2, 3, 4])), None); // port 0
        assert_eq!(decode_event(&record(1, 1, 80, &[1, 2, 3, 4])), None); // AF_UNIX
    }

    #[test]
    fn probe_missing_object_is_unavailable_not_panic() {
        std::env::set_var("CRABWALL_EBPF_OBJ", "/nonexistent/crabwall-ebpf-obj");
        let s = EbpfSensor::probe();
        assert!(matches!(s, EbpfSensor::Unavailable(_)));
        std::env::remove_var("CRABWALL_EBPF_OBJ");
    }
}
