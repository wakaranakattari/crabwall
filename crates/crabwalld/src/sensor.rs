//! Poll-based sensor. Watches `/proc/net/{tcp,tcp6,udp,udp6}` for new
//! remote endpoints and attributes them to PIDs via inode scan.
//!
//! The kernel publishes its socket tables as text, one line per socket
//! with hex-encoded addresses, a state column, and an inode. This module
//! parses those tables (see [`parse_table`], pure and unit-tested with
//! fixtures) and joins inodes to PIDs through [`enrich::inode_to_pid`].
//! TCP rows are filtered to ESTABLISHED and SYN_SENT: listeners teach
//! nothing about outbound traffic, and SYN_SENT is precisely the state
//! that matters for held first packets. UDP has no handshake state, so
//! only connected sockets (nonzero remote) are reported; bound-but-idle
//! sockets are skipped to keep the feed free of noise.
//!
//! The same tables back [`find_socket`]: given a queued packet's flow,
//! find the owning PID on demand, with local-port equality as the
//! disambiguator between parallel connections to one destination.
//!
//! Known limits: sub-second short connections can be missed between
//! polls, and the full `/proc` fd scan each round costs CPU under high
//! churn. The default 500ms poll interval keeps it usable on desktops;
//! the eBPF feed exists to close exactly this gap.

use crate::enrich;
use crabwall_common::Proto;
use crabwall_packet::frame::IpFlow;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, Clone)]
pub struct RawConnect {
    /// Owning PID at observation time; may be recycled by verdict time,
    /// which is why enrichment re-reads rather than trusts.
    pub pid: u32,
    /// Transport family as observed (TCP or connected UDP).
    pub proto: Proto,
    /// Local (source) port, for correlator keys.
    pub sport: u16,
    /// Local address as printed by the kernel table.
    pub src_ip: String,
    /// Remote address as printed by the kernel table.
    pub dst_ip: String,
    /// Remote port.
    pub dst_port: u16,
}

/// One socket-table row with both endpoints and its inode.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SockEntry {
    local_ip: String,
    local_port: u16,
    rem_ip: String,
    rem_port: u16,
    inode: u64,
}

/// Stateful poller: remembers every reported (remote, sport, inode)
/// tuple so each connection surfaces exactly once. Memory is bounded by
/// wholesale clear past 20k entries; the set holds no PIDs, only socket
/// identities, so clearing can never misattribute - at worst a connection
/// is reported twice across the clear boundary, and idempotent policy
/// absorbs duplicates.
#[derive(Default)]
pub struct ProcNetSensor {
    seen: HashSet<(String, u16, u16, u64)>,
}

impl ProcNetSensor {
    /// One poll round. Returns newly observed connections (TCP + connected UDP).
    pub fn poll(&mut self) -> Vec<RawConnect> {
        let mut out = Vec::new();
        let inode_pid = enrich::inode_to_pid();
        for (proto, path) in [
            (Proto::Tcp, "/proc/net/tcp"),
            (Proto::Tcp, "/proc/net/tcp6"),
            (Proto::Udp, "/proc/net/udp"),
            (Proto::Udp, "/proc/net/udp6"),
        ] {
            for entry in read_table(path, proto) {
                let key = (
                    entry.rem_ip.clone(),
                    entry.rem_port,
                    entry.local_port,
                    entry.inode,
                );
                if !self.seen.insert(key) {
                    continue;
                }
                if let Some(pid) = inode_pid.get(&entry.inode) {
                    out.push(RawConnect {
                        pid: *pid,
                        proto,
                        sport: entry.local_port,
                        src_ip: entry.local_ip,
                        dst_ip: entry.rem_ip,
                        dst_port: entry.rem_port,
                    });
                }
            }
        }
        // Bound memory: forget very old keys.
        if self.seen.len() > 20000 {
            self.seen.clear();
        }
        out
    }
}

/// Find the pid owning `flow` right now (queued-packet attribution).
/// Scans the socket tables for a matching local/remote pair.
pub fn find_socket(flow: &IpFlow) -> Option<u32> {
    let proto = match flow.proto {
        6 => Proto::Tcp,
        17 => Proto::Udp,
        _ => return None,
    };
    let tables = match proto {
        Proto::Tcp => ["/proc/net/tcp", "/proc/net/tcp6"],
        Proto::Udp => ["/proc/net/udp", "/proc/net/udp6"],
    };
    let dst = flow.dst.to_string();
    let inode = tables
        .into_iter()
        .flat_map(|path| read_table(path, proto))
        .find(|e| e.local_port == flow.sport && e.rem_ip == dst && e.rem_port == flow.dport)
        .map(|e| e.inode)?;
    if inode == 0 {
        return None;
    }
    enrich::inode_to_pid().get(&inode).copied()
}

/// Read + parse one table file; missing files (no v6) yield nothing.
fn read_table(path: &str, proto: Proto) -> Vec<SockEntry> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    parse_table(&text, path.ends_with('6'), proto)
}

/// Parse `/proc/net/{tcp,tcp6,udp,udp6}` text.
///
/// TCP: only ESTABLISHED(01) / SYN_SENT(02). UDP has no handshake state -
/// only connected sockets with a real remote (port != 0) are returned.
fn parse_table(text: &str, v6: bool, proto: Proto) -> Vec<SockEntry> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }
        let state = cols[3];
        if proto == Proto::Tcp && state != "01" && state != "02" {
            continue;
        }
        let inode: u64 = cols[9].parse().unwrap_or(0);
        if inode == 0 {
            continue;
        }
        let (Some(local), Some(rem)) = (parse_addr(cols[1], v6), parse_addr(cols[2], v6)) else {
            continue;
        };
        if rem.1 == 0 {
            continue; // unconnected UDP socket
        }
        // Skip loopback remotes; local loopback is fine (proxies).
        if rem.0.starts_with("127.") || rem.0 == "::1" {
            continue;
        }
        out.push(SockEntry {
            local_ip: local.0,
            local_port: local.1,
            rem_ip: rem.0,
            rem_port: rem.1,
            inode,
        });
    }
    out
}

fn parse_addr(s: &str, v6: bool) -> Option<(String, u16)> {
    let (hex_ip, hex_port) = s.split_once(':')?;
    let port = u16::from_str_radix(hex_port, 16).ok()?;
    if !v6 {
        let raw = u32::from_str_radix(hex_ip, 16).ok()?;
        // Kernel prints little-endian words on x86.
        let le = Ipv4Addr::from(raw.to_le_bytes());
        let _ = IpAddr::V4(le);
        return Some((le.to_string(), port));
    }
    // tcp6: 32 hex chars, 4x32-bit words little-endian each.
    if hex_ip.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for i in 0..4 {
        let w = u32::from_str_radix(&hex_ip[i * 8..i * 8 + 8], 16).ok()?;
        bytes[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    let ip = std::net::Ipv6Addr::from(bytes);
    Some((ip.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_v4() {
        // 0100007F:0035 = 127.0.0.1:53 in /proc little-endian form.
        let (ip, port) = parse_addr("0100007F:0035", false).unwrap();
        assert_eq!(ip, "127.0.0.1");
        assert_eq!(port, 53);
    }

    const FIXTURE: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1234 1 0000000000000000 100 0 0 10 0\n   1: C0A80105:C3A2 5DB8D822:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 9999 1 0000000000000000 100 0 0 10 0\n   2: C0A80105:1F90 5DB8D822:01BB 02 00000000:00000000 00:00000000 00000000  1000        0 9998 1 0000000000000000 100 0 0 10 0\n   3: C0A80105:0035 0100007F:0035 01 00000000:00000000 00:00000000 00000000  1000        0 9997 1 0000000000000000 100 0 0 10 0\n";

    #[test]
    fn table_filters_states_and_loopback() {
        let entries = parse_table(FIXTURE, false, Proto::Tcp);
        // Row 0: listener (0A) skipped. Row 3: loopback remote skipped.
        // Rows 1 (ESTABLISHED) and 2 (SYN_SENT) kept.
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].inode, 9999);
        assert_eq!(entries[0].local_port, 0xC3A2);
        assert_eq!(entries[0].rem_port, 443);
        assert_eq!(entries[1].inode, 9998);
    }
}
