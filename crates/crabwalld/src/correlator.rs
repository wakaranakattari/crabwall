//! 5-tuple to PID correlation for queued packets.
//!
//! NFQUEUE hands the daemon packets, not process identities: a queued
//! SYN carries addresses and ports, but no PID. The correlator bridges
//! that gap with recent observations. Every sensor that learns a PID for
//! a flow records it here - the poll loop with full 5-tuples including
//! source ports, the eBPF connect feed with source port unknown (marked
//! as 0). Entries live 5 seconds, comfortably longer than the
//! milliseconds between a connect event and its queued packet, and the
//! table is bounded with TTL-aware eviction so storms cannot grow it
//! without limit.
//!
//! Lookup has two tiers mirroring the two feed shapes. [`Correlator::lookup`]
//! is the exact tier: full key equality, used first. [`Correlator::lookup_any_sport`]
//! is the fuzzy tier for eBPF-fed entries: it scans live entries for the
//! (protocol, destination, port) triple and returns a PID only when every
//! candidate agrees. Disagreement - two processes racing connects to one
//! address - abstains to None, and the caller falls through to the exact
//! on-demand `/proc` scan. Agreement without evidence would be guessing,
//! and a firewall must never guess attribution.

use crabwall_packet::frame::IpFlow;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Flow key: protocol + full 5-tuple minus source port ambiguity -
///
/// The source port is included because it is stable per socket and is
/// what disambiguates parallel connections from one process to one
/// destination. eBPF connect events cannot know it (the port is assigned
/// after enter), so they file under sport 0 and resolve through the
/// fuzzy tier instead of this exact key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    /// 6 for TCP, 17 for UDP.
    pub proto: u8,
    /// Destination address.
    pub dst: IpAddr,
    /// Destination port.
    pub dport: u16,
    /// Source port.
    pub sport: u16,
}

impl FlowKey {
    /// Key for an observed or queued flow.
    pub fn of(proto: u8, dst: IpAddr, dport: u16, sport: u16) -> Self {
        Self {
            proto,
            dst,
            dport,
            sport,
        }
    }

    /// Key from an NFQUEUE-decoded flow.
    pub fn from_flow(flow: &IpFlow) -> Self {
        Self::of(flow.proto, flow.dst, flow.dport, flow.sport)
    }
}

/// 5-tuple to PID map with TTL eviction. Interior mutability (single
/// mutex) because inserts arrive from sensor loops, eBPF tasks, and the
/// queue thread concurrently. Expiry is lazy - checked on read, swept on
/// insert past capacity - which keeps the common path to one hash lookup
/// plus a timestamp comparison.
pub struct Correlator {
    inner: Mutex<HashMap<FlowKey, (u32, Instant)>>,
    ttl: Duration,
}

impl Correlator {
    /// New correlator; entries live `ttl` (5s is plenty: queued packets
    /// arrive milliseconds after the connect event).
    pub fn new(ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    /// Record a pid for a flow.
    pub fn insert(&self, key: FlowKey, pid: u32) {
        if let Ok(mut map) = self.inner.lock() {
            if map.len() > 8192 {
                map.retain(|_, (_, at)| at.elapsed() < self.ttl);
            }
            map.insert(key, (pid, Instant::now()));
        }
    }

    /// Look a flow up; expired entries miss and are dropped.
    pub fn lookup(&self, key: &FlowKey) -> Option<u32> {
        let mut map = self.inner.lock().ok()?;
        let (pid, at) = map.get(key)?;
        if at.elapsed() >= self.ttl {
            map.remove(key);
            return None;
        }
        Some(*pid)
    }

    /// Fuzzy lookup for event sources without a source port (eBPF
    /// connect events): all live entries for (proto, dst, dport).
    /// Returns a pid only when every candidate agrees - otherwise the
    /// caller must attribute precisely (on-demand `/proc` scan).
    pub fn lookup_any_sport(&self, proto: u8, dst: IpAddr, dport: u16) -> Option<u32> {
        let map = self.inner.lock().ok()?;
        let now = Instant::now();
        let mut pid: Option<u32> = None;
        for (key, (candidate, at)) in map.iter() {
            if key.proto != proto || key.dst != dst || key.dport != dport {
                continue;
            }
            if now.duration_since(*at) >= self.ttl {
                continue;
            }
            match pid {
                None => pid = Some(*candidate),
                Some(p) if p == *candidate => {}
                Some(_) => return None, // processes disagree
            }
        }
        pid
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn key() -> FlowKey {
        FlowKey::of(6, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443, 51234)
    }

    #[test]
    fn hit_and_miss() {
        let c = Correlator::new(Duration::from_secs(5));
        assert_eq!(c.lookup(&key()), None);
        c.insert(key(), 4242);
        assert_eq!(c.lookup(&key()), Some(4242));
        let mut other = key();
        other.sport = 1;
        assert_eq!(c.lookup(&other), None);
    }

    #[test]
    fn expired_entries_miss() {
        let c = Correlator::new(Duration::ZERO);
        c.insert(key(), 1);
        assert_eq!(c.lookup(&key()), None);
    }

    #[test]
    fn fuzzy_agrees_or_abstains() {
        use std::net::Ipv4Addr;
        let dst = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9));
        let c = Correlator::new(Duration::from_secs(5));
        assert_eq!(c.lookup_any_sport(6, dst, 443), None);
        // Same pid from two sports (eBPF sport-0 + poll exact): agree.
        c.insert(FlowKey::of(6, dst, 443, 0), 100);
        c.insert(FlowKey::of(6, dst, 443, 5000), 100);
        assert_eq!(c.lookup_any_sport(6, dst, 443), Some(100));
        // A second process connects to the same dst:port: abstain.
        c.insert(FlowKey::of(6, dst, 443, 0), 200);
        c.insert(FlowKey::of(6, dst, 443, 6000), 200);
        assert_eq!(c.lookup_any_sport(6, dst, 443), None);
        // Different port is unaffected.
        assert_eq!(c.lookup_any_sport(6, dst, 80), None);
    }
}
