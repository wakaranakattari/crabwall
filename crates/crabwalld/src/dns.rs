//! Best-effort IP -> domain cache.
//!
//! The cache answers one question - "have we seen this address named
//! before?" - from four sources in increasing order of cost: the
//! in-memory map of past observations, the passive packet sniffer's
//! DNS/SNI learning, `/etc/hosts`, and (opt-in) background PTR lookups.
//! Two lookup flavors exist because latency budgets differ along the
//! pipeline: [`DnsCache::lookup`] may touch the filesystem and is used
//! on the async attribution path, while [`DnsCache::lookup_cached`]
//! never leaves the mutex and serves the NFQUEUE fast path, where a
//! verdict must issue in microseconds. Time-to-live is 5 minutes;
//! capacity is bounded with wholesale clear, which is crude but
//! allocation-fair and impossible to poison incrementally.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Best-effort IP -> domain cache. See module docs for the source
/// hierarchy and the two latency tiers (`lookup` vs `lookup_cached`).
pub struct DnsCache {
    inner: Mutex<HashMap<IpAddr, (String, Instant)>>,
    ttl: Duration,
}

impl Default for DnsCache {
    fn default() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            ttl: Duration::from_secs(300),
        }
    }
}

impl DnsCache {
    pub fn lookup(&self, ip: &str) -> Option<String> {
        if let Some(hit) = self.lookup_cached(ip) {
            return Some(hit);
        }
        // Synchronous hosts-file fallback (cheap, no network).
        if let Some(d) = hosts_lookup(ip) {
            self.insert(ip, &d);
            return Some(d);
        }
        None
    }

    /// Map-only lookup: no file or network I/O. For hot paths
    /// (NFQUEUE fast verdicts) where latency matters.
    pub fn lookup_cached(&self, ip: &str) -> Option<String> {
        let addr: IpAddr = ip.parse().ok()?;
        let map = self.inner.lock().ok()?;
        let (d, at) = map.get(&addr)?;
        (at.elapsed() < self.ttl).then(|| d.clone())
    }

    pub fn insert(&self, ip: &str, domain: &str) {
        if let Ok(addr) = ip.parse::<IpAddr>() {
            if let Ok(mut map) = self.inner.lock() {
                map.insert(addr, (domain.to_string(), Instant::now()));
                if map.len() > 8192 {
                    map.clear();
                }
            }
        }
    }

    /// Learn mappings from a raw DNS message (sniffer entry point).
    pub fn learn_from_packet(&self, msg: &[u8]) {
        for (ip, domain) in crabwall_packet::dns_parse::parse_dns_response(msg) {
            self.insert(&ip, &domain);
        }
    }

    /// Learn a domain from a TLS ClientHello payload.
    /// Returns the SNI when present so callers can attribute immediately.
    pub fn learn_from_tls(&self, ip: &str, tls_payload: &[u8]) -> Option<String> {
        let sni = crabwall_packet::sni::extract_sni(tls_payload)?;
        self.insert(ip, &sni);
        Some(sni)
    }
}

fn hosts_lookup(ip: &str) -> Option<String> {
    let text = std::fs::read_to_string("/etc/hosts").ok()?;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let addr = parts.next()?;
        if addr == ip {
            if let Some(name) = parts.next() {
                return Some(name.to_string());
            }
        }
    }
    None
}
