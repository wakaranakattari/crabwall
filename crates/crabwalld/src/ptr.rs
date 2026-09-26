//! Opt-in reverse-DNS enrichment.
//!
//! When `CRABWALL_PTR=1`, destination IPs unknown to every other source
//! get a background PTR lookup via the system resolver. Results warm the
//! shared DNS cache for *future* connections; the in-flight connection is
//! never delayed waiting for an answer, because a firewall prompt must
//! appear in milliseconds, not after DNS round trips. Each address is
//! resolved at most once per process lifetime (bounded in-flight set),
//! which caps both query volume and memory. Off by default for three
//! honest reasons: PTR records are frequently absent, lookups cost
//! latency and leak query metadata to the resolver, and most users are
//! better served by the passive DNS/SNI sniffer, which costs nothing.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Mutex;

/// Background reverse-DNS resolver. Enabled solely by `CRABWALL_PTR=1`;
/// the flag is read once at construction so behavior never changes
/// mid-run. The in-flight set doubles as a once-per-process ledger.
pub struct PtrResolver {
    enabled: bool,
    in_flight: Mutex<HashSet<IpAddr>>,
}

impl PtrResolver {
    pub fn from_env() -> Self {
        Self {
            enabled: std::env::var("CRABWALL_PTR").as_deref() == Ok("1"),
            in_flight: Mutex::new(HashSet::new()),
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Spawn a background PTR lookup unless one is already running for `ip`.
    /// `on_done(domain)` is called on success (e.g. insert into DnsCache).
    /// Each IP is resolved at most once per process lifetime.
    pub fn resolve_bg<F>(&self, ip: IpAddr, on_done: F)
    where
        F: FnOnce(String) + Send + 'static,
    {
        if !self.enabled {
            return;
        }
        if let Ok(mut set) = self.in_flight.lock() {
            if !set.insert(ip) {
                return; // already resolved or resolving
            }
            if set.len() > 256 {
                set.clear();
                set.insert(ip);
            }
        }
        tokio::spawn(async move {
            let name = tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip).ok())
                .await
                .ok()
                .flatten();
            if let Some(n) = name {
                let n = n.trim_end_matches('.').to_string();
                if !n.is_empty() {
                    on_done(n);
                }
            }
        });
    }
}
