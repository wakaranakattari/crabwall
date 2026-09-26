//! nftables enforcement via the `nft` CLI.
//!
//! Two mechanisms share one table (`inet crabwall`). The primary one,
//! installed by [`NftEnforcer::ensure_queue`], steers TCP/UDP output into
//! NFQUEUE (`queue num 0 bypass`): the kernel then holds each new flow's
//! packets until userspace verdicts them, which is what makes first-packet
//! blocking possible. The `bypass` keyword is load-bearing: with no
//! userspace listener attached (daemon restarting, queue thread dead),
//! packets flow instead of stalling the machine. The secondary mechanism
//! is a pair of allow/deny sets per address family, written by
//! [`NftEnforcer::apply`]: the fallback path when NFQUEUE is unavailable
//! (no privileges), where verdicts land per destination IP with a 24h
//! timeout. Set enforcement is therefore IP-granular by construction,
//! while queue verdicts are per-packet and honor ports and domains.
//!
//! All commands are best-effort and idempotent: without root or without
//! the `nft` binary the enforcer logs and continues in dry-run, so plain
//! `cargo run` and CI stay green without privileges.

use crabwall_common::{Action, ConnectionTuple};
use std::process::Command;
use tracing::{debug, warn};

/// nftables via the `nft` CLI. Shelling out (rather than netlink)
/// is a deliberate tradeoff: zero native dependencies, trivially
/// auditable commands, and idempotent scripts. Rule installation is
/// rare (startup, verdicts); parsing speed is irrelevant.
pub struct NftEnforcer {
    /// True without root or without the `nft` binary: every method
    /// logs and returns, so development and CI never need privileges.
    pub dry_run: bool,
}

impl NftEnforcer {
    pub fn new() -> Self {
        // SAFETY: geteuid takes no arguments and has no side effects.
        let is_root = unsafe { libc::geteuid() } == 0;
        let has_nft = Command::new("nft").arg("--version").output().is_ok();
        let dry_run = !(is_root && has_nft);
        if dry_run {
            warn!("nft enforce dry-run (need root + nft binary)");
        }
        Self { dry_run }
    }

    pub fn ensure(&self) {
        if self.dry_run {
            return;
        }
        // Idempotent setup.
        let script = r#"
add table inet crabwall
add set inet crabwall allow_v4 { type ipv4_addr; flags timeout; }
add set inet crabwall deny_v4 { type ipv4_addr; flags timeout; }
add set inet crabwall allow_v6 { type ipv6_addr; flags timeout; }
add set inet crabwall deny_v6 { type ipv6_addr; flags timeout; }
add chain inet crabwall out { type filter hook output priority 0; policy accept; }
"#;
        run_nft_script(script);
        debug!("nft table ensured");
    }

    /// Steer TCP/UDP output into the NFQUEUE. `bypass` keeps traffic
    /// flowing when no userspace listener is attached (e.g. during
    /// daemon restart); an attached queue holds packets for verdicts.
    pub fn ensure_queue(&self, queue: u16) {
        if self.dry_run {
            return;
        }
        self.ensure();
        run_nft_script(&format!(
            "flush chain inet crabwall out\n\
             add rule inet crabwall out meta l4proto {{ tcp, udp }} queue num {queue} bypass\n"
        ));
        debug!("nft queue steering installed (num {queue})");
    }

    pub fn apply(&self, conn: &ConnectionTuple, action: Action) {
        if self.dry_run {
            debug!(?action, dst = %conn.dst_ip, "dry-run verdict");
            return;
        }
        let v6 = conn.dst_ip.contains(':');
        let set = match (action, v6) {
            (Action::Allow, false) => "allow_v4",
            (Action::Deny, false) => "deny_v4",
            (Action::Allow, true) => "allow_v6",
            (Action::Deny, true) => "deny_v6",
            (Action::Ask, _) => return,
        };
        // Remove from the opposite set, add to target with 24h timeout.
        let opposite = match (action, v6) {
            (Action::Allow, false) => "deny_v4",
            (_, false) => "allow_v4",
            (Action::Allow, true) => "deny_v6",
            (_, true) => "allow_v6",
        };
        let script = format!(
            "delete element inet crabwall {opposite} {{ {ip} }}\n\
             add element inet crabwall {set} {{ {ip} timeout 24h }}\n",
            opposite = opposite,
            set = set,
            ip = conn.dst_ip,
        );
        run_nft_script(&script);
    }
}

fn run_nft_script(script: &str) {
    let out = Command::new("nft").arg("-f").arg("-").arg(script).output();
    match out {
        Ok(o) if o.status.success() => {}
        Ok(o) => warn!("nft failed: {}", String::from_utf8_lossy(&o.stderr).trim()),
        Err(e) => warn!("nft exec failed: {e}"),
    }
}
