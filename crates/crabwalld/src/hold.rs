//! Verdict hold: how long a connection waits for the user, and what
//! happens when the answer never comes.
//!
//! A prompt is a rendezvous between kernel time and human time. The
//! packet (NFQUEUE path) or the connection (poll path) is held while the
//! TUI asks, but humans walk away, TUIs crash, and sockets die. The hold
//! therefore has exactly two outcomes: the user's verdict, or the
//! configured default on timeout or channel loss. The default is deny,
//! which makes every failure mode fail closed. `VerdictHold` owns only
//! the timing policy; applying the verdict stays with the caller, so the
//! NFQUEUE path can later inject kernel-level verdicts at the single
//! `wait` point without touching callers.

use crabwall_common::Action;
use std::time::Duration;
use tokio::sync::oneshot;

/// Timing policy for one prompt: how long the kernel/userspace waits,
/// and what a non-answer means. The default is deny, unconditionally -
/// there is no configuration that turns silence into permission.
pub struct VerdictHold {
    pub timeout: Duration,
    pub default: Action,
}

impl VerdictHold {
    pub fn new(timeout_secs: u64) -> Self {
        Self {
            timeout: Duration::from_secs(timeout_secs),
            default: Action::Deny,
        }
    }

    /// Wait for a user verdict; fall back to default (deny) on timeout
    /// or if the prompter went away.
    pub async fn wait(&self, rx: oneshot::Receiver<Action>) -> Action {
        tokio::time::timeout(self.timeout, rx)
            .await
            .ok()
            .and_then(|r| r.ok())
            .unwrap_or(self.default)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolves_verdict() {
        let h = VerdictHold::new(5);
        let (tx, rx) = oneshot::channel();
        tx.send(Action::Allow).unwrap();
        assert_eq!(h.wait(rx).await, Action::Allow);
    }

    #[tokio::test]
    async fn denies_on_timeout() {
        let h = VerdictHold::new(0);
        let (_tx, rx) = oneshot::channel::<Action>();
        // Zero timeout fires immediately even with a live sender.
        assert_eq!(h.wait(rx).await, Action::Deny);
    }
}
