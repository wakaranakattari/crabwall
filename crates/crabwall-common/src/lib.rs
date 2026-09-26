//! Shared vocabulary of the crabwall system: firewall rules, observed
//! connections, the daemon-to-UI protocol, and the matching engine.
//!
//! Design notes. A [`Rule`] describes one policy row: an application
//! identity (exact executable path or bare basename) plus optional
//! constraints on domain suffix, ports, container, and sandbox. Matching
//! is purely structural and total: every [`ConnectionTuple`] either
//! matches at least one rule, in which case the most specific match wins
//! (see [`Rule::specificity`]), or falls through to the daemon default
//! policy. There is no partial evaluation and no rule ordering to get
//! wrong; specificity is a static function of constraint count, which
//! makes decisions reproducible and unit-testable without I/O.
//!
//! Domain comparison folds ASCII case on both sides and accepts exact
//! equality as well as proper subdomain relations, so `google.com`
//! covers `mail.google.com` but never `notgoogle.com`. Port lists are
//! exact sets; an empty list means all ports. Container and sandbox
//! constraints are exact string equalities against the enriched identity.
//!
//! The IPC types ([`DaemonToClient`], [`ClientToDaemon`]) are serialized
//! as newline-delimited JSON over a Unix socket. All evolving structs
//! carry `#[serde(default)]` on newer fields so old and new binaries
//! fail soft instead of failing to parse. [`IPC_VERSION`] is exchanged
//! in the opening handshake; see `docs/STABILITY.md` for the frozen
//! guarantees of protocol version 2.
//!
//! Role assignment: `crabwalld` (privileged) produces `DaemonToClient`
//! events, while `crabwall` (unprivileged) replies with
//! `ClientToDaemon` verdicts. Neither side trusts the other for policy:
//! the daemon owns the rule set, the UI only answers prompts.

#![warn(missing_docs)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Connection identity
// ---------------------------------------------------------------------------

/// Sandboxed application identity, when the process runs confined.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Sandbox {
    /// Flatpak application id, e.g. `org.mozilla.firefox`.
    Flatpak(String),
    /// Snap name, e.g. `firefox`.
    Snap(String),
}

impl Sandbox {
    /// Short `kind:id` label for logs and the TUI.
    pub fn label(&self) -> String {
        match self {
            Sandbox::Flatpak(id) => format!("flatpak:{id}"),
            Sandbox::Snap(name) => format!("snap:{name}"),
        }
    }

    /// Bare identity without the kind prefix, for rule matching.
    pub fn id(&self) -> &str {
        match self {
            Sandbox::Flatpak(id) | Sandbox::Snap(id) => id,
        }
    }
}

/// Transport protocol of an observed connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    /// TCP stream.
    Tcp,
    /// UDP datagram flow (connected sockets only).
    Udp,
}

/// One observed outbound connection, enriched with process identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionTuple {
    /// Originating process id.
    pub pid: u32,
    /// Originating user id.
    pub uid: u32,
    /// Kernel comm name (`/proc/<pid>/comm`).
    pub comm: String,
    /// Resolved `/proc/<pid>/exe`, may be empty if process exited.
    #[serde(default)]
    pub exe: String,
    /// Full command line, space-joined.
    #[serde(default)]
    pub cmdline: String,
    /// Transport protocol.
    pub proto: Proto,
    /// Local address.
    pub src_ip: String,
    /// Remote address.
    pub dst_ip: String,
    /// Remote port.
    pub dst_port: u16,
    /// Reverse-DNS / DNS-snoop correlated domain, if known.
    #[serde(default)]
    pub domain: Option<String>,
    /// Docker/container id (12-char prefix) if detected from cgroup.
    #[serde(default)]
    pub container: Option<String>,
    /// Sandbox identity (Flatpak/Snap), if the process runs confined.
    #[serde(default)]
    pub sandbox: Option<Sandbox>,
}

impl ConnectionTuple {
    /// Stable application identity for rules, logs, and session allows:
    /// the executable path when the process still exists, otherwise the
    /// kernel comm name. Callers must treat this as an opaque key, not as
    /// a verified trust statement; PIDs are recycled and executables can
    /// be replaced between observation and verdict.
    pub fn app_key(&self) -> &str {
        if !self.exe.is_empty() {
            &self.exe
        } else {
            &self.comm
        }
    }

    /// Final path component of [`ConnectionTuple::app_key`]. Used for
    /// basename rules (`app = "firefox"`) and for compact TUI display.
    /// Never empty: falls back to the full key when no slash is present.
    pub fn basename(&self) -> &str {
        let p = self.app_key();
        p.rsplit('/').next().unwrap_or(p)
    }
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

/// Firewall decision for a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Let the traffic through.
    Allow,
    /// Block the traffic.
    Deny,
    /// Ask the user (TUI prompt with timeout-deny).
    Ask,
}

/// How long a user's verdict stays in effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Remember {
    /// Apply to this connection only.
    Once,
    /// Until daemon restart.
    Session,
    /// Persist to rules.toml.
    Always,
}

/// A firewall rule from `rules.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    /// Stable id assigned at load (`r0`, `r1`, ...).
    #[serde(default)]
    pub id: String,
    /// Exact exe path (e.g. /usr/bin/firefox) or bare basename (e.g. firefox).
    pub app: String,
    /// Suffix match on domain, e.g. "google.com" matches "a.google.com".
    #[serde(default)]
    pub domain_suffix: Option<String>,
    /// If None/empty, matches all ports.
    #[serde(default)]
    pub ports: Vec<u16>,
    /// Exact container id match (12-char prefix from cgroup).
    #[serde(default)]
    pub container: Option<String>,
    /// Exact sandbox identity match (Flatpak app id or snap name).
    #[serde(default)]
    pub sandbox: Option<String>,
    /// Decision to apply on match.
    pub action: Action,
}

impl Rule {
    /// Specificity score used to rank competing matches: more constrained
    /// rules win. Identity precision outranks any single constraint (exact
    /// path beats bare basename), and each additional constraint strictly
    /// refines. Ties resolve to the later rule in slice order, which keeps
    /// `match_rule` deterministic for any fixed rule vector.
    pub fn specificity(&self) -> u8 {
        let mut s = 0u8;
        if self.app.contains('/') {
            s += 2;
        } else {
            s += 1;
        }
        if self.domain_suffix.is_some() {
            s += 1;
        }
        if !self.ports.is_empty() {
            s += 1;
        }
        if self.container.is_some() {
            s += 1;
        }
        if self.sandbox.is_some() {
            s += 1;
        }
        s
    }

    /// Whether this rule matches the connection: app identity first,
    /// then optional domain-suffix, port, container and sandbox constraints.
    /// Every constraint is conjunctive; a single mismatch rejects the rule.
    /// Domain matching requires a known domain on the connection side, so
    /// rules with `domain_suffix` never match unattributed flows - they
    /// simply lose to less specific rules or to the default policy.
    pub fn matches(&self, conn: &ConnectionTuple) -> bool {
        // app: exact path or basename
        let app_hit = if self.app.contains('/') {
            conn.exe == self.app
        } else {
            conn.basename() == self.app || conn.comm == self.app
        };
        if !app_hit {
            return false;
        }
        if let Some(suffix) = &self.domain_suffix {
            let d = match conn.domain.as_deref() {
                Some(d) => d.to_ascii_lowercase(),
                None => return false,
            };
            let s = suffix.to_ascii_lowercase();
            if d != s && !d.ends_with(&format!(".{s}")) {
                return false;
            }
        }
        if !self.ports.is_empty() && !self.ports.contains(&conn.dst_port) {
            return false;
        }
        if let Some(want) = &self.container {
            if conn.container.as_deref() != Some(want.as_str()) {
                return false;
            }
        }
        if let Some(want) = &self.sandbox {
            if conn.sandbox.as_ref().map(Sandbox::id) != Some(want.as_str()) {
                return false;
            }
        }
        true
    }
}

/// Pick the most specific matching rule, or None.
/// Linear scan with a max-by-specificity reduction; rule sets are small
/// (tens of rows), so clarity beats indexing here. See [`Rule::matches`]
/// for per-constraint semantics and [`Rule::specificity`] for ranking.
pub fn match_rule<'a>(rules: &'a [Rule], conn: &ConnectionTuple) -> Option<&'a Rule> {
    rules
        .iter()
        .filter(|r| r.matches(conn))
        .max_by_key(|r| r.specificity())
}

/// Final decision for a connection given the rule set and default policy.
/// The default applies only when no rule matches; it never overrides an
/// explicit row. Typical deployments use `Ask` so unknown traffic always
/// surfaces as a prompt rather than passing silently.
pub fn decide(rules: &[Rule], conn: &ConnectionTuple, default: Action) -> Action {
    match_rule(rules, conn).map(|r| r.action).unwrap_or(default)
}

// ---------------------------------------------------------------------------
// Events / IPC
// ---------------------------------------------------------------------------

/// A new connection the daemon wants a verdict for.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewConnectionEvent {
    /// Unique id; echoed back in [`UserVerdict::event_id`].
    pub id: String,
    /// When the connection was observed.
    pub at: DateTime<Utc>,
    /// The enriched connection.
    pub conn: ConnectionTuple,
    /// Rule that matched, if any (id empty => default policy).
    #[serde(default)]
    pub matched_rule: Option<String>,
    /// Suggested action (Ask when user input required).
    pub suggested: Action,
}

/// Messages from daemon to UI clients (newline-delimited JSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DaemonToClient {
    /// First line on every connection: protocol version + policy.
    Hello {
        /// [`IPC_VERSION`] of the daemon.
        version: u32,
        /// Action applied when no rule matches.
        default_action: Action,
    },
    /// A connection needs a verdict. Boxed: the event dwarfs the rest.
    NewConnection(Box<NewConnectionEvent>),
    /// Rule set changed; clients should refresh.
    RuleChanged {
        /// Current rule count.
        count: usize,
    },
}

/// A user's answer to a [`NewConnectionEvent`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserVerdict {
    /// Id of the event being answered.
    pub event_id: String,
    /// Allow or deny (Ask is not a valid answer).
    pub action: Action,
    /// How long the answer stays in effect.
    pub remember: Remember,
}

/// Messages from UI clients to the daemon (newline-delimited JSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientToDaemon {
    /// Answer to a connection prompt.
    Verdict(UserVerdict),
    /// Ask daemon to resend rule count / subscribe. Sent once on connect.
    Subscribe,
}

/// IPC protocol version, exchanged in [`DaemonToClient::Hello`].
/// Bumped to 2 for the `sandbox`/`container` rule fields.
pub const IPC_VERSION: u32 = 2;

/// Unix socket path: `$CRABWALL_SOCK`, then `/run/crabwall.sock` for root,
/// else `$XDG_RUNTIME_DIR/crabwall.sock`, falling back to `/tmp`.
pub fn socket_path() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("CRABWALL_SOCK") {
        return std::path::PathBuf::from(p);
    }
    // Prefer /run/crabwall.sock when running as root service, else runtime dir.
    #[cfg(target_os = "linux")]
    {
        // SAFETY: geteuid takes no arguments and has no side effects.
        if unsafe { libc::geteuid() } == 0 {
            return std::path::PathBuf::from("/run/crabwall.sock");
        }
    }
    if let Ok(rt) = std::env::var("XDG_RUNTIME_DIR") {
        return std::path::PathBuf::from(rt).join("crabwall.sock");
    }
    std::path::PathBuf::from("/tmp/crabwall.sock")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(exe: &str, domain: Option<&str>, port: u16) -> ConnectionTuple {
        ConnectionTuple {
            pid: 123,
            uid: 1000,
            comm: exe.rsplit('/').next().unwrap().to_string(),
            exe: exe.to_string(),
            cmdline: String::new(),
            proto: Proto::Tcp,
            src_ip: "192.168.1.2".into(),
            dst_ip: "1.2.3.4".into(),
            dst_port: port,
            domain: domain.map(|s| s.to_string()),
            container: None,
            sandbox: None,
        }
    }

    fn rule(app: &str, action: Action) -> Rule {
        Rule {
            id: String::new(),
            app: app.into(),
            domain_suffix: None,
            ports: vec![],
            container: None,
            sandbox: None,
            action,
        }
    }

    #[test]
    fn exact_path_beats_basename() {
        let c = conn("/usr/bin/firefox", Some("example.com"), 443);
        let generic = rule("firefox", Action::Allow);
        let specific = Rule {
            domain_suffix: Some("example.com".into()),
            ports: vec![443],
            ..rule("/usr/bin/firefox", Action::Deny)
        };
        let rules = vec![generic, specific];
        let m = match_rule(&rules, &c).unwrap();
        assert_eq!(m.action, Action::Deny);
    }

    #[test]
    fn domain_suffix_match() {
        let r = Rule {
            domain_suffix: Some("google.com".into()),
            ..rule("curl", Action::Deny)
        };
        assert!(r.matches(&conn("/usr/bin/curl", Some("mail.google.com"), 443)));
        assert!(r.matches(&conn("/usr/bin/curl", Some("google.com"), 443)));
        assert!(!r.matches(&conn("/usr/bin/curl", Some("notgoogle.com"), 443)));
        assert!(!r.matches(&conn("/usr/bin/curl", None, 443)));
    }

    #[test]
    fn default_policy_when_no_match() {
        let c = conn("/usr/bin/curl", None, 80);
        assert_eq!(decide(&[], &c, Action::Ask), Action::Ask);
        assert_eq!(decide(&[], &c, Action::Allow), Action::Allow);
    }

    #[test]
    fn ports_filter() {
        let r = Rule {
            ports: vec![22],
            ..rule("ssh", Action::Allow)
        };
        assert!(r.matches(&conn("/usr/bin/ssh", None, 22)));
        assert!(!r.matches(&conn("/usr/bin/ssh", None, 2222)));
    }

    #[test]
    fn container_and_sandbox_filter() {
        let mut c = conn("/usr/bin/telegram", None, 443);
        c.container = Some("abc123def456".into());
        c.sandbox = Some(Sandbox::Flatpak("org.telegram.desktop".into()));
        let by_container = Rule {
            container: Some("abc123def456".into()),
            ports: vec![443],
            ..rule("telegram", Action::Deny)
        };
        assert!(by_container.matches(&c));
        let other_container = Rule {
            container: Some("000000000000".into()),
            ..rule("telegram", Action::Deny)
        };
        assert!(!other_container.matches(&c));
        let by_sandbox = Rule {
            sandbox: Some("org.telegram.desktop".into()),
            ..rule("telegram", Action::Allow)
        };
        assert!(by_sandbox.matches(&c));
        let bare = rule("telegram", Action::Allow);
        assert!(bare.matches(&c)); // no constraints still match
                                   // Most constrained rule wins (specificity 3 > 2 > 1).
        let rules = [bare, by_sandbox, by_container];
        let winner = match_rule(&rules, &c).unwrap();
        assert_eq!(winner.action, Action::Deny);
        assert_eq!(Sandbox::Flatpak("x".into()).label(), "flatpak:x");
        assert_eq!(Sandbox::Snap("y".into()).id(), "y");
    }

    #[test]
    fn ipc_json_roundtrip() {
        let ev = NewConnectionEvent {
            id: "abc".into(),
            at: Utc::now(),
            conn: conn("/usr/bin/curl", None, 80),
            matched_rule: None,
            suggested: Action::Ask,
        };
        let msg = DaemonToClient::NewConnection(Box::new(ev));
        let s = serde_json::to_string(&msg).unwrap();
        let back: DaemonToClient = serde_json::from_str(&s).unwrap();
        assert!(matches!(back, DaemonToClient::NewConnection(_)));
    }
}
