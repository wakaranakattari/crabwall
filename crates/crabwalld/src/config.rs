//! Daemon configuration: rule file loading, persistence, and paths.
//!
//! The rule file (`rules.toml`) is the single source of policy truth.
//! It uses a deliberately small schema - one `[[rule]]` table per row
//! with optional constraints - so that humans can write it by hand, the
//! TUI `allow`/`deny` commands can append to it, and the daemon can
//! rewrite it without a template engine. Loading is strict: a malformed
//! file is an error, never silently ignored policy. A missing file is
//! created with a commented example, so first launch is self-documenting.
//!
//! Path resolution order is environment override, then platform config
//! directory, then `/tmp` fallback. The override exists so tests, CI,
//! and multi-instance setups never touch real user state. The TUI
//! resolves the same way from the same environment, which is what makes
//! `crabwall up` (single env for both processes) structurally incapable
//! of the classic split-brain where daemon and UI read different files.
use anyhow::{Context, Result};
use crabwall_common::{Action, Rule};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRule {
    #[serde(default)]
    pub app: String,
    #[serde(default)]
    pub domain_suffix: Option<String>,
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub container: Option<String>,
    #[serde(default)]
    pub sandbox: Option<String>,
    #[serde(default = "default_action")]
    pub action: String,
}

fn default_action() -> String {
    "deny".into()
}

/// Resolved daemon configuration: where policy lives, where history
/// goes, and how undecided traffic is treated by default.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub rules_path: PathBuf,
    pub db_path: PathBuf,
    pub default_action: Action,
    pub prompt_timeout_secs: u64,
    pub poll_interval_ms: u64,
}

impl DaemonConfig {
    pub fn paths() -> (PathBuf, PathBuf) {
        if let Ok(p) = std::env::var("CRABWALL_RULES") {
            let db = std::env::var("CRABWALL_DB")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/tmp/crabwall-events.db"));
            return (PathBuf::from(p), db);
        }
        if let Some(dirs) = ProjectDirs::from("", "", "crabwall") {
            let cfg = dirs.config_dir().join("rules.toml");
            let data = dirs.data_dir().join("events.db");
            return (cfg, data);
        }
        (
            PathBuf::from("/tmp/crabwall-rules.toml"),
            PathBuf::from("/tmp/crabwall-events.db"),
        )
    }

    pub fn load() -> Result<(Self, Vec<Rule>)> {
        let (rules_path, db_path) = Self::paths();
        let default_action = std::env::var("CRABWALL_DEFAULT")
            .map(|s| match s.to_ascii_lowercase().as_str() {
                "allow" => Action::Allow,
                "deny" => Action::Deny,
                _ => Action::Ask,
            })
            .unwrap_or(Action::Ask);
        let cfg = Self {
            rules_path,
            db_path,
            default_action,
            prompt_timeout_secs: 30,
            poll_interval_ms: 500,
        };
        let rules = load_rules(&cfg.rules_path)?;
        Ok((cfg, rules))
    }
}

pub fn load_rules(path: &std::path::Path) -> Result<Vec<Rule>> {
    if !path.exists() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(
            path,
            r#"# crabwall rules - see README for format.
# Example:
# [[rule]]
# app = "firefox"
# domain_suffix = "google.com"
# ports = [80, 443]
# action = "deny"
"#,
        )
        .ok();
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    #[derive(Deserialize)]
    struct File {
        #[serde(default)]
        rule: Vec<FileRule>,
    }
    let f: File = toml::from_str(&text).context("parse rules.toml")?;
    Ok(f.rule
        .into_iter()
        .enumerate()
        .map(|(i, r)| Rule {
            id: format!("r{i}"),
            app: r.app,
            domain_suffix: r.domain_suffix,
            ports: r.ports,
            container: r.container,
            sandbox: r.sandbox,
            action: match r.action.to_ascii_lowercase().as_str() {
                "allow" => Action::Allow,
                "deny" => Action::Deny,
                _ => Action::Ask,
            },
        })
        .collect())
}

pub fn append_rule(path: &std::path::Path, rule: &Rule) -> Result<()> {
    let mut rules = load_rules(path)?;
    let mut r = rule.clone();
    r.id = format!("r{}", rules.len());
    rules.push(r);
    let mut out = String::new();
    for r in &rules {
        out.push_str("[[rule]]\n");
        out.push_str(&format!("app = {:?}\n", r.app));
        if let Some(d) = &r.domain_suffix {
            out.push_str(&format!("domain_suffix = {d:?}\n"));
        }
        if !r.ports.is_empty() {
            out.push_str(&format!("ports = {:?}\n", r.ports));
        }
        if let Some(c) = &r.container {
            out.push_str(&format!("container = {c:?}\n"));
        }
        if let Some(s) = &r.sandbox {
            out.push_str(&format!("sandbox = {s:?}\n"));
        }
        let a = match r.action {
            Action::Allow => "allow",
            Action::Deny => "deny",
            Action::Ask => "ask",
        };
        out.push_str(&format!("action = {a:?}\n\n"));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(path, out)?;
    Ok(())
}
