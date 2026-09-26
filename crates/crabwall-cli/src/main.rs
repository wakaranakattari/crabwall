//! crabwall: the unprivileged user frontend (TUI + CLI).
//!
//! Every subcommand talks to the daemon over the Unix socket when it
//! needs live state (`tui`, `status`), and edits plain files otherwise
//! (`allow`, `deny`, `rules`, `config`), so half the tool keeps working
//! with no daemon at all. `up` unifies both worlds: it spawns the daemon
//! with the identical environment, waits for its hello, runs the TUI,
//! and stops what it started on exit - one command, structurally no
//! path mismatches between UI and daemon.

mod config;
mod theme;
mod tui;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use crabwall_common::{socket_path, Action, Rule};
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "crabwall",
    version,
    about = "Little Snitch for Linux: per-app firewall prompts"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Launch live TUI (default).
    Tui {
        /// Theme id: phosphor, gruvbox, dracula, nord, tokyo, catppuccin, mono.
        /// Overrides CRABWALL_THEME.
        #[arg(long)]
        theme: Option<String>,
        /// Icon set: plain (everywhere) or nerd (needs Nerd Font).
        /// Overrides CRABWALL_ICONS.
        #[arg(long)]
        icons: Option<String>,
    },
    /// Start the daemon (if needed) and open the TUI. One command,
    /// one env: daemon and UI always resolve the same files.
    Up {
        /// Theme id (see tui).
        #[arg(long)]
        theme: Option<String>,
        /// Icon set (see tui).
        #[arg(long)]
        icons: Option<String>,
        /// Learn mode: allow unknown traffic for N seconds, write
        /// rules.suggested.toml for review.
        #[arg(long)]
        learn: Option<u64>,
        /// Default policy for unmatched traffic (overrides CRABWALL_DEFAULT).
        #[arg(long, value_parser = ["ask", "allow", "deny"])]
        default: Option<String>,
    },
    /// Stop a daemon previously started by `crabwall up`.
    Down,
    /// Check daemon status.
    Status,
    /// Show recent connection log.
    Logs {
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// Add an allow rule.
    Allow {
        #[arg(long)]
        app: String,
        #[arg(long)]
        domain: Option<String>,
        #[arg(long)]
        port: Option<u16>,
    },
    /// Add a deny rule.
    Deny {
        #[arg(long)]
        app: String,
        #[arg(long)]
        domain: Option<String>,
        #[arg(long)]
        port: Option<u16>,
    },
    /// List rules.
    Rules,
    /// Show or change persistent settings (config.toml).
    Config {
        #[command(subcommand)]
        action: Option<ConfigAction>,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Show effective settings and where each comes from.
    Show,
    /// Set a setting: `theme <id>` or `icons <plain|nerd>`.
    Set { key: String, value: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let cli = Cli::parse();
    match cli.cmd.unwrap_or(Cmd::Tui {
        theme: None,
        icons: None,
    }) {
        Cmd::Tui { theme, icons } => tui::run(tui::TuiOptions { theme, icons }).await,
        Cmd::Up {
            theme,
            icons,
            learn,
            default,
        } => up(theme, icons, learn, default).await,
        Cmd::Status => status().await,
        Cmd::Logs { limit, json } => logs(limit, json),
        Cmd::Allow { app, domain, port } => add_rule(app, domain, port, Action::Allow),
        Cmd::Deny { app, domain, port } => add_rule(app, domain, port, Action::Deny),
        Cmd::Rules => list_rules(),
        Cmd::Config { action } => config_cmd(action),
        Cmd::Down => down(),
    }
}

/// `crabwall up`: one command to rule the stack. If a daemon already
/// answers on the socket, just open the TUI. Otherwise spawn `crabwalld`
/// (found next to this binary, else in PATH) with the *same* environment,
/// so paths can never diverge, wait for its hello, run the TUI, and stop
/// the daemon we started on exit.
async fn up(
    theme: Option<String>,
    icons: Option<String>,
    learn: Option<u64>,
    default: Option<String>,
) -> Result<()> {
    if daemon_answers().await {
        println!("daemon already running - attaching TUI.");
        return tui::run(tui::TuiOptions { theme, icons }).await;
    }
    let daemon = find_daemon()?;
    let data_dir = data_dir();
    std::fs::create_dir_all(&data_dir).ok();
    let log_path = data_dir.join("crabwalld.log");
    let pid_path = data_dir.join("crabwalld.pid");
    let log_file = std::fs::File::create(&log_path)
        .with_context(|| format!("create log {}", log_path.display()))?;
    let mut cmd = std::process::Command::new(&daemon);
    if let Some(secs) = learn {
        cmd.env("CRABWALL_LEARN_SECS", secs.to_string());
    }
    if let Some(policy) = &default {
        cmd.env("CRABWALL_DEFAULT", policy);
    }
    // Same env as us: same socket, rules, db. Mismatch impossible.
    let child = cmd
        .stdin(std::process::Stdio::null())
        .stdout(log_file.try_clone().with_context(|| "clone log handle")?)
        .stderr(log_file)
        .spawn()
        .with_context(|| format!("start {}", daemon.display()))?;
    std::fs::write(&pid_path, child.id().to_string()).ok();
    println!(
        "daemon started (pid {}, log {})",
        child.id(),
        log_path.display()
    );
    if !wait_for_daemon().await {
        let _ = std::fs::remove_file(&pid_path);
        anyhow::bail!(
            "daemon did not answer on {} - see {}",
            socket_path().display(),
            log_path.display()
        );
    }
    let ui = tui::run(tui::TuiOptions { theme, icons }).await;
    // We started it, we stop it. `down` covers orphaned cases.
    let _ = std::process::Command::new("kill")
        .arg(child.id().to_string())
        .status();
    let _ = std::fs::remove_file(&pid_path);
    ui
}

/// True when something answers the hello on our socket.
async fn daemon_answers() -> bool {
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::time::timeout;
    let Ok(stream) = tokio::net::UnixStream::connect(&socket_path()).await else {
        return false;
    };
    let (rd, _) = stream.into_split();
    let mut lines = BufReader::new(rd).lines();
    let Ok(Ok(Some(_))) = timeout(Duration::from_millis(500), lines.next_line()).await else {
        return false;
    };
    true
}

/// Wait up to ~6s for a freshly spawned daemon to answer.
async fn wait_for_daemon() -> bool {
    for _ in 0..60 {
        if daemon_answers().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

/// Locate `crabwalld`: next to this executable (release installs,
/// `target/debug`), else in PATH.
fn find_daemon() -> Result<std::path::PathBuf> {
    let here = std::env::current_exe().with_context(|| "locate this binary")?;
    if let Some(dir) = here.parent() {
        let sibling = dir.join("crabwalld");
        if is_executable(&sibling) {
            return Ok(sibling);
        }
    }
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join("crabwalld");
            if is_executable(&candidate) {
                return Ok(candidate);
            }
        }
    }
    anyhow::bail!(
        "crabwalld not found next to {} nor in PATH; build it (`cargo build -p crabwalld`) or install the package",
        here.display()
    )
}

#[cfg(unix)]
fn is_executable(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &std::path::Path) -> bool {
    path.is_file()
}

/// Stop a daemon started by `up`. Refuses to kill anything else.
fn down() -> Result<()> {
    let pid_path = data_dir().join("crabwalld.pid");
    let pid: u32 = std::fs::read_to_string(&pid_path)
        .with_context(|| {
            "no pidfile - nothing started by `up` (use your service manager or pkill for the rest)"
        })?
        .trim()
        .parse()
        .with_context(|| format!("bad pidfile {}", pid_path.display()))?;
    let st = std::process::Command::new("kill")
        .arg(pid.to_string())
        .status();
    match st {
        Ok(s) if s.success() => {
            let _ = std::fs::remove_file(&pid_path);
            println!("daemon {pid} stopped.");
            Ok(())
        }
        _ => anyhow::bail!("could not signal pid {pid} - already gone? removing pidfile"),
    }
}

fn config_cmd(action: Option<ConfigAction>) -> Result<()> {
    match action.unwrap_or(ConfigAction::Show) {
        ConfigAction::Show => {
            let file = config::FileConfig::load().unwrap_or_default();
            let path = config::FileConfig::path();
            println!(
                "config: {}",
                path.map(|p| p.display().to_string())
                    .as_deref()
                    .unwrap_or("(no config dir)")
            );
            for (key, val, source) in effective_settings(&file) {
                println!("  {key:8} {val:12} ({source})");
            }
            Ok(())
        }
        ConfigAction::Set { key, value } => {
            let key = key.trim().trim_start_matches("tui.").to_ascii_lowercase();
            let mut file = config::FileConfig::load().unwrap_or_default();
            match key.as_str() {
                "theme" => {
                    let valid: Vec<_> = theme::THEMES.iter().map(|t| t.id).collect();
                    if !valid.contains(&value.as_str()) {
                        anyhow::bail!("unknown theme {value:?}; pick one of: {}", valid.join(", "));
                    }
                    file.tui.theme = value;
                }
                "icons" => {
                    if value != "plain" && value != "nerd" {
                        anyhow::bail!("icons must be 'plain' or 'nerd', got {value:?}");
                    }
                    file.tui.icons = value;
                }
                _ => anyhow::bail!("unknown setting {key:?}; known: theme, icons"),
            }
            file.save()?;
            println!("saved.");
            Ok(())
        }
    }
}

/// Effective (theme, icons) with provenance for `config show`.
fn effective_settings(file: &config::FileConfig) -> Vec<(&'static str, String, &'static str)> {
    let env_theme = std::env::var("CRABWALL_THEME")
        .ok()
        .filter(|v| !v.is_empty());
    let env_icons = std::env::var("CRABWALL_ICONS")
        .ok()
        .filter(|v| !v.is_empty());
    let (theme, theme_src) = if !file.tui.theme.is_empty() {
        (file.tui.theme.clone(), "file")
    } else if let Some(v) = env_theme {
        (v, "env")
    } else {
        ("phosphor".to_string(), "default")
    };
    let (icons, icons_src) = if !file.tui.icons.is_empty() {
        (file.tui.icons.clone(), "file")
    } else if let Some(v) = env_icons {
        (v, "env")
    } else {
        ("plain".to_string(), "default")
    };
    vec![("theme", theme, theme_src), ("icons", icons, icons_src)]
}

async fn status() -> Result<()> {
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::net::UnixStream;
    let path = crabwall_common::socket_path();
    let stream = UnixStream::connect(&path)
        .await
        .with_context(|| format!("no daemon at {}", path.display()))?;
    let (rd, _) = stream.into_split();
    let mut lines = BufReader::new(rd).lines();
    match lines.next_line().await? {
        Some(line) => match serde_json::from_str::<crabwall_common::DaemonToClient>(&line) {
            Ok(crabwall_common::DaemonToClient::Hello {
                version,
                default_action,
            }) => {
                println!(
                    "crabwalld: running ({}) ipc=v{version} default={default_action:?}",
                    path.display()
                );
            }
            Ok(other) => println!("crabwalld: unexpected greeting: {other:?}"),
            Err(e) => println!("crabwalld: unreadable greeting: {e}"),
        },
        None => println!("crabwalld: unreachable (empty greeting)"),
    }
    Ok(())
}

fn db_path() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("CRABWALL_DB") {
        return p.into();
    }
    if let Some(d) = directories::ProjectDirs::from("", "", "crabwall") {
        return d.data_dir().join("events.db");
    }
    "/tmp/crabwall-events.db".into()
}

/// Directory for daemon log + pidfile. Own override or platform default.
fn data_dir() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("CRABWALL_DATA_DIR") {
        return p.into();
    }
    if let Some(d) = directories::ProjectDirs::from("", "", "crabwall") {
        return d.data_dir().to_path_buf();
    }
    std::env::temp_dir()
}

fn rules_path() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("CRABWALL_RULES") {
        return p.into();
    }
    if let Some(d) = directories::ProjectDirs::from("", "", "crabwall") {
        return d.config_dir().join("rules.toml");
    }
    "/tmp/crabwall-rules.toml".into()
}

fn logs(limit: usize, json: bool) -> Result<()> {
    let db = db_path();
    if !db.exists() {
        println!(
            "no log db at {}. Is crabwalld running? Try: sudo -E crabwall logs",
            db.display()
        );
        return Ok(());
    }
    let conn = rusqlite::Connection::open(&db)?;
    let mut stmt = conn.prepare(
        "SELECT at,comm,dst_ip,dst_port,domain,decision FROM events ORDER BY id DESC LIMIT ?",
    )?;
    let rows = stmt.query_map([limit as i64], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, String>(5)?,
        ))
    })?;
    if json {
        let mut out = Vec::new();
        for r in rows.flatten() {
            let (at, comm, ip, port, domain, decision) = r;
            out.push(serde_json::json!({
                "at": at,
                "comm": comm,
                "dst_ip": ip,
                "dst_port": port,
                "domain": domain,
                "decision": decision,
            }));
        }
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }
    for r in rows.flatten() {
        let (at, comm, ip, port, domain, dec) = r;
        println!("{at} {comm} -> {}:{port} [{dec}]", domain.unwrap_or(ip));
    }
    Ok(())
}

fn add_rule(app: String, domain: Option<String>, port: Option<u16>, action: Action) -> Result<()> {
    let path = rules_path();
    let rule = Rule {
        id: String::new(),
        app,
        domain_suffix: domain,
        ports: port.into_iter().collect(),
        container: None,
        sandbox: None,
        action,
    };
    append_rule_toml(&path, &rule)?;
    println!("rule added to {}", path.display());
    Ok(())
}

fn append_rule_toml(path: &std::path::Path, rule: &Rule) -> Result<()> {
    use std::fmt::Write as _;
    let mut existing = std::fs::read_to_string(path).unwrap_or_default();
    let a = match rule.action {
        Action::Allow => "allow",
        Action::Deny => "deny",
        Action::Ask => "ask",
    };
    let _ = writeln!(existing, "\n[[rule]]");
    let _ = writeln!(existing, "app = {:?}", rule.app);
    if let Some(d) = &rule.domain_suffix {
        let _ = writeln!(existing, "domain_suffix = {d:?}");
    }
    if !rule.ports.is_empty() {
        let _ = writeln!(existing, "ports = {:?}", rule.ports);
    }
    let _ = writeln!(existing, "action = {a:?}");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(path, existing)?;
    Ok(())
}

fn list_rules() -> Result<()> {
    let path = rules_path();
    if !path.exists() {
        println!("no rules file yet at {}", path.display());
        return Ok(());
    }
    println!("{}", std::fs::read_to_string(&path)?);
    Ok(())
}
