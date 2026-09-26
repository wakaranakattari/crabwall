//! Crabwall dashboard TUI: live feed, prompt card, activity, top apps.
//!
//! Information architecture, top to bottom: a dashboard header (build
//! version, LIVE/DEMO status, theme, lifetime allow/deny counters),
//! the main split (connection feed beside a prompt/activity/top-apps
//! column), and a key footer. The prompt card always shows the selected
//! row in full - application, destination, sandbox badge, PID/UID,
//! protocol, age - because verdicts must be informed, and answering the
//! wrong row is the costliest possible misclick. Answered rows keep
//! their verdict marks, so a session's history reads at a glance.
//!
//! Event flow is one-directional and lossy by design: a background task
//! streams daemon events into a bounded channel, the frame loop drains
//! it, and verdicts go out over short-lived sockets (user actions are
//! rare, so connection setup cost is irrelevant). With no daemon, a demo
//! generator feeds synthetic traffic instead, clearly badged DEMO, with
//! answers that vanish - the honest alternative to fake persistence.
//!
//! Keys: y allow-once, Y allow-always, n deny-once, N deny-always,
//!   s allow-session, j/k or arrows to move, q quit.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::{event, execute, terminal};
use ratatui::{prelude::*, widgets::*};
use tokio::io::AsyncBufReadExt;

use crabwall_common::{
    Action, ClientToDaemon, ConnectionTuple, DaemonToClient, NewConnectionEvent, Proto, Remember,
    UserVerdict,
};

use crate::theme::{theme_by_id, IconSet, Theme, THEMES};

/// Startup options: CLI flags win over env, env wins over defaults.
pub struct TuiOptions {
    pub theme: Option<String>,
    pub icons: Option<String>,
}

impl TuiOptions {
    fn resolve(&self) -> (usize, IconSet) {
        // Flag > config file > env > default. A broken file is worth one
        // stderr line before we take over the screen.
        let file = match crate::config::FileConfig::load() {
            Ok(f) => f,
            Err(e) => {
                eprintln!("crabwall: {e:#} (using defaults)");
                crate::config::FileConfig::default()
            }
        };
        let theme_name = crate::config::FileConfig::resolve(
            self.theme.clone(),
            &file.tui.theme,
            "CRABWALL_THEME",
            "phosphor",
        );
        let icons_name = crate::config::FileConfig::resolve(
            self.icons.clone(),
            &file.tui.icons,
            "CRABWALL_ICONS",
            "plain",
        );
        let (idx, _) = theme_by_id(&theme_name);
        (idx, IconSet::parse(&icons_name))
    }
}

struct App {
    events: Vec<NewConnectionEvent>,
    answered: HashMap<String, Action>,
    allow_count: u64,
    deny_count: u64,
    timeline: VecDeque<Instant>,
    app_hits: HashMap<String, u64>,
    selected: usize,
    follow_latest: bool,
    connected: bool,
    tab: usize,
    theme_idx: usize,
    icons: IconSet,
    rules_text: String,
    rules_path: String,
    rules_tab_seen: bool,
}

impl App {
    fn theme(&self) -> Theme {
        THEMES[self.theme_idx % THEMES.len()]
    }

    fn record_event(&mut self, ev: NewConnectionEvent) {
        self.timeline.push_back(Instant::now());
        while self.timeline.len() > 512 {
            self.timeline.pop_front();
        }
        *self
            .app_hits
            .entry(ev.conn.basename().to_string())
            .or_insert(0) += 1;
        self.events.push(ev);
        if self.events.len() > 300 {
            self.events.remove(0);
        }
        if self.follow_latest {
            self.selected = self.events.len().saturating_sub(1);
        }
    }

    /// Record a verdict for the selected event. Returns false when this
    /// exact verdict was already given (key autorepeat or double press):
    /// the caller must not resend nor recount. A changed mind resends
    /// and moves the counter from the old action to the new one.
    fn answer_selected(&mut self, action: Action) -> bool {
        let Some(ev) = self.events.get(self.selected) else {
            return false;
        };
        if self.answered.get(&ev.id) == Some(&action) {
            return false;
        }
        if let Some(old) = self.answered.insert(ev.id.clone(), action) {
            match old {
                Action::Allow => self.allow_count = self.allow_count.saturating_sub(1),
                Action::Deny => self.deny_count = self.deny_count.saturating_sub(1),
                Action::Ask => {}
            }
        }
        match action {
            Action::Allow => self.allow_count += 1,
            Action::Deny => self.deny_count += 1,
            Action::Ask => {}
        }
        true
    }

    /// Events per second over the last 30 one-second buckets.
    fn activity(&self) -> Vec<u64> {
        let now = Instant::now();
        let mut buckets = vec![0u64; 30];
        for t in &self.timeline {
            let age = now.saturating_duration_since(*t).as_secs();
            if age < 30 {
                buckets[29 - age as usize] += 1;
            }
        }
        buckets
    }

    fn top_apps(&self, n: usize) -> Vec<(String, u64)> {
        let mut v: Vec<_> = self.app_hits.iter().map(|(k, c)| (k.clone(), *c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v.truncate(n);
        v
    }
}

const BLOCKS: [char; 8] = [' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇'];

/// Text sparkline: maps buckets to block characters, scaled to max.
fn sparkline(buckets: &[u64]) -> String {
    let max = buckets.iter().copied().max().unwrap_or(0).max(1);
    buckets
        .iter()
        .map(|b| BLOCKS[((b * 7) / max) as usize])
        .collect()
}

/// Text bar for top-apps: filled/empty blocks proportional to max.
fn bar(count: u64, max: u64, width: usize) -> String {
    let filled = count
        .saturating_mul(width as u64)
        .checked_div(max.max(1))
        .unwrap_or(0) as usize;
    let filled = filled.min(width);
    "█".repeat(filled) + &"░".repeat(width - filled)
}

fn time_ago(at: chrono::DateTime<chrono::Utc>) -> String {
    let secs = chrono::Utc::now()
        .signed_duration_since(at)
        .num_seconds()
        .max(0);
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else {
        format!("{}h", secs / 3600)
    }
}

pub async fn run(opts: TuiOptions) -> Result<()> {
    let (theme_idx, icons) = opts.resolve();
    let (ev_tx, mut ev_rx) = tokio::sync::mpsc::channel::<NewConnectionEvent>(256);
    let connected = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

    {
        let ev_tx = ev_tx.clone();
        let connected = connected.clone();
        tokio::spawn(async move {
            // Err means no daemon; the demo generator below covers that.
            let _ = ipc_loop(ev_tx, connected).await;
        });
    }
    // Demo generator when daemon absent.
    {
        let ev_tx = ev_tx.clone();
        let connected = connected.clone();
        tokio::spawn(async move { demo_loop(ev_tx, connected).await });
    }

    terminal::enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, terminal::EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut term = Terminal::new(backend)?;

    let mut app = App {
        events: Vec::new(),
        answered: HashMap::new(),
        allow_count: 0,
        deny_count: 0,
        timeline: VecDeque::new(),
        app_hits: HashMap::new(),
        selected: 0,
        follow_latest: true,
        connected: false,
        tab: 0,
        theme_idx,
        icons,
        rules_text: String::new(),
        rules_path: String::new(),
        rules_tab_seen: false,
    };
    let verdict_out = verdict_sender();

    loop {
        app.connected = connected.load(std::sync::atomic::Ordering::Relaxed);
        while let Ok(ev) = ev_rx.try_recv() {
            let _ = notify_rust::Notification::new()
                .summary("crabwall: new connection")
                .body(&format!(
                    "{} -> {}:{}",
                    ev.conn.app_key(),
                    ev.conn.domain.as_deref().unwrap_or(&ev.conn.dst_ip),
                    ev.conn.dst_port
                ))
                .show();
            app.record_event(ev);
        }
        if app.tab == 1 && !app.rules_tab_seen {
            let (path, text) = load_rules_text();
            app.rules_path = path;
            app.rules_text = text;
            app.rules_tab_seen = true;
        }
        if app.tab == 0 {
            app.rules_tab_seen = false;
        }

        term.draw(|f| draw(f, &app))?;

        if event::poll(Duration::from_millis(150))? {
            if let event::Event::Key(k) = event::read()? {
                // Holding a verdict key must not machine-gun verdicts:
                // autorepeat is ignored for decisions (navigation keeps it).
                let repeat = k.kind == event::KeyEventKind::Repeat;
                match k.code {
                    event::KeyCode::Char('q') | event::KeyCode::Esc => break,
                    event::KeyCode::Tab => app.tab = (app.tab + 1) % 2,
                    event::KeyCode::Char('t') => {
                        app.theme_idx = (app.theme_idx + 1) % THEMES.len();
                    }
                    event::KeyCode::Char('i') => app.icons = app.icons.toggle(),
                    event::KeyCode::Char('y') if !repeat => {
                        if app.answer_selected(Action::Allow) {
                            verdict(&app, &verdict_out, Action::Allow, Remember::Once).await;
                        }
                    }
                    event::KeyCode::Char('Y') if !repeat => {
                        if app.answer_selected(Action::Allow) {
                            verdict(&app, &verdict_out, Action::Allow, Remember::Always).await;
                        }
                    }
                    event::KeyCode::Char('n') if !repeat => {
                        if app.answer_selected(Action::Deny) {
                            verdict(&app, &verdict_out, Action::Deny, Remember::Once).await;
                        }
                    }
                    event::KeyCode::Char('N') if !repeat => {
                        if app.answer_selected(Action::Deny) {
                            verdict(&app, &verdict_out, Action::Deny, Remember::Always).await;
                        }
                    }
                    event::KeyCode::Char('s') if !repeat => {
                        if app.answer_selected(Action::Allow) {
                            verdict(&app, &verdict_out, Action::Allow, Remember::Session).await;
                        }
                    }
                    event::KeyCode::Up | event::KeyCode::Char('k') => {
                        if app.selected > 0 {
                            app.selected -= 1;
                            app.follow_latest = false;
                        }
                    }
                    event::KeyCode::Down | event::KeyCode::Char('j') => {
                        let last = app.events.len().saturating_sub(1);
                        if app.selected < last {
                            app.selected += 1;
                        }
                        if app.selected == last {
                            app.follow_latest = true;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    terminal::disable_raw_mode()?;
    execute!(term.backend_mut(), terminal::LeaveAlternateScreen)?;
    // Keys changed the look: remember it, so `t`/`i` stick without flags.
    persist_appearance(theme_idx, icons, app.theme_idx, app.icons);
    Ok(())
}

/// Write theme/icons back to config.toml when the TUI keys changed them.
/// Best-effort: a word on stderr on failure, silence on success... plus
/// one confirmation line so the persistence is discoverable.
fn persist_appearance(
    start_theme: usize,
    start_icons: IconSet,
    end_theme: usize,
    end_icons: IconSet,
) {
    if start_theme == end_theme && start_icons == end_icons {
        return;
    }
    let mut file = crate::config::FileConfig::load().unwrap_or_default();
    file.tui.theme = THEMES[end_theme % THEMES.len()].id.to_string();
    file.tui.icons = end_icons.label().to_string();
    match file.save() {
        Ok(()) => println!(
            "saved: theme {} + icons {} (config.toml)",
            file.tui.theme, file.tui.icons
        ),
        Err(e) => eprintln!("crabwall: save settings failed: {e:#}"),
    }
}

async fn verdict(
    app: &App,
    out: &tokio::sync::mpsc::Sender<(String, Action, Remember)>,
    action: Action,
    remember: Remember,
) {
    if let Some(ev) = app.events.get(app.selected) {
        let _ = out.send((ev.id.clone(), action, remember)).await;
    }
}

/// Long-lived verdict sender: opens a fresh socket per message (simple,
/// low-rate user actions only).
fn verdict_sender() -> tokio::sync::mpsc::Sender<(String, Action, Remember)> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(String, Action, Remember)>(64);
    tokio::spawn(async move {
        while let Some((id, action, remember)) = rx.recv().await {
            let path = crabwall_common::socket_path();
            let Ok(stream) = tokio::net::UnixStream::connect(&path).await else {
                continue; // demo mode: no daemon
            };
            let (rd, mut wr) = stream.into_split();
            // Drain hello.
            let mut lines = tokio::io::BufReader::new(rd).lines();
            let _ = tokio::time::timeout(Duration::from_millis(500), lines.next_line()).await;
            let msg = ClientToDaemon::Verdict(UserVerdict {
                event_id: id,
                action,
                remember,
            });
            if let Ok(line) = serde_json::to_string(&msg) {
                use tokio::io::AsyncWriteExt;
                let _ = wr.write_all(format!("{line}\n").as_bytes()).await;
                let _ = wr.shutdown().await;
            }
        }
    });
    tx
}

async fn ipc_loop(
    ev_tx: tokio::sync::mpsc::Sender<NewConnectionEvent>,
    connected: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let path = crabwall_common::socket_path();
    let stream = tokio::net::UnixStream::connect(&path).await?;
    connected.store(true, std::sync::atomic::Ordering::Relaxed);
    let (rd, mut wr) = stream.into_split();
    let mut lines = BufReader::new(rd).lines();
    // hello
    let _ = lines.next_line().await;
    // subscribe
    let sub = ClientToDaemon::Subscribe;
    if let Ok(line) = serde_json::to_string(&sub) {
        let _ = wr.write_all(format!("{line}\n").as_bytes()).await;
    }
    while let Ok(Some(line)) = lines.next_line().await {
        if let Ok(DaemonToClient::NewConnection(ev)) = serde_json::from_str::<DaemonToClient>(&line)
        {
            if ev_tx.send(*ev).await.is_err() {
                break;
            }
        }
    }
    connected.store(false, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

async fn demo_loop(
    ev_tx: tokio::sync::mpsc::Sender<NewConnectionEvent>,
    connected: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    use std::sync::atomic::Ordering;
    tokio::time::sleep(Duration::from_secs(2)).await;
    if connected.load(Ordering::Relaxed) {
        return;
    }
    let samples: [(&str, Option<&str>, &str, u16); 4] = [
        (
            "/usr/bin/firefox",
            Some("tracker.example.com"),
            "93.184.216.34",
            443,
        ),
        ("/usr/bin/curl", Some("api.github.com"), "140.82.121.6", 443),
        (
            "/usr/bin/spotify",
            Some("audio-fa.scdn.co"),
            "35.186.224.25",
            443,
        ),
        ("/usr/bin/ssh", None, "203.0.113.10", 22),
    ];
    let mut i = 0;
    loop {
        let (exe, domain, ip, port) = &samples[i % samples.len()];
        i += 1;
        let ev = NewConnectionEvent {
            id: uuid_simple(),
            at: chrono::Utc::now(),
            conn: ConnectionTuple {
                pid: 1000 + i as u32,
                uid: 1000,
                comm: exe.rsplit('/').next().unwrap().to_string(),
                exe: exe.to_string(),
                cmdline: String::new(),
                proto: Proto::Tcp,
                src_ip: "192.168.1.5".into(),
                dst_ip: ip.to_string(),
                dst_port: *port,
                domain: domain.map(|s| s.to_string()),
                container: None,
                sandbox: None,
            },
            matched_rule: None,
            suggested: Action::Ask,
        };
        if ev_tx.send(ev).await.is_err() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(4)).await;
    }
}

fn uuid_simple() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("demo-{n}")
}

/// Rules file content plus the path it came from. The path is shown in
/// the tab title: the daemon and the TUI each resolve it from env with a
/// home-dir fallback, so a mismatch (e.g. daemon on /tmp, TUI on ~/.config)
/// is visible instead of a mystery.
fn load_rules_text() -> (String, String) {
    let path = std::env::var("CRABWALL_RULES")
        .map(std::path::PathBuf::from)
        .ok()
        .or_else(|| {
            directories::ProjectDirs::from("", "", "crabwall")
                .map(|d| d.config_dir().join("rules.toml"))
        });
    let label = path
        .as_ref()
        .map(|p| shorten_home(p))
        .unwrap_or_else(|| "(no config dir)".into());
    let text = path
        .and_then(|p| std::fs::read_to_string(p).ok())
        .unwrap_or_else(|| "# no rules file yet - press Y on a prompt to create one".into());
    (label, text)
}

/// `~/.config/...` instead of `/home/user/.config/...` for tab titles.
fn shorten_home(p: &std::path::Path) -> String {
    let s = p.display().to_string();
    if let Ok(home) = std::env::var("HOME") {
        if let Some(rest) = s.strip_prefix(&home) {
            return format!("~{rest}");
        }
    }
    s
}

// --- drawing ---------------------------------------------------------------

fn draw(f: &mut Frame, app: &App) {
    let t = app.theme();
    f.render_widget(
        Block::default().style(Style::default().bg(t.bg).fg(t.fg)),
        f.area(),
    );
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Min(0),
            Constraint::Length(3),
        ])
        .split(f.area());

    draw_header(f, app, t, chunks[0]);
    if app.tab == 0 {
        let main = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(62), Constraint::Percentage(38)])
            .split(chunks[1]);
        draw_feed(f, app, t, main[0]);
        let side = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(13),
                Constraint::Length(6),
                Constraint::Min(0),
            ])
            .split(main[1]);
        draw_prompt(f, app, t, side[0]);
        draw_activity(f, app, t, side[1]);
        draw_top_apps(f, app, t, side[2]);
    } else {
        draw_rules(f, app, t, chunks[1]);
    }
    draw_footer(f, app, t, chunks[2]);
}

fn block(t: Theme, title: &str) -> Block<'_> {
    Block::default()
        .title(Span::styled(
            format!(" {title} "),
            Style::default().fg(t.accent),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(t.border))
        .style(Style::default().bg(t.bg).fg(t.fg))
}

fn draw_header(f: &mut Frame, app: &App, t: Theme, area: Rect) {
    let pending = app.events.len() as u64;
    let status = if app.connected {
        "● LIVE"
    } else {
        "○ DEMO"
    };
    let status_color = if app.connected { t.allow } else { t.ask };
    let lines = vec![
        Line::from(vec![
            Span::styled(
                "crabwall 1.0.0  ",
                Style::default().fg(t.fg).add_modifier(Modifier::BOLD),
            ),
            Span::styled(status, Style::default().fg(status_color)),
            Span::styled(
                format!("   {} {}", t.label, app.icons.label()),
                Style::default().fg(t.muted),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                format!("{} allow ", app.allow_count),
                Style::default().fg(t.allow),
            ),
            Span::styled(
                format!("{} deny ", app.deny_count),
                Style::default().fg(t.deny),
            ),
            Span::styled(format!("{} seen", pending), Style::default().fg(t.muted)),
        ]),
        Line::from(vec![
            Span::styled(
                if app.tab == 0 { "[feed]" } else { " feed " },
                Style::default()
                    .fg(if app.tab == 0 { t.accent } else { t.muted })
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("  ", Style::default()),
            Span::styled(
                if app.tab == 1 { "[rules]" } else { " rules " },
                Style::default()
                    .fg(if app.tab == 1 { t.accent } else { t.muted })
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("  (Tab)", Style::default().fg(t.muted)),
        ]),
    ];
    f.render_widget(Paragraph::new(lines).block(block(t, "dashboard")), area);
}

fn draw_feed(f: &mut Frame, app: &App, t: Theme, area: Rect) {
    let (ok, no, wait) = app.icons.verdict();
    let rows: Vec<Row> = app
        .events
        .iter()
        .map(|e| {
            let mark = match app.answered.get(&e.id) {
                Some(Action::Allow) => Span::styled(ok, Style::default().fg(t.allow)),
                Some(Action::Deny) => Span::styled(no, Style::default().fg(t.deny)),
                _ => Span::styled(wait, Style::default().fg(t.ask)),
            };
            let dest = e
                .conn
                .domain
                .clone()
                .unwrap_or_else(|| e.conn.dst_ip.clone());
            Row::new(vec![
                Cell::from(mark),
                Cell::from(Span::styled(time_ago(e.at), Style::default().fg(t.muted))),
                Cell::from(Span::styled(
                    format!("{}{}", app.icons.app(), e.conn.basename()),
                    Style::default().fg(t.fg),
                )),
                Cell::from(Span::styled(
                    format!("{}{}", app.icons.net(), dest),
                    Style::default().fg(t.accent),
                )),
            ])
        })
        .collect();
    let table = Table::new(
        rows,
        [
            Constraint::Length(4),
            Constraint::Length(5),
            Constraint::Percentage(35),
            Constraint::Percentage(45),
        ],
    )
    .header(
        Row::new(vec!["", "age", "app", "where"])
            .style(Style::default().fg(t.muted).add_modifier(Modifier::BOLD)),
    )
    .block(block(t, "live feed"))
    .row_highlight_style(Style::default().bg(t.border).add_modifier(Modifier::BOLD))
    .highlight_spacing(HighlightSpacing::Always);
    let mut state = TableState::default();
    state.select(Some(app.selected));
    f.render_stateful_widget(table, area, &mut state);
}

fn draw_prompt(f: &mut Frame, app: &App, t: Theme, area: Rect) {
    let b = app.icons.bullet();
    let lines = match app.events.get(app.selected) {
        None => vec![Line::from(Span::styled(
            "no connections yet - start something noisy",
            Style::default().fg(t.muted),
        ))],
        Some(e) => {
            let c = &e.conn;
            let dest = c.domain.clone().unwrap_or_else(|| c.dst_ip.clone());
            let mut v = vec![
                Line::from(vec![Span::styled(
                    format!("{b}{}", c.app_key()),
                    Style::default().fg(t.ask).add_modifier(Modifier::BOLD),
                )]),
                Line::from(Span::styled(
                    format!("{b}{} → {}:{}", c.basename(), dest, c.dst_port),
                    Style::default().fg(t.fg),
                )),
            ];
            if let Some(sb) = &c.sandbox {
                v.push(Line::from(Span::styled(
                    format!("{b}{}", sb.label()),
                    Style::default().fg(t.accent),
                )));
            }
            v.push(Line::from(Span::styled(
                format!(
                    "{b}pid {} · uid {} · {} · {}",
                    c.pid,
                    c.uid,
                    time_ago(e.at),
                    match c.proto {
                        Proto::Tcp => "tcp",
                        Proto::Udp => "udp",
                    }
                ),
                Style::default().fg(t.muted),
            )));
            v.push(Line::from(""));
            v.push(Line::from(vec![
                Span::styled(
                    "y",
                    Style::default().fg(t.allow).add_modifier(Modifier::BOLD),
                ),
                Span::styled(" allow  ", Style::default().fg(t.fg)),
                Span::styled(
                    "n",
                    Style::default().fg(t.deny).add_modifier(Modifier::BOLD),
                ),
                Span::styled(" deny  ", Style::default().fg(t.fg)),
                Span::styled(
                    "Y/N",
                    Style::default().fg(t.ask).add_modifier(Modifier::BOLD),
                ),
                Span::styled(" always  ", Style::default().fg(t.fg)),
                Span::styled(
                    "s",
                    Style::default().fg(t.accent).add_modifier(Modifier::BOLD),
                ),
                Span::styled(" session", Style::default().fg(t.fg)),
            ]));
            if !app.connected {
                v.push(Line::from(Span::styled(
                    "○ DEMO - answers vanish without crabwalld",
                    Style::default().fg(t.muted),
                )));
            }
            v
        }
    };
    f.render_widget(Paragraph::new(lines).block(block(t, "prompt")), area);
}

fn draw_activity(f: &mut Frame, app: &App, t: Theme, area: Rect) {
    let buckets = app.activity();
    let total: u64 = buckets.iter().sum();
    let lines = vec![
        Line::from(Span::styled(
            sparkline(&buckets),
            Style::default().fg(t.accent),
        )),
        Line::from(Span::styled(
            format!("{total} events / 30s"),
            Style::default().fg(t.muted),
        )),
    ];
    f.render_widget(Paragraph::new(lines).block(block(t, "activity")), area);
}

fn draw_top_apps(f: &mut Frame, app: &App, t: Theme, area: Rect) {
    let top = app.top_apps(8);
    let max = top.iter().map(|(_, c)| *c).max().unwrap_or(1);
    let width = 14usize;
    let lines: Vec<Line> = if top.is_empty() {
        vec![Line::from(Span::styled(
            "…waiting for traffic…",
            Style::default().fg(t.muted),
        ))]
    } else {
        top.iter()
            .map(|(name, count)| {
                Line::from(vec![
                    Span::styled(format!("{count:>4} "), Style::default().fg(t.accent)),
                    Span::styled(bar(*count, max, width), Style::default().fg(t.allow)),
                    Span::styled(format!(" {name}"), Style::default().fg(t.fg)),
                ])
            })
            .collect()
    };
    f.render_widget(Paragraph::new(lines).block(block(t, "top apps")), area);
}

fn draw_rules(f: &mut Frame, app: &App, t: Theme, area: Rect) {
    let title = if app.rules_path.is_empty() {
        "rules".to_string()
    } else {
        format!("rules ({})", app.rules_path)
    };
    f.render_widget(
        Paragraph::new(app.rules_text.clone())
            .style(Style::default().fg(t.fg))
            .block(block(t, &title)),
        area,
    );
}

fn draw_footer(f: &mut Frame, app: &App, t: Theme, area: Rect) {
    let line = Line::from(vec![
        Span::styled("y/Y", Style::default().fg(t.allow)),
        Span::styled(" allow · ", Style::default().fg(t.muted)),
        Span::styled("n/N", Style::default().fg(t.deny)),
        Span::styled(" deny · ", Style::default().fg(t.muted)),
        Span::styled("s", Style::default().fg(t.accent)),
        Span::styled(" session · ", Style::default().fg(t.muted)),
        Span::styled("t", Style::default().fg(t.fg)),
        Span::styled(
            format!(" theme:{} · ", t.label),
            Style::default().fg(t.muted),
        ),
        Span::styled("i", Style::default().fg(t.fg)),
        Span::styled(
            format!(" icons:{} · ", app.icons.label()),
            Style::default().fg(t.muted),
        ),
        Span::styled("Tab", Style::default().fg(t.fg)),
        Span::styled(" tab · ", Style::default().fg(t.muted)),
        Span::styled("q", Style::default().fg(t.fg)),
        Span::styled(" quit", Style::default().fg(t.muted)),
    ]);
    f.render_widget(Paragraph::new(line).block(block(t, "keys")), area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;

    fn sample_app(theme_idx: usize, icons: IconSet, tab: usize) -> App {
        let mut app = App {
            events: Vec::new(),
            answered: HashMap::new(),
            allow_count: 3,
            deny_count: 1,
            timeline: VecDeque::from(vec![Instant::now()]),
            app_hits: HashMap::from([("firefox".to_string(), 5), ("curl".to_string(), 2)]),
            selected: 0,
            follow_latest: true,
            connected: true,
            tab,
            theme_idx,
            icons,
            rules_text: "[[rule]]\napp = \"curl\"\naction = \"deny\"\n".into(),
            rules_path: "~/.config/crabwall/rules.toml".into(),
            rules_tab_seen: true,
        };
        app.record_event(NewConnectionEvent {
            id: "e1".into(),
            at: chrono::Utc::now(),
            conn: ConnectionTuple {
                pid: 42,
                uid: 1000,
                comm: "curl".into(),
                exe: "/usr/bin/curl".into(),
                cmdline: String::new(),
                proto: Proto::Tcp,
                src_ip: "192.168.1.5".into(),
                dst_ip: "93.184.216.34".into(),
                dst_port: 443,
                domain: Some("example.com".into()),
                container: None,
                sandbox: None,
            },
            matched_rule: None,
            suggested: Action::Ask,
        });
        app
    }

    /// Every theme × icon set × tab renders without panic on 120x40.
    #[test]
    fn all_themes_render() {
        for theme_idx in 0..THEMES.len() {
            for icons in [IconSet::Plain, IconSet::Nerd] {
                for tab in [0, 1] {
                    let app = sample_app(theme_idx, icons, tab);
                    let backend = TestBackend::new(120, 40);
                    let mut term = Terminal::new(backend).unwrap();
                    term.draw(|f| draw(f, &app)).unwrap();
                    let content: String = term
                        .backend()
                        .buffer()
                        .content()
                        .iter()
                        .map(|c| c.symbol())
                        .collect();
                    assert!(content.contains("crabwall"), "theme {theme_idx} tab {tab}");
                    if tab == 0 {
                        assert!(content.contains("example.com"), "feed row missing");
                    } else {
                        assert!(content.contains("[[rule]]"), "rules tab missing");
                    }
                }
            }
        }
    }

    #[test]
    fn theme_lookup_falls_back() {
        assert_eq!(theme_by_id("dracula").1.id, "dracula");
        assert_eq!(theme_by_id("DRACULA").1.id, "dracula");
        assert_eq!(theme_by_id("nope").1.id, "phosphor");
        assert_eq!(IconSet::parse("nerd"), IconSet::Nerd);
        assert_eq!(IconSet::parse("whatever"), IconSet::Plain);
        assert_eq!(IconSet::Nerd.toggle(), IconSet::Plain);
    }

    #[test]
    fn sparkline_and_bars() {
        assert_eq!(sparkline(&[0, 0, 0]).chars().count(), 3);
        let s = sparkline(&[0, 5, 10]);
        assert!(s.ends_with('▇'));
        assert_eq!(bar(5, 10, 10).chars().count(), 10);
        assert_eq!(bar(0, 0, 4), "░░░░");
    }

    #[test]
    fn answer_dedupes_repeats_and_moves_counters() {
        let mut app = sample_app(0, IconSet::Plain, 0);
        // First verdict counts and may send.
        assert!(app.answer_selected(Action::Allow));
        assert_eq!(app.allow_count, 4);
        // Same verdict again (held key): ignored.
        assert!(!app.answer_selected(Action::Allow));
        assert_eq!(app.allow_count, 4);
        // Changed mind: moves the counter, may send.
        assert!(app.answer_selected(Action::Deny));
        assert_eq!((app.allow_count, app.deny_count), (3, 2));
    }

    /// Visual review helper: `cargo test -p crabwall preview_layout -- --nocapture`.
    /// Throwaway output, asserts nothing beyond successful render.
    #[test]
    fn preview_layout() {
        if std::env::var("CRABWALL_PREVIEW").is_err() {
            return;
        }
        for (idx, icons) in [(0, IconSet::Plain), (2, IconSet::Nerd)] {
            let app = sample_app(idx, icons, 0);
            let backend = TestBackend::new(120, 40);
            let mut term = Terminal::new(backend).unwrap();
            term.draw(|f| draw(f, &app)).unwrap();
            println!("=== theme={} icons={:?} ===", THEMES[idx].label, icons);
            for y in 0..40 {
                let mut line = String::new();
                for x in 0..120 {
                    line.push_str(
                        term.backend()
                            .buffer()
                            .cell((x, y))
                            .map(|c| c.symbol())
                            .unwrap_or(" "),
                    );
                }
                println!("{line}");
            }
        }
    }
}
