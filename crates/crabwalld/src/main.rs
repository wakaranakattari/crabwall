//! crabwalld: the privileged firewall daemon.
//!
//! Architecture in one paragraph. Four sensors observe outbound traffic
//! at different fidelities: NFQUEUE holds first packets for verdicts,
//! the eBPF connect feed reports PIDs instantly, the AF_PACKET sniffer
//! learns names passively, and the `/proc` poller covers everything as
//! fallback. Observations converge in [`process`]: enrich identity,
//! resolve the domain, decide against the rule set, then enforce (queue
//! verdict or nft-set entry), log to SQLite, or prompt the user through
//! the broadcast channel and hold until answered or timed out into deny.
//!
//! Concurrency contract. The poll loop and the queue consumer never block
//! on prompts: every connection is processed in its own task, verdicts
//! rendezvous through oneshot channels keyed by event id, and at most 32
//! prompts race concurrently (overflow denies immediately, so connection
//! storms cannot pile up tasks). Shared state lives in [`Shared`] behind
//! short-lived mutex guards that are never held across `.await`; the
//! queue fast path and the sniffer additionally hold `Arc` clones of the
//! four thread-safe inputs they need.
//!
//! Failure philosophy. Privileges are probed, never assumed: NFQUEUE,
//! sniffer, eBPF, and nft each degrade to the next weaker mechanism with
//! one log line, and the daemon always ends up enforcing *something*.
//! Every degradation that weakens blocking (queue to sets) is fail-closed
//! in outcome if not in timing: unknown traffic still prompts, prompts
//! still time out to deny.

mod config;
mod correlator;
mod dns;
mod ebpf;
mod enforce;
mod enrich;
mod hold;
mod ipc;
mod nflink;
mod ptr;
mod queue;
mod sensor;
mod sniff;
mod store;

use anyhow::Result;
use config::{append_rule, load_rules, DaemonConfig};
use correlator::{Correlator, FlowKey};
use crabwall_common::{
    decide, Action, ConnectionTuple, NewConnectionEvent, Remember, Rule, Sandbox,
};
use crabwall_packet::frame::IpFlow;
use queue::VerdictRequest;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::oneshot;
use tracing::info;

/// Learn-mode suggestion: (app, domain-or-empty, port).
type Suggestion = (String, String, u16);

struct LearnState {
    until: Instant,
    path: PathBuf,
    seen: HashSet<Suggestion>,
}

/// Everything the daemon tasks share. Lock discipline: short critical
/// sections only, never hold a lock across `.await`. The four `Arc`
/// fields are also handed to background threads (queue fast path,
/// packet sniffer); the rest stays on async tasks.
struct Shared {
    rules: Arc<Mutex<Vec<Rule>>>,
    rules_path: PathBuf,
    rules_mtime: Mutex<Option<SystemTime>>,
    default_action: Action,
    log: store::EventLog,
    enricher: Arc<enrich::Enricher>,
    dns: Arc<dns::DnsCache>,
    correlator: Arc<Correlator>,
    enforcer: enforce::NftEnforcer,
    hold: hold::VerdictHold,
    ptr: ptr::PtrResolver,
    bcast: tokio::sync::broadcast::Sender<crabwall_common::DaemonToClient>,
    pending_tx: Mutex<HashMap<String, oneshot::Sender<Action>>>,
    pending_conn: Mutex<HashMap<String, ConnectionTuple>>,
    pending_pkt: Mutex<HashMap<String, (Arc<nflink::Nflink>, u32)>>,
    session_allows: Mutex<HashSet<String>>,
    learn: Mutex<Option<LearnState>>,
    queue_link: Mutex<Option<Arc<nflink::Nflink>>>,
    /// Caps concurrent prompts (DoS safety); overflow denies immediately.
    prompts: Arc<tokio::sync::Semaphore>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("crabwalld=info".parse().unwrap()),
        )
        .init();

    let (cfg, initial_rules) = DaemonConfig::load()?;
    info!(
        "crabwalld starting: {} rules, default={:?}, sock={}",
        initial_rules.len(),
        cfg.default_action,
        crabwall_common::socket_path().display()
    );

    let server = ipc::IpcServer::new(crabwall_common::socket_path());
    server.run(cfg.default_action).await?;
    let shared = Arc::new(Shared {
        rules: Arc::new(Mutex::new(initial_rules)),
        rules_path: cfg.rules_path.clone(),
        rules_mtime: Mutex::new(mtime_of(&cfg.rules_path)),
        default_action: cfg.default_action,
        log: store::EventLog::open(&cfg.db_path)?,
        enricher: Arc::new(enrich::Enricher::default()),
        dns: Arc::new(dns::DnsCache::default()),
        correlator: Arc::new(Correlator::new(Duration::from_secs(5))),
        enforcer: enforce::NftEnforcer::new(),
        hold: hold::VerdictHold::new(cfg.prompt_timeout_secs),
        ptr: ptr::PtrResolver::from_env(),
        bcast: server.tx.clone(),
        pending_tx: Mutex::new(HashMap::new()),
        pending_conn: Mutex::new(HashMap::new()),
        pending_pkt: Mutex::new(HashMap::new()),
        session_allows: Mutex::new(HashSet::new()),
        learn: Mutex::new(learn_state(&cfg.rules_path)),
        queue_link: Mutex::new(None),
        prompts: Arc::new(tokio::sync::Semaphore::new(32)),
    });
    let verdict_rx = server.verdict_rx;

    if shared.ptr.enabled() {
        info!("reverse-DNS warming enabled (CRABWALL_PTR=1)");
    }
    match ebpf::EbpfSensor::probe() {
        ebpf::EbpfSensor::Available => {
            match ebpf::EbpfReader::start(Arc::clone(&shared.correlator)) {
                Ok(()) => info!("ebpf sensor: streaming connect events"),
                Err(e) => info!("ebpf sensor: reader failed ({e:#}), poll only"),
            }
        }
        ebpf::EbpfSensor::Unavailable(reason) => {
            info!("ebpf sensor: fallback to poll sensor ({reason})")
        }
    }
    match sniff::Sniffer::try_open() {
        Some(sniffer) => {
            info!("packet sniffer: active (dns + sni learning)");
            sniffer.spawn(Arc::clone(&shared.dns));
        }
        None => info!("packet sniffer: disabled, hosts + ptr cache only"),
    }

    // NFQUEUE fast path, or nft-sets fallback.
    let (queue_tx, queue_rx) = tokio::sync::mpsc::channel::<VerdictRequest>(1024);
    match nflink::Nflink::bind(0) {
        Ok(link) => {
            shared.enforcer.ensure_queue(0);
            let ctx = Arc::new(queue::QueueCtx {
                rules: Arc::clone(&shared.rules),
                correlator: Arc::clone(&shared.correlator),
                enricher: Arc::clone(&shared.enricher),
                dns: Arc::clone(&shared.dns),
                out: queue_tx,
            });
            let (link, _thread) = queue::spawn(link, ctx);
            shared.queue_link.lock().map(|mut l| *l = Some(link)).ok();
            info!("nfqueue: active, first packets held for verdicts");
        }
        Err(e) => {
            shared.enforcer.ensure();
            info!("nfqueue unavailable ({e:#}); nft-set fallback (no first-packet hold)");
        }
    }

    spawn_verdict_handler(Arc::clone(&shared), verdict_rx);
    spawn_queue_consumer(Arc::clone(&shared), queue_rx);

    // Poll sensor loop (also feeds the correlator + hot-reload).
    // Each connection is processed in its own task: prompts must never
    // stall polling, reloads, or other connections.
    let mut sensor = sensor::ProcNetSensor::default();
    let poll = Duration::from_millis(cfg.poll_interval_ms);
    loop {
        tokio::time::sleep(poll).await;
        maybe_reload_rules(&shared);
        for raw in sensor.poll() {
            if let (Ok(dst), proto_num) = (raw.dst_ip.parse::<IpAddr>(), proto_num(raw.proto)) {
                shared.correlator.insert(
                    FlowKey::of(proto_num, dst, raw.dst_port, raw.sport),
                    raw.pid,
                );
            }
            let conn = enrich_poll(&shared, &raw);
            warm_ptr(&shared, &conn);
            let shared = Arc::clone(&shared);
            tokio::spawn(async move {
                process(&shared, conn, None).await;
            });
        }
    }
}

fn proto_num(proto: crabwall_common::Proto) -> u8 {
    match proto {
        crabwall_common::Proto::Tcp => 6,
        crabwall_common::Proto::Udp => 17,
    }
}

fn mtime_of(path: &std::path::Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

fn learn_state(rules_path: &std::path::Path) -> Option<LearnState> {
    let secs: u64 = std::env::var("CRABWALL_LEARN_SECS").ok()?.parse().ok()?;
    if secs == 0 {
        return None;
    }
    let path = rules_path.with_extension("suggested.toml");
    info!(
        "learn mode: allowing unknown traffic for {secs}s, suggestions -> {}",
        path.display()
    );
    Some(LearnState {
        until: Instant::now() + Duration::from_secs(secs),
        path,
        seen: HashSet::new(),
    })
}

// --- connection building -------------------------------------------------

fn enrich_poll(shared: &Shared, raw: &sensor::RawConnect) -> ConnectionTuple {
    let info = shared.enricher.lookup(raw.pid);
    ConnectionTuple {
        pid: raw.pid,
        uid: info.uid,
        comm: comm_or_pid(&info.comm, raw.pid),
        exe: info.exe,
        cmdline: info.cmdline,
        proto: raw.proto,
        src_ip: raw.src_ip.clone(),
        dst_ip: raw.dst_ip.clone(),
        dst_port: raw.dst_port,
        domain: shared.dns.lookup(&raw.dst_ip),
        container: info.container,
        sandbox: info.sandbox,
    }
}

fn comm_or_pid(comm: &str, pid: u32) -> String {
    if comm.is_empty() {
        format!("pid{pid}")
    } else {
        comm.to_string()
    }
}

/// Rebuild the flow carried by a queue request for the on-demand scan.
fn request_flow(req: &VerdictRequest) -> Option<IpFlow> {
    if req.proto_num != 6 && req.proto_num != 17 {
        return None;
    }
    Some(IpFlow {
        proto: req.proto_num,
        src: req.src_ip.parse().ok()?,
        dst: req.dst_ip.parse().ok()?,
        sport: req.sport,
        dport: req.dport,
    })
}

/// Attribute a queued packet: correlator pid, else on-demand scan
/// (the SYN sits in the table while the kernel holds the packet).
async fn attribute_queued(shared: &Shared, req: &VerdictRequest) -> ConnectionTuple {
    let mut pid = req.pid;
    if pid.is_none() {
        if let Some(flow) = request_flow(req) {
            for _ in 0..20 {
                if let Some(found) = sensor::find_socket(&flow) {
                    pid = Some(found);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
    let proto = if req.proto_num == 6 {
        crabwall_common::Proto::Tcp
    } else {
        crabwall_common::Proto::Udp
    };
    match pid {
        Some(pid) => {
            let info = shared.enricher.lookup(pid);
            ConnectionTuple {
                pid,
                uid: req.uid.unwrap_or(info.uid),
                comm: comm_or_pid(&info.comm, pid),
                exe: info.exe,
                cmdline: info.cmdline,
                proto,
                src_ip: req.src_ip.clone(),
                dst_ip: req.dst_ip.clone(),
                dst_port: req.dport,
                domain: shared.dns.lookup(&req.dst_ip),
                container: info.container,
                sandbox: info.sandbox,
            }
        }
        None => ConnectionTuple {
            pid: 0,
            uid: req.uid.unwrap_or(u32::MAX),
            comm: "unknown".into(),
            exe: String::new(),
            cmdline: String::new(),
            proto,
            src_ip: req.src_ip.clone(),
            dst_ip: req.dst_ip.clone(),
            dst_port: req.dport,
            domain: req
                .domain
                .clone()
                .or_else(|| shared.dns.lookup(&req.dst_ip)),
            container: None,
            sandbox: None,
        },
    }
}

fn warm_ptr(shared: &Shared, conn: &ConnectionTuple) {
    if conn.domain.is_some() {
        return;
    }
    if let Ok(addr) = conn.dst_ip.parse::<IpAddr>() {
        let dst = conn.dst_ip.clone();
        let dns = Arc::clone(&shared.dns);
        shared.ptr.resolve_bg(addr, move |name| {
            dns.insert(&dst, &name);
        });
    }
}

// --- policy ---------------------------------------------------------------

/// One connection through policy. `packet` carries the queued packet to
/// verdict when the NFQUEUE path is active; `None` means sets-fallback.
async fn process(
    shared: &Shared,
    conn: ConnectionTuple,
    packet: Option<(Arc<nflink::Nflink>, u32)>,
) {
    let app_key = conn.app_key().to_string();
    if let Ok(s) = shared.session_allows.lock() {
        if s.contains(&app_key) {
            enforce(shared, &conn, Action::Allow, &packet);
            return;
        }
    }
    let rules = shared.rules.lock().map(|r| r.clone()).unwrap_or_default();
    let action = decide(&rules, &conn, shared.default_action);
    if action == Action::Ask && learn_active(shared) {
        record_suggestion(shared, &conn);
        enforce(shared, &conn, Action::Allow, &packet);
    } else if action == Action::Ask {
        ask_user(shared, conn, packet).await;
    } else {
        enforce(shared, &conn, action, &packet);
    }
}

/// Apply a final decision: per-packet verdict on the queue path,
/// nft-set entry on the fallback path. Always logged.
fn enforce(
    shared: &Shared,
    conn: &ConnectionTuple,
    action: Action,
    packet: &Option<(Arc<nflink::Nflink>, u32)>,
) {
    if let Some((link, id)) = packet {
        let verdict = match action {
            Action::Allow => nflink::Verdict::Accept,
            _ => nflink::Verdict::Drop,
        };
        if let Err(e) = link.verdict(*id, verdict) {
            tracing::warn!("nfqueue verdict failed: {e:#}");
        }
    } else {
        shared.enforcer.apply(conn, action);
    }
    shared.log.append(conn, action);
    info!(
        "{}:{} -> {:?} ({})",
        conn.dst_ip,
        conn.dst_port,
        action,
        conn.app_key()
    );
}

/// Prompt the user; hold the queued packet (if any) until answered.
/// Timeout verdicts deny. At most 32 prompts race; overflow denies
/// immediately instead of piling up tasks under connection storms.
async fn ask_user(
    shared: &Shared,
    conn: ConnectionTuple,
    packet: Option<(Arc<nflink::Nflink>, u32)>,
) {
    let _permit = match shared.prompts.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            tracing::warn!("prompt overflow, denying {}:{}", conn.dst_ip, conn.dst_port);
            enforce(shared, &conn, Action::Deny, &packet);
            return;
        }
    };
    let id = uuid::Uuid::new_v4().to_string();
    let ev = NewConnectionEvent {
        id: id.clone(),
        at: chrono::Utc::now(),
        conn: conn.clone(),
        matched_rule: None,
        suggested: Action::Ask,
    };
    let (tx, rx) = oneshot::channel();
    shared
        .pending_tx
        .lock()
        .map(|mut p| p.insert(id.clone(), tx))
        .ok();
    shared
        .pending_conn
        .lock()
        .map(|mut m| m.insert(id.clone(), conn.clone()))
        .ok();
    if let Some((link, packet_id)) = &packet {
        shared
            .pending_pkt
            .lock()
            .map(|mut m| m.insert(id.clone(), (Arc::clone(link), *packet_id)))
            .ok();
    }
    let _ = shared
        .bcast
        .send(crabwall_common::DaemonToClient::NewConnection(Box::new(ev)));
    let chosen = shared.hold.wait(rx).await;
    enforce(shared, &conn, chosen, &packet);
    shared.pending_tx.lock().map(|mut p| p.remove(&id)).ok();
    shared.pending_conn.lock().map(|mut m| m.remove(&id)).ok();
    shared.pending_pkt.lock().map(|mut m| m.remove(&id)).ok();
}

fn learn_active(shared: &Shared) -> bool {
    shared
        .learn
        .lock()
        .map(|l| l.as_ref().is_some_and(|s| s.until > Instant::now()))
        .unwrap_or(false)
}

fn record_suggestion(shared: &Shared, conn: &ConnectionTuple) {
    let key: Suggestion = (
        conn.app_key().to_string(),
        conn.domain.clone().unwrap_or_default(),
        conn.dst_port,
    );
    let in_session = shared
        .learn
        .lock()
        .map(|mut l| {
            let state = l.as_mut()?;
            Some((!state.seen.insert(key.clone()), state.path.clone()))
        })
        .unwrap_or(None);
    let Some((duplicate, path)) = in_session else {
        return;
    };
    if duplicate {
        return;
    }
    let (app, domain, port) = key;
    let mut block = String::from("[[rule]]\n");
    block.push_str(&format!("app = {app:?}\n"));
    if !domain.is_empty() {
        block.push_str(&format!("domain_suffix = {domain:?}\n"));
    }
    block.push_str(&format!("ports = [{port}]\naction = \"allow\"\n\n"));
    // Restart-safe: skip when the exact block is already on disk.
    let mut out = std::fs::read_to_string(&path).unwrap_or_else(|_| {
        format!(
            "# crabwall learned suggestions - REVIEW, then merge into rules.toml\n\
             # generated {}\n\n",
            chrono::Utc::now().to_rfc3339()
        )
    });
    if !out.ends_with('\n') {
        out.push('\n');
    }
    if out.contains(&block) {
        return;
    }
    out.push_str(&block);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    if let Err(e) = std::fs::write(&path, out) {
        tracing::warn!("learn: write suggestions failed: {e:#}");
    }
}

// --- background tasks ------------------------------------------------------

fn spawn_verdict_handler(
    shared: Arc<Shared>,
    mut verdict_rx: tokio::sync::mpsc::Receiver<(String, Action, Remember)>,
) {
    tokio::spawn(async move {
        while let Some((event_id, action, remember)) = verdict_rx.recv().await {
            let conn = shared
                .pending_conn
                .lock()
                .map(|m| m.get(&event_id).cloned())
                .ok()
                .flatten();
            if let Ok(mut p) = shared.pending_tx.lock() {
                if let Some(tx) = p.remove(&event_id) {
                    let _ = tx.send(action);
                }
            }
            match remember {
                Remember::Once => {}
                Remember::Session => {
                    if let Some(c) = &conn {
                        if let Ok(mut s) = shared.session_allows.lock() {
                            s.insert(c.app_key().to_string());
                        }
                    }
                }
                Remember::Always => {
                    if let Some(c) = conn {
                        let rule = Rule {
                            id: String::new(),
                            app: if c.exe.is_empty() {
                                c.comm.clone()
                            } else {
                                c.exe.clone()
                            },
                            domain_suffix: c.domain.clone(),
                            ports: vec![],
                            container: c.container.clone(),
                            sandbox: c.sandbox.as_ref().map(Sandbox::id).map(str::to_string),
                            action,
                        };
                        if let Ok(mut r) = shared.rules.lock() {
                            r.push(rule.clone());
                        }
                        if let Err(e) = append_rule(&shared.rules_path, &rule) {
                            tracing::warn!("persist rule failed: {e:#}");
                        }
                    }
                }
            }
        }
    });
}

fn spawn_queue_consumer(shared: Arc<Shared>, mut rx: tokio::sync::mpsc::Receiver<VerdictRequest>) {
    tokio::spawn(async move {
        while let Some(req) = rx.recv().await {
            // Same rule as the poll loop: never let one prompt stall the
            // queue behind it; attribute inline, prompt in a task.
            let link = shared.queue_link.lock().ok().and_then(|l| l.clone());
            let Some(link) = link else {
                continue;
            };
            let packet_id = req.packet_id;
            let conn = attribute_queued(&shared, &req).await;
            warm_ptr(&shared, &conn);
            let shared = Arc::clone(&shared);
            tokio::spawn(async move {
                process(&shared, conn, Some((link, packet_id))).await;
            });
        }
    });
}

fn maybe_reload_rules(shared: &Shared) {
    let current = mtime_of(&shared.rules_path);
    let changed = shared
        .rules_mtime
        .lock()
        .map(|mut m| {
            let changed = *m != current;
            *m = current;
            changed
        })
        .unwrap_or(false);
    if !changed {
        return;
    }
    match load_rules(&shared.rules_path) {
        Ok(rules) => {
            let count = rules.len();
            shared.rules.lock().map(|mut r| *r = rules).ok();
            let _ = shared
                .bcast
                .send(crabwall_common::DaemonToClient::RuleChanged { count });
            info!("rules reloaded: {count} rules");
        }
        Err(e) => tracing::warn!("rules reload failed (keeping old set): {e:#}"),
    }
}
