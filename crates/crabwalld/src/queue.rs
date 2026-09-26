//! NFQUEUE fast path: verdict obvious packets on a background thread,
//! forward everything else to the async daemon for full attribution.
//!
//! Threading model, stated exactly once because it is the subtlest part
//! of the system. The queue thread owns receiving: it blocks in `recv`,
//! decodes each packet's 5-tuple, and attempts an instant decision from
//! cache-grade data only (correlator hit, hosts-level domain, in-memory
//! rules). Allow and Deny verdicts issue right there, in microseconds.
//! Anything requiring judgment - unknown PID, `Ask` policy, undecided
//! default - is forwarded as a [`VerdictRequest`] over a bounded Tokio
//! channel to the async side, which enriches fully (on-demand `/proc`
//! scan with retries, PTR warming, user prompt) and verdicts later
//! through the shared [`Nflink`] handle, whose socket sends are
//! thread-safe. A full request channel means the daemon is overloaded:
//! the packet drops fail-closed and the loop moves on, so backpressure
//! can never wedge the queue. Prompt floods are additionally capped by
//! the semaphore in `main`.

use crate::correlator::{Correlator, FlowKey};
use crate::dns::DnsCache;
use crate::enrich::Enricher;
use crate::nflink::{Nflink, QueuedPacket, Verdict};
use crabwall_common::{decide, Action, ConnectionTuple, Rule};
use crabwall_packet::frame::parse_ip_packet;
use std::sync::{Arc, Mutex};
use tracing::{debug, warn};

/// A queued packet the fast path could not decide alone.
/// Carries everything the async side needs to attribute and judge the
/// flow without re-reading the wire: kernel packet id for the eventual
/// verdict, decoded 5-tuple fields, socket-owner UID when the queue was
/// created with the UID_GID flag, and any domain the cache already knew.
#[derive(Debug)]
pub struct VerdictRequest {
    /// Kernel packet id to verdict later.
    pub packet_id: u32,
    /// Attributed pid, when the correlator knew the flow.
    pub pid: Option<u32>,
    /// Socket-owner uid from `NFQA_UID`, when present.
    pub uid: Option<u32>,
    /// Source/destination as strings for connection building.
    pub src_ip: String,
    pub dst_ip: String,
    /// Transport protocol number (6/17).
    pub proto_num: u8,
    /// Ports from the decoded headers.
    pub sport: u16,
    pub dport: u16,
    /// Domain if the cache already knew the destination.
    pub domain: Option<String>,
}

/// Shared fast-path inputs. Everything behind is thread-safe.
/// The queue thread reads rules, correlator, enricher, and DNS cache
/// concurrently with async tasks; all four synchronize internally
/// (mutexes with short critical sections), so no outer locking exists
/// and the fast path can never deadlock the daemon.
pub struct QueueCtx {
    pub rules: Arc<Mutex<Vec<Rule>>>,
    pub correlator: Arc<Correlator>,
    pub enricher: Arc<Enricher>,
    pub dns: Arc<DnsCache>,
    /// Bounded: backpressure drops fail-closed (see below).
    pub out: tokio::sync::mpsc::Sender<VerdictRequest>,
}

/// Start the queue thread. Returns the shared link for deferred verdicts.
pub fn spawn(link: Nflink, ctx: Arc<QueueCtx>) -> (Arc<Nflink>, std::thread::JoinHandle<()>) {
    let link = Arc::new(link);
    let worker = Arc::clone(&link);
    let handle = std::thread::Builder::new()
        .name("crabwall-queue".into())
        .spawn(move || run_loop(&worker, &ctx))
        .expect("queue thread spawns");
    (link, handle)
}

fn run_loop(link: &Nflink, ctx: &QueueCtx) {
    loop {
        let pkt = match link.next_packet() {
            Ok(p) => p,
            Err(e) => {
                // Socket errors are fatal to this thread; the daemon keeps
                // running on the poll path (fail-open would be worse, but a
                // dead queue thread with an installed queue rule stalls
                // traffic - the nft rule uses `bypass`, so packets flow
                // once no userspace listener holds them... in practice the
                // link lives as long as the process; log loudly and exit).
                warn!("nfqueue thread ending: {e:#}");
                return;
            }
        };
        handle_packet(link, ctx, &pkt);
    }
}

fn handle_packet(link: &Nflink, ctx: &QueueCtx, pkt: &QueuedPacket) {
    debug!(
        id = pkt.id,
        hook = pkt.hook,
        hw = pkt.hw_proto,
        "nfqueue: packet"
    );
    let Some(flow) = parse_ip_packet(&pkt.payload) else {
        // Only TCP/UDP are steered here; anything else is dropped
        // fail-closed rather than mis-attributed.
        debug!("nfqueue: undecodable payload, drop");
        verdict_log(link, pkt.id, Verdict::Drop);
        return;
    };
    if flow.proto != 6 && flow.proto != 17 {
        debug!("nfqueue: non-tcp/udp, drop");
        verdict_log(link, pkt.id, Verdict::Drop);
        return;
    }
    let key = FlowKey::from_flow(&flow);
    // Exact hit (poll-fed, with sport), else fuzzy (eBPF-fed, sport 0).
    let pid = ctx.correlator.lookup(&key).or_else(|| {
        ctx.correlator
            .lookup_any_sport(flow.proto, flow.dst, flow.dport)
    });
    let domain = ctx.dns.lookup_cached(&flow.dst.to_string());
    // Fast verdict only with cache-grade attribution; the slow path
    // re-decides with full enrichment (PTR/on-demand scan/prompts).
    let action = match pid {
        Some(pid) => {
            let info = ctx.enricher.lookup(pid);
            let conn = ConnectionTuple {
                pid,
                uid: pkt.uid.unwrap_or(info.uid),
                comm: info.comm.clone(),
                exe: info.exe.clone(),
                cmdline: String::new(),
                proto: if flow.proto == 6 {
                    crabwall_common::Proto::Tcp
                } else {
                    crabwall_common::Proto::Udp
                },
                src_ip: flow.src.to_string(),
                dst_ip: flow.dst.to_string(),
                dst_port: flow.dport,
                domain: domain.clone(),
                container: info.container.clone(),
                sandbox: info.sandbox.clone(),
            };
            let rules = ctx.rules.lock().map(|r| r.clone()).unwrap_or_default();
            // `Ask` (or an undecided default) is not fast-pathable.
            match decide(&rules, &conn, Action::Ask) {
                Action::Ask => None,
                decided => Some(decided),
            }
        }
        None => None,
    };
    match action {
        Some(Action::Allow) => verdict_log(link, pkt.id, Verdict::Accept),
        Some(Action::Deny) => verdict_log(link, pkt.id, Verdict::Drop),
        // Ask, unknown pid, or undecided: defer to async processing.
        _ => {
            let req = VerdictRequest {
                packet_id: pkt.id,
                pid,
                uid: pkt.uid,
                src_ip: flow.src.to_string(),
                dst_ip: flow.dst.to_string(),
                proto_num: flow.proto,
                sport: flow.sport,
                dport: flow.dport,
                domain,
            };
            if ctx.out.try_send(req).is_err() {
                warn!("nfqueue: request channel full, drop (fail-closed)");
                verdict_log(link, pkt.id, Verdict::Drop);
            }
        }
    }
}

fn verdict_log(link: &Nflink, id: u32, verdict: Verdict) {
    if let Err(e) = link.verdict(id, verdict) {
        warn!("nfqueue: verdict failed: {e:#}");
    }
}
