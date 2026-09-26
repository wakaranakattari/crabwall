//! Unix-socket IPC server (newline-delimited JSON).
//!
//! The protocol has three message kinds and a strict opening ritual.
//! Every client, on connect, first receives a `Hello` carrying the
//! protocol version and the daemon default policy, then sends a single
//! `Subscribe` to join the event broadcast. Afterwards the server pushes
//! one `NewConnection` object per prompt-worthy connection over the
//! shared broadcast channel (lagging clients drop messages rather than
//! backpressure the daemon - a slow UI must never stall the firewall),
//! and clients answer with `Verdict` lines that are funneled into one
//! mpsc queue consumed by the verdict task in `main`. Malformed lines
//! are logged and skipped; a dead client only aborts its own writer
//! task. The socket path resolves identically on both ends (see
//! `crabwall_common::socket_path`), which is why `crabwall up` cannot
//! desynchronize daemon and UI.

use anyhow::Result;
use crabwall_common::{Action, ClientToDaemon, DaemonToClient, IPC_VERSION};
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, warn};

/// IPC server handle. `tx` is the broadcast every client subscribes to;
/// `verdict_tx`/`verdict_rx` is the single answer queue. The receiver is
/// moved out by `main` after `run`, which is why the field never reads
/// as borrowed afterwards.
pub struct IpcServer {
    pub path: PathBuf,
    pub tx: broadcast::Sender<DaemonToClient>,
    pub verdict_tx: mpsc::Sender<(String, Action, crabwall_common::Remember)>,
    #[allow(dead_code)]
    pub verdict_rx: mpsc::Receiver<(String, Action, crabwall_common::Remember)>,
}

impl IpcServer {
    pub fn new(path: PathBuf) -> Self {
        let (tx, _) = broadcast::channel(256);
        let (verdict_tx, verdict_rx) = mpsc::channel(256);
        Self {
            path,
            tx,
            verdict_tx,
            verdict_rx,
        }
    }

    pub async fn run(&self, default_action: Action) -> Result<()> {
        let _ = std::fs::remove_file(&self.path);
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).ok();
            }
        }
        let listener = UnixListener::bind(&self.path)?;
        debug!("ipc listening on {}", self.path.display());
        let tx = self.tx.clone();
        let verdict_tx = self.verdict_tx.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                let tx = tx.clone();
                let verdict_tx = verdict_tx.clone();
                tokio::spawn(handle_client(stream, tx, verdict_tx, default_action));
            }
        });
        Ok(())
    }
}

async fn handle_client(
    stream: UnixStream,
    tx: broadcast::Sender<DaemonToClient>,
    verdict_tx: mpsc::Sender<(String, Action, crabwall_common::Remember)>,
    default_action: Action,
) {
    let (rd, mut wr) = stream.into_split();
    let mut rx = tx.subscribe();
    // hello
    let hello = DaemonToClient::Hello {
        version: IPC_VERSION,
        default_action,
    };
    if let Ok(line) = serde_json::to_string(&hello) {
        let _ = wr.write_all(format!("{line}\n").as_bytes()).await;
    }
    let write_task = tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            if let Ok(line) = serde_json::to_string(&msg) {
                if wr.write_all(format!("{line}\n").as_bytes()).await.is_err() {
                    break;
                }
            }
        }
    });
    let mut lines = BufReader::new(rd).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        match serde_json::from_str::<ClientToDaemon>(&line) {
            Ok(ClientToDaemon::Verdict(v)) => {
                let _ = verdict_tx.send((v.event_id, v.action, v.remember)).await;
            }
            Ok(ClientToDaemon::Subscribe) => {}
            Err(e) => warn!("bad ipc line: {e}"),
        }
    }
    write_task.abort();
}
