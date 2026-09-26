//! SQLite event log: every decided connection, queryable by the CLI.
//!
//! One table, six indexed columns, no ORM. Rows are appended under a
//! mutex (writes are rare - one per connection decision - so a pool
//! would be pure overhead) and the table is pruned to roughly the last
//! 50k rows on every write, which bounds disk usage without a vacuum
//! schedule. Schema evolution follows the additive-migration discipline
//! of `docs/STABILITY.md`: the `user_version` pragma records the schema
//! generation (1 for the initial table), and future versions may only
//! add tables, columns, or indexes, never rename or remove, so any 1.x
//! database stays readable by any 1.x daemon.
use anyhow::Result;
use chrono::Utc;
use crabwall_common::{Action, ConnectionTuple};
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::Mutex;

/// Append-only SQLite log behind one mutex. Single-writer discipline
/// (the daemon is the only writer; the CLI only reads) keeps locking
/// trivial and the schema migration-free within major versions.
pub struct EventLog {
    db: Mutex<Connection>,
}

impl EventLog {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(path)?;
        // Schema version for additive migrations (see docs/STABILITY.md).
        // v1: the events table as created below.
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version == 0 {
            conn.execute("PRAGMA user_version = 1", [])?;
        }
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS events(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              at TEXT NOT NULL,
              pid INTEGER NOT NULL,
              uid INTEGER NOT NULL,
              comm TEXT NOT NULL,
              exe TEXT NOT NULL,
              proto TEXT NOT NULL,
              src_ip TEXT NOT NULL,
              dst_ip TEXT NOT NULL,
              dst_port INTEGER NOT NULL,
              domain TEXT,
              decision TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_at ON events(at);
            CREATE INDEX IF NOT EXISTS idx_events_dst ON events(dst_ip, dst_port);",
        )?;
        Ok(Self {
            db: Mutex::new(conn),
        })
    }

    pub fn append(&self, conn: &ConnectionTuple, decision: Action) {
        let d = match decision {
            Action::Allow => "allow",
            Action::Deny => "deny",
            Action::Ask => "ask",
        };
        let proto = match conn.proto {
            crabwall_common::Proto::Tcp => "tcp",
            crabwall_common::Proto::Udp => "udp",
        };
        if let Ok(db) = self.db.lock() {
            let _ = db.execute(
                "INSERT INTO events(at,pid,uid,comm,exe,proto,src_ip,dst_ip,dst_port,domain,decision)
                 VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                params![
                    Utc::now().to_rfc3339(),
                    conn.pid as i64,
                    conn.uid as i64,
                    conn.comm,
                    conn.exe,
                    proto,
                    conn.src_ip,
                    conn.dst_ip,
                    conn.dst_port as i64,
                    conn.domain,
                    d
                ],
            );
            // Best-effort rotation: keep last ~50k rows.
            let _ = db.execute(
                "DELETE FROM events WHERE id <= (SELECT MAX(id)-50000 FROM events)",
                [],
            );
        }
    }
}
