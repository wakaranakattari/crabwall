//! /proc enrichment: exe, cmdline, uid, container id, sandbox identity.
//!
//! The kernel exposes process truth through procfs, and this module is
//! the daemon's only reader of it. Two access patterns coexist. The hot
//! pattern is [`Enricher::lookup`]: a 2-second TTL cache keyed by PID
//! that turns repeated observations of long-lived processes (browsers
//! opening dozens of connections) into HashMap hits instead of syscalls.
//! The cache is deliberately small in time, not in space, because PIDs
//! are recycled by the kernel: a stale entry attributes a new process's
//! traffic to the old one, so entries must die fast. The cold pattern is
//! [`inode_to_pid`]: a full `/proc/*/fd` scan mapping socket inodes to
//! PIDs, expensive but exact, used once per sensor round and shared by
//! every connection observed in it.
//!
//! Sandbox detection trusts cheap signals first: `FLATPAK_ID` and
//! `SNAP_NAME` in `/proc/<pid>/environ`, then `/.flatpak-info` at the
//! process root as fallback. Container ids come from cgroup paths.
//! Everything degrades to None rather than failing: enrichment is
//! advisory, and policy must decide on partial identity.

use crabwall_common::Sandbox;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Process identity snapshot: everything policy needs about one PID.
pub struct ProcInfo {
    /// Resolved `/proc/<pid>/exe` target; empty when the process exited
    /// between observation and read (racing executables is normal).
    pub exe: String,
    /// Space-joined argv; informational, never matched by rules.
    pub cmdline: String,
    /// Real UID from the `Uid:` status line; used when NFQA_UID is absent.
    pub uid: u32,
    /// Kernel comm name, short but always present while PID lives.
    pub comm: String,
    /// Docker-style container id from cgroup paths, if any.
    pub container: Option<String>,
    /// Flatpak/Snap confinement, if detected (see `detect_sandbox`).
    pub sandbox: Option<Sandbox>,
}

/// Cached `/proc` reader. The TTL (2s) is the whole design: long enough
/// to collapse bursts from chatty processes into cache hits, short
/// enough that PID recycling cannot misattribute for long. Oversize is
/// handled by wholesale clear, same philosophy as the DNS cache.
pub struct Enricher {
    cache: Mutex<HashMap<u32, (Instant, ProcInfo)>>,
    ttl: Duration,
}

impl Default for Enricher {
    fn default() -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
            ttl: Duration::from_secs(2),
        }
    }
}

impl Enricher {
    pub fn lookup(&self, pid: u32) -> ProcInfo {
        if let Ok(cache) = self.cache.lock() {
            if let Some((at, info)) = cache.get(&pid) {
                if at.elapsed() < self.ttl {
                    return ProcInfo {
                        exe: info.exe.clone(),
                        cmdline: info.cmdline.clone(),
                        uid: info.uid,
                        comm: info.comm.clone(),
                        container: info.container.clone(),
                        sandbox: info.sandbox.clone(),
                    };
                }
            }
        }
        let info = read_proc(pid);
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(
                pid,
                (
                    Instant::now(),
                    ProcInfo {
                        exe: info.exe.clone(),
                        cmdline: info.cmdline.clone(),
                        uid: info.uid,
                        comm: info.comm.clone(),
                        container: info.container.clone(),
                        sandbox: info.sandbox.clone(),
                    },
                ),
            );
            if cache.len() > 4096 {
                cache.clear();
            }
        }
        info
    }
}

fn read_proc(pid: u32) -> ProcInfo {
    let base = format!("/proc/{pid}");
    let exe = std::fs::read_link(format!("{base}/exe"))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let comm = std::fs::read_to_string(format!("{base}/comm"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let cmdline = std::fs::read(format!("{base}/cmdline"))
        .map(|b| {
            let s = String::from_utf8_lossy(&b).replace('\0', " ");
            s.trim().to_string()
        })
        .unwrap_or_default();
    let uid = std::fs::read_to_string(format!("{base}/status"))
        .ok()
        .and_then(|t| {
            t.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse().ok()))
        })
        .unwrap_or(1000);
    let container = std::fs::read_to_string(format!("{base}/cgroup"))
        .ok()
        .and_then(|t| {
            // docker/<id> or kubepods/.../<id>
            for line in t.lines() {
                if let Some(idx) = line.find("docker-") {
                    let id = &line[idx + 7..];
                    let id: String = id.chars().take(12).collect();
                    if id.len() == 12 {
                        return Some(id);
                    }
                }
                if line.contains("docker/") {
                    if let Some(last) = line.rsplit('/').next() {
                        let id: String = last.chars().take(12).collect();
                        if id.len() == 12 {
                            return Some(id);
                        }
                    }
                }
            }
            None
        });
    let sandbox = detect_sandbox(pid, &base, &exe);
    ProcInfo {
        exe,
        cmdline,
        uid,
        comm,
        container,
        sandbox,
    }
}

/// Identify Flatpak/Snap confinement. Cheap signals first: `FLATPAK_ID`
/// and `SNAP_NAME` in `/proc/<pid>/environ` (one small read, no traversal).
/// Then `/.flatpak-info` at the process root as fallback, which every
/// Flatpak runtime mounts; `/proc/<pid>/root` traversal can fail on
/// permissions, in which case confinement simply stays unknown. A bare
/// `container=flatpak` marker without an id is not identity and is
/// ignored. `/snap/...` executable paths are a last hint, excluding the
/// `bin` wrapper directory.
fn detect_sandbox(pid: u32, base: &str, exe: &str) -> Option<Sandbox> {
    if let Ok(env) = std::fs::read(format!("{base}/environ")) {
        if let Some(sb) = sandbox_from_environ(&env) {
            return Some(sb);
        }
    }
    // Flatpak runtimes always mount .flatpak-info at the sandbox root.
    let info = std::fs::read_to_string(format!("/proc/{pid}/root/.flatpak-info")).ok()?;
    parse_flatpak_info(&info).map(Sandbox::Flatpak).or_else(|| {
        // Snap confinement without SNAP_NAME (unusual): exe under /snap.
        exe.strip_prefix("/snap/")
            .and_then(|rest| rest.split('/').next())
            .filter(|s| !s.is_empty() && *s != "bin")
            .map(|s| Sandbox::Snap(s.to_string()))
    })
}

/// Pure environ scan: NUL-separated `KEY=VALUE` pairs.
/// Non-UTF8 pairs are skipped, not fatal: environ is attacker-adjacent
/// input (any process controls its own), so parsing must be total.
/// Explicit ids win; a bare `container=flatpak` marker carries no
/// identity and is ignored.
fn sandbox_from_environ(env: &[u8]) -> Option<Sandbox> {
    let mut flatpak_id = None;
    let mut snap_name = None;
    for pair in env.split(|b| *b == 0) {
        let Ok(s) = std::str::from_utf8(pair) else {
            continue;
        };
        let Some((k, v)) = s.split_once('=') else {
            continue;
        };
        match k {
            "FLATPAK_ID" if !v.is_empty() => flatpak_id = Some(v),
            "SNAP_NAME" if !v.is_empty() => snap_name = Some(v),
            _ => {}
        }
    }
    // Prefer the explicit ids; `container=flatpak` alone has no id.
    flatpak_id
        .map(|id| Sandbox::Flatpak(id.to_string()))
        .or_else(|| snap_name.map(|n| Sandbox::Snap(n.to_string())))
}

/// Parse `[Application] name=<app-id>` from .flatpak-info.
/// Section-aware: a `name=` under any other section is not the app id.
/// Empty names are rejected; whitespace is trimmed.
fn parse_flatpak_info(info: &str) -> Option<String> {
    let mut in_app = false;
    for line in info.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_app = line == "[Application]";
            continue;
        }
        if in_app {
            if let Some(name) = line.strip_prefix("name=") {
                let name = name.trim();
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
        }
    }
    None
}

/// Build inode -> pid map by scanning /proc/*/fd. Expensive; caller should
/// cache for the duration of one poll round.
/// Vanished processes and unreadable descriptors are skipped silently:
/// procfs is racy by nature (PIDs die mid-scan) and partial results are
/// still useful. First PID wins per inode; sharing an inode across
/// processes (fork without exec, SCM_RIGHTS passing) is rare enough that
/// determinism beats completeness here.
pub fn inode_to_pid() -> HashMap<u64, u32> {
    let mut map = HashMap::new();
    let Ok(proc) = std::fs::read_dir("/proc") else {
        return map;
    };
    for entry in proc.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let fd_dir = format!("/proc/{pid}/fd");
        let Ok(fds) = std::fs::read_dir(&fd_dir) else {
            continue;
        };
        for fd in fds.flatten() {
            // read_link on /proc/pid/fd/N gives "socket:[12345]"
            if let Ok(link) = std::fs::read_link(fd.path()) {
                if let Some(s) = link.to_str() {
                    if let Some(inner) =
                        s.strip_prefix("socket:[").and_then(|t| t.strip_suffix(']'))
                    {
                        if let Ok(inode) = inner.parse::<u64>() {
                            map.entry(inode).or_insert(pid);
                        }
                    }
                }
            }
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environ_detects_flatpak_and_snap() {
        let env = b"PATH=/usr/bin\0FLATPAK_ID=org.mozilla.firefox\0container=flatpak\0";
        assert_eq!(
            sandbox_from_environ(env),
            Some(Sandbox::Flatpak("org.mozilla.firefox".into()))
        );
        let env = b"SNAP_NAME=firefox\0SNAP=/snap/firefox/1\0";
        assert_eq!(
            sandbox_from_environ(env),
            Some(Sandbox::Snap("firefox".into()))
        );
        assert_eq!(sandbox_from_environ(b"PATH=/usr/bin\0"), None);
        assert_eq!(sandbox_from_environ(b"container=flatpak\0"), None); // no id
        assert_eq!(sandbox_from_environ(b"\xff\xfe=bad\0"), None);
    }

    #[test]
    fn flatpak_info_parses_app_section() {
        let info = "[Application]\nname=org.telegram.desktop\nruntime=runtime/org.gnome.Platform/x86_64/45\n[Environment]\nFOO=1\n";
        assert_eq!(
            parse_flatpak_info(info).as_deref(),
            Some("org.telegram.desktop")
        );
        assert_eq!(parse_flatpak_info("[Environment]\nname=nope\n"), None);
        assert_eq!(parse_flatpak_info(""), None);
    }
}
