# crabwall architecture

Three processes, one privilege boundary.

```
app connect()
  ├─► NFQUEUE (kernel holds first packet, needs privs)
  │     ├─ fast path (queue thread): correlator + rules → Accept/Drop now
  │     └─ slow path (async): full attribution → prompt → verdict by id
  ├─► eBPF tracepoint (connect feed → correlator, observe-only)
  ├─► AF_PACKET sniffer (DNS responses + TLS SNI → domain cache)
  └─► /proc poll (fallback sensor + on-demand socket scan)
            │
            ▼
     enrich (/proc exe/uid/cgroup/sandbox, NFQA_UID)
            │
            ▼
     decide (rules.toml, most-specific match wins, default Ask)
            ├─ Allow/Deny → enforce + sqlite log
            └─ Ask → TUI prompt (30s, timeout = deny) → enforce + log
```

## Crates

- `crabwall-common` - rules, matching engine, IPC protocol (frozen v2).
- `crabwall-packet` - pure parsers (DNS, SNI, IP frames). No I/O;
  fuzzed (`fuzz/`) and benchmarked (`cargo xtask bench`).
- `crabwalld` - the daemon (root): sensors, enforcement, IPC server.
  - `nflink` - hand-rolled NETLINK_NETFILTER client (libc only, no
    libnetfilter_queue, no GPL). Pure codec, unit-tested against the
    kernel header layouts.
  - `queue` - fast-path thread: instant verdicts, Ask defers to async.
  - `correlator` - 5-tuple→pid map (poll/eBPF-fed, 5s window) with
    fuzzy fallback for sport-less eBPF events.
  - `enforce` - nftables sets (fallback) + `queue num 0 bypass` steering.
- `crabwall-cli` - `crabwall` TUI (ratatui, demo mode without daemon) + CLI.
- `crabwall-ebpf` - tracepoint program (`sys_enter_connect` → perf events).
  Built by `cargo xtask build-ebpf`, never linked into host binaries.

## Key invariants

1. **Never silent-allow on the Ask path.** Unknown = prompt; timeout,
   channel-full, lost race = deny/drop (fail-closed).
2. **Fallbacks compose, never replace.** No privs → sets instead of queue;
   no eBPF object → poll; no sniffer → hosts/PTR cache. Each step logs.
3. **Fast path decides only what it can prove.** Anything needing a user
   goes to async with full enrichment.
4. **Untrusted bytes stay in `crabwall-packet`.** Length-capped outputs
   (DNS 253, SNI 255); fuzzed continuously.
