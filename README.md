# crabwall 🦀🧱

[![CI](https://github.com/wakaranakattari/crabwall/actions/workflows/ci.yml/badge.svg)](https://github.com/wakaranakattari/crabwall/actions)
[![Rust](https://img.shields.io/badge/rust-1.87%2B-orange)](https://www.rust-lang.org)
[![Linux](https://img.shields.io/badge/platform-linux-blue)](https://github.com/wakaranakattari/crabwall)
[![License](https://img.shields.io/badge/license-MIT-green)](https://github.com/wakaranakattari/crabwall)

Little Snitch for Linux: see which application connects where, allow or
deny with one key. The first packet waits for your answer.

```
cargo install --path crates/crabwall-cli
crabwall up
```

## Why crabwall

Outbound traffic is invisible by default. Editors phone home telemetry,
messengers resolve trackers, and a compromised dependency exfiltrates
through the same HTTPS every legitimate app uses. Packet filters see
ports; crabwall sees *applications*: every connection is attributed to
a process, enriched with domain, container, and sandbox identity, then
matched against your policy. Unknown traffic prompts instead of passing
silently, and every decision lands in a queryable log.

What this is not: not an antivirus, not an IDS, not a port firewall,
and never TLS interception. See `docs/LIMITS.md` for the honest list.

## Features

- **First-packet hold.** With privileges, TCP/UDP output steers into
  NFQUEUE and each new flow waits for your verdict (timeout denies).
  Hand-rolled netlink client, no libnetfilter_queue, no GPL.
- **Fast attribution.** eBPF connect feed, 5-tuple correlator, on-demand
  `/proc` scan, socket-owner UID from queued packets.
- **Passive naming.** AF_PACKET sniffer learns IP to domain from DNS
  responses and TLS SNI; `/etc/hosts` and opt-in PTR fill the gaps.
- **Sandbox aware.** Flatpak app ids, snap names, and Docker container
  ids are first-class rule constraints.
- **Any init.** systemd, runit, OpenRC, s6, SysVinit, one installer.
- **Vibey TUI.** Seven themes, two icon sets, live feed, prompt card,
  activity sparkline, top apps, rules tab. Demo mode without a daemon.
- **Hardened.** Fuzzed parsers with protocol-max output caps, fail-closed
  defaults everywhere, `clippy -D warnings`, docs build clean.

## Quickstart

Needs Linux, kernel 5.8+, `nftables`, and root for enforcement. Without
root everything still runs in dry-run: observation, prompts (answered
into the void), and logs.

```
# one command: daemon (if needed) + TUI, same env throughout
crabwall up

# with learn mode (allows unknowns for 5 min, writes suggestions)
crabwall up --learn 300

# as a service instead of a session
sudo ./packaging/install.sh
```

## How it works

```
app connect()
  |-NFQUEUE holds the first packet (privileged) ──┐
  |-eBPF connect feed - PID instantly              │
  |-AF_PACKET sniffer - DNS responses + TLS SNI    ├─► attribute
  |-/proc poll - fallback sensor                   │
                                                   ▼
                       enrich (exe/uid/cgroup/sandbox/NFQA_UID)
                                                   ▼
                       decide (most-specific rule wins, else default)
                          ├─ allow/deny → verdict + sqlite log
                          └─ ask → TUI prompt (30s, timeout = deny)
```

Sensors degrade gracefully, each with one log line: no queue, nft-sets;
no eBPF object, poll; no sniffer, hosts and PTR cache. Details:
`docs/ARCHITECTURE.md`.

## Rules

File: `~/.config/crabwall/rules.toml` (override with `CRABWALL_RULES`).
Hot-reloaded on save; the TUI rules tab shows the live file and the
path it was read from, so split-brain setups are visible, not mysterious.

```toml
[[rule]]
app = "firefox"              # basename or full /usr/bin/... path
domain_suffix = "google.com" # optional: exact or subdomain match
ports = [80, 443]            # optional: empty means all ports
container = "abc123def456"   # optional: Docker id from cgroup
sandbox = "org.foo.Bar"      # optional: Flatpak id or snap name
action = "deny"              # allow | deny | ask
```

| Field | Matching |
|---|---|
| `app` with `/` | exact executable path equality |
| `app` bare | basename or comm equality |
| `domain_suffix` | ASCII case-folded exact or subdomain match; needs a known domain |
| `ports` | exact set membership |
| `container` | exact container id equality |
| `sandbox` | exact Flatpak id or snap name equality |

Ranking: exact path (2 points) beats basename (1), plus one point per
constraint. Ties resolve to the later row. No match means the default
policy (`ask` unless `CRABWALL_DEFAULT` says otherwise).

## CLI reference

```
crabwall                    # TUI (attaches, or demo mode)
crabwall up [--learn SECS] [--default ask|allow|deny] [--theme ID] [--icons SET]
crabwall down               # stop a daemon started by up
crabwall status             # hello handshake: version + default policy
crabwall logs [--limit N] [--json]
crabwall allow --app APP [--domain D] [--port P]
crabwall deny --app APP [--domain D] [--port P]
crabwall rules              # print the rules file
crabwall config [show]      # effective settings + provenance
crabwall config set theme dracula|icons nerd
```

## Configuration

`~/.config/crabwall/config.toml` (`CRABWALL_CONFIG` overrides):

```toml
[tui]
theme = "dracula"   # phosphor, gruvbox, dracula, nord, tokyo, catppuccin, mono
icons = "nerd"      # plain (everywhere) or nerd (needs Nerd Font)
```

Precedence, strongest first: CLI flag, config file, environment
(`CRABWALL_THEME`, `CRABWALL_ICONS`), default. `config show` prints each
value with its source. The TUI saves theme/icons on exit when changed
with `t`/`i`, so keys become permanent without flags.

Daemon knobs (environment): `CRABWALL_DEFAULT` (ask/allow/deny),
`CRABWALL_PTR=1` (reverse-DNS warming), `CRABWALL_LEARN_SECS=N` (learn
mode), `CRABWALL_SOCK`/`CRABWALL_RULES`/`CRABWALL_DB`/`CRABWALL_EBPF_OBJ`
(path overrides). Full reference: `man crabwalld`.

## TUI guide

| Key | Action |
|---|---|
| `y` / `Y` | Allow once / always (persists a rule) |
| `n` / `N` | Deny once / always (persists a rule) |
| `s` | Allow until daemon restart |
| `j`/`k`, arrows | Move (autorepeat scrolls) |
| `Tab` | Feed / rules tabs |
| `t` / `i` | Cycle theme / toggle icon set (saved on exit) |
| `q` / `Esc` | Quit |

Held verdict keys never machine-gun: autorepeat is ignored for
decisions, and answering one event twice only counts once (changing
your mind moves the counter). In demo mode the prompt card says so:
answers vanish without a daemon.

## Services

One installer, init auto-detected (systemd, runit, OpenRC, s6, SysVinit):

```
sudo ./packaging/install.sh
```

| Init | Manual equivalent |
|---|---|
| systemd | `cp packaging/systemd/crabwalld.service /etc/systemd/system/ && systemctl enable --now crabwalld` |
| runit | copy `run` + `log/run` to `/etc/sv/crabwalld`, link into the service dir |
| OpenRC | `cp packaging/openrc/crabwalld /etc/init.d/crabwalld && rc-update add crabwalld default` |
| s6 | copy `packaging/s6/crabwalld` into the scandir |
| SysVinit | `cp packaging/sysvinit/crabwalld /etc/init.d/crabwalld && update-rc.d crabwalld defaults` |

The daemon is init-agnostic (plain process, stdout logs, no
systemd-only features). Env knobs go in the unit file, `chpst -e`,
`s6-envdir`, or init.d exports depending on init.

## Building from source

```
cargo test --workspace --exclude crabwall-ebpf
cargo clippy --workspace --exclude crabwall-ebpf --all-targets -- -D warnings
cargo run -p xtask -- bench            # dependency-free smoke benchmarks
cargo run -p xtask -- build-ebpf       # needs bpf-linker + rust-src
cd fuzz && cargo +nightly fuzz run dns -- -max_total_time=60
```

Requirements: stable Rust for host code; nightly plus `rust-src`
plus `bpf-linker` only for the eBPF object; `llvm` for its section
check; `clang` for the AUR build. Debian packages:
`packaging/debian` (`dpkg-buildpackage`). Arch: `packaging/aur`.
NixOS: `packaging/nix` flake plus `services.crabwall.enable`.

## Layout

- `crates/crabwall-common/` - rules, matching engine, IPC protocol v2 (frozen)
- `crates/crabwall-packet/` - pure parsers, fuzzed, no I/O
- `crates/crabwalld/` - daemon: queue, sensors, enforcement, IPC server
- `crates/crabwall-cli/` - TUI (demo mode without daemon) + CLI
- `crates/crabwall-ebpf/` - tracepoint program (`cargo xtask build-ebpf`)
- `packaging/` - inits, installer, AUR/Nix/debian, demo tape
- `docs/` - ARCHITECTURE, LIMITS, STABILITY
- `fuzz/` - cargo-fuzz targets + seeds
- `man/` - `crabwall.1`, `crabwalld.8`

## Docs

- `docs/ARCHITECTURE.md` - components, threading, invariants
- `docs/LIMITS.md` - what the firewall does not do (read this)
- `docs/STABILITY.md` - frozen formats and support matrix

## FAQ

**Does it need root?** For enforcement, yes (nftables, NFQUEUE, sniffer,
eBPF). Without root it observes, prompts, and logs in dry-run.

**systemd only?** No. Five init systems, plus `crabwall up` for sessions.

**Wayland/X11?** Neither. TUI plus libnotify.

**Any telemetry?** None. No accounts, no network calls home, no
phone-home code paths exist. Verify with the firewall itself.

**Windows/macOS?** Linux only. The entire enforcement stack is
netfilter/eBPF/procfs.