# crabwall stability guarantees (1.0)

## Frozen formats

- **IPC protocol v2** (`crabwall-common`): newline-delimited JSON,
  `DaemonToClient` / `ClientToDaemon`. v1 clients get a versioned
  `Hello` and should refuse on major mismatch. No breaking changes
  without a major version bump.
- **`rules.toml` schema**: `[[rule]]` with `app`, `domain_suffix`,
  `ports`, `container`, `sandbox`, `action`. Unknown keys are ignored
  (forward-compatible); renamed keys never happen in 1.x.
- **SQLite schema** (`events.db`): additive migrations only, tracked by
  `PRAGMA user_version`. The daemon reads dbs from any 1.x.

## Support matrix

- Kernels ≥5.8, nftables ≥0.9, systemd/runit/OpenRC/s6/SysVinit.
- eBPF object is optional; everything works without it (slower,
  poll-only attribution).
- `x86_64` and `aarch64` release builds.

## Behavioral guarantees

- Default policy `ask`: unmatched traffic prompts, never passes silently.
- Queue overflow, full request channel, lost races, prompt timeout:
  all deny/drop (fail-closed). The only fail-open element is the nft
  `bypass` flag, which exists solely to survive daemon restarts.
- Logs rotate at ~50k rows; rules reload without restart.
