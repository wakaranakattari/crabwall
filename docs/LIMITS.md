# crabwall limits (read before trusting it)

Honest list of what crabwall 1.0 does not do. Contributions welcome;
marketing claims never.

## Encrypted DNS (DoH/DoT) blinds the DNS sniffer

Port-53 snooping sees nothing when the resolver speaks HTTPS/TLS.
Mitigations, in order: TLS SNI sniffing (sees the domain of the HTTPS
connection itself), PTR warming (`CRABWALL_PTR=1`), prompt shows the raw
IP. Rule on IP + port when the domain is unknown.

## ECH (Encrypted Client Hello) blinds SNI

With ECH the SNI is encrypted too. Same fallbacks as above; the prompt
is the last line of defense, by design.

## VPNs and proxies move the trust boundary

Through a VPN, crabwall still sees *which local app* connects *to what*
(the packets leave via tun), but the ultimate destination is the VPN
server. Rules match the visible flow. Documented, not fixed.

## Containers share the host view

Docker ids come from cgroup paths and are matchable in rules
(`container = "..."`). A root inside a container can lie about its
cgroup; crabwall is a single-user desktop firewall, not a container
escape detector.

## Poll sensor can miss sub-second connections

Without the eBPF object, connections shorter than the poll interval
(500ms) may never be observed. The queue path still holds their first
packet (attribution may read `unknown`). Ship the eBPF object.

## Set-fallback is IP-level

Without NFQUEUE, verdicts apply per destination IP (ports/domains still
decide, but enforcement is IP granularity, 24h set timeout). The queue
path enforces per packet.

## No TLS interception, ever

crabwall never MITMs, never installs CA certificates, never reads
payloads beyond headers (DNS answers, ClientHello SNI). That is a
permanent design rule, not a missing feature.

## Platform scope

Linux only, kernel ≥5.8, `nftables` for enforcement. No Wayland/X
dependency (TUI + libnotify only).
