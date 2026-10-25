# Changelog

All notable changes to vRouter are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## Unreleased

### Added

- **Control protocol v3 (ADR-015):** request-versioned envelopes keep v2
  response shapes byte-compatible while v3 `status` adds `protocol_version`,
  `config_revision`, `restart_pending`, `config_writable` and
  `restart_supported`. The daemon owns the config bytes through a revisioned
  `ConfigStore`, and v3-only `config.get` returns the current document,
  revision, source path and writability. Config-sized work runs on a dedicated
  worker, and the client accepts 16 MiB config responses. v3 list reads expose
  ports, bridges, interfaces, routes, DHCP, DNS and firewall configuration from
  the current on-disk document.
- **Read-only web admin preview (post-v1, ADR-011):** opt-in `vrouterweb`
  built with `zig build web`. The Zig process serves server-rendered HTMX 4.0.0
  pages and fragments with embedded assets, plus a same-origin JSON API backed
  by the Unix control socket. It binds loopback only, authenticates with an
  Argon2id password and server-side sessions, validates `Host`/`Origin`, and
  exposes status, NAT and conntrack without host mutations. No Node build step,
  package manager or runtime asset directory is required. It is read-only,
  excluded from the default build, and not part of the 0.2.0 scope. See
  `docs/WEB.md`.
- **Crash recovery:** `vrouter doctor` is now read-only but works after a
  daemon crash, and `vrouter doctor --repair` replays journal inverses while
  refusing to run against a live daemon. Malformed journal tails are quarantined
  to `<instance>.journal.quarantine.<timestamp>`; malformed records before valid
  ones refuse repair without mutating host state. `scripts/test_crash.sh` covers
  kill -9, dry-run, live-daemon refusal, unmanaged-state preservation, and
  malformed-journal handling.
- **Live NAT updates (ADR-014):** `vrouter nat add|del masquerade` and
  `vrouter nat add|del port-forward` validate and atomically save the config,
  apply the complete desired NAT tables over the protocol-v2 `nat.apply`
  control operation, and restore the previous config if the daemon rejects the
  update. With no daemon the change is saved with a warning. The NAT apply queue
  is bounded, keeps the datapath lock-free, and publishes a snapshot
  immediately. `scripts/nat_matrix.sh` covers live add/delete, rollback and
  restart persistence.
- **IPv6 core (ADR-013):** dual-stack forwarding between L2 ports, SVIs and
  TUN ports; NDP neighbor discovery with a bounded pending queue; ICMPv6 echo,
  errors and packet-too-big; IPv6 static/connected routes; and software repair
  of forwarded TCP/UDP checksums.
- IPv6 configuration: `interfaces.<name>.addresses` for additional IPv4/IPv6
  CIDRs, IPv6 routes with family-checked next hops, firewall `family` and
  `proto: "icmpv6"`, and `firewall.rate_limit.ndp`. IPv6-enabled interfaces
  require MTU >= 1280.
- `vrouter iface set|del` and `vrouter route add|del` accept IPv6 values and
  journal AF_INET6 host mutations; `vrouter firewall test` accepts IPv6
  addresses and `icmpv6`.
- `scripts/test_ipv6.sh` netns test for IPv6 ping and TCP forwarding.

- R7 Linux control socket: line-delimited JSON over
  `/run/vrouter/control.sock` (mode `0660`, peer-uid check), live read-only
  `status`, `nat.list` and `conntrack.list`, and the `vrouter up`, `vrouter doctor`,
  `vrouter nat list` and `vrouter conntrack list` CLI commands. The daemon publishes
  immutable datapath snapshots once per second. A run-dir lock rejects a
  second daemon, concurrent `vrouter up` starts are serialized, and `vrouter down`
  refuses while a matching daemon is live. `vrouter up` writes daemon stderr to
  `<state_dir>/vrouterd.log` and reports its path and tail on failure.
- R7 foundation: reusable daemon lifecycle (`src/app/service.zig`) shared by
  `vrouterd` and the versioned C ABI (`include/vrouter.h`, `src/ffi.zig`), an
  injected-fd L3 port for Android `VpnService`, stable lifecycle/error/status
  codes, and a compiled C header/link smoke test.
- Optional Linux kernel-bridge offload (`bridge.offload = "kernel"`): creates a
  journaled kernel bridge, enslaves existing L2 members, and attaches a veth
  trunk as the bridge's synthetic userspace port. Kernel VLAN filtering/STP,
  transactional rollback, `vrouter down` restoration, and the
  `scripts/test_offload.sh` L2/SVI/DHCP/NAT/STP parity test are included.
  Offloaded members reject `create`/`mtu` overrides and warn when per-port
  `storm_control` cannot be enforced by the kernel bridge.
- R0 scaffold: `build.zig`/`build.zig.zon`, cross-compilation for Linux and
  Android, CI matrix.
- Strict JSON configuration schema, parser and semantic validator.
- `vrouter` CLI with `version`, `validate` and `help`.
- `std.Io` context helper and leveled text/JSON logger (stack-buffered).
- `Port` vtable, in-memory reference port, fixed-size buffer pool.
- Golden Ethernet/IPv4/UDP frame fixtures and round-trip tests.
- ADR-001…006 (router-first, hybrid datapath, Android tiers, overlay deferred,
  conntrack/NAT, config/journal).
- Userspace L2 bridge datapath: bridge membership, MAC learning/FDB aging,
  unicast/flood forwarding, per-bridge SVI addressing, bridge ARP resolution,
  and DHCP serving on any member port.
- VLAN-aware bridging: 802.1Q PVID/trunk/access membership, per-VLAN FDB keys,
  egress tagging/filtering, and per-SVI VLAN addressing.
- DHCP conflict probe: ARP the candidate address before OFFER and DECLINE on a
  conflict; DHCP client-id (option 61) is used as the lease identity when
  present.
- Strict uRPF-lite anti-spoofing in the forwarding path via
  `firewall.rp_filter`.
- Ordered firewall rules with `proto`, `src`/`dst`, `sport`/`dport`,
  `iif`/`oif` (port, interface or bridge), `accept`/`drop`/`reject`,
  `ct_state`, per-rule counters, and default deny before the conntrack
  established shortcut.
- `vrouter firewall list` prints the ordered rule set, default policies and
  control-plane rate limits.
- `vrouter firewall test` evaluates a synthetic packet against the configured
  rules and prints the matching rule or default action.
- `vrouter firewall counters` reads the per-rule packet and drop snapshot that
  `vrouterd` writes to the run directory every 5 s and on shutdown.
- Token-bucket limits for generated ICMP errors, ARP processing and DHCP
  server requests (`firewall.rate_limit`); `0` disables a limit.
- `vrouter bridge list` shows bridge membership, effective PVID/tagged VLANs,
  tri-state STP/offload and SVI addressing.
- Per-port storm control (`ports.<name>.storm_control`, default 1000
  flooded frames/s, `0` disables) with a `storm_dropped` counter.
- Optional userspace 802.1D STP for bridges: root election from received
  BPDUs, 2 s hello transmission, blocking/listening/learning/forwarding
  transitions, and STP-state filtering in the bridge datapath.
- VLAN netns test covering access/trunk forwarding, SVI reachability and
  per-port VLAN isolation.

### Changed

- **Breaking:** rename the project from vNAT to vRouter (ADR-012). The CLI and
  daemon are now `vrouter` and `vrouterd`; the C ABI is `vrouter_*` in
  `include/vrouter.h` (ABI 2); environment variables, default config and run
  paths, the control socket, journals and the daemon log use
  `vrouter`/`VROUTER`. There are no compatibility aliases. Stop the old daemon
  and run `vnat down` before upgrading; `/run/vnat` state is not migrated.
- Bump the project version to 0.1.0.
- Live NAT edits preserve unrelated JSON keys while normalizing the config file
  to two-space indentation. The control protocol is now version 2 and requests
  may be up to 64 KiB.
- Forwarded IPv4 checksums are repaired once before conntrack/NAT; NAT rewrites
  adjust TCP/UDP/ICMP checksums incrementally (RFC 1624) instead of rescanning
  the payload on every rewrite (ADR-007, ADR-014).
- The datapath now waits on port readiness with `poll` instead of a fixed 1 ms
  sleep, so idle frames are picked up immediately, and drains up to 256 frames
  per port before moving on.

### Fixed

- Close DNS sockets only after joining the UDP/TCP workers, and shut down the
  TCP listener to wake a blocked `accept` during shutdown.
- Recover 802.1Q tags stripped by VLAN offload using `PACKET_AUXDATA` before
  ingress classification, and add a veth access/trunk netns test.
- Bound the ARP neighbour cache and miss-rate map; stale entries are pruned and
  the oldest entry is evicted at capacity (spoofed-ARP memory exhaustion).
- Synchronize the DNS cache between UDP/TCP workers, use separate upstream
  sockets per worker, and bound TCP query reads with a deadline.
- Age cached DNS record TTLs, apply RFC 2308 negative-cache TTLs from SOA
  records, return NODATA for non-A local-zone queries, and accept zone-only DNS
  configs.
- Reject DHCP pools that contain the router address and refuse to commit or
  decline that address defensively.
- Make journal address ownership host-exact rather than network-exact, and drop
  journal records when a link/address/route mutation fails.
- Make `examples/minimal.json` runnable with L2 ports and reject unsupported
  existing L3 ports, duplicate port devices, routes without a device,
  masquerade interfaces without an address, and DHCP pools containing the
  router address.
- Harden the DHCP client: random transaction IDs, reply/xid/server-id checks,
  NAK handling, T1/T2 renew and rebind timers, and explicit masquerade opt-in.
- Bring daemon-created TUN/TAP devices up before handing them to the datapath.
- Record the boot time in the persisted DHCP lease database and discard leases
  from a previous boot, so monotonic expiry timestamps cannot keep stale
  bindings alive after a reboot.
- Scope port forwards with the optional `in` ingress selector and match rules
  by ingress port.
- Cap supported MTUs at 1600 bytes (the 2048-byte frame buffer limit) and
  reject jumbo configuration with a typed validation error.
- Enforce firewall default input/forward policies (`drop`/`reject`/`accept`)
  and ordered rules in the datapath. Explicit port forwards are treated as
  administrator allows, and `default_out` rejects non-accept values until
  outbound policy is implemented.
- Keep bridge floods running when one member is down or its MTU is exceeded,
  rate-limit bridge-wide ARP resolution, and send valid ARP probes for DHCP
  conflict detection.
- Retry DHCP client acquisition after repeated failures, accept ACKs/NAKs from
  a replacement server during RENEWING/REBINDING, and scope conflict detection
  to the local L2 segment.
- Fix negative DNS caching for NXDOMAIN responses that also carry a CNAME, and
  discard pre-`boot_ms` lease databases instead of restoring potentially stale
  leases.

### R2 — IPv4 forwarding (core)

- Ethernet II and IPv4 parsers/builders with strict length and checksum
  validation; single 802.1Q tag is parsed (VLAN forwarding in R5).
- ARP request/reply generation, learning cache with freshness and port scoping,
  and rate-limited broadcast resolution requests.
- Longest-prefix-match FIB for connected and static routes.
- Forwarding pipeline: TTL decrement, IPv4/TCP/UDP checksum repair (ADR-007),
  ICMP unreachable/time-exceeded/frag-needed, egress MTU enforcement, Ethernet
  and TUN egress.
- `vrouterd` data loop: polls ports, forwards frames and logs counters.
- Config interfaces/static routes populate local addresses, connected routes
  and the FIB.
- `scripts/test_route.sh`: two isolated hosts ping and fetch HTTP through
  `vrouterd`; verifies TTL=63, TCP and graceful shutdown.
- Gratuitous ARP announcements for configured local addresses at daemon start.
- ARP pending-packet queue (32 slots, 1 s): the first packet to an unresolved
  neighbor is flushed on reply instead of being dropped.
- TUN/L3 ingress and egress: bare IPv4, local echo replies, ICMP errors and
  forwarding between TUN and L2 ports. `scripts/test_tun.sh` covers ICMP and
  TCP through a kernel TUN peer.
- `vrouter iface set|del|up|down` and `vrouter route add|del` with journal-before-
  mutation, ownership-gated deletes, and `vrouter down` reverse rollback.
- JSONL journal under `$VROUTER_RUN_DIR` (default `/run/vrouter`), atomic and
  fsynced; failed applies remove their record; partial rollback keeps the
  journal for inspection and retry.
- `vrouter journal` for inspecting recorded mutations.
- `scripts/test_journal.sh`: address/route/link mutations, duplicate no-ops,
  unmanaged-delete rejection, pre-existing state preservation and rollback.

### R4 — DHCP and DNS (in progress)

- DHCPv4 server in the forwarding path: pool allocation, MAC reservations,
  OFFER/ACK/NAK, DECLINE quarantine, RELEASE/INFORM, configurable lease time,
  domain, MTU, NTP and DNS options.
- Optional atomic lease database (`lease_db`): active bindings are restored
  on start, expired/conflicting records are ignored, and the file is rewritten
  every 60 s and on shutdown.
- UDP DNS forwarder with upstream retry, TTL cache, basic negative caching,
  configurable cache size (`dns.max_entries`) and counters.
- `scripts/test_dhcp.sh`: raw Ethernet DHCP client obtains a lease, pings the
  router and verifies persistence across a daemon restart.
- `scripts/test_dns.sh`: query through `vrouterd`, answer from the fake upstream,
  then a cache hit; both tests run in CI.
- Not yet: DNS DoH/DoT.
- Added: initial DHCP client on the uplink, DNS over TCP, split zones and a
  local `vrouter.` / `router.vrouter.` status zone.

### R3 — NAT and conntrack

- Userspace conntrack table: both-direction 5-tuple keys, TCP new/established/
  closing timeouts, UDP/ICMP/generic timeouts, 1 s GC, 65,536-entry cap and
  counters.
- SNAT/masquerade for TCP, UDP and ICMP echo: source address/port rewrite,
  source-port preservation, deterministic collision allocation, reverse
  translation, and incremental IP/L4 checksum adjustment after one repair.
- Forwarded TCP/UDP/ICMP-echo flows are tracked even without NAT; replies to a
  NAT address are reverse-translated before local delivery.
- DNAT/port forwarding for TCP/UDP with reverse translation; hairpin NAT SNATs
  back out the ingress port when the target is on the same segment.
- ICMP-error translation for tracked NAT flows: outer and quoted tuples are
  restored and quoted IP/L4 checksums are adjusted incrementally (RFC 1624).
- A translated-key conntrack index maps post-NAT packets back to their flow
  without colliding with original/reply keys.
- `scripts/nat_matrix.sh`: UDP source-port preservation and collision, ICMP
  echo, TCP HTTP through masquerade, WAN-to-internal DNAT, hairpin DNAT and
  SNAT/DNAT ICMP-error translation.
- Masquerade on a DHCP uplink is installed after the client binds; fragments
  and non-echo ICMP on SNAT egress are still dropped and counted until
  translation lands. Live add/delete is config-backed (ADR-014).

### R1 — Linux ports

- AF_PACKET L2 ports with promiscuous membership and outgoing-frame filtering.
- TUN (`IFF_NO_PI`) and TAP ports, created from config (`"create": "tun"|"tap"`).
- rtnetlink link dump and link/addr/neigh monitor with bounds-checked parsing.
- Port manager with stable IDs, MTU application and hotplug refresh.
- `vrouter port list`, `vrouter status`, `vrouter selftest`, and the `vrouterd` daemon
  skeleton with graceful SIGINT/SIGTERM shutdown.
- `scripts/test_netns.sh`: veth L2 forwarding, TUN/TAP creation, netlink dump,
  manager status and daemon hotplug in a private netns.
