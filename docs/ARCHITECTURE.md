# vNET — Architecture

> Router-first design. The overlay/P2P work from the earlier draft is deferred
> to a future uplink module (ADR-004); the engine described here is the product.
> Scope: [CORE-SCOPE.md](./CORE-SCOPE.md). Plan: [PLAN.md](./PLAN.md).

## 1. Principles

1. **The core is the router.** Bridging, routing, NAT, DHCP, DNS and filtering
   live in Zig and do not depend on `iptables`/`nft`/`netd` being present.
2. **Ports, not interfaces-as-strings.** Everything is a `Port` with typed
   capabilities; platform code only opens ports and applies host mutations.
3. **Userspace reference, kernel fast path.** Correctness is defined by the
   userspace pipeline; kernel offloads are optional accelerators selected by
   config.
4. **Control plane / data plane split.** The data plane never blocks on the
   control plane; config changes are compiled to immutable routing/bridge/NAT
   tables and swapped atomically.
5. **Journal before mutation.** Every host change has a recorded inverse.
6. **No GUI in v1, one API.** CLI and a Unix-socket API are the only v1
   interfaces; the C ABI is for hosts (Android). A post-v1 optional `vnetweb`
   adapter is an unprivileged client of the same API (ADR-011).
7. **Hostile input.** Decoders are bounds-checked and fuzzed; no `unreachable`
   on wire data.

## 2. Repository layout

```
vnet/
├── build.zig
├── build.zig.zon
├── test.zig
├── fuzz.zig
├── AGENTS.md
├── CHANGELOG.md
├── README.md
├── docs/
│   ├── PRODUCT.md
│   ├── CORE-SCOPE.md
│   ├── ANDROID.md
│   ├── ARCHITECTURE.md
│   ├── PLAN.md
│   ├── RESEARCH.md
│   ├── SOURCES.md
│   ├── WEB.md
│   ├── WEB-SCOPE.md
│   └── adr/
├── src/
│   ├── lib.zig                  public Zig API / shard composition
│   ├── ffi.zig                  C ABI (R7)
│   ├── shard_core.zig           vnet-core module root
│   ├── shard_port.zig           vnet-port module root
│   ├── shard_l2.zig             vnet-l2 module root
│   ├── shard_l3.zig             vnet-l3 module root
│   ├── shard_conntrack.zig      vnet-conntrack module root
│   ├── shard_nat.zig            vnet-nat module root
│   ├── shard_dhcp.zig           vnet-dhcp module root
│   ├── shard_dns.zig            vnet-dns module root
│   ├── shard_ctl.zig            vnet-ctl module root
│   ├── thread.zig               std/pthread thread backend
│   ├── io.zig                   std.Io wiring, timers, cancellation
│   ├── log.zig                  leveled text/JSON logger
│   ├── types.zig                PortId, Mac, IpAddr, Mtu, VlanId
│   ├── errors.zig               typed error taxonomy
│   ├── app/
│   │   └── service.zig          shared daemon/FFI lifecycle
│   ├── config/
│   │   ├── schema.zig           typed config model
│   │   ├── parse.zig            strict JSON parser
│   │   ├── validate.zig         references, subnets, conflicts
│   │   ├── write.zig            canonical writer
│   │   └── store.zig            revisioned on-disk config
│   ├── port/
│   │   ├── port.zig             Port vtable, PortInfo, Stats
│   │   ├── manager.zig          config → ports, hotplug pump
│   │   ├── pool.zig             buffer pools
│   │   ├── memory.zig           in-memory port for tests
│   │   ├── fd.zig               host-injected L3 port
│   │   ├── linux/
│   │   │   ├── sys.zig          non-blocking fd helpers, errno mapping
│   │   │   ├── iface.zig        SIOCGIF* control ioctls
│   │   │   ├── af_packet.zig    L2 port (TPACKET_V3 later)
│   │   │   ├── tun.zig          TUN (IFF_NO_PI) and TAP
│   │   │   └── netlink.zig      link dump + link/addr/neigh monitor
│   │   └── android/             R7/R8 (planned)
│   ├── l2/
│   │   ├── ethernet.zig         Ethernet II + 802.1Q parse/build (R2)
│   │   └── stp.zig              optional 802.1D
│   ├── l3/
│   │   ├── ipv4.zig             header, checksum, TTL (R2)
│   │   ├── ipv6.zig             header, extension parsing, checksums
│   │   ├── fib.zig              IPv4 LPM (flat R2, trie R3)
│   │   ├── fib6.zig             IPv6 LPM (parallel to fib.zig)
│   │   ├── arp.zig              cache + request/reply (R2)
│   │   ├── ndp.zig              NS/NA + neighbor cache (RA v1.1)
│   │   ├── icmp.zig             IPv4 errors + echo (R2)
│   │   ├── icmpv6.zig           ICMPv6 errors + echo
│   │   ├── rate.zig             ICMP/ARP error rate limiting
│   │   └── forward.zig          composition engine: bridge, FW, services, L2/TUN
│   ├── nat/
│   │   ├── conntrack.zig        5-tuple table, timeouts, GC, port allocator (R3)
│   │   └── nat.zig              SNAT/DNAT rewrite, RFC 1624 checksum adjust (R3)
│   ├── services/
│   │   ├── dhcp/
│   │   │   ├── message.zig      wire parser/builder
│   │   │   ├── server.zig       pool, reservations, options, DECLINE
│   │   │   └── leases.zig       atomic JSON lease persistence
│   │   └── dns/
│   │       ├── message.zig      wire parser/builder
│   │       ├── cache.zig        TTL cache
│   │       ├── probe.zig        diagnostics client
│   │       └── service.zig      UDP/TCP forwarder and split zones
│   ├── control/
│   │   ├── server.zig           unix socket, JSON lines (R7)
│   │   ├── client.zig           CLI/web client
│   │   ├── protocol.zig         request/response schema
│   │   ├── transport.zig        framing
│   │   ├── unix.zig             socket helpers
│   │   ├── journal.zig          JSONL forward ops, ownership, rollback (R2)
│   │   ├── host.zig             iface/route mutations + journal (R2)
│   │   ├── offload.zig          kernel bridge plan + veth trunk (R5, Linux)
│   │   ├── config_apply.zig     canonical diff and apply
│   │   ├── transaction.zig      staged apply/rollback
│   │   ├── state.zig            snapshot publication
│   │   ├── read_model.zig       typed read views
│   │   └── firewall_counters.zig
│   └── web/
│       ├── root.zig             module surface
│       ├── server.zig           HTTP, auth, CSRF
│       ├── pages.zig            server-rendered pages
│       ├── operations.zig       control-socket operations
│       ├── auth.zig             password/session handling
│       ├── html.zig             template helpers
│       └── assets/              embedded CSS, JS, HTMX 4
├── exec/
│   ├── vnet/main.zig            CLI
│   ├── vnetd/main.zig           daemon
│   └── vnetweb/main.zig         POST-V1: unprivileged web admin (ADR-011)
├── include/vnet.h
├── test/
│   ├── examples.zig
│   ├── fuzz.zig
│   ├── golden.zig
│   └── ffi_smoke.c
└── scripts/
    ├── test_netns.sh
    ├── test_route.sh
    ├── test_tun.sh
    ├── test_ipv6.sh
    ├── test_journal.sh
    ├── test_crash.sh
    ├── test_offload.sh
    ├── test_dhcp.sh
    ├── test_dns.sh
    ├── test_firewall.sh
    ├── test_vlan.sh
    ├── nat_matrix.sh
    └── perf.sh
```

Planned phase-2 moves from ADR-018: `l2/bridge.zig`, `l2/vlan.zig`,
`firewall/`, `l3/rib.zig`, `l3/mtu.zig`, `control/events.zig` and `overlay/`.
The paths above describe the current tree; those files are not present yet.

### 2.1 Build graph

The shard roots are compiled as named Zig modules (ADR-018). They are thin
re-export surfaces; implementation files stay in the directories above until
the forwarding-engine split.

| Module | Allowed dependencies |
|---|---|
| `vnet-core` | none |
| `vnet-port`, `vnet-l2`, `vnet-l3`, `vnet-dhcp`, `vnet-conntrack` | core |
| `vnet-nat` | core, l3, conntrack |
| `vnet-dns` | core, thread |
| `vnet-ctl` | core, port, dns, thread |
| `vnet-fw`, `vnet-tunnel` | reserved; not built yet |

`src/lib.zig`, `src/app/service.zig` and `src/ffi.zig` are the composition
layer. Shards may not import the composition layer, and `vnet-l3` may not import
NAT, firewall or services. CLI and FFI builds map `vnet-thread` to different
backends, so `vnet-dns` and `vnet-ctl` are built once per profile.

## 3. Core interfaces

### 3.1 Port

```zig
pub const PortId = enum(u32) { _ };

pub const PortKind = enum { ethernet, wifi, cellular, usb, tun, tap, bridge, memory };

pub const Capabilities = struct {
    l2: bool,
    l3: bool,
    promiscuous: bool,
    multicast: bool,
    vlan_filter: bool,
    checksum_offload: bool,
    gso: bool,
    can_set_mtu: bool,
};

pub const Frame = struct {
    port: PortId,
    data: []u8,
    len: u32,
    vlan: ?u16,
    offload: Offload,
};

pub const Port = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        read:  *const fn (ctx: *anyopaque, io: std.Io, buf: []u8) anyerror!usize,
        write: *const fn (ctx: *anyopaque, io: std.Io, frame: []const u8) anyerror!void,
        info:  *const fn (ctx: *anyopaque) PortInfo,
        set_up: *const fn (ctx: *anyopaque, io: std.Io, up: bool) anyerror!void,
        set_mtu: *const fn (ctx: *anyopaque, io: std.Io, mtu: u16) anyerror!void,
        close: *const fn (ctx: *anyopaque, io: std.Io) void,
    };
};
```

- `read`/`write` are the only hot-path calls.
- `PortInfo` carries name, ifindex, mac, mtu, link state, speed, counters.
- L2 vs L3 is a capability; the pipeline asserts the frame type matches.

### 3.2 Data-plane pipeline

```
ingress port
   │  parse L2 (if L2)
   ▼
[ bridge lookup ]──hit──▶ egress port (L2)
   │ miss / routed port
   ▼
[ L3 parse: IPv4/IPv6 ]
   ▼
[ conntrack lookup ]──established──▶ NAT reverse + FIB
   │ new
   ▼
[ firewall: prerouting ]
   ▼
[ DNAT (port forward) ]
   ▼
[ FIB lookup ]──no route──▶ drop/ICMP
   ▼
[ firewall: forward ]
   ▼
[ SNAT (masquerade) ]
   ▼
[ TTL/hop decrement, checksum, MSS clamp ]
   ▼
egress port write
```

- Tables (`BridgeTable`, `Rib`, `NatTable`, `RuleSet`) are immutable snapshots
  swapped by the control plane; workers read the current pointer (RCU-style
  with epoch reclamation).
- Per-port ingress queues; a worker owns a set of ports (no cross-thread
  packet handoff on the fast path).

**R2 status.** The implemented path is Ethernet (L2) or bare IPv4 (TUN) →
ARP/IPv4 → FIB → TTL/MTU → neighbor cache/pending queue → egress. It generates
ICMP errors, writes bare IP back to TUN ports, and repairs TCP/UDP checksums
in software (ADR-007). R3 adds conntrack before routing, DNAT before the FIB,
reverse translation for replies (including replies addressed to a local NAT
IP), and SNAT after the FIB/MTU checks. Hairpin flows SNAT back out the ingress
port. Bridge, firewall and MSS clamping are not yet in the loop.

### 3.3 Bridge

```zig
pub const Bridge = struct {
    id: BridgeId,
    ports: []PortId,
    vlan_aware: bool,
    stp: bool,
    fdb: Fdb,          // (vlan, mac) → port, aging
};
```

- Learning on ingress, lookup on egress.
- Flood set precomputed per VLAN.
- Optional kernel offload (`bridge.offload = "kernel"`): `control/offload.zig`
  creates one kernel bridge and a veth trunk per bridge, enslaves the physical
  members, and opens the trunk peer as the bridge's only synthetic port.
  Userspace bridging, SVIs, routing, NAT, DHCP and firewall keep working on
  that synthetic port; kernel STP replaces userspace STP when enabled.

### 3.4 Router / FIB

```zig
pub const Route = struct {
    dst: IpPrefix,
    via: ?IpAddr,
    dev: PortId,
    metric: u32,
    source: RouteSource, // connected | static | dhcp | kernel
    table: u32,
};

pub const Fib = struct {
    pub fn lookup(self: *const Fib, dst: IpAddr, mark: u32) ?NextHop;
};
```

- IPv4 and IPv6 use separate LPM tables (`fib.zig`, `fib6.zig`) with O(prefix
  bits) lookup; route and next-hop families must match.
- Policy rules: ordered `(from, iif, mark) → table`.
- Connected routes generated from interface addresses; removed on port loss.

### 3.5 NAT / conntrack

```zig
pub const CtEntry = struct {
    key: FlowKey,
    reply_key: FlowKey,
    state: FlowState,
    proto_state: ProtoState, // TCP FSM
    nat: ?NatInfo,           // snat/dnat applied
    timeout: i64,
    counters: Counters,
};
```

- R3 uses one `Conntrack` table with both directions mapped to the same entry
  and the ingress/egress port as the zone; the data plane is single-threaded.
  Sharding/epoch reclamation is deferred.
- GC is a 1 s full sweep with a 65,536-entry cap; exhausted tables drop new
  flows and increment counters. Entries are not yet evicted on port teardown.
- SNAT allocation preserves the source port when free, otherwise hashes and
  probes 1024–65535. Ports are released by GC.
- Forwarded IPv4 transport checksums are repaired once after the forwarding
  copy and before conntrack/NAT (ADR-007). NAT rewrites then adjust
  TCP/UDP/ICMP checksums incrementally with RFC 1624; egress and pending-flush
  paths do not rescan the payload.
- Live NAT changes use a control queue (ADR-014): the control thread copies the
  complete desired tables, the data loop compiles and swaps them between packet
  batches, and the server acknowledges synchronously. Existing conntrack
  entries keep their translation until timeout.
- DNAT/port forwarding and hairpin are implemented for TCP/UDP; ICMP port
  forwards are rejected. ICMP errors quoting a tracked NAT flow are translated
  (outer and quoted tuple, RFC 1624 quoted-L4 checksum adjustment); fragments
  and unrelated or non-echo ICMP on a SNAT egress are dropped and counted.

### 3.6 Services

- DHCP server is a state machine per interface, backed by a persisted lease DB.
- DNS forwarder has its own cache and upstream pool; no blocking on the
  forwarding path (async requests with timeouts).
- Both are optional modules; the router works without them.

### 3.7 Control plane

```
CLI / API ──▶ config::diff ──▶ mutation list ──▶ journal ──▶ apply
                                                   │
                                                   └──▶ event bus
```

- `config::diff` compares desired vs current compiled state; produces ordered
  mutations (remove dependents before parents, add parents before children).
- `apply` is transactional: on failure, replay the inverse of already-applied
  mutations and return a typed error.
- Hot-reload fields: NAT rules use the dedicated `nat.apply` queue (ADR-014);
  routes, firewall rules and DNS upstreams still require the planned
  diff/apply path. Restart-required: ports, bridges, addresses.
- Events: `port_up/down`, `link_change`, `addr_change`, `dhcp_lease`,
  `nat_expired`, `config_applied`, `error`.
- Post-v1, an optional `vnetweb` adapter may expose this API over
  authenticated HTTP. It remains an unprivileged client of the Unix socket and
  never mutates host state directly (ADR-011).

## 4. Datapath backends

| Backend | Where | When | Trade-off |
|---|---|---|---|
| `userspace` | Linux, Android root | Default; portable | CPU-bound, full control |
| `kernel_bridge` | Linux | `bridge.offload=kernel` | Fast L2 via kernel bridge; routed traffic crosses a veth trunk |
| `kernel_nat` | Linux/Android root | `nat.offload=kernel` | Fast NAT via nft/iptables, control-plane only |
| `nfqueue` | Android root (experimental) | `intercept=nfqueue` | Userspace control of tethered traffic, slower |
| `proxy` | Android VPN mode | No raw uplink; sockets only | Works unrooted, TCP/UDP proxy NAT |

Selection is a config policy, not a runtime guess. The core refuses to start
if the requested backend is unavailable, with an actionable error (never a
silent fallback).

## 5. Threading model

**v1: `Io.Threaded` with per-port workers.**

```
main thread ── control plane, signals, journal
   │
   ├── port worker A: read(port) → pipeline → write(egress)
   ├── port worker B: ...
   └── timer thread: conntrack GC, DHCP lease expiry, DNS cache
```

- One worker per port (or per queue on multi-queue TUN/AF_PACKET).
- No packet handoff between workers; a packet is fully processed by the
  ingress worker.
- Shared state is immutable snapshots (FIB, rules) + sharded mutable tables
  (conntrack, FDB, ARP) with per-shard locks.
- Backpressure: bounded ingress queues; drop-oldest or drop-tail with counters.
- `Io.Threaded` gives task concurrency and cancellation when built with
  threads; use `io.async` for timers/control operations.

Post-v1: custom epoll/kqueue reactor or AF_XDP for > 5 Gbps.

## 6. Platform backends

### 6.1 Linux

| Concern | API |
|---|---|
| L2 port | `AF_PACKET` + `PACKET_MMAP`/TPACKET_V3 |
| L3 port | `/dev/net/tun` + `TUNSETIFF` |
| Addresses/routes/neighbors | rtnetlink |
| Link events | rtnetlink multicast groups |
| MTU/speed | netlink/ethtool |
| Kernel bridge | netlink (`RTM_NEWLINK` with `IFLA_MASTER`) |
| Kernel NAT | nftables (netlink) preferred; iptables fallback |
| DNS host config | resolv.conf / systemd-resolved (optional, opt-in) |
| Namespaces | `setns` for tests and container deployments |

Privileges: `CAP_NET_ADMIN` + `CAP_NET_RAW`; drop everything else. Provide a
systemd unit with `AmbientCapabilities`.

### 6.2 Android

| Mode | Backend |
|---|---|
| VPN (no root) | `fd_port` (VpnService fd) + proxy NAT over protected sockets |
| Root | `raw.zig` (`AF_PACKET`) + `tun.zig` + `netlink` + kernel/nfqueue interception |

Host app responsibilities and lifecycle are in [ANDROID.md](./ANDROID.md).

### 6.3 Future (macOS/Windows)

Design for it now: `Port` vtable, `HostOps` trait (routes, addresses, DNS),
and no `if (os == ...)` in the core. macOS: utun/BPF, PF_ROUTE, pf. Windows:
Wintun/Npcap, IP Helper, WFP/New-NetNat.

## 7. Configuration and journal

- Strict schema, versioned; unknown keys rejected.
- Validation is pure (no side effects) and runs before apply.
- R2 journal: `$VNET_RUN_DIR/<instance>.journal` (default `/run/vnet`),
  one forward op per JSON line, fsynced and atomically replaced before the
  netlink mutation. `vnet down` derives inverses in reverse order; deletes are
  gated by journal ownership; a failed apply removes its record.
- The R7 control socket, read-only status, `vnet doctor` diagnostics, and the
  run-dir daemon lock are implemented. Pending/applied reconciliation and
  batch apply remain.
- Secrets (if any) come from env/file descriptors, never the config file.

## 8. Security

- Control socket is `0660` owned by the daemon uid and primary group; server
  authorization currently accepts root or that uid. No TCP listener.
- Privilege separation option (post-v1): privileged datapath helper +
  unprivileged control process, communicating over a socketpair.
- Firewall default-deny for inbound/forward.
- Anti-spoofing: drop packets whose source is not reachable via the ingress
  port (uRPF-lite) when `firewall.rp_filter = true`.
- Rate limits: ICMP errors, ARP, DHCP, DNS.
- No packet payload logging by default; `pcap` is explicit and time-boxed.
- Root journal is integrity-checked on replay (no shell interpolation).

## 9. Performance

Performance targets are measured in R9a for the Linux 0.2.0 preview.
`scripts/perf.sh` produces the reproducible baseline and release report; no
throughput or latency claim is made without that report and its host details.

- Batch reads/writes (`recvmmsg`/`sendmmsg`, AF_PACKET rings).
- Per-core buffer pools; no allocation in `read → forward → write`.
- Checksums: software, vectorized; offload only when negotiated.
- Sharded conntrack (`2^n` shards by hash) to avoid a global lock.
- FIB snapshot swap, no locks on lookup.
- Optional `kernel_nat`/`kernel_bridge` for line-rate paths.
- Profiling hooks: per-stage cycle counters, drop reasons, queue depth.

## 10. Testing

| Layer | Approach |
|---|---|
| Parsers | Unit + fuzz (Ethernet, VLAN, IPv4/6, TCP/UDP, DHCP, DNS) |
| Tables | Property tests for FIB/LPM and conntrack |
| Pipeline | In-memory ports with golden packet vectors |
| Topology | Linux netns + veth + TUN (`scripts/test_netns.sh`) |
| Forwarding | Two-host netns ping + TCP (`scripts/test_route.sh`) |
| IPv6 | NDP, ping6 and TCP repair (`scripts/test_ipv6.sh`) |
| TUN | Kernel TUN peer ↔ veth host, ICMP + TCP (`scripts/test_tun.sh`) |
| Journal | iface/route mutations + `vnet down` (`scripts/test_journal.sh`) |
| NAT/conntrack | SNAT UDP/ICMP/TCP, DNAT/hairpin, live add/del (`scripts/nat_matrix.sh`) |
| NAT matrix | Emulated EIM/EDM, hairpin, port-forward, exhaustion |
| DHCP/DNS | Client emulators; lease persistence across restart |
| Security/privilege | Journal rollback, default-deny policy, netns isolation |
| Crash safety | kill -9, journal replay, `vnet doctor --repair` (`scripts/test_crash.sh`) |
| Android | Emulator (VPN mode), rooted device (root mode) |
| Performance | `iperf3`, `pktgen`, 64 B and 1500 B, multi-flow |

## 11. ADRs

| ADR | Decision |
|---|---|
| [001](adr/001-router-first.md) | Router-first product scope |
| [002](adr/002-hybrid-datapath.md) | Userspace reference + kernel fast path |
| [003](adr/003-android-capability-tiers.md) | Android VPN + root router tiers |
| [004](adr/004-overlay-deferred.md) | Overlay/P2P deferred to a future uplink module |
| [005](adr/005-conntrack-nat.md) | Conntrack/NAT design (port allocation, timeouts) |
| [006](adr/006-config-journal.md) | Config schema and R2 journal format |
| [007](adr/007-userspace-checksum-repair.md) | Repair transport checksums on forwarded IPv4 |
| [008](adr/008-userspace-stp.md) | Optional userspace 802.1D STP |
| [009](adr/009-kernel-bridge-offload.md) | Kernel bridge offload with a veth trunk |
| [010](adr/010-embedded-c-abi.md) | Embedded C ABI and host fd injection |
| [011](adr/011-web-admin.md) | Optional local web admin (post-v1) |
| [012](adr/012-project-rename.md) | Rename vNAT to vRouter (superseded) |
| [013](adr/013-ipv6-r9-core.md) | IPv6 core for v1.0 |
| [014](adr/014-live-nat-updates.md) | Config-backed live NAT updates |
| [015](adr/015-control-protocol-v3.md) | Versioned control protocol and staged writes |
| [016](adr/016-network-model-and-staged-config.md) | Network model and staged configuration |
| [017](adr/017-project-rename-vnet.md) | Rename vRouter to vNET |
| [018](adr/018-shard-build-graph.md) | Named shard build graph |
