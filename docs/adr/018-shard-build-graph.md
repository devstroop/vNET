# ADR-018 — Shard build graph

- **Status:** Accepted
- **Date:** 2026-10-26
- **Related:** [ADR-017](017-project-rename-vnet.md), [ARCHITECTURE](../ARCHITECTURE.md)

## Context

vNET is still compiled as one Zig module rooted at `src/lib.zig`. Every file can
reach every other file with a relative import, so the documented L2/L3/NAT/DHCP/
DNS/control split is a directory convention rather than a compiler-checked
boundary. `src/l3/forward.zig` alone is the forwarding engine, bridge, firewall
glue and service integration, which makes the dependency direction impossible
to verify.

The rename to vNET (ADR-017) fixed the product identity. This ADR starts the
next step: give each subsystem an explicit module boundary and a build graph
that fails when a dependency is not declared.

Phase 1 is deliberately a **build-graph change, not a source-tree move**. The
files stay where they are and the public `vnet` module keeps its current
exports. This keeps the change reviewable and lets the forwarding-engine split
land separately.

## Decision

Introduce thin shard roots at `src/shard_<name>.zig` and compile them as named
Zig modules. A shard root is a stable, small surface that re-exports the
shard's public types; implementation files remain in their existing
directories for now.

The roots sit at the top of `src/` because a Zig module cannot import a file
outside its root source directory. Keeping the roots at `src/shard_*.zig` lets
them reach the existing `src/port/`, `src/l3/`, `src/control/` and
`src/services/` trees without a temporary file move.

| Module | Responsibility | Allowed dependencies |
|---|---|---|
| `vnet-core` | Types, errors, `std.Io` helpers, logging, version, config schema/parser/writer/store | none |
| `vnet-port` | Port vtable, memory/fd ports, buffer pool, Linux ports, port manager | core |
| `vnet-l2` | Ethernet/802.1Q parsing, STP; bridge/VLAN split follows | core |
| `vnet-l3` | IPv4/IPv6/ARP/NDP/FIB/ICMP/rate parsing and lookup; no forwarding engine | core |
| `vnet-conntrack` | Flow table, timeouts, GC and counters | core |
| `vnet-nat` | SNAT/DNAT and checksum rewrites | core, l3, conntrack |
| `vnet-dhcp` | DHCPv4 message, server and lease persistence | core |
| `vnet-dns` | DNS message, cache, probe and forwarder | core, thread |
| `vnet-ctl` | Unix control socket, protocol, transactions, journal, host/offload changes, read model | core, port, dns, thread |
| `vnet-fw` | Ordered firewall rules and matching | core, l3, conntrack |
| `vnet-tunnel` | Future overlay/P2P uplink (ADR-004) | core, port |

`vnet-fw` and `vnet-tunnel` are reserved names but not instantiated in phase 1.
Firewall matching currently lives in the forwarding engine; it moves out when
`forward.zig` is split.

The following composition rules apply:

1. **No cycles.** The build graph is a DAG. `vnet-l3` must never import NAT,
   firewall or services; NAT/firewall depend on L3 packet helpers, not the
   reverse.
2. **Composition belongs above the shards.** `src/lib.zig`, `src/app/` and
   `src/ffi.zig` compose shards. They may import multiple shards; shards may not
   reach back into the composition root.
3. **The control plane owns mutation.** `vnet-ctl` is the only shard that
   journals host changes. Data-plane shards consume immutable snapshots or
   return typed actions; they do not call the journal.
4. **No hot-path allocation is introduced by the boundary.** Shard APIs pass
   slices, ids and fixed-size values; allocations remain control-plane work.
5. **Thread backend is a product profile.** CLI modules map `vnet-thread` to the
   non-pthread backend; FFI modules map it to the pthread backend. `dns` and
   `ctl` are instantiated once per profile because they spawn threads; pure
   shards are shared.
6. **The public umbrella stays stable.** `src/lib.zig` re-exports the shard
   surfaces, so `exec/vnet`, `exec/vnetd`, tests and existing Zig consumers do
   not change. `include/vnet.h` and the C ABI are unchanged by this ADR.
7. **Every shard has its own test artifact.** `zig build test` runs shard tests,
   the umbrella tests, fuzz smoke and the FFI smoke. A shard root imports its
   implementation files in a `test` block so tests cannot silently disappear
   when a file is moved.

### Phase 1 graph

```
                 ┌──────────────┐
                 │  vnet-core   │
                 └──────┬───────┘
        ┌───────────────┼───────────────┬──────────────┐
        ▼               ▼               ▼              ▼
     vnet-port       vnet-l2         vnet-l3       vnet-dhcp
                                        │
                          ┌─────────────┴─────────────┐
                          ▼                           ▼
                    vnet-conntrack                vnet-nat
                                                      │
                                                      ▼
                                                   vnet-fw

     vnet-thread ──▶ vnet-dns ──▶ vnet-ctl
```

`vnet-nat` also depends on conntrack. `vnet-ctl` additionally depends on port.
The forwarding engine (`src/l3/forward.zig`), `src/app/service.zig` and
`src/ffi.zig` remain in the composition layer until phase 2.

### Migration phases

1. **Build graph and leaf shards (this ADR).** Core, port, L2, L3 packet/lookup,
   conntrack, NAT, DHCP, DNS and ctl get module roots (`src/shard_*.zig`) and
   tests. No implementation file moves, no behavior change. FFI thread
   selection is preserved.
2. **Split the engine.** Move bridge/VLAN and firewall matching out of
   `forward.zig` into `vnet-l2` and `vnet-fw`; make the forwarding engine an
   explicit composition module. Convert direct service calls to typed events
   where they cross the data/control boundary.
3. **Product profiles and headers.** Add build-time shard selection and
   manifests for `gateway`, `dns-only`, `dhcp-only`, `nat-only`, `switch`,
   `edge` and `hotspot`; generate per-shard C headers from one source.
4. **Tunnel.** Add `vnet-tunnel` as a future uplink shard once ADR-004 work
   starts.

## Consequences

- A missing or cyclic module dependency fails at compile time instead of
  surviving as a relative import.
- `dns` and `ctl` are built twice (CLI and FFI thread profiles). Pure shards and
  their tests are compiled once.
- `src/lib.zig` remains a larger-than-ideal umbrella until phase 2, but its
  exports are now assembled from named shards rather than one flat module.
- The firewall and engine split is still outstanding; this ADR makes the
  remaining coupling visible rather than pretending it is already modular.
- Implementation paths do not move in phase 1, so `git blame`, scripts and
  docs keep working. A later phase can relocate files and roots after the graph
  stabilizes.

## Alternatives

- **Move every directory into `src/shards/` now.** Large path churn mixed with
  API changes; review and bisection suffer.
- **Keep one module and rely on review.** Zero enforcement; cycles and service
  imports continue to creep in.
- **Separate repositories now.** Versioning and atomic changes become harder
  before the APIs are stable.
- **Add build-time shard selection immediately.** Premature; the forwarding
  engine and firewall are not split yet, so profiles would only hide a
  monolithic core.
- **Make every shard depend only on core in phase 1.** Requires moving packet
  codecs and thread plumbing first; that is phase 2/3 work, not a mechanical
  build-graph change.
