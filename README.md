# vNET

A programmable virtual network implemented in Zig 0.16.x.

vNET attaches network interfaces, forwards Ethernet, IPv4 and IPv6 traffic,
and provides NAT, DHCP, DNS, and journal-backed host configuration. It runs as a
daemon with a command-line interface and exposes a C ABI for embedded hosts.

> **Renamed:** vNET was previously vRouter, and before that vNAT. The
> pre-1.0 rename changes binary, ABI and default path names; see
> [ADR-017](docs/adr/017-project-rename-vnet.md) and
> [ADR-012](docs/adr/012-project-rename.md).

## Capabilities

- AF_PACKET L2 ports and TUN/TAP L3 ports
- ARP and NDP handling, IPv4/IPv6 forwarding, ICMP/ICMPv6 errors, and
  TTL/hop-limit processing
- Userspace IPv4 connection tracking and garbage collection
- Source NAT, destination NAT, port forwarding, and hairpin handling
- Live `vnet nat add|del` updates with atomic config save and rollback
- DHCPv4 server and client with lease persistence (DHCPv6 in v1.1)
- DNS forwarding with cache, TCP fallback, and split zones
- Atomic, journaled route/address/link changes with rollback
- Cross-compilation for Linux and Android targets
- Compiler-checked `vnet-*` shard modules with per-shard tests
  ([ADR-018](docs/adr/018-shard-build-graph.md))

## Requirements

- Zig 0.16.x
- Linux kernel with AF_PACKET support

## Build

```sh
zig build
zig build --release=fast
```

Linux release artifacts:

```sh
ZIG=/path/to/zig bash scripts/package.sh --rpm
```

This writes a tarball, `.deb`, `.rpm` and checksums to `dist/`.

## Test

```sh
zig build test
bash scripts/test_netns.sh
bash scripts/test_route.sh
bash scripts/test_tun.sh
bash scripts/test_ipv6.sh
bash scripts/test_journal.sh
bash scripts/test_crash.sh
bash scripts/nat_matrix.sh
bash scripts/test_firewall.sh
bash scripts/test_vlan.sh
bash scripts/test_offload.sh
bash scripts/test_dhcp.sh
bash scripts/test_dns.sh
```

Soak and performance:

```sh
ZIG=/path/to/zig bash scripts/soak.sh --duration 5m
ZIG=/path/to/zig bash scripts/perf.sh --scenario all
```

Cross-build:

```sh
zig build -Dtarget=x86_64-linux
zig build -Dtarget=aarch64-linux
zig build -Dtarget=aarch64-linux-android
zig build -Dtarget=arm-linux-androideabi
```

## Usage

Validate a configuration:

```sh
./zig-out/bin/vnet validate examples/minimal.json
```

Start the daemon:

```sh
./zig-out/bin/vnetd -c examples/minimal.json
```

Common commands:

```sh
vnet status [-c <config>]
vnet port list
vnet iface set <dev> <cidr> [-c <config>]
vnet route add <dst> [via <ip>] dev <dev> [-c <config>]
vnet nat add|del masquerade --out <iface|port> [-c <config>]
vnet nat add|del port-forward --proto tcp|udp --ext-port <n> [--to <ip:port>] [--in <name>] [-c <config>]
vnet down [-c <config>]
vnet doctor [--repair] [-c <config>]
vnet journal [-c <config>]
vnet dhcp status [-c <config>]
vnet dns query <name> [-c <config>]
```

## Configuration

- `examples/minimal.json`: runnable example
- `examples/travel-router.json`: illustrative target-state configuration
- `examples/README.md`: example status notes

## Documentation

1. `docs/QUICKSTART.md`
2. `docs/TROUBLESHOOTING.md`
3. `docs/PERFORMANCE.md`
4. `docs/RELEASE.md`
5. `docs/PRODUCT.md`
6. `docs/CORE-SCOPE.md`
7. `docs/ANDROID.md`
8. `docs/ARCHITECTURE.md`
9. `docs/PLAN.md`
10. `docs/RESEARCH.md`
11. `docs/SOURCES.md`
12. `docs/adr/`

Contributor rules: `AGENTS.md`.

## Implementation Status

- R0-R6: complete, including live NAT add/del and incremental checksum
  rewrites
- R9a (current): Linux 0.2.0 preview. IPv6, crash recovery, performance and
  soak harnesses, packaging, systemd unit and release workflow are in place.
  The 24 h/72 h evidence, 64 B packet-rate budget and GSO handling remain
  release blockers; see `docs/PERFORMANCE.md` and `docs/RELEASE.md`.
- R7: Linux control socket and C ABI foundation complete; Android
  JNI/VpnService host and proxy NAT pending
- R8: planned
- R9b: Android release and v1.0, after R7/R8
- R10 (post-v1): optional local web admin via HTMX and the Unix-socket API
  (ADR-011)

See `docs/PLAN.md` for milestone details.
