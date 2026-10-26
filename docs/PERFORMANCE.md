# Performance

This is a baseline report, not a green R9a gate. The 1500 B forwarding, L2 and
NAT budgets are met on the reference host; the 64 B packet-rate budget is not.

## Reference host

- Arch Linux, kernel `7.2.10-arch1-1`, x86_64
- Intel Core i5-8365U (4 cores / 8 threads, 1.6 GHz base, 4.1 GHz turbo)
- 8 logical CPUs, unprivileged network namespace
- Zig 0.16.0, `zig build --release=fast`
- Synthetic veth pairs; not a physical NIC or a multi-queue workload

CPU frequency scaling was left at the system default. Re-run on a quiet,
frequency-pinned host before using these numbers for a release decision.

## Method

`scripts/perf.sh` creates two hosts and a vNET instance in a fresh netns:

```
host A 10.0.1.2/24 -- veth -- vnet lan0 10.0.1.1/24
                                      |
                              L3 forward / L2 bridge / SNAT
                                      |
host B 10.0.2.2/24 -- veth -- vnet wan0 10.0.2.1/24
```

The script disables TX checksum, GSO, TSO and GRO on the synthetic host veths
with `scripts/netdev_offload.c`. Without that, veth checksum-partial and GSO
frames dominate the result and do not represent forwarded Ethernet frames.
UDP uses `SO_NO_CHECK` because the userspace bridge does not repair
checksum-partial frames; this isolates forwarding from offload artifacts.

`scripts/loadgen.c` generated traffic:

- UDP 64 B payload, 5 s, as fast as the sender can transmit
- UDP 1400 B payload, 5 s
- TCP 256 MiB, one stream
- UDP RTT, 500 sequential datagrams

Run:

```sh
ZIG=/path/to/zig bash scripts/perf.sh --scenario all
# quick smoke only:
ZIG=/path/to/zig bash scripts/perf.sh --scenario forward --duration 1
```

Use `--no-offload-reset` only when deliberately measuring offload effects.
Use `--no-build` only after `zig build --release=fast`; a debug `zig-out` gives meaningless results.

## Results

Measured 2026-10-26. Throughput is server-received end-to-end traffic.

| Scenario | 64 B UDP | 1400 B UDP | 256 MiB TCP | UDP RTT p99 |
|---|---:|---:|---:|---:|
| L3 forward | 165,957 pps / 0.085 Gbps | 1.613 Gbps | 1.014 Gbps | 92.9 us |
| L2 bridge | 199,892 pps / 0.102 Gbps | 2.060 Gbps | 1.338 Gbps | 103.1 us |
| SNAT (masquerade) | 160,536 pps / 0.082 Gbps | 1.665 Gbps | 0.992 Gbps | 100.7 us |

The sender offered about 391–493 kpps at 64 B, so the receiver is the
forwarding bottleneck, not the traffic generator. At 1400 B the sender offered
360–451 kpps.

## Budget status

| CORE-SCOPE §12 budget | Result | Status |
|---|---|---|
| L3 forward, 1500 B: >= 1 Gbps | 1.613 Gbps (1400 B payload) | met |
| L3 forward, 64 B: >= 1 Mpps | 166 kpps | **not met** |
| L2 bridge: >= 2 Gbps | 2.060 Gbps | met, marginal |
| SNAT: >= 800 Mbps | 1.665 Gbps | met |
| Added latency: p99 < 1 ms | 93–103 us | met |

The 64 B test uses a 64 B UDP payload, about 106 B on the wire, so it is not a
smaller workload than the stated budget. The current datapath processes one
packet per `recvmsg`/`sendmsg` cycle and does not use `recvmmsg`, `sendmmsg`,
`PACKET_MMAP`/TPACKET_V3 rings or multiple RX queues. Reaching 1 Mpps needs
those changes, not tuning alone.

The 2.060 Gbps L2 result is close enough to the 2 Gbps budget that run-to-run
variation can move it below the line. Report a median of at least three runs
before signing off.

## GSO and checksum caveat

The benchmark workaround masks a real limitation. A local veth peer can emit
64 KiB GSO frames. vNET's RX buffer is 2048 bytes (`src/app/service.zig`) and
the forwarder's packet buffer is also 2048 bytes, so those frames are dropped.
ADR-007 deferred offload-aware input. This does not affect normal Ethernet
frames from a physical switch, but it affects veth peers, containers and some
virtualized hosts. The bridge path also does not repair checksum-partial
frames from an offloading peer. Keep the veth offload workaround in tests and
treat GSO support as release-blocking for those deployments.

## Next measurements

- Three runs per scenario on a fixed-frequency reference host.
- 64 B with `recvmmsg`/`sendmmsg` batching and multi-queue veths after datapath
  work.
- 24 h soak results from `scripts/soak.sh`, including restart and flap counts.
- Conntrack table pressure and GC behavior at the documented cap.
