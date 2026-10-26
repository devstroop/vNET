# ADR-007 — Repair transport checksums on forwarded IPv4

**Status:** Accepted (R2; amended R3)
**Date:** 2026-10-23

## Context

vNET reads frames from `AF_PACKET`. Locally generated packets can reach the
packet socket while the kernel still carries `CHECKSUM_PARTIAL`: the NIC (or
veth peer) is expected to finish the TCP/UDP checksum. vNET copies the bytes,
rewrites the Ethernet header on another port and transmits them through a new
packet socket, so the offload metadata is lost and the peer receives an
invalid L4 checksum. ICMP is unaffected because the kernel computes its
checksum in software.

This was observed as successful ICMP but failed TCP through two veth pairs.

## Decision

For every forwarded, non-fragmented IPv4 packet, vNET repairs the TCP or
UDP checksum once after the forwarding copy and before conntrack/NAT. NAT then
adjusts TCP/UDP/ICMP checksums incrementally with RFC 1624 (ADR-014) instead of
rescanning the payload. The IPv4 header checksum is always recomputed. UDP
checksum `0` remains "no checksum" as allowed by RFC 768; fragmented packets
are forwarded as-is because their L4 checksum covers the reassembled datagram.

## Consequences

- Forwarding is correct on veth, TAP and offload-enabled NICs without
  negotiating offload per port.
- One pass over the L4 payload per forwarded packet, not one per rewrite. NAT
  updates remain incremental for multi-rewrite flows (for example hairpin).
- The repair must happen before the first NAT rewrite; egress and pending-flush
  paths rely on the stored packet already being repaired.
- Offload negotiation could still remove the initial repair; it does not change
  the NAT ordering.
- Fragmented traffic still depends on the sender's checksum; reassembly or
  offload-awareness is deferred.
