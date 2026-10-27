# ADR-007 — Repair transport checksums and segment offloaded frames

**Status:** Accepted (R2; amended R3, R9a)
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
A local veth peer can also emit GSO super-frames up to the IPv4/IPv6 64 KiB
limit. They exceed the ingress MTU and carry the same lost offload metadata;
without splitting, the fixed 2 KiB forwarding buffers and egress MTU checks
drop them.

## Decision

For every forwarded, non-fragmented IPv4 packet, vNET repairs the TCP or
UDP checksum once after the forwarding copy and before conntrack/NAT. NAT then
adjusts TCP/UDP/ICMP checksums incrementally with RFC 1624 (ADR-014) instead of
rescanning the payload. The IPv4 header checksum is always recomputed. UDP
checksum `0` remains "no checksum" as allowed by RFC 768; fragmented packets
are forwarded as-is because their L4 checksum covers the reassembled datagram.

AF_PACKET RX allocates 65,600 bytes per frame so a full TCP super-frame can be
read, and counts `MSG_TRUNC` frames as drops. Before bridge/L3 dispatch, an
IPv4 or IPv6 TCP super-frame larger than the ingress MTU is split into
wire-sized segments. Each segment gets a recomputed IP length, TCP sequence
number and TCP checksum; only the final segment retains PSH/FIN. Segments then
re-enter the normal bridge/L3 path, preserving VLAN, firewall, conntrack, NAT
and egress MTU behavior. The bridge copy repairs IPv4 and IPv6 TCP/UDP
checksums before transmit.

## Consequences

- Forwarding is correct on veth, TAP and offload-enabled NICs without
  negotiating offload per port.
- A normal forwarded packet pays one checksum pass. A GSO super-frame pays one
  copy and checksum pass per generated segment; the bridge path adds a repair
  pass. NAT updates remain incremental for multi-rewrite flows (for example
  hairpin).
- The repair must happen before the first NAT rewrite; egress and pending-flush
  paths rely on the stored packet already being repaired.
- Offload negotiation could still remove the initial repair; it does not change
  the NAT ordering.
- Only TCP GSO is split. UDP GSO and other non-TCP super-frames are still
  dropped, and the IPv6 parser rejects payloads above 65,535 bytes. The
  datapath still uses an in-band copy rather than `PACKET_VNET_HDR`.
- Fragmented traffic still depends on the sender's checksum; reassembly or
  offload-awareness is deferred.
