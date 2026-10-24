# ADR-013 — IPv6 core for v1.0

- **Status:** Accepted
- **Date:** 2026-10-24

## Context

`docs/CORE-SCOPE.md` promised IPv4 and IPv6 forwarding in v1, while the R2
implementation and later milestones only shipped IPv4. The v1 contract also
deferred NDP to v1.1, which would make IPv6 forwarding unusable on ordinary
Ethernet links. Shipping IPv6 without neighbor discovery would force static
neighbors on every deployment and contradict the router-first scope.

A full IPv6 service stack — router advertisements, SLAAC, DHCPv6, NAT66/NAT64,
IPv6 conntrack, MLD snooping and Android IPv6 host integration — is too large
for the v1.0 hardening milestone. The project needs a clearly bounded core that
makes dual-stack routing work end to end without expanding the v1 ABI or
pretending the remaining pieces exist.

## Decision

Implement an IPv6 **R9 core** in v1.0 and defer the rest to v1.1.

### In scope for v1.0

1. **Packet path.** IPv6 base-header parsing and building, extension-header
   walking (hop-by-hop, routing, fragment, destination options), hop-limit
   decrement, and IPv6 pseudo-header checksum repair for forwarded TCP/UDP.
   Link-local sources and destinations are never forwarded to another link
   (RFC 4291 §2.5.6).
2. **NDP.** Neighbor solicitation/advertisement, source/target link-layer
   options, solicited-node multicast mapping, a bounded neighbor cache, and a
   bounded pending-packet queue while resolution is in progress. Unsolicited
   advertisements update the cache. The router does not initiate duplicate
   address detection, but it answers DAD probes for its configured addresses.
3. **ICMPv6.** Echo request/reply, destination unreachable, packet too big
   (including the MTU field) and time exceeded for locally generated errors
   over IPv6.
4. **Configuration.** Keep `interfaces.<name>.address` as an IPv4 CIDR or
   `"dhcp"`. Add `interfaces.<name>.addresses`, an array of additional IPv4 or
   IPv6 CIDRs, for dual-stack interfaces. `"dhcp"` is not valid in `addresses`.
   The config version stays 1 because the new key is optional.
5. **Routes.** Static routes accept IPv6 destinations and IPv6 next hops. The
   next-hop family must match the destination family. Connected routes are
   generated from IPv6 addresses on ports and SVIs.
6. **Firewall.** Rules gain `family` (`ipv4`, default; `ipv6`; `any`) and
   `proto: "icmpv6"`. `src`/`dst` accept IPv6 prefixes when the family allows
   it. IPv6 evaluation is stateless; `ct_state` is rejected unless the rule is
   IPv4. `firewall.rate_limit.ndp` bounds received NDP messages; generated
   solicitations are limited per unresolved target.
7. **MTU.** An interface with an IPv6 address or route requires MTU >= 1280,
   both at config validation and at `Forwarder.fromConfig`. vRouter does not
   fragment IPv6; oversized packets are dropped and counted, and ICMPv6 Packet
   Too Big is generated where possible.
8. **Host/CLI.** `vrouter iface set|del` and `vrouter route add|del` accept IPv6
   values and mutate the host through AF_INET6 netlink. The journal records the
   same operations and `vrouter down` reverses them. The daemon's declarative
   config path still does not add kernel addresses or routes.

### Explicitly deferred to v1.1

- Router advertisements, SLAAC, DHCPv6 and prefix delegation.
- NAT66, NAT64, IPv6 port forwarding and IPv6 conntrack.
- MLD/MLD snooping, jumbograms and atomic fragments beyond safe forwarding.
- IPv6 DNS service and IPv6-aware DHCP options.
- Android IPv6 routing/DNS/proxy integration.
- Duplicate address detection, privacy addresses and automatic link-local
  address assignment (operators configure link-local explicitly if desired).

## Consequences

- A Linux vRouter can route IPv6 between configured ports and SVIs using static
  addresses and routes, with working neighbor discovery and checksum repair.
- The v1 firewall remains stateless for IPv6; stateful policy requires IPv4 or a
  future explicit IPv6 conntrack design.
- `CORE-SCOPE.md` §4.2 no longer defers NDP; RA remains v1.1. The contract and
  milestone plan are updated with this ADR.
- The C ABI is unchanged: IPv6 configuration remains a text/CIDR concern at the
  config and CLI boundary, and no new exported symbol is required.
- Android rooted mode can use the same userspace datapath in principle, but its
  host routing and DNS integration are not part of v1.0.
- IPv6-enabled interfaces reject MTUs below 1280 instead of silently dropping
  traffic; this is a new validation error for otherwise valid IPv4 configs that
  add an IPv6 address to a small-MTU port.

## Alternatives

- **Defer all IPv6 to v1.1.** Keeps v1.0 small, but breaks the router-first
  contract and leaves the IPv6 parser/FIB work unused.
- **Ship RA/SLAAC/DHCPv6 in v1.0.** Makes IPv6 a first-class service but adds
  several weeks and a second stateful control plane; the R9 schedule cannot
  absorb it.
- **Reuse IPv4 conntrack/NAT for IPv6.** Would require a rewritten flow key and
  NAT semantics; stateless IPv6 firewalling is the smaller, testable v1 cut.
- **Require static neighbors.** Avoids NDP but makes IPv6 impractical on
  Ethernet and contradicts normal IPv6 operation.
