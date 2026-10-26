# ADR-017 — Rename vRouter to vNET

- **Status:** Accepted
- **Date:** 2026-10-26
- **Supersedes:** [ADR-012](012-project-rename.md)

## Context

ADR-012 renamed vNAT to vRouter when the product outgrew source NAT. The name
has since become too narrow again: vRouter describes the L3 function, while the
product also owns bridging, VLANs, connection tracking, NAT, DHCP, DNS and the
firewall. The useful mental model is a virtual network, not only a router.

The project is pre-1.0 with no released tags, installed C consumers or frozen
ABI. The cost of renaming now is a mechanical source change; the cost after the
ABI and packaging stabilize would be permanent aliases or a breaking release.

The same change introduces a shard taxonomy (`vnet-core`, `vnet-port`,
`vnet-l2`, `vnet-l3`, `vnet-conntrack`, `vnet-nat`, `vnet-fw`, `vnet-dhcp`,
`vnet-dns`, `vnet-ctl`, `vnet-tunnel`). That modularization is deliberately
separate: this ADR renames the project without moving `src/*`, so the two
churns can be reviewed independently.

## Decision

Use **vNET** in prose and `vnet` in commands, identifiers, paths and package
names. The casing is deliberate: uppercase `VNET` reads as an acronym and
`vNet` competes with Azure's spelling; `vNetwork` and `VirtualNetwork` are
descriptive and fail as command names.

1. **Product and documentation.** The product is vNET; use lowercase `vnet`
   anywhere a machine reads the name.
2. **Executables and artifacts.** `vrouter`, `vrouterd` and `vrouterweb`
   become `vnet`, `vnetd` and `vnetweb`. Documentation may call the web
   adapter `vnet-web`. Build module and package names use `vnet`; libraries
   are `libvnet` and `libvnet.a`.
3. **C ABI.** `include/vrouter.h` becomes `include/vnet.h`; exported functions,
   types, enum values and macros become `vnet_*` / `VNET_*`. The status struct
   layout and lifecycle semantics are unchanged, but the symbol namespace
   change is a breaking ABI event, so `VNET_ABI_VERSION` becomes 3.
4. **Paths and environment.** Defaults become `/run/vnet`,
   `/etc/vnet/vnet.json` and `<state_dir>/vnetd.log`; environment variables use
   the `VNET_` prefix. Socket and lock file names remain `control.sock`,
   `control.sock.lock` and `control.sock.up.lock` inside the new run directory.
   The local DNS status zone becomes `vnet.` / `router.vnet.`.
5. **Generated interface names.** Kernel bridge-offload helpers use `vnbr`,
   `vnpt` and `vnbs` prefixes instead of `vrbr`, `vrpt` and `vrbs`.
6. **No compatibility aliases.** There are no `vrouter` symlinks, forwarding C
   symbols, duplicated paths or environment fallbacks. Pre-1.0 consumers are
   expected to update.
7. **Migration is explicit.** Stop any pre-rename daemon with the old
   `vrouter down` before installing the new binaries. Journals and runtime
   state under `/run/vrouter` are not copied automatically because they
   describe live host state that must be reconciled, not replayed under a new
   name. Pre-rename configs remain valid JSON but must be moved to the new
   default path or passed explicitly.
8. **Repository hosting.** The GitHub repository and local remote were renamed
   to `devstroop/vnet` after the source rename. Open pull requests remain on the
   same branch and are not closed by the move.
9. **Shard split is separate.** The package/module graph, per-shard headers and
   build-time shard selection get their own ADR and incremental PRs.

## Consequences

- Product, binaries, C ABI, environment variables and default paths share one
  consistent identity.
- Any local scripts, configs or hosts linked against `vrouter_*` must update.
- ABI 3 makes the symbol/header break explicit; there is no mixed-name support.
- The historical ADR-012 and pre-rename changelog entries remain as the record
  of the vNAT→vRouter transition.
- Reviewing the rename separately from the shard layout keeps both changes
  reversible.

## Alternatives

- **Keep vRouter.** Accurate for L3 only and misleading for a product that
  owns L2, services and filtering.
- **Use `VNET` or `vNet`.** Both collide visually with common virtual-network
  abbreviations and make CLI/package casing inconsistent.
- **Use vNetwork or VirtualNetwork.** Descriptive, long and already associated
  with other virtualization products.
- **Rename and split shards in one change.** Two large mechanical churns at
  once; reviewability and bisectability would suffer.
- **Keep vRouter with vNET aliases.** Permanently doubles the public surface for
  a pre-1.0 project with no installed consumers.
