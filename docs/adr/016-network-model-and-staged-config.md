# ADR-016 — Network model and staged configuration

- **Status:** Accepted for the web preview (2026-10-25)
- **Date:** 2026-10-25
- **Related:** [ADR-011](011-web-admin.md), [ADR-014](014-live-nat-updates.md),
  [ADR-015](015-control-protocol-v3.md), [WEB-SCOPE](../WEB-SCOPE.md)

## Context

The first web write path exposed NAT as a flat list of global rules. Each
dialog submit called `config.apply` and `nat.apply` immediately. That works as
a command interface, but it is a poor model for a router:

- a masquerade rule belongs to an egress interface or network, not to a global
  NAT table;
- a port forward belongs to an ingress network and a destination subnet;
- editing several related rules one at a time produces several revisions,
  several audit entries and a non-atomic datapath update;
- the page still called itself a read-only preview while it was writing.

Proxmox VE SDN is a useful reference because it separates three concerns that
the current NAT page conflates:

1. **Attachment.** A physical NIC is connected through an existing bridge or
   fabric. SDN does not treat the NIC itself as the logical network.
2. **Intent.** Zones, VNets and subnets describe isolation, addressing and
   services. A subnet carries the gateway, SNAT, IPAM/DHCP and DNS scope.
3. **Rollout.** New changes are recorded as pending, reviewed, and applied as
   one atomic rollout. `.running-config` and `.version` distinguish the live
   state from the proposed state.

Proxmox also shows that implementation choices (VLAN, QinQ, VXLAN, EVPN) should
not be the primary mental model for an operator. They are backends behind an
intent such as "isolated network with NAT" or "bridged uplink".

vRouter already has the invariants needed for this model: a port belongs to at
most one bridge or router zone, L2 and L3 are both first-class, and the control
plane applies immutable snapshots. The missing piece is the UI model and the
transaction boundary.

## Decision

### 1. Model networks in layers

Use the following model for navigation and future pages:

```text
physical/virtual port (attachment, link, MTU, VLANs)
        |
        v
bridge or router network (isolation, forwarding, gateway)
        |
        v
subnet (CIDR, gateway, DHCP/DNS, SNAT)
        |
        v
service (NAT, firewall, ...)
```

- **Ports** are attachments. A port exposes link state, MTU, driver/device and
  its bridge or network membership. A port cannot belong to two bridges or
  zones.
- **Networks** are logical L2/L3 domains. The user-facing term is "network";
  "zone" remains an internal term for the isolation/backend choice.
- **Subnets** carry addressing and service scope. DHCP, DNS and SNAT are
  configured on a subnet or network, not as global tables.
- **Services** are filtered views over the objects they belong to. A global NAT
  table is allowed only as a cross-network overview, never as the primary place
  where scope is chosen.

For NAT specifically:

- masquerade is an egress property of a network or uplink;
- a port forward is scoped to an ingress network and a destination subnet;
- the NAT page must show or select that scope, even when the underlying config
  is still a flat array.

### 2. Configuration is a draft document

Every configuration page follows one flow:

1. **Edit** stages changes in a draft. A draft edit does not touch the daemon,
   the config file, the datapath or the journal.
2. **Review** builds a proposed complete document and calls `config.diff`. The
   UI shows affected resources, the unified diff and `restart_required`.
3. **Apply** sends the reviewed draft through one `config.apply` transaction
   and the corresponding live update. The running state is replaced only after
   the daemon accepts the transaction.
4. **Discard** drops the draft and reloads the running state.

The draft is carried in the page as an opaque, escaped value and submitted with
each edit, review and apply request. The web process does not need a
server-side draft store; a stale page simply submits a stale draft, which the
revision check rejects. This keeps the preview stateless and crash-safe.

A page must show one of these states explicitly:

- **Running** — the value came from the daemon and is live.
- **Pending** — the value exists only in the browser draft.
- **Applied** — the daemon accepted the transaction; show a human summary.
- **Restart required** — the change cannot be live-applied; do not pretend it
  was.
- **Unavailable** — the capability or backend is missing; disable the action
  with a reason.

### 3. Apply once, not per dialog

Create/edit/remove dialogs may remain the interaction primitive, but their
submit handlers stage a change. Only the explicit Apply action may mutate the
router. Remove actions stage a deletion and can be discarded like any other
change.

A successful Apply shows a short summary ("3 NAT changes applied"). A link to
the audit/transaction detail is future work; the transaction id is diagnostic
data, not the primary success message.

### 4. Keep physical and logical state separate

The UI must not hide the physical attachment:

- show link state, MTU, addresses and bridge/network membership on the port
  page;
- show the resulting topology when a network is created or changed;
- validate conflicts before Apply (duplicate masquerade egress, duplicate
  forward, port in multiple networks);
- surface MTU consequences for VLAN, QinQ and overlay backends;
- keep underlay/fabric configuration separate from logical network intent.

### 5. First slice: NAT

NAT is the first vertical slice because ADR-014 already provides a live apply
path. The slice implements:

- staged add/edit/remove of masquerade and port-forward rules;
- a pending-changes bar with Review, Apply and Discard;
- `config.diff` review with affected resources and the unified diff;
- one `config.apply` plus `nat.apply` on Apply;
- running/pending state and honest error reporting.

DHCP and DNS were added as the next slices. They reuse the same
draft/review/apply/discard flow but call only `config.apply`; both sections
return `restart_required`, so the UI saves the config and reports that the
service activates after a daemon restart rather than claiming a live apply.

Other resources adopt the same pattern as their read/write APIs become
available. No new source of truth is introduced: the daemon still owns
validation, revisions, transactions and audit.

## Consequences

- The NAT page becomes a small staged editor rather than a command form. It
  needs a larger request body because the draft is submitted with each action;
  the preview raises its bounded body limit accordingly.
- The web process remains unprivileged and stateless with respect to drafts.
  A browser refresh discards pending changes, which is the same as an explicit
  Discard and must be visible in the UI copy.
- `config.apply` and `nat.apply` are still two calls. The UI must report a
  partial failure ("config saved, live NAT update failed") until the daemon can
  apply config and datapath in one transaction. It must not claim atomicity
  that the backend does not provide.
- Future pages inherit the pending/apply/discard model. This is deliberate
  scope: a correct interaction model is more valuable than a collection of
  immediate-write forms.
- The target navigation becomes Overview, Network (Ports, Networks, Subnets),
  Services (NAT, DHCP/DNS, Firewall), System (Config, Audit), with one global
  pending-changes surface. The preview may expose only the pages that are
  actually implemented, but new pages must fit this structure.

## Alternatives

- **Immediate apply per dialog (current NAT behavior):** rejected. It creates
  revision churn, makes multi-rule changes non-atomic and hides the difference
  between editing and mutating the router.
- **A client-side SPA draft:** rejected for the same appliance reasons as
  ADR-011. Server-rendered HTML with a stateless draft is enough and keeps the
  no-Node constraint.
- **Copy Proxmox zone types into the UI:** rejected. VLAN/VXLAN/EVPN are
  backends; operators should choose intent and see advanced options only when
  needed.
- **Keep NAT as a global table:** rejected as the primary model. A global view
  is useful for search and cross-network inspection, but scope belongs to the
  network/subnet object.
- **Store drafts in the web process:** rejected for the preview. It adds
  lifetime, cleanup and multi-tab semantics before the backend transaction
  model is complete. The page-carried draft plus revision checks is simpler and
  fails safely.
