# vRouter web admin — full functionality scope

- **Status:** Draft for review
- **Date:** 2026-10-25
- **Related:** [ADR-011](adr/011-web-admin.md), [ADR-014](adr/014-live-nat-updates.md),
  [WEB.md](WEB.md), [PLAN.md](PLAN.md) R10

## 1. Summary

The current `vrouterweb` preview is read-only and exposes only status, NAT and
conntrack. The gap to a useful admin is mostly backend: the daemon has no
general read model for configuration, no general write path, and no way to
apply structural changes without a restart.

This assumes v1.0 has shipped, the control socket is stable, and the deployment
is Linux with one daemon and one web process per instance.

This scope makes the web admin functionally complete for a single local
administrator, except for offline teardown/repair, which stays CLI-only:

- read and write every configuration object;
- perform the live-daemon operational actions currently spread across the CLI;
- route every web write through the daemon control socket;
- validate, diff, confirm, audit and roll back every configuration change;
- audit operational actions and journal them where applicable;
- keep the web process unprivileged and loopback-only.

In the target model, the daemon is the only component that mutates host state
while it is running. Offline CLI teardown/repair (`vrouter down`,
`vrouter doctor --repair`) is the explicit exception. The web process never opens netlink, writes the
journal or edits the config file directly.

### Baseline decisions

- Cover all configuration objects and live-daemon operational actions; stage
  high-risk actions. Offline teardown/repair remains CLI.
- Use a hybrid daemon-owned apply model: live operations where a proven runtime
  transaction exists, restart-required for structural changes.
- Keep one local administrator with an Argon2id password; no RBAC in this scope.
- Require validation, diff, confirmation, audit and rollback for every
  configuration write; operational actions are audited and journaled where
  applicable.
- Put firewall changes and daemon lifecycle in phase 2; journal repair stays an
  offline CLI operation.

## 2. Goals and non-goals

### Goals

1. **Full configuration coverage.** Ports, bridges, interfaces/SVIs, routes,
   NAT, DHCP, DNS, firewall, logging and advanced settings are visible and
   editable from the web.
2. **Operational coverage.** Status, counters, leases, conntrack, journal,
   audit, validation, apply, rollback, link state and diagnostics are available
   from the web, plus stop/restart when a supervisor is configured. Starting a
   stopped daemon remains a service-manager/CLI action.
3. **One write path.** Web and CLI use the same versioned control API when the
   daemon is running. The daemon owns validation, journaling, apply and
   rollback.
4. **Safe writes.** Every configuration write is validated server-side, shown
   as a diff, explicitly confirmed, audited, and reversible. Operational
   actions are audited and journaled where applicable.
5. **Honest apply semantics.** Changes that can be applied live are applied
   live. Structural changes return `restart_required` with a clear maintenance
   warning; the web never pretends a restart happened.
6. **No privilege leak.** The web process stays unprivileged, loopback-only and
   unable to bypass the control socket.
7. **Testable.** Protocol, daemon apply/rollback, host mutations, web handlers,
   security negatives and browser flows are covered before release.

### Non-goals

- Multi-user accounts, RBAC, SSO, per-user permissions or delegated admin.
- Remote multi-router management, cloud control, telemetry or analytics.
- Built-in TLS termination or remote browser access. The web stays
  loopback-only; use an SSH tunnel. A TLS reverse proxy is a future deployment
  option and needs a separate trusted-proxy/public-origin contract.
- Arbitrary shell, file browser, raw netlink, packet capture or config-file
  upload.
- Android web UI. Android continues to use its native host UI over the C ABI.
- Live apply for every resource. Only operations with a proven transactional
  path are live in the first phases.
- Conntrack flush/kill, traffic shaping, dynamic routing or new protocol
  features.
- Multiple instances behind one web process. One web process talks to one
  control socket.

## 3. Current state and gap

### What exists

- `src/web/server.zig` serves server-rendered HTMX 4.0.0 pages and fragments
  with embedded assets, plus a small same-origin JSON API backed by the Unix
  control socket.
- The configuration API is read-only: `GET /api/status`, `GET /api/nat`,
  `GET /api/conntrack`. Login and logout are POSTs but do not mutate router
  configuration.
- Control protocol v2 supports `ping`, `status`, `nat.list`, `nat.apply` and
  `conntrack.list`. The parser is strict: a v2 daemon rejects v3 envelope
  fields as `invalid_request`.
- NAT is the only live configuration update (`ADR-014`). The CLI writes the
  config atomically, sends the complete NAT tables, and restores the file on a
  clear rejection. The daemon applies the tables but does not own the config
  file today.
- The daemon publishes a fixed read-only snapshot with status, counters, NAT
  and up to 256 conntrack entries.
- The daemon loads ports, bridges, interfaces, routes, DHCP, DNS and firewall
  from startup config. Those compiled structures have no live reload path.
- The CLI mutates addresses, links and routes directly through the journaled
  `Host` path. `bridge` is read-only. `nat` writes the config and calls the
  control socket. `dhcp status`, `dns query`, `firewall list/counters/test` are
  diagnostics.
- The control socket accepts root or the daemon effective uid; group-based
  authorization is not implemented. The socket is mode `0660`.
- The web process authenticates with one Argon2id password, server-side
  sessions, CSRF for logout, Host/Origin checks and a strict CSP. Sessions are
  invalidated on process restart.

### Gaps

1. **No read model for most resources.** The snapshot does not contain ports,
   bridges, interfaces, routes, DHCP config/leases, DNS config, firewall rules
   or journal/audit data.
2. **No general write API.** Only `nat.apply` exists. There is no config
   validate/diff/apply/rollback, no link/address/route write, no firewall write
   and no lifecycle operation.
3. **No single write path.** CLI address/route mutations bypass the daemon.
   Running them while `vrouterd` is live can race the datapath and the config.
4. **No live structural apply.** Ports, bridges, interfaces, routes, DHCP, DNS
   and firewall changes require a daemon restart today.
5. **No write authorization.** Read and write scopes are not distinct.
6. **No audit trail.** Host mutations are journaled, but there is no
   operator-facing audit log for web writes.
7. **Fixed response limits.** One request per connection, a 64 KiB request
   limit, a 128 KiB response limit, a 2 s server apply deadline, a 5 s client
   timeout and fixed snapshot caps are too small for full config (up to 4 MiB)
   and large tables.
8. **Unprivileged deployment is not wired.** The server accepts root or the
   daemon effective uid only; group authorization is absent. State-directory
   creation is inconsistent: the control server and `vrouter up` use `0750`
   without a group owner, while journal and firewall-counter paths create it
   `0700`. Whichever runs first wins, and a CLI mutation before the daemon can
   leave a `0700` directory that blocks the group deployment. There is no
   read-only socket, so the documented `sudo -u vrouter` deployment does not
   work yet.
9. **No config store.** The daemon receives only a parsed `Config`, not the
   path, raw bytes, revision or canonical serializer. `src/config/write.zig`
   only renders and saves NAT. A general read/diff/apply/rollback path has no
   durable object to operate on.
10. **No crash-consistent apply.** Writing the config, applying live state and
    journaling host changes are not coordinated by a pending transaction or
    startup recovery marker.
11. **Offload restart hazard.** A normal daemon exit leaves kernel-offload
    bridge/veth state in place; a restart-required offload change can fail
    preflight on the next start.

## 4. Scope

### 4.1 Resource coverage

Phases are defined in §8. "Live" means no daemon restart; "restart" means the
daemon writes the config, returns `restart_required`, and the service manager
restarts it after confirmation.

| Area | Read | Write | Apply | Phase |
|---|---|---|---|---|
| Dashboard, status, counters | Instance, version, uptime, ports, counters, health | — | — | P0 |
| Ports | List/detail, link state, config, counters | Create/edit/delete, MTU, PVID, tagged VLANs, storm control | Link up/down live; structural restart | P0 read; P1 write |
| Bridges | List/detail, members, SVI count, STP/VLAN/offload | Create/edit/delete, member ports, STP, VLAN-aware, offload | Restart | P0 read; P1 write |
| Interfaces/SVIs | List/detail, addresses, bridge/port/VLAN, link state | Create/edit/delete, address add/remove, link up/down, VLAN | Address/link live where supported; membership/VLAN restart | P0 read; P1 write |
| Routes | List/detail, IPv4/IPv6, table/metric | Add/edit/delete | Live if the route transaction is implemented; otherwise restart | P0 read; P1 write |
| NAT | Masquerade and port forwards | Add/edit/delete | Live (existing) | P0 read; P1 write |
| DHCP | Server config, pool, options, reservations, leases | Server/reservation CRUD; lease actions if supported | Restart for config; lease actions live in P2 | P0 read; P1 config write; P2 lease actions |
| DNS | Upstreams, cache, listen, zones, query test | Config CRUD; diagnostic query | Restart for config; query live in P2 | P0 read; P1 config write; P2 query |
| Firewall | Defaults, rp_filter, rate limits, ordered rules, counters, test probe | Rule/default/rate CRUD, reorder | Restart in P2; live firewall apply is future work | P0 read; P2 write |
| Logging/advanced | Log level/format, instance, lease DB path | Edit | Restart; instance/lease DB need extra confirmation | P0 read; P2 write |
| Conntrack | Paginated/filterable table | — | — | P0 |
| Journal | Health, bounded entries, malformed tail | — (repair is offline CLI) | Offline CLI; `doctor.status` live | P0 read; P2 repair guidance |
| Lifecycle | Daemon status, config revision, restart-required state | Validate, diff, apply, rollback; stop/restart while connected | Daemon/service manager; start is CLI/service manager | P0 read; P1 apply; P2 lifecycle |
| Audit | Append-only write history, filters | — | — | P0 read; P1 write |
| Config | Raw JSON view, revision, diff | Apply/rollback only; no raw write editor | Daemon | P0 read; P1 apply/rollback |
| System | Paths, socket, build/version, uptime, session | — | — | P0 |

Notes:

- The web never calls the raw `nat.apply` operation. It uses `config.apply` so
  NAT changes get revision checks, diff, confirm and audit. `nat.apply` stays
  for CLI compatibility.
- `link.set` is operational and journal-backed; it is not written to the config
  and does not survive a daemon restart. Address and route writes are
  config-backed.
- The web cannot start a stopped daemon because it cannot reach a stopped
  control socket. `start` remains the service manager or `vrouter up`.
- Typed forms edit a complete config document round-tripped from `config.get`;
  fields outside the form are preserved by the daemon's typed serializer.
- The schema is strict, so unknown keys are rejected by validation rather than
  silently preserved.

### 4.2 Operational actions

- `config.validate`: parse and validate a proposed complete config.
- `config.diff`: return a unified diff, affected resources and
  `restart_required`.
- `config.apply`: two-phase commit of the config, live changes, journaled host
  changes and audit entry; returns a transaction id.
- `config.rollback`: restore a retained committed config snapshot through the
  same revision/confirm/idempotency transaction as `config.apply`; it is not a
  raw file restore and does not bypass diff/audit.
- `link.set`: link up/down; operational, journal-backed, not config-backed.
- `iface.addr.add` / `iface.addr.del`: config-backed address changes; CLI
  compatibility wrappers that build a complete proposed config and run the
  same transaction.
- `route.add` / `route.del`: config-backed route changes when safe; same
  wrapper and transaction rules.
- `nat.apply`: existing live NAT transaction, retained for CLI compatibility;
  the web uses `config.apply`.
- `firewall.test`: dry-run probe (read-only diagnostic).
- `dns.query`: diagnostic query (P2).
- `journal.list` / `doctor.status`: read-only diagnostics (P1).
- `journal.repair`: **not a live control operation.** Repair mutates the journal
  while the daemon is stopped, so the UI shows the exact offline command
  (`vrouter down` then `vrouter doctor --repair`) instead of pretending it can
  perform the repair through a socket that no longer exists. This is an
  explicit exception to the "all operations from the web" goal.
- `daemon.stop` / `daemon.restart`: lifecycle (P2, only while connected and
  only when a supervisor is configured; otherwise `restart_unavailable`). The
  web cannot start a stopped daemon.

### 4.3 Explicitly excluded

- Raw config editing in the browser. The web may display JSON and a diff, but
  writes go through typed forms or a validated proposed config.
- Arbitrary file paths for config or lease DB. Advanced paths are validated and
  restricted to configured locations.
- Direct web access to the control socket, journal, netlink or config files.
- Deleting active conntrack entries.
- Hot-plugging physical devices or creating arbitrary kernel links beyond the
  configured port kinds.
- Multi-instance discovery or switching.
- Backup/restore archives, packet capture, metrics export, alerting.
- Journal repair through the web. Repair is an offline CLI operation because it
  requires the daemon to be stopped and the control socket to be absent.

## 5. Architecture

### 5.1 Principles

1. **Daemon is the only mutator while it is running.** Web sends intent; the
   daemon validates, applies and journals. Offline CLI teardown/repair is the
   explicit exception.
2. **Config is the durable source of truth.** Runtime state is compiled from it
   and published read-only.
3. **No duplicate logic.** Validation, diffing, apply and rollback live in the
   daemon/core, not in the web layer.
4. **No new source of truth.** The web stores only session state.
5. **Journal before host mutation.** Existing `Host` semantics remain.
6. **Immutable runtime snapshots.** The data plane never takes a lock per
   packet; live updates swap compiled structures between packet batches.
7. **No silent fallback.** Missing capability, permission, supervisor or
   backend returns a typed error with an actionable message.

### 5.2 Control protocol v3

The architecture in this section is the baseline for the scope. §10 lists only
implementation details that remain open.

Protocol v3 extends the line-delimited JSON protocol additively. A v3 server
accepts v2 read operations and v2 `nat.apply`. New write operations require v3.

Compatibility is explicit:

- `status` gains `protocol_version`, `config_revision`, `restart_pending`,
  `config_writable` and `restart_supported`.
- The client checks `protocol_version` from `status` before enabling writes.
  If it is below 3, write controls are disabled; the client does not send a v3
  envelope and does not silently fall back.
- A v3 server treats an absent `version` as v2. V3-only fields are rejected
  when `version` is absent or less than 3.
- The current v2 parser rejects unknown fields. That is why the client must
  negotiate before sending a v3 envelope; a v2 daemon will answer
  `invalid_request`, not a typed version error.
- Existing v2 `nat.apply` remains supported for the CLI. The web uses
  `config.apply` so NAT changes get revision, diff, confirm and audit.

Request envelope:

```json
{
  "version": 3,
  "id": 42,
  "op": "config.apply",
  "instance": "travel-router",
  "revision": "sha256:...",
  "confirm": "one-time-token",
  "idempotency_key": "uuid",
  "config": { "...": "complete proposed config" }
}
```

- `instance` must match the daemon.
- `revision` is the config revision the client read. A stale revision is
  rejected with `stale_revision`; the client must re-read and re-diff.
- `confirm` is a short-lived token returned by `config.diff` and bound to the
  revision and diff hash. It prevents replay and accidental apply.
- `idempotency_key` is scoped to the instance and operation, retained for a
  bounded window. A retry with the same key returns the original result; a
  different payload with the same key returns `idempotency_conflict`.
- The daemon derives the actor from peer credentials, never from a
  client-supplied user field.

Response envelope:

```json
{
  "ok": true,
  "id": 42,
  "op": "config.apply",
  "revision": "sha256:...",
  "transaction": "uuid",
  "result": "applied",
  "restart_required": false,
  "affected": ["nat"],
  "audit_id": "..."
}
```

- Every response echoes `id` and `op`.
- Errors return `ok:false`, a stable `error_code` and a short `message`.
- `config.diff` returns `diff`, `affected`, `restart_required`, warnings and a
  one-time `confirm` token.
- List operations return `data`, `total`, `returned` and `next_cursor`.
- `config.apply` returns `result` (`applied`, `restart_required`,
  `rolled_back`) and a `transaction` id.
- `daemon.restart` returns a `restart_token` and a `restart_supported` flag.

Frame limits:

- Status, list and diagnostic operations keep the current 64 KiB request and
  128 KiB response limits.
- `config.get`, `config.validate`, `config.diff`, `config.apply` and
  `config.rollback` use a config-sized frame: 16 MiB request and response,
  four times the 4 MiB config limit to cover serialization, escaping and diff
  overhead.
- Config operations use a 30 s server deadline and a 35 s client timeout.
- The daemon preflights the config size and returns `too_large` with an
  actionable message instead of truncating. Chunked transfer is not part of P1.

Read operations:

| Operation | Result |
|---|---|
| `config.get` | Raw config, revision, hash, source path, writable flag |
| `ports.list` | Port config, device state, counters, validation warnings |
| `bridges.list` | Bridge config, members, SVI count, warnings |
| `interfaces.list` | Interface config, addresses, link state |
| `routes.list` | Routes with family, table, metric, ownership |
| `nat.list` | Existing NAT tables |
| `dhcp.list` | Server configs and reservations |
| `dhcp.leases` | Paginated leases, filters |
| `dns.list` | Upstreams, cache, listen, zones |
| `firewall.list` | Defaults, rate limits, ordered rules |
| `firewall.counters` | Persisted and live counters |
| `journal.list` | Bounded tail, health, malformed suffix |
| `audit.list` | Bounded audit tail, filters |
| `conntrack.list` | Existing, plus cursor pagination |
| `doctor.status` | Journal/config/socket/runtime health |

Write operations:

| Operation | Notes |
|---|---|
| `config.validate` | No mutation; returns typed errors/warnings |
| `config.diff` | No mutation; returns diff, affected resources, restart flag, confirm token |
| `config.apply` | Requires revision + confirm + idempotency key; two-phase commit; live apply or restart-required |
| `config.rollback` | Restores a retained committed config snapshot |
| `link.set` | Up/down; live; journal-backed, not config-backed |
| `iface.addr.add` / `iface.addr.del` | Config-backed; live only with a runtime transaction |
| `route.add` / `route.del` | Config-backed; live only where safe |
| `nat.apply` | Existing complete-table transaction; CLI compatibility, not used by the web |
| `firewall.test` | Read-only probe |
| `dns.query` | Read-only diagnostic |
| `journal.repair` | **Not exposed.** Repair is an offline CLI operation while the daemon is stopped |
| `daemon.stop` / `daemon.restart` | P2; requires a supervisor and a live connection |

`config.validate`, `config.diff`, `firewall.test` and `dns.query` do not
mutate state and may be exposed on the read-only socket. `config.apply`,
`config.rollback`, `link.set`, address/route writes and lifecycle operations
require the read/write socket.

Error codes are stable and mapped to UI messages. V2 codes remain valid:

`invalid_request`, `invalid_argument`, `validation_failed`,
`stale_revision`, `confirm_required`, `confirm_expired`, `busy`,
`unauthorized`, `read_only`, `not_found`, `conflict`, `restart_required`,
`restart_unavailable`, `unsupported`, `timeout`, `outcome_unknown`,
`internal`, `unknown_op`, `instance_mismatch`, `server_stopped`, `too_large`,
`config_not_writable`, `permission_denied`, `version_unsupported`,
`daemon_running`, `restart_pending`, `idempotency_conflict`.

### 5.3 Write transaction

1. Web reads `config.get` and the relevant resource list.
2. The user edits a typed form. The form produces a complete proposed config
   from the round-tripped document; fields outside the form are preserved by
   the daemon's typed serializer.
3. Web calls `config.validate`; field errors are shown inline.
4. Web calls `config.diff`; the daemon returns:
   - unified JSON diff;
   - affected resources;
   - `restart_required` and the reason;
   - warnings;
   - a one-time confirm token bound to the revision and diff hash.
5. The user reviews the diff and confirms. Destructive or high-risk changes
   require typing the resource name.
6. Web calls `config.apply` with revision, confirm token and idempotency key.
7. The daemon takes the shared config lock and serializes the apply. It then:
   - validates the complete config again;
   - computes a resource-level plan from the diff;
   - stages `config.pending` with the new bytes, previous revision,
     transaction id and diff hash, and fsyncs it;
   - journals host changes before netlink calls;
   - applies live resources transactionally through the datapath;
   - on success, atomically replaces the config, clears `config.pending`,
     writes the audit entry and returns `applied`;
   - on failure, reverses live changes with the journal, removes
     `config.pending`, keeps the previous config and returns the error;
   - if the plan contains restart-required resources, commits the config,
     writes a `restart.pending` marker and returns `restart_required`.
8. Web shows the result, transaction id and audit link. The UI never reports
   success before the daemon acknowledges.

`config.apply` is all-or-nothing for live resources. If any live resource
fails, every live change from that transaction is reversed and the previous
config remains. Restart-required resources are not applied live; they are
listed in `affected` with `restart_required:true`. The daemon never applies part
of a plan and then reports plain success.

Crash recovery:

- On startup, a leftover `config.pending` is resolved by comparing the live
  config hash with the pending record's new hash. If they match, the
  transaction committed: keep the new config and clear the marker. Otherwise
  restore the previous config, replay the journal inverse for that transaction
  and record a recovery audit entry.
- A committed config with a `restart.pending` marker stays in place. The daemon
  reports `restart_pending` until a successful start clears it.
- The offload host state is reconciled on clean exit or startup before the new
  plan is applied, so a restart-required bridge/offload change cannot fail
  preflight against stale kernel objects.

Locks:

- `config.lock` is the shared advisory lock for every config writer, including
  the CLI and the daemon.
- The daemon additionally serializes control applies through its single
  write-queue.
- The existing `control.sock.lock` remains the one-daemon-per-state-dir lock.
  It is not a config writer lock.

Rollback:

- The daemon retains the previous committed config plus a bounded transaction
  history (default 10) under the state directory, mode `0600`.
- `config.rollback` restores the previous committed snapshot by default and may
  select a retained transaction id.
- A rollback that requires restart is surfaced as such. The audit log records
  both the original apply and the rollback.

### 5.4 Single write path and CLI

When `vrouterd` is running, CLI write commands use the control API instead of
mutating the host directly. The direct `Host` path remains for:

- `vrouter down` and `vrouter doctor --repair` when the daemon is stopped;
- offload setup inside the daemon at startup and teardown;
- bootstrap paths that run before the control socket exists.

`vrouter up` only starts/checks the daemon; it is not a `Host` bootstrap path.
This removes the current race between CLI address/route edits and the live
datapath. The CLI keeps its existing output and exit-code contract; only the
transport changes.

NAT is the current exception: the CLI writes the config file and then calls
`nat.apply`, while the daemon only applies the tables. The target is for the
daemon to own the config write for NAT too, so CLI and web share one
transaction. Until that migration lands, `vrouter nat` remains the documented
exception and the web must not use raw `nat.apply`.

### 5.5 Authorization and scopes

The control socket is the security boundary. The web service account is a
member of the read/write group; read-only deployments use a separate socket.

Baseline implementation:

- `control.sock` — mode `0660`, group `vrouter-admin`, read/write.
- `control-ro.sock` — mode `0660`, group `vrouter`, read-only.
- Both sockets use the same protocol; the server rejects write ops on the
  read-only socket with `read_only`.
- Peer credentials (`SO_PEERCRED`) identify the uid/pid. The daemon records
  them in the audit entry.
- The web process does not accept a client-supplied actor identity.

This satisfies ADR-011's requirement that read and write capabilities are
distinct. The exact group names are deployment configuration; the daemon must
fail closed if the groups cannot be applied.

Current deployment gaps that must be closed first:

- The peer check is uid-only. It must accept the configured write/read gids,
  including supplementary groups where supported, and reject everyone else.
- The state directory is created `0750` without a group owner. It must be
  group-owned and traversable by the socket group.
- `vrouterweb` needs `--control-ro` (or equivalent) and a startup check that
  refuses write mode when the socket is read-only.
- Tests must cover the actual `vrouterd`/`vrouterweb` uid/gid split, not just
  unit-level peer checks.

Until group authorization lands in P1, only root or the daemon uid can read the
socket. P0 read-only UI testing uses that path; it is not yet the documented
unprivileged deployment.

The web stays loopback-only. Remote access uses an SSH tunnel. A TLS reverse
proxy is not part of this scope; supporting one later requires a public-origin
allowlist, trusted-proxy handling and a `Secure` cookie contract.

### 5.6 Config ownership

The daemon needs a `ConfigStore` that owns the config path, raw bytes, revision,
canonical serializer and atomic writer. `vrouterd` currently discards the path
after parsing and `src/config/write.zig` only handles NAT; this store is a
prerequisite, not an implementation detail.

- The daemon owns the config path and writes it atomically.
- The web never opens the config file.
- Writes preserve the existing mode, reject symlinks, take `config.lock` and
  fsync before replace.
- If the daemon cannot write the config path, `config.apply` fails with
  `config_not_writable` or `permission_denied` and an actionable message.
- `instance` rename and `lease_db` path changes are advanced operations with
  extra confirmation and restart requirements. They are not phase 1.
- The in-memory config is updated after a successful live apply so subsequent
  reads and diffs see the new NAT and resource state.

### 5.7 Read model and pagination

The existing fixed snapshot stays for dashboard status. Resource reads are
serialized on demand from daemon-owned config and live tables, so adding a
resource does not require another fixed-size array.

The control server currently reads one fixed snapshot under a mutex and has a
special queue only for `nat.apply`. P0 adds a bounded read-command path (a
request queue or per-resource immutable snapshots) so on-demand serialization
does not block the datapath or allocate without limit.

- `conntrack.list`, `dhcp.leases`, `journal.list` and `audit.list` support
  `limit`, `cursor` and filters.
- Responses include `total`, `returned` and `next_cursor`.
- The server enforces a maximum response size and returns `too_large` with a
  pagination hint instead of truncating silently.
- Journal and audit reads are bounded tails, not full-file dumps.
- Read operations never mutate state.

### 5.8 Restart orchestration

Structural changes require a restart. The web must not call `systemctl` and the
unprivileged process must not signal the daemon arbitrarily.

- The daemon detects a supervisor through an explicit deployment setting and
  exposes `restart_supported` in `status`. It does not guess from PID 1.
- The supervisor contract (requested stop/restart versus crash) is deployment
  configuration. If the unit cannot distinguish them, `daemon.stop` and
  `daemon.restart` return `restart_unavailable` and the UI gives the exact
  service-manager command.
- If a supervisor is configured, `config.apply` returns `restart_required` with
  a restart token. `daemon.restart` asks the daemon to exit cleanly; the
  supervisor restarts it. The web waits for the control socket to return and
  re-authenticates the session if needed.
- `daemon.stop` is a separate operation. It also requires a supervisor and a
  live connection; it does not imply a subsequent start.
- If no supervisor is configured, `daemon.restart` returns
  `restart_unavailable` and the UI shows the exact CLI command.
- The web cannot start a stopped daemon. Start remains the service manager or
  `vrouter up`.
- The daemon never reports `applied` for a change that is only durable but not
  live.
- On clean exit for a restart, the daemon tears down or reconciles offload host
  state before exiting. Startup reconciles it again before applying a new plan.
- The UI shows a persistent "restart required" banner with the affected
  resources and a maintenance warning.

### 5.9 Audit and rollback

Every write creates an append-only audit entry under the state directory:

```json
{
  "ts_ms": 0,
  "transaction": "uuid",
  "request_id": "uuid",
  "actor": {"uid": 0, "pid": 0},
  "op": "config.apply",
  "instance": "travel-router",
  "revision_before": "sha256:...",
  "revision_after": "sha256:...",
  "affected": ["routes", "nat"],
  "restart_required": false,
  "result": "applied"
}
```

- The daemon audit actor is derived from peer credentials. The web records its
  own session id in its audit log and correlates by `request_id`; a
  client-supplied session id is not treated as verified identity.
- No passwords, session tokens, packet payloads or secret values.
- Rotation: size-capped JSONL with a small retained history; exact retention is
  a deployment setting.
- Audit is a local operational trail, not tamper-proof against local root and
  not a remote immutable log.
- Journal entries remain the host rollback mechanism. Config snapshots are the
  config rollback mechanism.

### 5.10 Implementation prerequisites

These are not optional polish; the scope cannot be implemented without them:

1. **Config store.** Path, raw bytes, revision, canonical serializer, atomic
   writer, shared lock, previous snapshot and transaction history.
2. **Always-available `Host`.** The daemon only opens `Host` for kernel offload
   today. Live address/route/link writes need a journaled host path and a state
   directory even when offload is off.
3. **Runtime update APIs.** The forwarder compiles local addresses, FIB and
   ports at startup. Live address/route/link operations need transactional
   add/remove/refresh APIs, or those resources must be explicitly
   restart-required.
4. **General read-command path.** A bounded queue or immutable per-resource
   snapshots; the current fixed snapshot and NAT-only queue are insufficient.
5. **Group authorization and deployment.** Read/write gids, state-dir/socket
   ownership, `vrouterweb --control-ro`, supervisor detection and tests.
6. **Transaction artifacts.** Diff format (canonical JSON text or RFC 6902),
   revision hash input, confirm-token store/TTL, idempotency store, audit store,
   pagination cursors, config snapshot retention and size preflight.
7. **Offload restart reconciliation.** Clean exit and startup must reconcile
   kernel bridge/veth state before a new plan is applied.
8. **Governance and docs.** An ADR for protocol v3/config apply, an ADR-011
   amendment for the group split and loopback-only/SSH-only transport,
   `PLAN.md` R10 re-baseline (including its stale LAN-bind/TLS/HTTPS exit),
   `CORE-SCOPE.md` §9 and JSON schema updates, plus `README.md`/`AGENTS.md`
   alignment for the HTMX preview.

## 6. UX scope

### Navigation

Dashboard, Ports, Bridges, Interfaces, Routes, NAT, DHCP, DNS, Firewall,
Connections, Journal, Audit, System.

### Page pattern

Each resource page has:

- a header with primary action and refresh;
- filters/search where the table can grow;
- a dense table with semantic status badges;
- a detail sheet with config, runtime state and validation warnings;
- create/edit forms with inline validation;
- empty, loading, error and permission-denied states;
- links to related resources and audit entries.

### Write workflow

1. Edit.
2. Validate.
3. Review diff and affected resources.
4. Confirm, with typed confirmation for destructive/high-risk changes.
5. Apply.
6. See result: applied, restart required, rejected or rolled back.
7. Open audit entry or roll back.

The UI never optimistically shows a write as applied. Buttons disable while a
transaction is pending; repeated submits use an idempotency key.

Typed forms operate on the full config document returned by `config.get`. They
change only the fields they own and submit the complete proposed config; the
daemon preserves all other fields through its typed serializer. There is no raw
config write editor in P1.

### Cross-cutting UX

- Persistent config revision and daemon health in the shell.
- Stale-revision conflict dialog with "reload and re-diff".
- Restart-required banner with affected resources.
- Error messages map stable daemon codes to actionable text.
- Mobile: tables become cards; primary actions remain reachable.
- Keyboard navigation, visible focus, labelled controls and adequate contrast.
- Dark mode remains.
- `script-src` remains `self`-only; no inline scripts. The current policy still
  allows inline styles, which is acceptable until the UI no longer needs them.

## 7. Security

Existing controls remain: loopback bind, Host/Origin validation, Argon2id,
server-side sessions, HttpOnly/SameSite=Strict cookies, per-session CSRF, login
rate limiting, `script-src 'self'` CSP, `nosniff`, `DENY` framing and
`no-store`. The current CSP also allows inline styles; that is not a script
execution path and can be tightened later.

Additional requirements:

- Every write requires a valid session and CSRF token; logout is not the only
  CSRF-protected action.
- Write endpoints reject wrong methods, content types, oversized bodies and
  unknown fields.
- `config.apply` requires a fresh confirm token bound to revision and diff.
- Replayed or stale confirms fail closed.
- The read-only socket cannot execute writes.
- The web process runs as a dedicated unprivileged account in the read/write
  group only when writes are enabled.
- Session fixation is prevented by rotating the session id on login.
- Login rate limiting remains global and gains a per-account backoff. Per-IP
  limiting is not meaningful on a loopback-only listener and is not in scope.
  Audit records failures without passwords.
- Config paths are not user-controlled; symlinks are rejected.
- Server-side HTML escaping remains mandatory; no raw control-plane strings
  are written into templates.
- The listener stays loopback-only. Remote access is an SSH tunnel, not a
  browser-facing reverse proxy. A future TLS proxy needs a separate
  public-origin/trusted-proxy contract and a `Secure` cookie mode.
- No secrets in logs or audit entries.

Threat checklist:

| Threat | Mitigation |
|---|---|
| Unauthorized write | Read/write socket split, peer credentials, session auth |
| CSRF | Per-session token on every write, Origin/Host checks |
| Replay | One-time confirm token, revision binding, idempotency key |
| Stale overwrite | Revision check, `stale_revision`, re-diff |
| Path traversal | Asset allowlist, no file browser, fixed config path |
| Symlink config swap | `O_NOFOLLOW`/symlink rejection, atomic replace |
| XSS | Server-side HTML escaping, CSP, no inline scripts |
| Session theft | HttpOnly, SameSite=Strict, short TTL, `Secure` when TLS is added |
| Brute force | Rate limit, per-account backoff, audit, constant-time check |
| Privilege leak | Web has no netlink/journal/config access |
| Partial apply | Two-phase apply, journal inverse, config snapshot rollback |
| Stale offload state | Clean-exit teardown and startup reconciliation |

## 8. Delivery phases

| Phase | Scope | Exit |
|---|---|---|
| P0 — Read model and protocol | `ConfigStore`, protocol v3 envelope, read ops, on-demand serialization, pagination, config revision, audit scaffolding, read-only UI pages for all resources | Every resource is visible; no writes |
| P1 — Safe CRUD | Config validate/diff/apply/rollback; two-phase apply; live NAT and link state; address/route live only where a runtime transaction is implemented, otherwise restart-required; typed forms; diff/confirm; audit; rollback; group auth/deployment; CLI uses the control API when the daemon is running | Operator can perform safe live changes without SSH; restart-required changes are staged and show the exact restart command; every write is audited and reversible |
| P2 — High-risk operations | Firewall CRUD/reorder, DHCP lease actions, DNS query, logging/advanced settings, journal repair guidance, daemon stop/restart with supervisor | Full live coverage including high-risk actions, with extra confirmation and maintenance UX; offline repair remains CLI |
| P3 — Hardening and release | systemd unit, packaging, SSH-tunnel docs, full Playwright/security suite, fuzz/soak, operator docs | CI green, security negatives pass, docs complete |

Indicative effort: 6–8 engineering weeks for one engineer, excluding Android
and unrelated release work. This re-baselines R10: the existing 2–3 week
estimate did not include protocol v3, a config store, two-phase apply, write
authorization, audit, full CRUD, lifecycle or the deployment plumbing.
`PLAN.md` R10 is updated after this scope is approved, not silently
reinterpreted.

## 9. Testing and acceptance

### Test matrix

- **Protocol unit tests:** parse/serialize v2 and v3, version negotiation,
  v2-daemon rejection behavior, unknown ops, pagination, error codes,
  revision/confirm/idempotency binding, config-sized frames.
- **Daemon integration:** validate/diff/apply/rollback, atomic config write,
  journal inverse, restart-required, stale revision, concurrent apply,
  idempotent retry, crash recovery, pending/committed markers, audit entries.
- **Netns:** ports, bridges, VLANs, interfaces, routes, NAT, DHCP, DNS,
  firewall; reuse `scripts/test_netns.sh`, `test_route.sh`, `test_vlan.sh`,
  `test_offload.sh`, `nat_matrix.sh`, `test_firewall.sh`, `test_dhcp.sh`,
  `test_dns.sh`, `test_tun.sh`, `test_ipv6.sh`, `test_journal.sh`,
  `test_crash.sh`.
- **Deployment:** `vrouterd`/`vrouterweb` uid/gid split, state-dir and socket
  ownership, read-only socket rejection, supervisor detection.
- **Web handlers:** auth, session rotation, CSRF on every write, Origin/Host,
  method/content-type/body limits, path traversal, read-only socket.
- **Playwright:** login, every page, create/edit/delete, diff/confirm,
  validation errors, stale revision, rollback, restart-required banner, audit,
  mobile and dark mode. Playwright runs through the `webapp-testing` skill; it
  is not a runtime or build dependency and no Node build is required.
- **Security negatives:** unauthorized write, read-only write, CSRF, session
  fixation, brute force, XSS, symlink config, oversized request, replayed
  confirm, idempotency conflict.
- **Performance:** apply latency, large config diff, paginated tables, no
  packet-path regression. `scripts/perf.sh` is referenced by `AGENTS.md` but is
  absent; add it or define an equivalent before/after measurement.

### Acceptance criteria

1. Every resource has the read/write coverage described in §4.1; anything not
   covered is explicitly listed as excluded.
2. Every write goes through the daemon control API; the web has no direct host,
   journal or config access.
3. Every configuration write is validated, diffed, confirmed, audited and
   reversible; operational actions are audited and journal-backed where
   applicable.
4. Structural changes return `restart_required`; the UI never claims they are
   live.
5. Read and write scopes are distinct; a read-only deployment cannot write.
6. CLI and web do not race when the daemon is running.
7. The daemon owns the config path, revision and two-phase apply; a crash
   between stage and commit recovers without leaving a half-applied config.
8. Offload host state survives a clean restart or is reconciled before the new
   plan is applied.
9. V2 clients retain read and `nat.apply` compatibility; v3 writes fail
   explicitly on a v2 daemon.
10. `zig build test`, web tests, netns scripts and Playwright security flows
    pass.
11. `docs/WEB.md`, `docs/PLAN.md` R10, ADR-011, ADR-014, `CHANGELOG.md` and
    `README.md` reflect the final behavior.

## 10. Risks and open decisions

| Risk | Impact | Mitigation |
|---|---|---|
| Missing config store | Cannot implement get/diff/apply/rollback | Build `ConfigStore` first; treat as P0 prerequisite |
| Missing group auth/deployment | Unprivileged web cannot connect or write | Gid checks, socket/state-dir ownership, read-only socket, deployment tests |
| CLI/daemon dual write race | Config and runtime diverge | Move CLI writes onto the control API when the daemon is live |
| Live apply scope creep | Complexity and packet-path risk | NAT and link state live in P1; address/route only with a runtime transaction; everything else restart |
| Crash between stage and commit | Half-applied config | Pending/committed markers, journal inverse, startup recovery |
| Offload restart hazard | Restart fails on stale kernel objects | Clean-exit teardown and startup reconciliation |
| Config file permissions | Apply fails in production | Preflight writability; `config_not_writable`; document ownership |
| Firewall ordering/rollback | Traffic outage | Ordered rules, diff preview, typed confirmation, restart in P2 |
| Audit is local | Root can tamper | State it plainly; optional remote log is out of scope |
| Journal repair cannot be live | Web cannot complete an offline repair | Live `doctor.status`; UI gives the exact offline command |
| Fixed protocol limits | Large config/table failures | Config-sized frames, pagination, `too_large` preflight |
| Session loss on restart | Operator re-login | Expected; show maintenance state and re-auth |
| No RBAC | Single admin only | Explicit non-goal; document deployment boundary |
| Estimate drift | Scope and schedule diverge | Re-baseline PLAN R10 after approval; no silent reinterpretation |
| Testing burden | Security regressions | Security negatives, deployment tests and Playwright are release gates |

Open implementation details (not baseline decisions):

1. **Diff format:** canonical JSON text (recommended for readable review) or
   RFC 6902 JSON Patch; machine-readable affected resources are returned either
   way.
2. **Audit retention:** size-capped JSONL, default 10 MiB × 5 files
   (recommended).
3. **Config snapshot retention:** previous committed config plus the last 10
   transaction snapshots (recommended).
4. **Advanced settings:** instance rename and `lease_db` path in P2 with extra
   confirmation (recommended); keep them CLI-only if the risk is unacceptable.
5. **Idempotency window:** 10 minutes per instance/operation (recommended).
6. **Supervisor detection and contract:** explicit daemon setting or
   environment variable (recommended) rather than guessing from PID 1; the
   unit must distinguish requested stop/restart from a crash or lifecycle
   returns `restart_unavailable`.
7. **Target release:** keep this as post-v1 R10 (recommended), not 0.2.0.
8. **Future remote access:** a TLS reverse proxy contract is out of scope now;
   define it separately if remote browser access becomes a requirement.

## 11. References

- [ADR-006 — Config journal](adr/006-config-journal.md)
- [ADR-009 — Kernel bridge offload](adr/009-kernel-bridge-offload.md)
- [ADR-011 — Optional local web admin](adr/011-web-admin.md)
- [ADR-014 — Config-backed live NAT updates](adr/014-live-nat-updates.md)
- [WEB.md — current preview](WEB.md)
- [PLAN.md — R10](PLAN.md)
- [CORE-SCOPE.md — config and control socket](CORE-SCOPE.md)
- [ARCHITECTURE.md — control plane](ARCHITECTURE.md)
