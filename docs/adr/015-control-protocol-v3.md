# ADR-015 — Control protocol v3 and crash-consistent config apply

- **Status:** Proposed (R10, post-v1)
- **Date:** 2026-10-25
- **Related:** [ADR-006](006-config-journal.md), [ADR-011](011-web-admin.md),
  [ADR-014](014-live-nat-updates.md), [WEB-SCOPE](../WEB-SCOPE.md)

## Context

The v2 control protocol exposes `ping`, `status`, `nat.list`, `nat.apply` and
`conntrack.list`. It has one worker, one request per connection, a 64 KiB
request limit and a 128 KiB response limit. The daemon publishes one fixed
snapshot and the CLI still writes addresses, routes and NAT by editing the
config file directly.

A full web admin needs a config store, a general read/write API, revision and
confirmation checks, audit and crash recovery. Those additions create four
specific hazards that the scope must resolve before implementation:

1. A v3 server that adds fields to existing responses can break deployed v2
   clients whose JSON parser rejects unknown fields.
2. A 16 MiB config frame handled by the single worker can stall status,
   conntrack and NAT applies for the 30 s config deadline.
3. `transaction.pending` without a journal checkpoint cannot identify which
   host mutations to reverse after a crash.
4. Writing the config, journal and audit entry in separate files creates crash
   windows where a committed config has no audit entry or a stale pending
   marker survives.

This ADR fixes those decisions. It does not implement them; implementation is
gated by the phases in `WEB-SCOPE.md`.

## Decision

### 1. Version negotiation and v2 response compatibility

Protocol v3 is additive, but **response shape is request-versioned**:

- A request without `version` is a v2 request. A v3 server returns the exact
  v2 response shape for every v2 operation: no new fields in `status`, `nat` or
  `conntrack`, and no new top-level response fields.
- A request with `version: 3` may receive v3 fields. Existing objects may gain
  fields directly because a v3 client knows them.
- `config.get`, `config.validate`, `config.diff`, `config.apply`,
  `config.rollback`, `ports.list`, `bridges.list`, `interfaces.list`,
  `routes.list`, `dhcp.list`, `dhcp.leases`, `dns.list`, `firewall.list`,
  `firewall.counters`, `journal.list`, `audit.list` and `doctor.status` are
  v3-only operations. Sending them without `version: 3` returns
  `version_unsupported` from a v3 server; a v2 server returns
  `invalid_request`.
- A v2 server rejects a v3 envelope as `invalid_request`; the client must not
  retry a write as v2. To bootstrap, the client sends `status` with `version:3`;
  on `invalid_request` it retries that read as v2, learns the daemon is old,
  and disables writes.
- A v3 server treats `version` greater than 3 as `version_unsupported`.
- The v2 `nat.apply` operation and all v2 reads remain available. They keep
  their v2 response shapes and existing semantics.

This is deliberately stricter than “clients should ignore unknown fields”.
Deployed v2 clients use Zig's strict JSON parser, so ignoring unknown fields is
not a safe compatibility assumption.

### 2. Config store and revision

The daemon gains a `ConfigStore` that owns:

- the config path, opened without following symlinks;
- the exact on-disk bytes and their SHA-256 revision;
- a canonical serializer used for writes and diffs;
- the atomic writer, shared `config.lock`, previous committed snapshot and a
  bounded transaction history.

`revision` is `sha256:` plus the SHA-256 of the exact bytes the client read.
The daemon re-reads and verifies the current revision before accepting a diff
or apply. A canonical write produces a new revision from the new bytes. The
store fsyncs the file and its directory before replacing the config.

The web never opens the config path. The daemon writes it. If the path is not
writable, `config.apply` fails with `config_not_writable` or
`permission_denied`.

### 3. Transaction record and journal checkpoint

Every mutating transaction writes a single `transaction.pending` record before
the first host mutation. It is written atomically, fsynced, and contains at
least:

```json
{
  "kind": "config.apply",
  "transaction": "uuid",
  "state": "staged",
  "revision_before": "sha256:...",
  "revision_after": "sha256:...",
  "journal_checkpoint": 123,
  "journal_after": 130,
  "audit_id": "uuid",
  "audit_entry": { "...": "final audit fields without result" },
  "restart_required": false,
  "affected": ["nat"]
}
```

- `journal_checkpoint` is `journal.lineCount()` immediately before the first
  journal append for this transaction.
- `journal_after` is the line count after the last append. It is informational;
  rollback uses `downTo(journal_checkpoint)`, which reverses only records after
  the checkpoint and truncates them.
- `audit_entry` is the complete audit intent, excluding the final `result`.
  This makes audit completion recoverable without re-deriving the change.
- `kind` also covers operational transactions (`link.set`, `daemon.stop`,
  `daemon.restart`), which have no config revision but do have a journal
  checkpoint and audit intent.

The apply sequence is:

1. Acquire `config.lock` and the daemon write queue.
2. Re-read the config, validate the proposal and compute the plan.
3. Write `transaction.pending` in `staged` state; fsync it and the directory.
4. Journal each host mutation before applying it.
5. Apply live resources transactionally.
6. Atomically replace the config; fsync the file and directory.
7. Append the final audit entry; fsync the audit log.
8. Write `restart.pending` when required, then clear `transaction.pending`.
9. Return `applied`, `restart_required` or `rolled_back`.

If the live apply fails at step 5, reverse the journal to `journal_checkpoint`,
restore the previous config, append a `rolled_back` audit entry and clear the
pending record. The config remains `revision_before`.

### 4. Crash recovery

On startup, before loading the datapath:

- **Pending `staged`, config hash equals `revision_before`:** the transaction did
  not commit. Call `downTo(journal_checkpoint)`, keep the previous config,
  append a `rolled_back` audit entry with `recovered: true`, then clear the
  pending record.
- **Pending `staged`, config hash equals `revision_after`:** the config
  committed but the marker was not cleared. Keep the config and the journal
  entries after the checkpoint, append the audit entry with
  `recovered: true` if it is not already present, clear the pending record and
  preserve or create `restart.pending` when required.
- **Pending `committed`:** the config committed; ensure the audit entry exists,
  clear the pending record and preserve `restart.pending`.
- **Pending `rolled_back`:** reverse the journal to the checkpoint, keep
  `revision_before`, ensure the audit entry exists and clear the pending
  record.
- **Hash matches neither revision:** fail closed with `config_conflict` and
  require `vrouter doctor --repair`. Do not overwrite an externally changed
  config and do not start the datapath with an ambiguous pending record.

A committed config with `restart.pending` stays in place. The daemon reports
`restart_pending` until a successful start clears the marker.

### 5. Audit ordering

Audit is an append-only JSONL file under the state directory. The pending
record contains the audit intent, so audit completion is recoverable:

- Normal path: append the final entry after the config replace, fsync, then
  clear the pending record.
- Crash after config replace but before audit append: startup appends the entry
  from `audit_entry` with `result` set from the observed commit state and
  `recovered: true`.
- Crash after audit append but before clearing the pending record: startup
  scans the bounded audit tail for the transaction id. If present, it does not
  append a duplicate; it only clears the pending record.
- If the audit entry was rotated out before recovery, startup appends a
  recovery entry with the same transaction id and `recovered: true`. A rare
  duplicate is preferable to a missing write record.
- Operational transactions use the same pending/audit flow, with `kind`
  identifying the action and no config revision.

The audit entry is never written before the mutation it describes is durable.
The intent in the pending record is not treated as a completed audit entry.
`daemon.stop` and `daemon.restart` have no host mutation; their accepted-request
audit entry is written and fsynced before the daemon exits.

### 6. Config-sized frames and worker isolation

Config-sized frames must not run on the existing single worker:

- The existing worker keeps serving status, NAT, conntrack and v2 requests.
- A dedicated config worker (or a bounded worker pool) handles `config.get`,
  `config.validate`, `config.diff`, `config.apply` and `config.rollback` with
  the 16 MiB request/response limits and 30 s server deadline.
- `config.apply` and `config.rollback` are serialized by the daemon write
  queue. A second config write waits for a bounded period and then returns
  `busy`; it does not block the accept loop.
- `config.get` and `config.diff` are read-only and may run concurrently with
  status and conntrack, but only one may hold the config lock at a time.
- `nat.apply` remains on its existing queue. The config worker does not share
  the snapshot mutex for the duration of a 16 MiB read or write.
- The client keeps a 35 s timeout for config operations. Other operations keep
  their existing short timeouts.

Chunked transfer is still not part of P1. The daemon preflights config size and
returns `too_large` rather than truncating.

### 7. State directory and socket ownership

One canonical helper creates and validates the state directory. It never
creates a `0700` directory.

| Path | Mode | Owner:Group | Purpose |
|---|---|---|---|
| state dir | `0750` | `root:vrouter` | Traverse/list for the read-only and write web accounts |
| `control.sock` | `0660` | `root:vrouter-admin` | Read/write control |
| `control-ro.sock` | `0660` | `root:vrouter` | Read-only control |
| `*.lock` | `0600` | daemon | Lock files |
| `vrouter.json` | existing mode, default `0600` | daemon | Config |
| journal/audit/pending | `0600` | daemon | Transaction state |

Group membership:

- Read-only web account: `vrouter` only.
- Read/write web account: `vrouter` and `vrouter-admin`. It needs `vrouter` to
  traverse the state directory and open the read-only socket, and
  `vrouter-admin` to open the read/write socket.
- The daemon runs as root or with the capabilities needed for netlink; it owns
  the files.

If an existing state directory has the wrong owner or mode, startup fails with
`permission_denied` and an actionable message. Root may repair it explicitly;
the daemon does not silently `chmod` or `chown` an existing directory.

Group authorization and this ownership matrix are P1 gates. P0 read-only
testing may use root or the daemon uid, but the documented unprivileged
deployment is not complete until the P1 deployment tests pass.

### 8. Diff and confirmation coverage

Every configuration mutation follows the same validate → diff → confirm →
apply path:

| Operation | Validate | Diff | Confirm | Revision | Idempotency | Audit | Journal |
|---|---|---|---|---|---|---|---|
| `config.apply` | yes | yes | yes | yes | yes | yes | yes |
| `config.rollback` | target snapshot | current → target | yes | yes | yes | yes | yes |
| `iface.addr.add/del` | yes | yes | yes | yes | yes | yes | yes |
| `route.add/del` | yes | yes | yes | yes | yes | yes | yes |
| `link.set` | no config | no | typed target name | n/a | yes | yes | yes |
| `daemon.stop` | n/a | no | typed `stop` | n/a | yes | yes | n/a |
| `daemon.restart` | n/a | no | restart token | n/a | yes | yes | n/a |
| `firewall.test`, `dns.query` | n/a | no | no | n/a | n/a | no | n/a |
| `journal.repair` | not exposed | — | — | — | — | — | — |

- `config.diff` accepts either a complete proposed config or a rollback target
  (`target_revision` or `target_transaction`). The confirm token is bound to
  the current revision, the target/diff hash and the operation.
- `config.rollback` is not a raw file restore. It uses the same transaction,
  diff, confirm and audit path.
- `nat.apply` remains a v2 compatibility operation. It is not used by the web.
  After the P1 CLI migration, `vrouter nat` also uses `config.apply`; raw
  `nat.apply` remains only for already-deployed v2 clients.

### 9. Restart token and result semantics

`config.apply` and `config.rollback` return one of:

- `applied`: live resources applied and the config committed; no restart.
- `restart_required`: the config is committed durably, live state is unchanged,
  and `restart.pending` is set. This is not reported as `applied`.
- `rolled_back`: a live apply failed and was reversed; the config remains at
  `revision_before`; the response is `ok:false` with the original error code
  and the transaction/audit ids. For `config.rollback`, the pre-rollback config
  is retained, so the UI must not present it as a successful rollback.

A validation or precondition failure before mutation is `ok:false` with no
`result` (or `result:"rejected"` in v3); it creates no config or journal change.

Restart token rules:

- A `restart_required` response includes an opaque, one-time `restart_token`
  only when `restart_supported` is true. It is bound to the transaction id,
  `revision_after`, the daemon boot id and a short TTL.
- `daemon.restart` requires the current token. A missing, expired, superseded
  or wrong-boot token returns `confirm_required`, `confirm_expired` or
  `restart_pending` as appropriate.
- Only one restart token is outstanding. A new `config.apply` or
  `config.rollback` invalidates the previous token and replaces
  `restart.pending` with the latest transaction.
- A successful daemon start clears `restart.pending` and invalidates all
  tokens. A failed start leaves the marker and requires `doctor --repair`.
- If `restart_supported` is false, the response still says `restart_required`
  but has no token; the UI shows the exact service-manager command.
- `daemon.stop` does not use a restart token; it uses typed confirmation.

## Consequences

- Deployed v2 clients keep working without a parser change.
- A config apply can take up to 30 s without blocking status or conntrack.
- Crash recovery has one authoritative pending record and one journal
  checkpoint per transaction.
- A committed config always has an audit entry after recovery, even if the
  process died between the config replace and the audit append.
- The daemon gains a config worker, a pending/audit store and a canonical
  serializer. These are real implementation work, not documentation-only
  changes.
- The state directory layout becomes a deployment contract. Existing `0700`
  directories must be repaired explicitly.
- The v2 `nat.apply` compatibility path remains until the P1 CLI migration and
  can outlive the web preview.

## Alternatives

- **Add fields to all responses and require clients to ignore unknown fields:**
  rejected. Existing Zig clients parse strictly.
- **Read 16 MiB on the single worker:** rejected. It stalls status, conntrack
  and NAT for the duration of the config operation.
- **Use `transaction.pending` without a journal checkpoint:** rejected. Recovery
  cannot distinguish transaction journal entries from earlier user changes.
- **Write audit before the config replace:** rejected. A crash would leave an
  audit record for a change that never committed.
- **Write audit after clearing pending:** rejected. A crash loses the only
  record that the audit is owed.
- **Store config revision as a timestamp or generation counter:** rejected.
  A content hash is what the client read and can verify.
- **Use a separate database for transactions:** rejected for P1. A single
  fsynced JSON record plus the existing journal is sufficient and inspectable
  offline.
