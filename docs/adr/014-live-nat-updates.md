# ADR-014 — Config-backed live NAT updates

- **Status:** Accepted (R3)
- **Date:** 2026-10-24

## Context

R3 shipped NAT rules only at daemon start. Operators had to edit JSON, stop and
restart the daemon to add a masquerade or port forward, dropping conntrack state
and traffic. The control socket already published read-only NAT snapshots, but
had no write path and no way to keep the config file and the running datapath in
sync.

A write path has to answer three questions:

1. **Which state is authoritative?** The config file is the durable source of
   truth, but the datapath owns the compiled NAT tables.
2. **How does a one-shot CLI reach a single-threaded datapath safely?** The data
   plane must not take a lock per packet or observe a half-built ruleset.
3. **What happens when the daemon is absent or the apply fails?** Silently
   leaving the file and the datapath different is not acceptable.

## Decision

`vrouter nat add|del` is a **config-backed live update** for both masquerade and
port forwards (ADR-005).

### CLI transaction

1. Read and strictly parse and validate the current config.
2. Mutate only the `nat` object in memory. An idempotent add returns success
   without touching the file; a delete of an absent rule does the same. A
   conflicting port-forward key with a different target is an error rather than
   a silent overwrite.
3. Validate the complete resulting config.
4. If the control socket is absent (`FileNotFound`, `ConnectionRefused`), save
   the new config atomically and print a warning that the daemon is not running.
5. Otherwise check the daemon `status` instance, save the new config, and send
   `nat.apply` with the complete desired masquerade and port-forward arrays.
6. On a connect failure or a clear daemon rejection, restore the original
   config bytes atomically and exit non-zero. A transport timeout has an
   unknown outcome, so the CLI keeps the new file and tells the operator to
   check `vrouter nat list` instead of racing a rollback.

The writer (`src/config/write.zig`) rewrites the `nat` key in the parsed JSON
document instead of serializing the typed config. Unrelated keys and unknown
future keys survive the edit; formatting is normalized to two-space JSON. The
save is guarded by a per-config advisory lock, validated after rendering, and
replaced atomically with the existing file mode preserved.

### Control protocol

Protocol version 2 adds `nat.apply`:

```json
{"id":1,"op":"nat.apply","nat":{
  "instance":"travel-router",
  "masquerade":[{"out":"wan0"}],
  "port_forward":[{"proto":"tcp","ext_port":8080,"to":"10.10.0.5:80","ingress":null}]
}}
```

- The request carries the **complete** desired NAT tables, not a diff.
- The daemon checks the instance and resolves interface/port references against
  its immutable startup config.
- The control server copies the request into its queue and waits for the service
  loop to acknowledge it. There is one pending apply; a concurrent request gets
  `busy`. The request limit is 64 KiB so a full 64 SNAT + 128 forward ruleset
  fits.
- The service drains the queue before the next forwarding tick. It compiles new
  SNAT and forward arrays transactionally; any invalid reference, duplicate key
  or unresolvable masquerade leaves the old arrays and conntrack untouched. A
  successful apply swaps the arrays, publishes a new snapshot immediately, and
  returns `ok`.
- Errors are stable codes (`instance_mismatch`, `busy`, `invalid_argument`,
  `timeout`, `server_stopped`) with a short message.

### Datapath and conntrack

- No datapath lock is added. The control thread queues data; the single data
  loop performs the swap between packet batches.
- Existing conntrack entries keep their NAT translation and continue to flow
  until their normal timeout. Removing a rule affects **new** flows only; the
  CLI does not flush conntrack.
- Host state is not mutated, so live NAT updates create no journal entry.
  `vrouter down` restores host routes/addresses/links, while the config remains
  the durable NAT record.

### Checksum ordering

The same transaction exposed an ordering requirement. Forwarded IPv4 packets
are repaired once after the forwarding copy, before conntrack/NAT. NAT rewrites
then adjust TCP/UDP/ICMP checksums incrementally (RFC 1624) instead of scanning
the payload again. Egress and pending-flush paths no longer re-repair checksums.
ADR-007 is amended accordingly.

## Consequences

- A successful live update leaves the config file and datapath identical without
  a restart; a failed update restores the previous file and keeps the previous
  ruleset.
- Operators get idempotent add/delete behavior and an explicit conflict error
  for a reused public port.
- The config file may be reformatted on the first live edit. Comments are not
  supported by the config format and unknown keys are preserved.
- Only NAT is hot-applied. Routes, addresses, firewall rules and other compiled
  state still require a restart; full config diff/apply remains future work.
- If the datapath has not claimed a queued apply by the deadline, the server
  cancels it and returns `timeout`; the CLI can restore the config safely. Once
  claimed, the server waits for the swap to finish before replying, and the
  client allows more time than the server deadline. A transport-level timeout
  is still reported as an unknown outcome and deliberately keeps the new config
  for the operator to inspect rather than racing a rollback.
- The protocol version bump is additive for reads. An old v1 daemon rejects
  `nat.apply` as an unsupported operation, so the CLI restores the previous
  config rather than leaving the file ahead of the datapath.

## Alternatives

- **Restart the daemon on every rule change.** Simple, but drops all conntrack
  state, interrupts traffic and needs service-manager integration.
- **Mutate the datapath directly from the control thread.** Would require
  datapath locks or unsafe concurrent array swaps; violates the immutable
  snapshot rule.
- **Write the config and wait for a reload watcher.** Adds file-watching and
  does not provide synchronous success/failure or rollback to the CLI.
- **Use kernel nftables for live NAT.** Contradicts the pure-Zig data plane and
  the portable core; remains a future offload backend.
- **Full config diff/apply in R3.** Larger scope than NAT and unnecessary for the
  R3 exit criterion.
