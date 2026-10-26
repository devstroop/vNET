# Web admin preview

`vnetweb` is an opt-in web frontend for a running Linux vNET.
It is a post-v1 preview of ADR-011, not part of the default 0.2.0 build and not
yet a replacement for the CLI.

The adapter is unprivileged and has no direct netlink, journal or config-file
access; link changes, DNS probes, lease revokes and lifecycle requests are
requests to the daemon. It renders server-side HTML with HTMX fragments and
exposes a small JSON API, all backed by the existing Unix control socket.
Reads use v2/v3 list ops; writes
are staged drafts that are diffed and applied by the daemon through
`config.diff`/`config.apply`, never by direct host mutation.

## Architecture

- `src/web/server.zig` — HTTP server, form auth, pages, fragments and JSON API.
- `src/web/pages.zig` — server-rendered pages and HTMX fragments for NAT/DHCP/DNS.
- `src/web/operations.zig` — interfaces, clients, routes, firewall, diagnostics,
  logs and config views plus shared staged-form helpers.
- `src/web/html.zig` — escaping and layout helpers.
- `src/web/assets/` — vendored HTMX 4.0.0 (0BSD), CSS and progressive-
  enhancement JavaScript, embedded with `@embedFile`.
- `src/web/auth.zig` — Argon2id password verification, sessions, CSRF.
- `exec/vnetweb/main.zig` — loopback-only process and CLI flags.
- `src/control/` — the existing Unix-socket control client used by the server.

There is no frontend build step, Node runtime, package manager, CDN or runtime
asset directory. `zig build web` builds only the `vnetweb` executable.

## Build

```bash
zig build web
./zig-out/bin/vnetweb --help
```

The default `zig build` does not install `vnetweb`.

## Create an admin password

The password is stored as an Argon2id PHC string. Keep the file mode `0600`.

```bash
printf '%s\n' 'replace-me-with-a-long-password' \
  | ./zig-out/bin/vnetweb --hash-password \
  > /tmp/web-password
chmod 600 /tmp/web-password
```

The password is read from stdin without echo suppression; avoid leaving shell
history that contains it.

## Run

```bash
sudo -u vnet \
  ./zig-out/bin/vnetweb \
    --listen 127.0.0.1:8080 \
    --control /run/vnet/control.sock \
    --password-hash-file /tmp/web-password
```

Options:

| Flag | Default | Meaning |
|---|---|---|
| `--listen` | `127.0.0.1:8080` | Loopback address only. |
| `--control` | `$VNET_RUN_DIR/control.sock` | Existing control socket. |
| `--password-hash-file` | `/etc/vnet/web-password` | Argon2id PHC file. |
| `--session-ttl-hours` | `12` | Session lifetime, 1–168 hours. |
| `--hash-password` | — | Read a password from stdin and print a PHC hash. |

Restart-required saves return a one-time token. To let the web restart
or stop the daemon locally, start it with `--enable-restart`:

```bash
./zig-out/bin/vnetd -c /etc/vnet/vnet.json --enable-restart
```

Restart performs a clean teardown and re-exec; stop exits and expects the
supervisor to start it again. This option is not a service manager. `vnet
up` passes it automatically when it launches the daemon. Without it,
`restart_supported` is false, restart prints the exact `systemctl restart
vnetd` command, and the stop control is disabled.

## Pages and fragments

The browser loads a full page once, then HTMX refreshes only the live region:

| Path | Kind | Purpose |
|---|---|---|
| `/login` | page | Password form; sets the session cookie. |
| `/overview` | page | Ports, uptime, forwarding, drops, conntrack and NAT counters. |
| `/nat` | page | Masquerade and port-forward rules. |
| `/connections` | page | Up to 200 active flows with state and text filters. |
| `/audit` | page | Up to 200 audit records with result and text filters. |
| `/journal` | page | Up to 200 journal records with valid/malformed and text filters. |
| `/system` | page | Runtime identity, paths, restart-required banner and supervised stop. |
| `/dhcp` | page | DHCP servers, pools and reservations. |
| `/dns` | page | Resolver settings and split-DNS zones. |
| `/interfaces` | page | Ports, bridges and interfaces/SVIs with staged CRUD. |
| `/clients` | page | DHCP leases, kernel neighbours and static reservations. |
| `/clients/lease` | action | Forgets a DHCP lease after typed address confirmation. |
| `/routes` | page | IPv4/IPv6 routes with staged add/edit/remove. |
| `/firewall` | page | Defaults, rp_filter, rate limits and ordered rules. |
| `/diagnostics` | page | Kernel links, addresses, neighbours and daemon health. |
| `/logs` | page | Bounded daemon log tail (48 KiB) with line/size metadata. |
| `/config` | page | Revision/source/writability, logging editor and running JSON. |
| `/restart` | action | Accepts a one-time restart token from a restart-required apply. |
| `/stop` | action | Stops vnetd after typed `stop` confirmation and a supervisor check. |
| `/nat/rules` | action | Stages NAT masquerade/port-forward drafts. |
| `/nat/review` | action | Diffs the staged NAT draft. |
| `/nat/apply` | action | Applies the staged NAT draft and live NAT. |
| `/dhcp/rules` | action | Stages DHCP servers, pools and reservations. |
| `/dhcp/review` | action | Diffs the staged DHCP draft. |
| `/dhcp/apply` | action | Applies the staged DHCP draft. |
| `/dns/query` | action | Sends a read-only A/AAAA diagnostic query through the daemon. |
| `/dns/rules` | action | Stages resolver and split-DNS changes. |
| `/dns/review` | action | Diffs the staged DNS draft. |
| `/dns/apply` | action | Applies the staged DNS draft. |
| `/interfaces/link` | action | Journals and changes kernel link state after typed confirmation. |
| `/interfaces/rules` | action | Stages port, bridge and interface drafts. |
| `/interfaces/review` | action | Diffs the staged interfaces draft. |
| `/interfaces/apply` | action | Applies the staged interfaces draft. |
| `/routes/rules` | action | Stages route add/edit/remove. |
| `/routes/review` | action | Diffs the staged route draft. |
| `/routes/apply` | action | Applies the staged route draft. |
| `/firewall/rules` | action | Stages rule, default-policy and rate-limit edits. |
| `/firewall/review` | action | Diffs the staged firewall draft. |
| `/firewall/apply` | action | Applies the staged firewall draft. |
| `/config/logging` | action | Diffs a staged log level/format change. |
| `/config/apply` | action | Applies the staged logging change. |
| `/partials/status` | fragment | Overview live region (5 s refresh). |
| `/partials/nat` | fragment | NAT live region (10 s refresh). |
| `/partials/conntrack` | fragment | Connections live region (5 s refresh). |
| `/partials/audit` | fragment | Audit live region (10 s refresh). |
| `/partials/journal` | fragment | Journal live region (10 s refresh). |
| `/partials/system` | fragment | System live region (10 s refresh). |
| `/partials/interfaces` | fragment | Discard target for the staged interfaces draft. |
| `/partials/clients` | fragment | Clients live region (10 s refresh). |
| `/partials/routes` | fragment | Discard target for the staged routes draft. |
| `/partials/firewall` | fragment | Discard target for the staged firewall draft. |
| `/partials/diagnostics` | fragment | Diagnostics live region (10 s refresh). |
| `/partials/logs` | fragment | Logs live region (10 s refresh). |
| `/healthz` | text | Unauthenticated liveness check. |

The connections form sends `state` and `q` to `/partials/conntrack`; the live
region includes the same form values so auto-refresh preserves the filter. The
audit form sends `result` and `q`; the journal form sends `state` and `q`. Both
read bounded state-directory tails through v3 `audit.list` and `journal.list`.
HTMX 4.0.0 uses explicit `hx-target`/`hx-swap` on every request; the preview
does not rely on attribute inheritance.

## JSON API

The same-origin JSON endpoints remain available for compatibility and tests.
They are not used by the HTML pages.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/healthz` | no | Plain-text liveness check. |
| `GET` | `/api/session` | no | `{authenticated, csrf?}`. |
| `POST` | `/api/login` | no | `{password}`; sets the session cookie. |
| `POST` | `/api/logout` | yes + CSRF | `{csrf}`; clears the session. |
| `GET` | `/api/status` | yes | Instance, version, uptime, ports, counters. |
| `GET` | `/api/nat` | yes | Masquerade and port-forward rules. |
| `GET` | `/api/conntrack` | yes | Up to 100 active flows. |
| `GET` | `/api/network` | yes | Kernel links, addresses and neighbours. |
| `GET` | `/api/clients` | yes | DHCP leases (up to 512). |
| `GET` | `/api/firewall` | yes | Firewall counters. |
| `GET` | `/api/logs` | yes | Bounded daemon log tail. |
| `GET` | `/api/config` | yes | Running config, revision, source path and writability. |

## Security model

- Binds loopback only and refuses any non-loopback listen address.
- Validates the `Host` header against the configured loopback address,
  `localhost` or `127.0.0.1`/`::1` at the same port, which blocks DNS-rebinding
  reads.
- Requires an Argon2id password and a server-side session. Session tokens are
  random, HttpOnly, `SameSite=Strict`, and invalidated on process restart.
- Rejects cross-origin POSTs by comparing `Origin` with the validated `Host`.
  Some local browser contexts report `Origin: null` for same-document form
  posts; that case is accepted only after the loopback `Host` check and with
  `SameSite=Strict` session cookies.
- Requires a per-session CSRF token for logout; login is protected by
  `SameSite=Strict` and the origin check.
- Login attempts are rate-limited after five failures.
- Sends a strict CSP (`script-src 'self'`, no inline scripts), `nosniff`,
  `DENY` framing and `no-store` caching.
- Escapes every control-plane value written into HTML. Templates never
  concatenate raw daemon strings.
- Writes are staged: hidden page drafts feed `config.diff`, then only a
  confirmed `config.apply` mutates the config. The web process has no direct
  netlink, journal or config-file access, and all mutations are audited by the
  daemon. Restart-required changes never report plain success. A rejected
  staging request leaves the draft unchanged.

This preview speaks plain HTTP. It must not be exposed beyond loopback without a
TLS-terminating reverse proxy; the cookie does not set `Secure`.

## Tests

```bash
zig build web-test
zig build web
```

The Zig suite covers Argon2id verification, session expiry/eviction, CSRF token
issuance, loopback checks, embedded assets, form/query decoding, HTML escaping,
connection filters and page helpers. Playwright flows use the
`webapp-testing` skill and are not a runtime or build dependency.

The full read/write scope, including protocol v3 and crash-consistent config
apply, is in [WEB-SCOPE.md](WEB-SCOPE.md) and
[ADR-015](adr/015-control-protocol-v3.md). The preview covers staged edits for
interfaces, routes, firewall, NAT, DHCP, DNS and logging; conntrack and journal
remain read-only.
