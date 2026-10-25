# Web admin preview

`vrouterweb` is an opt-in, read-only web frontend for a running Linux vRouter.
It is a post-v1 preview of ADR-011, not part of the default 0.2.0 build and not
yet a replacement for the CLI.

The adapter is unprivileged and has no netlink, journal or config access. It
renders server-side HTML with HTMX fragments and exposes a small JSON API, all
backed by the existing Unix control socket (`status`, `nat.list`,
`conntrack.list`). It never mutates host state.

## Architecture

- `src/web/server.zig` — HTTP server, form auth, pages, fragments and JSON API.
- `src/web/pages.zig` — server-rendered pages and HTMX fragments.
- `src/web/html.zig` — escaping and layout helpers.
- `src/web/assets/` — vendored HTMX 4.0.0 (0BSD), CSS and progressive-
  enhancement JavaScript, embedded with `@embedFile`.
- `src/web/auth.zig` — Argon2id password verification, sessions, CSRF.
- `exec/vrouterweb/main.zig` — loopback-only process and CLI flags.
- `src/control/` — the existing Unix-socket control client used by the server.

There is no frontend build step, Node runtime, package manager, CDN or runtime
asset directory. `zig build web` builds only the `vrouterweb` executable.

## Build

```bash
zig build web
./zig-out/bin/vrouterweb --help
```

The default `zig build` does not install `vrouterweb`.

## Create an admin password

The password is stored as an Argon2id PHC string. Keep the file mode `0600`.

```bash
printf '%s\n' 'replace-me-with-a-long-password' \
  | ./zig-out/bin/vrouterweb --hash-password \
  > /tmp/web-password
chmod 600 /tmp/web-password
```

The password is read from stdin without echo suppression; avoid leaving shell
history that contains it.

## Run

```bash
sudo -u vrouter \
  ./zig-out/bin/vrouterweb \
    --listen 127.0.0.1:8080 \
    --control /run/vrouter/control.sock \
    --password-hash-file /tmp/web-password
```

Options:

| Flag | Default | Meaning |
|---|---|---|
| `--listen` | `127.0.0.1:8080` | Loopback address only. |
| `--control` | `$VROUTER_RUN_DIR/control.sock` | Existing control socket. |
| `--password-hash-file` | `/etc/vrouter/web-password` | Argon2id PHC file. |
| `--session-ttl-hours` | `12` | Session lifetime, 1–168 hours. |
| `--hash-password` | — | Read a password from stdin and print a PHC hash. |

## Pages and fragments

The browser loads a full page once, then HTMX refreshes only the live region:

| Path | Kind | Purpose |
|---|---|---|
| `/login` | page | Password form; sets the session cookie. |
| `/overview` | page | Ports, uptime, forwarding, drops, conntrack and NAT counters. |
| `/nat` | page | Masquerade and port-forward rules. |
| `/connections` | page | Up to 200 active flows with state and text filters. |
| `/system` | page | Runtime identity, paths and preview scope. |
| `/partials/status` | fragment | Overview live region (5 s refresh). |
| `/partials/nat` | fragment | NAT live region (10 s refresh). |
| `/partials/conntrack` | fragment | Connections live region (5 s refresh). |
| `/partials/system` | fragment | System live region (10 s refresh). |
| `/healthz` | text | Unauthenticated liveness check. |

The connections form sends `state` and `q` to `/partials/conntrack`; the live
region includes the same form values so auto-refresh preserves the filter.
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
- Read-only: there are no write handlers and no direct host mutations.

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
