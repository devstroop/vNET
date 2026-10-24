# Web admin preview

`vrouterweb` is an opt-in, read-only web frontend for a running Linux vRouter.
It is a post-v1 preview of ADR-011, not part of the default 0.2.0 build and not
yet a replacement for the CLI.

The adapter is unprivileged and has no netlink, journal or config access. It
serves a React/shadcn single-page app and exposes a small JSON API backed by the
existing Unix control socket (`status`, `nat.list`, `conntrack.list`). It never
mutates host state.

## Architecture

- `web/` — Vite + React + TypeScript + Tailwind CSS + shadcn UI.
- `src/web/server.zig` — JSON API, static asset serving, SPA fallback, auth.
- `src/web/auth.zig` — Argon2id password verification, sessions, CSRF.
- `exec/vrouterweb/main.zig` — loopback-only process and CLI flags.
- `src/control/` — the existing Unix-socket control client used by the API.

The Zig process serves the built SPA from `--assets` (default
`$VROUTER_WEB_ASSETS` or `zig-out/share/vrouter-web`). Client routes such as
`/overview`, `/nat`, `/connections` and `/system` fall back to `index.html`.

## Build

Requires Node.js 22+ and npm.

```bash
zig build web
./zig-out/bin/vrouterweb --help
```

`zig build web` runs `npm ci` and `npm run build` in `web/`, installs the
frontend into `zig-out/share/vrouter-web`, and builds `vrouterweb`. The default
`zig build` does not install `vrouterweb`.

For frontend-only work:

```bash
cd web
npm install
npm run dev
```

The Vite dev server listens on `127.0.0.1:5173` and proxies `/api` and
`/healthz` to `127.0.0.1:8080`. The proxy rewrites `Origin` to the backend
origin so the same-origin login check behaves the same as production.

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
    --password-hash-file /tmp/web-password \
    --assets /usr/share/vrouter-web
```

Options:

| Flag | Default | Meaning |
|---|---|---|
| `--listen` | `127.0.0.1:8080` | Loopback address only. |
| `--control` | `$VROUTER_RUN_DIR/control.sock` | Existing control socket. |
| `--password-hash-file` | `/etc/vrouter/web-password` | Argon2id PHC file. |
| `--assets` | `$VROUTER_WEB_ASSETS` or `zig-out/share/vrouter-web` | Built SPA directory. |
| `--session-ttl-hours` | `12` | Session lifetime, 1–168 hours. |
| `--hash-password` | — | Read a password from stdin and print a PHC hash. |

## API

All endpoints are same-origin, `no-store`, and return JSON unless noted.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/healthz` | no | Plain-text liveness check. |
| `GET` | `/api/session` | no | `{authenticated, csrf?}`. |
| `POST` | `/api/login` | no | `{password}`; sets the session cookie. |
| `POST` | `/api/logout` | yes + CSRF | `{csrf}`; clears the session. |
| `GET` | `/api/status` | yes | Instance, version, uptime, ports, counters. |
| `GET` | `/api/nat` | yes | Masquerade and port-forward rules. |
| `GET` | `/api/conntrack` | yes | Up to 100 active flows. |

The SPA calls these endpoints through `web/src/api/client.ts`. A `401` triggers
the login screen; the browser never talks to the control socket directly.

## Security model

- Binds loopback only and refuses any non-loopback listen address.
- Validates the `Host` header against the configured loopback address,
  `localhost` or `127.0.0.1`/`::1` at the same port, which blocks DNS-rebinding
  reads.
- Requires an Argon2id password and a server-side session. Session tokens are
  random, HttpOnly, `SameSite=Strict`, and invalidated on process restart.
- Rejects cross-origin POSTs by comparing `Origin` with the validated `Host`.
- Requires a per-session CSRF token for logout; login is protected by
  `SameSite=Strict` and the origin check.
- Login attempts are rate-limited after five failures.
- Sends a strict CSP (`script-src 'self'`, no inline scripts), `nosniff`,
  `DENY` framing and `no-store` caching.
- React escapes values rendered from the API; no HTML is constructed from
  control-plane strings.
- Read-only: there are no write handlers and no direct host mutations.

This preview speaks plain HTTP. It must not be exposed beyond loopback without a
TLS-terminating reverse proxy; the cookie does not set `Secure`.

## Pages

- `/overview` — instance, version, uptime, port count, forwarding counters.
- `/nat` — masquerade and port-forward rules.
- `/connections` — up to 100 active flows, search and state filter.
- `/system` — runtime identity, paths and preview scope.
- `/healthz` — unauthenticated liveness check.

Ports, bridges, routes, DHCP leases, firewall rules and journal pages need new
read operations in the control protocol. They are not part of this preview.

## Tests

```bash
zig build web-test
cd web && npm run build && npm run lint
```

The Zig suite covers Argon2id verification, session expiry/eviction, CSRF token
issuance, loopback checks, asset-path traversal and content types. The frontend
build runs `tsc -b` before Vite. Browser/Playwright coverage for the full R10
scope (session fixation, rate limits and every page) is still required before
calling R10 complete.
