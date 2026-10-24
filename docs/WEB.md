# Web admin preview

`vrouterweb` is an opt-in, read-only web frontend for a running Linux vRouter.
It is a post-v1 preview of ADR-011, not part of the default 0.2.0 build and not
yet a replacement for the CLI.

The adapter is unprivileged and has no netlink, journal or config access. Every
page is rendered from the existing Unix control socket (`status`, `nat.list`,
`conntrack.list`). It never mutates host state.

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
- Sends a strict CSP with no script sources, `nosniff`, `DENY` framing and
  `no-store` caching.
- Escapes every value rendered from the control socket.
- Read-only: there are no write handlers and no direct host mutations.

This preview speaks plain HTTP. It must not be exposed beyond loopback without a
TLS-terminating reverse proxy; the cookie does not set `Secure`.

## Pages

- `/` — instance, version, uptime, port count and forwarding counters.
- `/nat` — masquerade and port-forward rules.
- `/conntrack` — up to 100 active flows.
- `/healthz` — unauthenticated liveness check.

Ports, bridges, routes, DHCP leases, firewall rules and journal pages need new
read operations in the control protocol. They are not part of this preview.

## Tests

```bash
zig build web-test
```

The suite covers Argon2id verification, session expiry/eviction, form decoding,
HTML escaping, loopback address checks and CSRF token issuance. Browser/Playwright
coverage for the full R10 scope (session fixation, rate limits and every page) is
still required before calling R10 complete.
