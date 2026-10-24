# vRouter web admin

Read-only React frontend for `vrouterweb`. See `docs/WEB.md` for the full build,
run and security model.

## Development

```bash
npm install
npm run dev
```

Vite listens on `127.0.0.1:5173` and proxies `/api` and `/healthz` to
`127.0.0.1:8080`.

## Build

```bash
npm run build
```

`zig build web` runs this build and installs `dist/` into
`zig-out/share/vrouter-web`.
