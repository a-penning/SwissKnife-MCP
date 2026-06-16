# Deployment

HTTP only. The server listens on `PORT` (default `12345`); the MCP endpoint is `POST /mcp`, liveness at `GET /healthz`.

> ⚠️ **No authentication.** Run it on localhost, inside a private network, or behind a reverse proxy that handles auth. Do not expose the bare server to the internet.

## Configuration

| Env var / flag | Default | Purpose |
|----------------|---------|---------|
| `PORT` / `--port` | `12345` | listen port |
| `HOST` / `--host` | `127.0.0.1` | bind address (`0.0.0.0` in the Docker image) |
| `SWISSKNIFE_ALLOWED_HOSTS` | loopback only | Comma-separated hostnames accepted in the `Host` header (DNS-rebinding defense on `POST /mcp`). `localhost`/`127.0.0.1`/`::1` and the bind address are always allowed; add your public hostname here when serving behind a proxy. Matching is port-agnostic. |
| `SWISSKNIFE_ALLOWED_ORIGINS` | _(none)_ | Comma-separated `Origin` values accepted on `POST /mcp` (browser-CSRF defense). Requests with no `Origin` header (non-browser MCP clients) always pass; a browser request with a non-listed `Origin` is refused. |
| `SWISSKNIFE_RATE_LIMIT` | `300` | Per-IP requests/minute on `POST /mcp` (fixed window); `0` disables. `/healthz` and `/` are never limited. `req.ip` is the proxy's address unless Express `trust proxy` is set, so prefer a rate limit at the reverse proxy for shared hosting. |
| `SWISSKNIFE_MAX_CONCURRENT_VM` | `4` | Max simultaneous `script` (QuickJS VM) and `regex` (worker thread) runs; excess calls queue. Bounds worst-case memory/CPU from a burst of expensive calls. |
| `LOG_LEVEL` | `info` | `silent` \| `info` (requests logged to stderr — method + tool name + duration only, never argument values; `silent` suppresses the access log and the internal-error log) |
| `SWISSKNIFE_BLOCK_PRIVATE_NETWORKS` | _(off)_ | SSRF guard. When set, every outbound code path resolves the host first and refuses loopback/private/link-local/CGNAT addresses (e.g. `169.254.169.254`). Covers `http`, every `inputUrl` fetcher, `jwt` JWKS URLs (incl. cache refreshes), `inspect` kind `tls` (dials the pinned IP) and `whois` `whoisServer`, the `dns` `resolver` parameter, and the RDAP bootstrap + lookup chain (redirects are followed manually with per-hop revalidation, capped at 3 hops). Plain `http`/`inputUrl` redirects are not auto-followed at all. Leave **off** when the server's job includes probing localhost/LAN. |

## Docker (recommended)

Multi-stage `Dockerfile`:

1. **build stage** — `node:22-alpine`, `npm ci`, `npm run build`
2. **runtime stage** — `node:22-alpine`, copy `dist/` + production `node_modules`, run as non-root `node` user, `HEALTHCHECK` against `/healthz`, `EXPOSE 12345`

```bash
docker build -t swissknife-mcp .
docker run -d --name swissknife -p 12345:12345 swissknife-mcp
# or
docker compose up -d
```

`docker-compose.yml` keeps it to one service with a restart policy and the healthcheck. Suitable for a homelab box, a VPS behind Caddy/Traefik/nginx, or any container platform (Fly.io, Railway, ECS…) once you're ready to host it on the web.

## npx — without publishing

The package defines `bin: { "swissknife-mcp": "dist/index.js" }` but is **not published**. Options, best first:

1. **From the repo checkout**
   ```bash
   npm run build && npx . --port 12345
   ```
2. **Tarball** — closest simulation of the real npx experience:
   ```bash
   npm pack                      # → swissknife-mcp-<version>.tgz
   npx ./swissknife-mcp-*.tgz
   ```
3. **Global link** for day-to-day use on your own machine:
   ```bash
   npm link                      # then: swissknife-mcp --port 12345
   ```
4. **Git remote** (once pushed somewhere): `npx github:a-penning/SwissKnife-MCP` — needs a `prepare` script so the build runs on install.

When/if publishing later: it's `npm publish --access public` plus nothing else — the `bin`, `files`, and `prepare` fields are set up for it from day one.

## Client configuration

```json
// Claude Code (.mcp.json) / Claude Desktop — HTTP server
{
  "mcpServers": {
    "swissknife": {
      "type": "http",
      "url": "http://localhost:12345/mcp"
    }
  }
}
```

Or via CLI: `claude mcp add --transport http swissknife http://localhost:12345/mcp`

## Hosting on the web

- Terminate TLS at a reverse proxy (Caddy/Traefik/nginx) and proxy to the container.
- Add auth at the proxy if needed (basic auth, mTLS, IP allowlist) — the server itself stays auth-free by design.
- **Set `SWISSKNIFE_BLOCK_PRIVATE_NETWORKS=1`.** `http`, every `inputUrl` fetcher, `jwt` JWKS, `inspect` (TLS chain + WHOIS server override), the `dns` `resolver` parameter, and RDAP all make server-side outbound requests; a front proxy does nothing to stop them reaching internal addresses (cloud metadata, internal services). The guard refuses requests resolving to private/loopback/link-local ranges across every one of those paths. Don't enable it if probing your own localhost/LAN is the point.
- **Set `SWISSKNIFE_ALLOWED_HOSTS` to your public hostname.** `POST /mcp` rejects any other `Host` by default, which blocks DNS-rebinding (a foreign page resolving its own name to your bind address and POSTing to the server) and browser CSRF. Behind a proxy the server sees the proxied `Host`, so list it (e.g. `swissknife.example.com`). If browsers call it directly, also set `SWISSKNIFE_ALLOWED_ORIGINS`.
- Stateless transport ⇒ multiple replicas behind a load balancer need no sticky sessions.
- Set conservative proxy limits: request body ≤ 1 MB is plenty for every tool.
- **`trust proxy` is off by default**, so the per-IP rate limit and any IP logging see the *proxy's* address, not the client's. If you need per-client limits, also rate-limit at the proxy, or run the server with Express `trust proxy` configured to your hop count.
- **SSRF guard coverage gap:** the WHOIS *fallback* path (when no `whoisServer` override is given) lets the `whoiser` library open raw port-43 TCP to **registry-supplied** servers using its own DNS — those hosts come from whoiser's vetted bootstrap tables, not user input, and are *not* IP-pinned. A user-supplied `whoisServer` *is* resolved and pinned. RDAP (the preferred path) is fully guarded.
