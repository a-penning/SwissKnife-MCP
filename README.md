# SwissKnife MCP

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D22-43853d.svg)](.nvmrc)
[![CI](https://github.com/a-penning/SwissKnife-MCP/actions/workflows/ci.yml/badge.svg)](https://github.com/a-penning/SwissKnife-MCP/actions/workflows/ci.yml)

A self-hostable **HTTP MCP server of deterministic developer utilities** — base64, JWT, hashing, timestamps, UUIDs, data-format conversion and friends. Connect it to any MCP client and stop pasting your tokens into random utility websites: the LLM does the job exactly, with zero guesswork.

> **Status: v0.1.0** — 18 tools implemented, covered by per-tool vector tests and a cross-tool conformance suite. Not published to npm or any registry, by design.

## Features

- 🔢 **Encode / decode** — base64, base64url, base32, hex, URL, HTML entities, unicode escapes, number bases, gzip/deflate/brotli
- 🔐 **Hashing** — MD5, SHA-1/2/3, BLAKE2, CRC32, and HMAC variants
- 🔏 **Crypto** — AEAD (AES-GCM, ChaCha20-Poly1305), RSA-OAEP, sign/verify (Ed25519 / ECDSA / RSA-PSS), key generation (raw + OpenPGP), KDFs (Argon2id, scrypt, PBKDF2, HKDF), ECDH, PEM ↔ DER ↔ JWK, inspect
- 🎫 **JWT** — decode, verify (HMAC / RSA / EC / EdDSA / JWKS), sign
- 🆔 **Identifiers** — UUID v4/v5/v7, ULID, Nano ID, random strings, passwords
- ⏰ **Time** — unix ↔ ISO conversion, timezones, date math, cron explanation + next runs
- 🔄 **Data formats** — JSON ↔ YAML ↔ TOML ↔ XML ↔ CSV, pretty-print, minify
- ✏️ **Text utilities** — case conversion, slugify, sort/dedupe lines, counts, normalize, trim, escaping
- 🔍 **Regex** — match / replace / split with capture groups
- 🔣 **Numbers** — bytes ↔ human sizes, durations, roman numerals, locale formatting
- 🗂️ **JSON query** — JSONPath extraction and filtering with normalized paths
- 📑 **Diff** — text diff (lines / words / chars)
- 🌐 **HTTP** — probe endpoints and call APIs: status, headers, timing, parsed JSON
- 🌍 **DNS** — A/AAAA/MX/TXT/CNAME/NS/SOA/SRV/CAA lookups + reverse PTR
- 🧮 **Network** — IPv4/IPv6 parse & classify, CIDR math, containment
- 🔎 **Inspect** — URL decomposition, X.509/PEM certificates, live TLS chains, WHOIS (domain / IP / ASN)
- 🎨 **Color** — hex / rgb / hsl / hwb / named conversion + WCAG contrast
- 🧰 **Script** — a sandboxed JS environment that composes every other tool in one call

All packed into **18 tools** so your MCP client's tool list stays clean. Every tool is a pure, deterministic function — same input, same output, explicit errors. The exceptions are the network-facing ones whose job *is* to observe live state (`http`, `dns`, `inspect`'s `tls` / `whois` modes, `jwt` verifying via a JWKS URL), and the document-shaped tools that touch the network only when the caller opts in by passing `inputUrl` (`convert-data`, `diff` (`aUrl`/`bUrl`), `encode`, `hash`, `json-query`, `text`, `regex`, and `jwt` — which can fetch the token to inspect). Everything else is pure-compute.

## Quickstart

```bash
# From a local checkout (not published yet)
npm ci && npm run build
npx .                         # serves http://localhost:12345/mcp

# Or via tarball — the real npx experience
npm pack && npx ./swissknife-mcp-*.tgz

# Docker
docker compose up -d
```

`GET /` shows a tool index, `GET /healthz` is the liveness probe. Flags/env: `--port`/`PORT`, `--host`/`HOST`, `LOG_LEVEL=silent|info` (logs method + tool name + duration only — never argument values), `SWISSKNIFE_BLOCK_PRIVATE_NETWORKS=1` (SSRF guard: refuse `http`/`inputUrl`/`jwt` JWKS/`inspect` TLS+WHOIS/`dns` resolver/RDAP traffic that resolves to loopback/private/link-local addresses — leave off when probing localhost), `SWISSKNIFE_ALLOWED_HOSTS`/`SWISSKNIFE_ALLOWED_ORIGINS` (comma-separated `Host`/`Origin` allow-lists for `POST /mcp` — DNS-rebinding & browser-CSRF defense; loopback is always allowed, set your public hostname when serving behind a proxy), `SWISSKNIFE_RATE_LIMIT` (per-IP requests/minute on `POST /mcp`, default 300, `0` disables), `SWISSKNIFE_MAX_CONCURRENT_VM` (cap on simultaneous `script`/`regex` runs, default 4). See [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) for the full table.

Then point your MCP client at it. Clients that support the **HTTP** transport (Claude Code, Cursor, …) connect directly:

```json
{
  "mcpServers": {
    "swissknife": { "type": "http", "url": "http://localhost:12345/mcp" }
  }
}
```

If your client only supports the **stdio** transport (e.g. Claude Desktop via `claude_desktop_config.json`), bridge it with the [`mcp-remote`](https://www.npmjs.com/package/mcp-remote) proxy instead:

```json
{
  "mcpServers": {
    "swissknife": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "http://localhost:12345/mcp"]
    }
  }
}
```

See [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md#client-configuration) for config-file locations and per-transport notes.

> ⚠️ **No authentication.** `docker compose up -d` publishes to `127.0.0.1` by default, but `docker run -p 12345:12345 swissknife-mcp` (no host prefix) exposes every tool — including the `http` / `dns` / `inspect` outbound primitives — to anything that can reach the port. Keep it bound to `127.0.0.1` (`-p 127.0.0.1:12345:12345`) and behind a proxy/VPN. Two built-in backstops: `POST /mcp` rejects unexpected `Host`/`Origin` (DNS-rebinding/CSRF — set `SWISSKNIFE_ALLOWED_HOSTS` for your real hostname), and `SWISSKNIFE_BLOCK_PRIVATE_NETWORKS=1` stops the server probing your internal network. See [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) for the full hosting checklist.

## Using it with an LLM

[`docs/AGENT-INSTRUCTIONS.md`](docs/AGENT-INSTRUCTIONS.md) is a short operating manual for any agent that has SwissKnife wired up — when to reach for it over Bash or inline JS, how to use the `script` tool for chained work, and a few gotchas worth knowing. **Paste it into your personal `CLAUDE.md` / `AGENTS.md` / equivalent system-prompt file** so the model has it on every turn. It's deliberately small (a couple of hundred tokens) and doesn't duplicate the per-tool descriptions the MCP client already loads.

## Documentation

- [`docs/AGENT-INSTRUCTIONS.md`](docs/AGENT-INSTRUCTIONS.md) — short operating manual for LLM agents (include in your `CLAUDE.md` / `AGENTS.md`)
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — transport, server core, codebase layout
- [`docs/TOOLS.md`](docs/TOOLS.md) — conventions for authoring tools (naming, descriptions, input/output shape, errors). For the live list of tools and their schemas, read `src/tools/*.ts` or call `tools/list` on a running server.
- [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) — Docker, npx, hosting, client configuration
- [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) — local setup, testing, adding a tool
- [`docs/TESTING-STRATEGY.md`](docs/TESTING-STRATEGY.md) — how we test (read before writing tests)

## Contributing & security

- Contributing guide: [CONTRIBUTING.md](CONTRIBUTING.md) (run `npm run verify`, ship a test, don't bump the version)
- Reporting vulnerabilities: [SECURITY.md](SECURITY.md) — please use private disclosure, not a public issue
- Community standards: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

## License

MIT — see [LICENSE](LICENSE).
