# Architecture

## Stack

| Concern | Choice | Rationale |
|---------|--------|-----------|
| Runtime | Node.js ≥ 22 (LTS) | native `fetch`, `node:crypto` covers most hashing/UUID needs |
| Language | TypeScript 6.x, `strict`, ESM only | |
| MCP SDK | `@modelcontextprotocol/sdk` | official SDK, Streamable HTTP transport |
| Schemas | `zod` | SDK-native input/output validation |
| HTTP framework | `express` 5 | what the SDK's `StreamableHTTPServerTransport` examples target; boring and fine |
| Build | `tsup` | single-command ESM bundle with shebang banner for the CLI |
| Test | `vitest` | fast, TS-native |
| Lint/format | `biome` | one tool instead of eslint+prettier |

## Transport

**HTTP only.** No stdio — this server is meant to run as a long-lived HTTP service (local or hosted) shared by all MCP clients.

```
 HTTP POST /mcp ──► StreamableHTTPServerTransport ──► McpServer ──► tools/registry ──► pure handlers
```

- `StreamableHTTPServerTransport` in **stateless mode** (`sessionIdGenerator: undefined`, `enableJsonResponse: true`). Every tool is a fast pure function, so there is no session state and no need for SSE streaming. Stateless mode means any replica can answer any request — horizontal scaling is free.
- A new `McpServer` + transport pair is created **per request** (the stateless pattern from the SDK docs) to avoid request-ID collisions between concurrent clients.

### Endpoints

| Route | Purpose |
|-------|---------|
| `POST /mcp` | MCP Streamable HTTP endpoint |
| `GET /healthz` | liveness — returns `{ status: "ok", version }` |
| `GET /` | tiny HTML index listing tools |
| `GET, DELETE /mcp` | `405` — stateless server, no session to resume/terminate |

No authentication, by design. If exposed publicly, put it behind a reverse proxy / VPN — see [DEPLOYMENT.md](DEPLOYMENT.md).

## Codebase layout

```
swissknife/
├── src/
│   ├── index.ts            # CLI entry: arg/env parsing (--port, PORT), starts HTTP server
│   ├── server.ts           # buildServer(): McpServer factory, registers all tools
│   ├── http.ts             # express app, stateless StreamableHTTPServerTransport, /healthz
│   ├── tools/
│   │   ├── registry.ts     # AUTO-GENERATED ToolDef[] — written by scripts/gen-registry.mjs
│   │   ├── types.ts        # ToolDef interface, shared err()/ok() result helpers
│   │   └── <tool>.ts       # one file per tool (encode, hash, jwt, dns, net, script, …)
│   └── lib/                # pure helpers shared by tools (radix, base32, pem/cert,
│                           #   color math, jsonpath, units, net, whois/rdap, ssrf, …)
├── scripts/
│   └── gen-registry.mjs   # scans src/tools/*.ts → writes src/tools/registry.ts
├── tests/
│   ├── tools/<tool>.test.ts # per-tool unit tests (independently-derived vectors)
│   ├── conformance.test.ts  # registry-driven cross-tool contract suite
│   └── integration.test.ts  # SDK client ↔ HTTP server round-trip
├── docs/
├── Dockerfile
├── docker-compose.yml
├── package.json            # bin: { "swissknife-mcp": "dist/index.js" }
├── tsconfig.json
├── biome.json
└── vitest.config.ts
```

Adding a tool is essentially one file in `src/tools/` — see
[DEVELOPMENT.md](DEVELOPMENT.md).

## Tool definition pattern

Every tool is one file exporting a `ToolDef`:

```ts
// src/tools/types.ts
import { z } from "zod";

export interface ToolDef<S extends z.ZodRawShape = z.ZodRawShape> {
  name: string;
  title: string;
  description: string;        // LLM-facing: when to use, what it guarantees
  inputSchema: S;
  handler: (args: z.objectOutputType<S, z.ZodTypeAny>) => ToolResult;
}
```

`server.ts` iterates `registry.ts` and calls `server.registerTool(...)` for each. **Adding a tool means adding one file in `src/tools/`** — `registry.ts` is auto-generated from a directory scan by `scripts/gen-registry.mjs`, which fires via `pre*` npm hooks before dev / build / test / lint / typecheck. A regular tool exports `<camel>Tool`; a factory tool exports `build<Camel>Tool(otherTools)` (used by `script` to compose every other tool). The generator picks both up by export shape; `tests/registry-sync.test.ts` fails if `registry.ts` is hand-edited. Handlers are **pure functions** wherever possible; the async ones earn it: the network-facing tools (`http`, `dns`, `inspect`'s `tls` / `whois` modes, `jwt` verify-via-JWKS), every tool that supports `inputUrl` for remote source (`convert-data`, `diff`, `encode`, `hash`, `json-query`, `text`, `regex`, `jwt` — `jwt` sits in both buckets: it verifies via a JWKS URL *and* can fetch the token via `inputUrl`), and the two that run user code in a worker (`script`'s QuickJS VM, `regex`'s `worker_thread`).

### Conventions

- **Discriminated operations.** Tools take an `action`/`format` enum rather than multiplying tool count. Zod `discriminatedUnion` where option sets differ per action.
- **Structured output.** Handlers return both human-readable `content` text and machine-readable `structuredContent` (with matching `outputSchema`) so clients can consume either.
- **Errors are values.** Invalid input → `{ isError: true }` tool result with a precise message ("invalid base64 at offset 17"), never a thrown exception leaking a stack trace, and never a silent best-effort result.
- **Binary-safe.** Tools that may handle binary accept/emit `base64` alongside `utf8` via an `inputEncoding`/`outputEncoding` parameter.
- **Remote inputs.** Document-shaped tools accept `inputUrl` (or `aUrl`/`bUrl`) as an explicit opt-in alternative to inline input, resolved by a shared `src/lib/input.ts` fetcher (GET, 10 s timeout, 5 MB cap). Network access never happens unless the caller passes a URL.

## Dependency budget

Keep the runtime dependency list short and auditable:

`@modelcontextprotocol/sdk`, `zod`, `express`, `jose` (JWT), `yaml`, `smol-toml`, `fast-xml-parser`, `papaparse` (CSV), `ulid`, `nanoid`, `cron-parser`, `diff`, `ipaddr.js` (IP/CIDR), `whoiser` (legacy WHOIS fallback), `quickjs-emscripten` (the `script` tool's sandbox), `undici` (the SSRF guard's pinned `fetch` dispatcher — see below).

Everything hashing/UUID/random comes from `node:crypto`; DNS uses `node:dns`. No lodash, no moment — timezone work uses `Intl` APIs. JSONPath (`lib/jsonpath.ts`), unit conversions (`lib/units.ts`), colour math, RDAP/WHOIS normalisation, and the SSRF guard are in-house rather than dependencies, same as base32/crc32/radix.

`undici` is the one fetch-adjacent dependency: it *is* Node's built-in `fetch`, but the module isn't importable directly, and the global `fetch` exposes no way to dial a pre-resolved IP while keeping the hostname for TLS. When `SWISSKNIFE_BLOCK_PRIVATE_NETWORKS` is on, `lib/ssrf.ts`'s `guardedFetch` routes through an undici `Agent` whose connector resolves, SSRF-screens, and dials in one step — closing the DNS-rebinding TOCTOU that a separate check-then-fetch leaves open. Guard off ⇒ plain global `fetch`, no undici on the path.
