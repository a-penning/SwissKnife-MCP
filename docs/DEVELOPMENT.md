# Development

## Prerequisites

- Node.js ≥ 22 (use the version in `.nvmrc`)
- npm (lockfile is `package-lock.json`)

## Setup

```bash
npm ci
npm run dev          # tsx watch src/index.ts — serves http://localhost:6789/mcp
```

## Scripts

| Script | Does |
|--------|------|
| `npm run dev` | watch-mode server via `tsx` |
| `npm run build` | `tsup` → `dist/` (ESM, shebang on entry) |
| `npm test` | `vitest run` |
| `npm run test:watch` | `vitest` |
| `npm run lint` | `biome check .` |
| `npm run lint:fix` | `biome check --write .` |
| `npm run typecheck` | `tsc --noEmit` |
| `npm run gen:registry` | scan `src/tools/*.ts` → regenerate `src/tools/registry.ts` (auto-fires via `pre*` hooks before dev/build/test/lint/typecheck — you almost never need to run it by hand) |

Two composite scripts wrap the multi-step routines — prefer them over running
the steps by hand so the order and exit semantics stay consistent:

| Script | Runs | Use for |
|--------|------|---------|
| `npm run verify` | `lint` → `typecheck` → `build` → `test` | **Before every commit / PR.** Fails fast on the first step that errors. |
| `npm run deploy` | `docker compose up -d --build --force-recreate` → `healthcheck` | Rebuild the image from the working tree and refresh the running container, then poll `/healthz` for up to 8s; non-zero exit if it doesn't come up healthy. Local Docker only — there is no publish target yet. |
| `npm run healthcheck` | curl-polls `http://127.0.0.1:12345/healthz` (up to 8s) | Standalone liveness probe; `deploy` chains into it. |

## Testing

The full approach — and the rules every test must follow — lives in
[TESTING-STRATEGY.md](TESTING-STRATEGY.md). **Read it before writing or editing
tests.** In short, the suite has three layers:

- **Per-tool unit tests** (`tests/tools/*.test.ts`) — drive the handler directly
  (pure functions, no HTTP) against *independently-derived* expected values
  (RFC/NIST vectors, computed results), covering a *range* of positive and
  negative inputs, not a single value.
- **Cross-tool conformance suite** (`tests/conformance.test.ts`) — registry-driven,
  so every tool is automatically held to one baseline contract (metadata,
  result shape, error contract, determinism, batch envelope, gateway parity).
  Its fixture-coverage gate forces any new tool to opt in before the suite goes
  green.
- **Integration test** (`tests/integration.test.ts`) — starts the HTTP server on
  an ephemeral port, connects with the SDK's `Client` +
  `StreamableHTTPClientTransport`, and exercises the real wire protocol
  (`tools/list` shape, one `tools/call` per tool, strict-mode + renamed-param
  boundary behaviour).

## Manual testing

```bash
npm run dev
npx @modelcontextprotocol/inspector   # point it at http://localhost:6789/mcp
```

Or one-shot with curl:

```bash
curl -s http://localhost:6789/mcp \
  -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"encode","arguments":{"direction":"encode","format":"base64","input":"hello"}}}'
```

## Adding a tool

1. Create `src/tools/<name>.ts` exporting either:
   - `export const <camel>Tool = defineTool({...})` for a regular tool, or
   - `export function build<Camel>Tool(otherTools) { return defineTool({...}) }`
     for a factory that needs the other tools (today only `script`).

   The file name and the export name must match (kebab file → camelCase export).
2. That's it for registration — `src/tools/registry.ts` is **auto-generated** by
   `scripts/gen-registry.mjs`, which fires automatically before dev / build /
   test / lint / typecheck via `pre*` npm hooks. A new tool file is picked up
   the next time you run any of those. The registry file is checked in so it
   stays diffable; never hand-edit it (`tests/registry-sync.test.ts` will
   catch you if you do — re-run `npm run gen:registry` to fix).
3. Add `tests/tools/<name>.test.ts` — range-based, positive + negative, per
   [TESTING-STRATEGY.md](TESTING-STRATEGY.md).
4. Register its conformance fixtures (`HAPPY`/`NETWORK_ONLY` + `SAD`) in
   `tests/conformance.test.ts` — the suite stays red until you do.
5. Give it an accurate, LLM-facing description (follow the conventions in
   [TOOLS.md](TOOLS.md)).

Before writing the handler, scan the
[shared-helpers inventory in TOOLS.md](TOOLS.md#shared-helpers--reach-for-these-before-reinventing)
— `errors`, `input`, `batch`, `ssrf`, `strict-codec`, `datetime`, `semaphore`,
and the boundary helpers in `src/tools/types.ts` already cover most of the
recurring patterns (URL fetching, batch envelopes, schema coercion, strict
base64/hex decoding). Reaching for one of those over a hand-rolled equivalent
is the expected default.

Checklist for the `ToolDef` (see [TOOLS.md](TOOLS.md) for the full conventions):
- Description states *when to use it* and *what it guarantees* (deterministic, no network).
- Enum-discriminated `action`/`format` rather than a new tool per operation.
- `outputSchema` + `structuredContent` returned alongside readable text.
- Errors as `isError: true` results with precise messages — never a thrown exception.
- Array input (if supported) returns the `{ results, failures }` batch envelope.
- **Non-string fields coerce from their string forms at the boundary.** See "The harness-coercion trap" below.

## The harness-coercion trap

Claude's tool-call harness serializes **every** parameter value as a string before it hits the MCP server. When the LLM writes `byteLength: 32` or `armor: true`, the wire payload arrives as `{"byteLength": "32", "armor": "true"}`. Strict-typed schemas reject those calls — and the resulting "expected boolean, received string" / "expected number, received string" rejection is one of the most-repeated failure modes we hit across tools.

The fix is **coercion at the schema boundary**, not strict types:

| Field type | Wrong | Right |
|---|---|---|
| number / integer | `z.number()` | `z.coerce.number()` (then refine for `int`, range) |
| boolean | `z.boolean()` | A boolean schema that accepts `"true"`/`"false"` strings as well as real booleans |
| array / object | `z.array(...)` | Schema that pre-parses JSON-string forms (`"[\"a\",\"b\"]"` → `["a","b"]`) before validating |

This is **only** required at the MCP boundary schema. Handlers receive the already-coerced values, so the rest of the code can assume the declared types. The `script` gateway calls handlers from JS where types are preserved natively, so it works either way — but **the boundary path won't work without coercion**, and divergence between the two paths (script accepts string `"true"`, direct rejects it) is itself a parity bug.

When in doubt: write a test pair that calls the tool with the native-typed value AND the string-encoded form and asserts both succeed with identical results — see [TESTING-STRATEGY.md §8a](TESTING-STRATEGY.md#8a-test-tags-cc-n-and-pv-n) for the PV-N tags that pin this contract.

## Conventions

- ESM only, TypeScript `strict`, no `any` in tool handlers.
- Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`…).
- Keep runtime deps to the audited list in [ARCHITECTURE.md](ARCHITECTURE.md) — new dependencies need a reason.
