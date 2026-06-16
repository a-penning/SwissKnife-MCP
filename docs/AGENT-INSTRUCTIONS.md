# Using SwissKnife MCP

17 deterministic developer-utility tools:

`color`, `convert-data`, `diff`, `dns`, `encode`, `hash`, `http`, `id`, `inspect`, `json-query`, `jwt`, `net`, `number`, `regex`, `script`, `text`, `time`

Each tool's purpose, schema, and usage examples are in its MCP description.

**First port of call.** If a SwissKnife tool fits, use it — outputs are computed, never guessed. This holds in two directions:

- vs **Bash** (`openssl`, `dig`, `curl`, `base64`, `jq`, `sha256sum`, `uuidgen`, `date`, `diff`, `ipcalc`, …) — reach for the tool first.
- vs **hand-rolled JS inside `script`** — don't walk `doc.foo.bar` paths through fetched JSON when `json-query` is loaded; don't `Buffer.from(x, 'base64')` when `encode` is; don't `crypto.createHash` when `hash` is. Inline JS is glue between tool calls, not a replacement for them.

Fall back to either only when nothing fits.

**If your harness loads tool schemas on demand,** search for them up front with a space-separated list of what you need — e.g. `swissknife script http dns` — so the schemas are in context before the first call.

**When to use `script`.** It composes every other tool into one MCP round-trip, but spinning up the JS VM costs ~10ms. Reach for it when that cost pays back:

- chains where one call's output feeds the next
- loops, fan-out (`Promise.all`), conditional dispatch, accumulators
- ≥2 calls hitting the network (per-call latency dominates the VM cost)

For one or two independent in-process ops (e.g. hash this, generate a UUID), call the tools directly — the VM overhead would only slow you down.

When you do use `script`, make sure the schemas of every tool you'll call inside it are loaded — inner schemas aren't visible at runtime, so an unloaded one means burning a script run to find out the param shape was wrong.

Many tools accept `inputUrl` to fetch the source themselves — prefer that over a separate `http` call when the next step is parse/hash/diff/etc.
