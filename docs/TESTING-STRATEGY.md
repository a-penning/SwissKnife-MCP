# Testing Strategy

How we test SwissKnife tools. Read this before writing or editing tests. The
goal is coverage that actually catches regressions and edge cases, plus
cross-tool consistency that holds the whole suite to one contract.

The promise every tool makes is **"results are never guessed."** Our tests
exist to keep that promise honest — which means the tests must not guess either.

---

## 1. Core principles

- **Test ranges, never single values.** A test that asserts one input→output
  pair proves almost nothing. Every behavioural test covers a *range* of
  inputs via `it.each([...])` — varied shapes, sizes, encodings, boundaries.

- **Always cover positive AND negative cases.** For every "valid input →
  expected output" range, there is a matching "invalid input → clean error"
  range. Cover *multiple distinct failure modes* (malformed, out-of-range,
  wrong type, boundary violations, illegal characters), not just one.

- **Derive expected values independently — never paste tool output.**
  Compute the expectation from first principles: `node:crypto` for hashes,
  RFC 4648 vectors for base-N, `Intl.NumberFormat` for locale formatting,
  arithmetic for CIDR/duration math, reference RFC vectors for UUIDv5/JWT.
  If you run the tool and copy whatever it returns into the assertion, you
  cement its current behaviour — bugs included — as "correct."

- **When a new case fails, find out who is wrong.** Either your expected
  value is wrong (fix the test) or the *tool* is wrong (a real bug). Never
  silently change the assertion to match buggy output. If the tool is wrong,
  keep the **correct** assertion (leave it failing) and treat it as a fix-me
  spec (see §4).

- **Boundaries are where bugs live.** Empty string, zero, off-by-one at unit
  promotion (`1023`/`1024`, `999999`/`1000000`), leap days, DST transitions,
  `/0` and `/31`/`/32` prefixes, astral-plane unicode, max-length inputs.

---

## 2. Anatomy of a tool test file

Each tool is unit-tested in `tests/tools/<tool>.test.ts`. Tests import the
tool **handler directly** and drive it through small local helpers that fill
the schema defaults the MCP boundary would otherwise apply:

```ts
import { numberTool } from "../../src/tools/number.js";
type Args = Parameters<typeof numberTool.handler>[0];

async function run(args: Partial<Args>): Promise<CallToolResult> {
  return (await numberTool.handler({
    /* schema defaults */ unit: "ms", locale: "en-US", ...args,
  } as Args)) as CallToolResult;
}
// `structured` / `result` assert no error and return the payload.
```

Conventions:

- Use `it.each([...])` for ranges. Label rows so failures are legible
  (`"%j → %s"`, `"rejects %j"`).
- Keep the file's existing helper names (`run` / `result` / `structured` /
  `text`) — don't invent parallel ones.
- One `describe` per behaviour/action; a `describe` for the error ranges.
- Comments explain *why* an expected value is what it is (the RFC, the
  computation), not what the code does.

---

## 3. Where to test what — handler vs MCP boundary

A tool has two validation layers, and tests must target the right one:

- **Zod schema** (enum membership, `.strict()` unknown-key rejection, type
  coercion, defaults, cross-field `superRefine`) runs at the **MCP boundary**,
  *before* the handler. Calling `tool.handler(args)` directly **bypasses it.**
- **Handler logic** (semantic validation, computation, `err()`/`ok()`) runs
  inside the handler.

Therefore:

- Semantic errors (bad base64, out-of-range roman, unparseable date) →
  test via the handler `run()` helper, assert `res.isError`.
- Schema-level rejection (unknown `kind`, misspelled key, wrong type) →
  test against the schema, not the handler:
  ```ts
  const schema = z.object(tool.inputSchema as z.ZodRawShape);
  expect(schema.safeParse({ ...bad }).success).toBe(false);
  ```
  (See `id.test.ts` "supported-kind contract" — `uuid-v1` rejection.)
- End-to-end boundary behaviour (strict-mode unknown keys, renamed-param
  migration hints) → `tests/integration.test.ts`, which drives the real MCP
  server over the wire.

---

## 4. Fix-me specs (red now, green when fixed)

When a test surfaces a real bug or a consistency gap we've decided to fix, we
**leave the correct assertion in place and let it fail.** The failing test is
the specification of the fix; it turns green the moment the tool is corrected.

Rules:

- Write the assertion for the **desired** behaviour, not the current one.
- Add a `// FAILING SPEC` (or `// FIX-ME:`) comment block explaining the gap,
  the desired contract, and where the fix goes.
- Use plain `it` / `it.each`. **Do NOT use `it.fails`** — it inverts the
  semantics (the test would go *red* when the bug is *fixed*, and stay green
  while broken). We want red-while-broken, green-when-fixed.
- Cover the bug as a range too (e.g. the `net` IPv4 bypass pins hex octets,
  3/2/1-part shorthand, and all-hex forms — all the shapes one fix must cover).

No outstanding fix-me specs at the moment. When you add one, list it below
with the file it lives in and a one-line statement of the contract it pins,
and delete the entry once the fix lands.

---

## 5. The cross-tool conformance suite

`tests/conformance.test.ts` is **registry-driven**: it iterates `tools` from
`src/tools/registry.ts`, so every tool — including any new one — is
automatically held to the baseline contract. It enforces:

- **Metadata** — kebab-case unique name, non-empty title, ≥40-char
  description, non-empty Zod input shape, handler is a function.
- **Happy-path shape** — `content[0]` is non-empty text, `structuredContent`
  is a non-null object, and the result is **JSON-serialisable** (guards
  against a tool leaking a `BigInt`/circular ref — the reason `net` returns
  host counts as decimal strings).
- **Error contract** — given a schema-valid-but-wrong input, the tool returns
  `err()` (`isError`, text prefixed `Error: `) and **never throws**.
- **Determinism** — deterministic tools return byte-identical output across
  repeated calls (the core "never guessed" promise). Offline only; network
  tools and intentionally-random tools (`id`, `script` timing) are exempt.
- **Batch consistency** — array-input transform tools share the
  `{results, failures}` envelope and isolate per-item failures.
- **Script gateway parity** — every tool reached via `tools.<name>()` inside
  the `script` sandbox returns exactly what the direct handler returns.

### The fixture-coverage gate (how new tools are forced to comply)

The suite asserts that **every registered tool appears in the conformance
fixtures** (`HAPPY` + `NETWORK_ONLY`, and `SAD`). Add a tool without declaring
its fixtures and the suite goes red with a message telling you what to add.
This is the mechanism that keeps coverage from rotting as tools are added.

**When you add a tool you must:**
- Add an offline happy-path fixture to `HAPPY` (or list it in `NETWORK_ONLY`
  and cover its happy path in `integration.test.ts`).
- Add a schema-valid-but-wrong fixture to `SAD` that errors offline.
- Write its own `tests/tools/<tool>.test.ts` following §1–§2.
- If it accepts array input, conform to the `{results, failures}` envelope and
  add it to the batch block.

---

## 6. Cross-tool consistency contracts

These invariants hold across all tools. Honour them in new tools; the
conformance suite enforces most of them.

- **`err()` / `ok()` only.** Exceptions never escape a handler. Errors come
  back as `err()` with a precise, caller-actionable message — never a raw
  library trace (cf. the convert-data "Option columns is empty" / XML "column
  undefined" guards).
- **Batch envelope.** Array input → `{ results: [...], failures: [...] }`,
  with `failures` **always present** (empty array when nothing failed), and
  per-item isolation (one bad item never sinks the whole batch). `failures`
  entries are `{ index, value, error }`.
- **Single vs batch parity.** A single-item result echoes the same per-item
  fields a batch entry would (e.g. `color` echoes `value`).
- **Parameter naming.** `input` / `inputUrl` for data being *transformed*;
  `value` / `host` / `url` for a *target* being looked up. Rename rather than
  alias in early-alpha, but surface a migration hint at the boundary (see the
  `requestBodyEncoding` / `token`→`input` superRefines).
- **Serialisable output.** No `BigInt`, no circular refs in
  `structuredContent`. Large integers (IPv6 host counts) are decimal strings.
- **Empty/`null` distinctness.** "no records" / "no match" is a successful
  empty result, distinct from "lookup failed" (see DNS ENODATA, json-query
  null-present vs absent).

---

## 7. Network and determinism

- **No live external network in unit tests.** Real DNS / WHOIS / RDAP / remote
  HTTP make tests slow and flaky. Cover network tools via: a local
  `127.0.0.1` server (see `http`/integration), canned response fixtures fed to
  the parse functions (`whois`/`rdap` lib tests), or **offline error paths**
  that fail before any network call (bad URL, mutually-exclusive params,
  SSRF-blocked target, invalid host syntax).
- If a tool's happy path is fundamentally one-live-call-per-test with no
  offline surface, leave it to `integration.test.ts` and the
  `NETWORK_ONLY` conformance list — don't add live calls to broaden it.
- Any genuinely-live blocks that remain (e.g. `dns`/`inspect` against stable
  public records) must be gated behind `SWISSKNIFE_LIVE_TESTS` via a
  `const liveDescribe = process.env.SWISSKNIFE_LIVE_TESTS ? describe : describe.skip;`
  so the default run and CI stay hermetic; the offline/validation blocks in the
  same file always run.
- **Determinism is offline-only.** We aim for byte-identical repeat output for
  computed tools, but anything depending on a web source, the clock, or a
  CSPRNG is legitimately non-deterministic and is exempted from the
  determinism conformance block.

---

## 8. Keep the docs in sync

The tool's MCP `description` (in `src/tools/<name>.ts`) and the prose in
`docs/TOOLS.md` are how an LLM picks and calls a tool — they must match
reality. A capability that's documented but unimplemented (e.g. claimed `jq`
support, `INI` conversion, `uuid-v1`, a `kind:'json'` diff) is a usability bug:
the caller follows the docs and hits an error or silent wrong behaviour.

When you add, remove, or rename a capability:
- Update the tool's `description` and any matching prose in `docs/` in the same change.
- If a doc claim can't be unit-tested directly, add a test that locks the
  *actual* contract (e.g. `id`'s supported-kind contract asserts the real kinds
  and that the phantom ones are rejected) so docs and code can't silently drift.

---

## 8a. Test tags: CC-N and PV-N

Some conformance and per-tool tests carry a `CC-N` or `PV-N` tag so a test and
the rule it enforces stay greppable together:

- **CC-N — Cross-Cutting Contracts.** Invariants every tool must satisfy,
  enforced registry-wide in `tests/conformance.test.ts` (e.g. CC-2: `failures`
  is always an array; plus the result-shape, determinism, and batch-envelope
  contracts).
- **PV-N — Parameter-Validation rules.** Boundary-validation behaviours: strict
  unknown-key rejection, renamed-param migration hints, primitive coercion from
  string forms, etc.

The authoritative list lives in `tests/conformance.test.ts`. When you add a
cross-cutting invariant or a parameter-validation rule, give it the next number
and tag the test.

### The harness-coercion contract — required for every non-string field

Claude's tool-call harness serializes every parameter value as a string before
it reaches the MCP server (the same flow Claude Code, Desktop, and the SDK
default-transport all use). When the LLM writes `byteLength: 32`, the wire
payload is `"byteLength": "32"`; `armor: true` becomes `"armor": "true"`.

Strict Zod types reject those payloads. The fix is **coercion at the schema
boundary**, and the testing requirement is **proving both forms work** — see
[DEVELOPMENT.md](DEVELOPMENT.md#the-harness-coercion-trap) for the schema-side
rules. The tests pin the contract:

- For every non-string field, `it.each` over `(native, string-form)` pairs
  asserting **identical** results:
  ```ts
  it.each([
    ["native bool",    { armor: true  }],
    ["string-form",    { armor: "true" }],
    ["native number",  { byteLength: 32   }],
    ["string-form",    { byteLength: "32" }],
  ])("%s coerces", (_label, override) => { /* same expected output */ });
  ```
- **Cross-path parity.** The conformance suite's script-gateway parity block
  (CC-N) automatically asserts that calling a tool via `tools.<name>()` inside
  `script` returns the same shape as a direct handler call. Boolean / number /
  array coercion bugs typically surface here as **script accepts, direct
  rejects** — treat any such divergence as a fix-me spec, not a quirk.
- **Negative coverage stays strict.** Coercion is opt-in per-type, not a free
  pass — `armor: "yes"` / `byteLength: "abc"` / `recipients: "not-an-array"`
  must still be rejected with the usual schema error. The coercion accepts the
  obvious string forms (`"true"`/`"false"`, decimal-numeric strings, JSON-array
  strings) and nothing else.

This trap recurs across tools every time someone reaches for `z.boolean()` /
`z.number()` / `z.array()` directly. Catching it in the test suite is cheaper
than catching it in the field.

---

## 9. Checklist — adding or editing a tool's tests

- [ ] Every behavioural assertion uses `it.each` over a **range** of inputs.
- [ ] Positive **and** negative ranges; multiple distinct failure modes.
- [ ] Expected values derived **independently**, with a comment on the source.
- [ ] Boundaries covered (empty, zero, unit-promotion edges, min/max, unicode).
- [ ] Schema-level rejection tested via the schema; semantic errors via the handler.
- [ ] Any real bug found is left as a **failing** fix-me spec (plain `it`, not
      `it.fails`) with a `// FAILING SPEC` rationale — never matched to buggy output.
- [ ] New tool: added to conformance `HAPPY`/`NETWORK_ONLY` + `SAD`; batch
      envelope honoured if it takes arrays.
- [ ] No new live-network calls.
- [ ] Tool description + `docs/TOOLS.md` updated to match the behaviour under test.
