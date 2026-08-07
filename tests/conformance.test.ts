import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import { tools } from "../src/tools/registry.js";

// ---------------------------------------------------------------------------
// Cross-tool conformance suite.
//
// Every tool in the registry is held to the same baseline contract — metadata
// shape, ok()/err() result shape, JSON-serialisability, and "errors come back
// as err(), never a thrown exception" (the promise made in CLAUDE.md / types.ts).
//
// This is registry-driven: it iterates `tools`, so a NEW tool is automatically
// subjected to every check. The fixture-coverage tests below fail the moment a
// tool is added without declaring a happy-path + error-path fixture — which
// forces every new (or renamed) tool to prove it meets the baseline before the
// suite goes green. Editing an existing tool's schema in a way that breaks its
// fixture also trips these.
// ---------------------------------------------------------------------------

const byName = new Map(tools.map((t) => [t.name, t]));
const toolNames = [...byName.keys()].sort();

// biome-ignore lint/suspicious/noExplicitAny: fixtures are validated against each tool's own schema at runtime
type Fixture = Record<string, any>;

// One OFFLINE, deterministic happy-path input per tool. Tools whose only
// success path touches the network are declared in NETWORK_ONLY instead; their
// happy path is exercised end-to-end in integration.test.ts against the local
// server, so we don't make unit tests reach out to the internet.
const HAPPY: Record<string, Fixture> = {
  encode: { direction: "encode", format: "base64", input: "hi" },
  hash: { algorithm: "sha256", input: "hi" },
  jwt: { action: "decode", input: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0." },
  id: { action: "generate", kind: "uuid-v4" },
  time: { action: "convert", input: "0" },
  "convert-data": { from: "json", to: "yaml", input: '{"a":1}' },
  text: { action: "case", input: "hello world", target: "camel" },
  regex: { action: "match", pattern: "\\d+", input: "a1 b2" },
  inspect: { kind: "url", value: "https://example.com/p?x=1" },
  diff: { a: "x\n", b: "y\n" },
  "json-query": { query: "$.a", input: '{"a":1}' },
  number: { action: "roman", input: 42 },
  net: { action: "parse", value: "192.168.1.1" },
  color: { input: "#ff0000" },
  script: { source: "return 1 + 1;" },
};

// Tools with no offline happy path. They still get metadata + error-contract
// coverage; their happy path lives in integration.test.ts.
const NETWORK_ONLY = new Set(["dns", "http"]);

// One schema-valid-but-semantically-wrong input per tool. Each MUST return an
// err() result — isError true, no thrown exception, no network access.
const SAD: Record<string, Fixture> = {
  encode: { direction: "decode", format: "base64", input: "!!!" },
  hash: { algorithm: "sha256" }, // neither input nor inputUrl
  jwt: { action: "decode", input: "not.a.jwt" },
  id: { action: "generate", kind: "uuid-v5" }, // missing namespace/name
  time: { action: "convert", input: "definitely not a timestamp" },
  "convert-data": { from: "json", to: "yaml", input: "{ not json" },
  text: { action: "unescape", input: "'x'", style: "shell-posix" }, // unsupported
  regex: { action: "match", pattern: "(unclosed" },
  inspect: { kind: "url", value: "not a url" },
  diff: {}, // neither a nor aUrl
  "json-query": { query: "$.a", input: "{not valid json" }, // malformed JSON document
  number: { action: "roman", input: 0 }, // out of 1..3999
  net: { action: "parse", value: "999.999.999.999" },
  color: { input: "not-a-color" },
  script: { source: "this is not valid javascript ((" },
  dns: { host: "a", ip: "1.2.3.4" }, // mutually exclusive — offline validation
  http: { url: "not-a-url" }, // invalid URL — offline validation
};

function schemaOf(tool: (typeof tools)[number]) {
  return z.object(tool.inputSchema as z.ZodRawShape).strict();
}

async function invoke(
  tool: (typeof tools)[number],
  raw: Fixture,
): Promise<CallToolResult> {
  // Validate + fill defaults exactly as the MCP boundary does before calling
  // the handler, then run it. A throw here is itself a conformance failure.
  const parsed = schemaOf(tool).parse(raw);
  return (await Promise.resolve(
    tool.handler(parsed as never),
  )) as CallToolResult;
}

describe("conformance: registry metadata", () => {
  it("tool names are unique", () => {
    expect(tools.length).toBe(new Set(tools.map((t) => t.name)).size);
  });

  it.each(tools.map((t) => [t.name, t] as const))(
    "%s has well-formed metadata",
    (_name, tool) => {
      // kebab-case, MCP-safe name.
      expect(tool.name).toMatch(/^[a-z][a-z0-9-]*$/);
      expect(typeof tool.title).toBe("string");
      expect(tool.title.length).toBeGreaterThan(0);
      // Description is what an LLM uses to pick the tool — must be substantial.
      expect(typeof tool.description).toBe("string");
      expect(tool.description.length).toBeGreaterThanOrEqual(40);
      // inputSchema is a non-empty Zod raw shape.
      const shape = tool.inputSchema as z.ZodRawShape;
      expect(Object.keys(shape).length).toBeGreaterThan(0);
      for (const [key, def] of Object.entries(shape)) {
        expect(def instanceof z.ZodType, `${tool.name}.${key}`).toBe(true);
      }
      expect(typeof tool.handler).toBe("function");
    },
  );
});

describe("conformance: fixture coverage (new tools must opt in)", () => {
  it("every tool has a happy-path fixture or is declared NETWORK_ONLY", () => {
    const covered = [
      ...new Set([...Object.keys(HAPPY), ...NETWORK_ONLY]),
    ].sort();
    // If this fails after adding a tool: add it to HAPPY (offline happy path)
    // or NETWORK_ONLY (happy path covered in integration.test.ts).
    expect(covered).toEqual(toolNames);
  });

  it("every tool has an error-path fixture", () => {
    // If this fails after adding a tool: add a schema-valid-but-wrong input to
    // SAD that the tool rejects via err() (offline, no network).
    expect(Object.keys(SAD).sort()).toEqual(toolNames);
  });
});

describe("conformance: happy-path result shape", () => {
  const cases = Object.keys(HAPPY).map((name) => [name] as const);
  it.each(cases)("%s returns a well-formed ok() result", async (name) => {
    const tool = byName.get(name);
    if (!tool) throw new Error(`no such tool: ${name}`);

    let res: CallToolResult;
    try {
      res = await invoke(tool, HAPPY[name] as Fixture);
    } catch (e) {
      throw new Error(`${name}: handler threw on a valid input: ${String(e)}`);
    }

    expect(res.isError, JSON.stringify(res.content)).toBeFalsy();

    // Text content block present and non-empty.
    const block = res.content?.[0] as { type?: string; text?: string };
    expect(block?.type).toBe("text");
    expect(typeof block?.text).toBe("string");
    expect((block?.text ?? "").length).toBeGreaterThan(0);

    // Structured content present, an object, and JSON-serialisable (guards
    // against BigInt/circular leaking into the wire — see net's host counts).
    expect(typeof res.structuredContent).toBe("object");
    expect(res.structuredContent).not.toBeNull();
    expect(() => JSON.stringify(res.structuredContent)).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Conformance: every batch (array-input) tool shares one envelope and
// isolates per-item errors.
//
//   color / inspect / hash / encode → { results:[...], failures:[...] }
//
// One bad item lands in `failures` (with its index, original value, and
// the error message); the good items still come back in `results`.
// `failures` is always present, even when empty — callers don't have to
// defensively check for the key (CC-2).
//
// `id` inspect is intentionally excluded: an un-parseable id there is a
// valid ANSWER (`valid:false`), not an operation failure — it belongs in
// `results`.
// ---------------------------------------------------------------------------
interface BatchCase {
  tool: string;
  base: Fixture; // non-array args
  field: string; // which field carries the array
  valid: unknown[]; // all-valid items
  mixed: unknown[]; // valid + invalid items
  badIndices: number[]; // indices within `mixed` expected to fail
}

const BATCH: BatchCase[] = [
  {
    tool: "color",
    base: {},
    field: "input",
    valid: ["#fff", "red", "rgb(0 128 255)"],
    mixed: ["#fff", "nope", "red", "stillnotacolor"],
    badIndices: [1, 3],
  },
  {
    tool: "inspect",
    base: { kind: "url" },
    field: "value",
    valid: ["https://a.com", "http://b.org/x?y=1"],
    mixed: ["https://a.com", "not a url", "https://c.net"],
    badIndices: [1],
  },
  {
    tool: "hash",
    base: { algorithm: "sha256", inputEncoding: "base64" },
    field: "input",
    valid: ["YQ==", "Yg==", "Yw=="],
    mixed: ["YQ==", "!!!not base64", "Yg=="],
    badIndices: [1],
  },
  {
    tool: "encode",
    base: { direction: "decode", format: "base64" },
    field: "input",
    valid: ["YQ==", "Yg=="],
    mixed: ["YQ==", "!!!not base64", "Yg=="],
    badIndices: [1],
  },
];

describe("conformance: batch tools share one envelope + isolate failures", () => {
  it.each(BATCH.map((c) => [c.tool, c] as const))(
    "%s: all-valid array returns results[] with an (empty) failures[]",
    async (_name, c) => {
      const tool = byName.get(c.tool);
      if (!tool) throw new Error(`no such tool: ${c.tool}`);
      const res = await invoke(tool, { ...c.base, [c.field]: c.valid });
      expect(res.isError, JSON.stringify(res.content)).toBeFalsy();
      const sc = res.structuredContent as {
        results?: unknown[];
        failures?: unknown[];
      };
      expect(Array.isArray(sc.results), `${c.tool}.results`).toBe(true);
      expect(sc.results).toHaveLength(c.valid.length);
      // failures must ALWAYS be present (CC-2), even when empty.
      expect(Array.isArray(sc.failures), `${c.tool}.failures`).toBe(true);
      expect(sc.failures).toHaveLength(0);
    },
  );

  it.each(BATCH.map((c) => [c.tool, c] as const))(
    "%s: a bad item is isolated into failures, good items still return",
    async (_name, c) => {
      const tool = byName.get(c.tool);
      if (!tool) throw new Error(`no such tool: ${c.tool}`);
      let res: CallToolResult;
      try {
        res = await invoke(tool, { ...c.base, [c.field]: c.mixed });
      } catch (e) {
        throw new Error(`${c.tool}: batch threw on one bad item: ${String(e)}`);
      }
      expect(res.isError, `${c.tool} aborted the whole batch`).toBeFalsy();
      const sc = res.structuredContent as {
        results?: unknown[];
        failures?: Array<{ index: number; value: unknown; error: string }>;
      };
      expect(sc.results).toHaveLength(c.mixed.length - c.badIndices.length);
      expect(sc.failures).toHaveLength(c.badIndices.length);
      for (const f of sc.failures ?? []) {
        expect(typeof f.index).toBe("number");
        expect(c.badIndices).toContain(f.index);
        expect(typeof f.error).toBe("string");
      }
    },
  );
});

describe("conformance: script gateway parity with direct handler", () => {
  // Every non-script tool is reachable a second way: via `tools.<name>(args)`
  // inside the `script` sandbox. That gateway must return exactly what the
  // handler returns directly — otherwise a script silently sees different data
  // than a direct MCP call. Reuses the deterministic HAPPY fixtures (random
  // `id` excluded — two calls would differ by design).
  const scriptTool = byName.get("script");
  const cases = Object.keys(HAPPY)
    .filter((name) => name !== "id" && name !== "script")
    .map((name) => [name] as const);

  it.each(cases)("%s: gateway result equals direct handler", async (name) => {
    const tool = byName.get(name);
    if (!tool || !scriptTool) throw new Error(`missing tool: ${name}`);

    const direct = await invoke(tool, HAPPY[name] as Fixture);

    const scriptRes = (await Promise.resolve(
      scriptTool.handler({
        source: "return await tools[args.name](args.fixture);",
        args: { name, fixture: HAPPY[name] },
        timeoutMs: 10_000,
        maxToolCalls: 5,
        trace: false,
      } as never),
    )) as CallToolResult;

    expect(scriptRes.isError, JSON.stringify(scriptRes.content)).toBeFalsy();
    const gatewayValue = (scriptRes.structuredContent as { result: unknown })
      .result;
    // Deep-equal (key order irrelevant after the VM's JSON round-trip).
    expect(gatewayValue).toEqual(direct.structuredContent);
  });
});

describe("conformance: determinism (the core 'never guessed' promise)", () => {
  // SwissKnife's headline promise is that results are computed, not guessed —
  // so a deterministic tool must return byte-identical output for identical
  // input. This catches a future tool leaking nondeterminism (Date.now(),
  // unordered object keys, Math.random()) into its result.
  //
  // Exempt: `id` (CSPRNG-backed by design) and `script` (its structuredContent
  // carries durationMs telemetry that legitimately varies). Network tools are
  // already absent from HAPPY.
  const DETERMINISM_EXEMPT = new Set(["id", "script"]);
  const cases = Object.keys(HAPPY)
    .filter((name) => !DETERMINISM_EXEMPT.has(name))
    .map((name) => [name] as const);

  it.each(cases)("%s is byte-identical across repeated calls", async (name) => {
    const tool = byName.get(name);
    if (!tool) throw new Error(`no such tool: ${name}`);
    const [a, b] = await Promise.all([
      invoke(tool, HAPPY[name] as Fixture),
      invoke(tool, HAPPY[name] as Fixture),
    ]);
    expect(JSON.stringify(a.structuredContent)).toBe(
      JSON.stringify(b.structuredContent),
    );
  });
});

describe("conformance: error-path contract (err(), never a throw)", () => {
  const cases = Object.keys(SAD).map((name) => [name] as const);
  it.each(cases)(
    "%s returns err() on bad input, never throws",
    async (name) => {
      const tool = byName.get(name);
      if (!tool) throw new Error(`no such tool: ${name}`);

      let res: CallToolResult;
      try {
        res = await invoke(tool, SAD[name] as Fixture);
      } catch (e) {
        throw new Error(
          `${name}: handler threw instead of returning err(): ${String(e)}`,
        );
      }

      expect(res.isError, `${name} should have errored`).toBe(true);
      const block = res.content?.[0] as { type?: string; text?: string };
      expect(block?.type).toBe("text");
      // err() prefixes every message with "Error: " (see src/tools/types.ts).
      expect(block?.text ?? "").toMatch(/^Error: /);
    },
  );
});

// ---------------------------------------------------------------------------
// Some MCP clients serialise numeric params as JSON strings ("20000" not
// 20000). Number-shaped input fields use `z.coerce.number()` so a stringified
// number is accepted at the boundary rather than rejected as "expected number,
// received string".
//
// We test the cross-cutting behaviour here (any number-shaped field accepts
// a string-coerced value at the MCP boundary) rather than per-tool, because
// the failure mode is systemic and the fix has to be too.
// ---------------------------------------------------------------------------
interface CoerceCase {
  tool: string;
  args: Fixture;
  // Field that's expected to come back in structuredContent matching the
  // coerced value — or simply that the call doesn't reject.
  expectCoerced?: { field: string; value: number };
}

const NUMERIC_COERCION: CoerceCase[] = [
  {
    tool: "diff",
    args: { a: "x\n", b: "y\n", context: "3" },
  },
  {
    tool: "json-query",
    args: { query: "$.a", input: '{"a":1}', limit: "5" },
  },
  {
    tool: "regex",
    args: { action: "match", pattern: "\\d", input: "a1b2", limit: "10" },
  },
  {
    tool: "convert-data",
    args: { from: "json", to: "yaml", input: '{"a":1}', indent: "4" },
  },
  {
    tool: "id",
    args: { action: "generate", kind: "uuid-v4", count: "3" },
  },
  {
    tool: "encode",
    args: {
      direction: "encode",
      format: "radix",
      input: "255",
      radixFrom: "10",
      radixTo: "16",
    },
  },
  {
    tool: "number",
    args: {
      action: "format",
      input: 1234.5678,
      minimumFractionDigits: "2",
      maximumFractionDigits: "2",
    },
  },
  {
    tool: "time",
    args: { action: "cron", expression: "* * * * *", count: "3" },
  },
];

describe("conformance: numeric inputs coerce from strings", () => {
  it.each(NUMERIC_COERCION.map((c) => [c.tool, c] as const))(
    "%s: string-coerced number passes schema validation",
    async (_n, c) => {
      const tool = byName.get(c.tool);
      if (!tool) throw new Error(`no such tool: ${c.tool}`);
      let res: CallToolResult;
      try {
        res = await invoke(tool, c.args);
      } catch (e) {
        throw new Error(
          `${c.tool}: handler threw on coerced input: ${String(e)}`,
        );
      }
      expect(res.isError, JSON.stringify(res.content)).toBeFalsy();
    },
  );
});
