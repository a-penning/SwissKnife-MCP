import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import { tools } from "../src/tools/registry.js";

// ---------------------------------------------------------------------------
// Wire-coercion suite.
//
// MCP transports routinely stringify JSON values on the wire: `true` arrives as
// "true", `["a","b"]` as the literal JSON string. The `coerceBoolean` /
// `singleOrArray` helpers parse those back BEFORE z.boolean()/z.union() so a
// documented call (`unique: true`, batch `input: [...]`, `type: ["CAA","NS"]`)
// is reachable from the most common transport — not just from inside `script`,
// which passes native JS values. Strict-typed mistakes must still fail loud.
//
// We parse through each tool's own `inputSchema` (the MCP boundary) and, where
// the happy path is offline, push the parsed args through the handler to prove
// the coerced value flows end-to-end.
// ---------------------------------------------------------------------------

const byName = new Map(tools.map((t) => [t.name, t]));

function toolOf(name: string): (typeof tools)[number] {
  const t = byName.get(name);
  if (!t) throw new Error(`tool not found: ${name}`);
  return t;
}

function parse(name: string, raw: Record<string, unknown>) {
  return z.object(toolOf(name).inputSchema as z.ZodRawShape).parse(raw);
}

async function run(
  name: string,
  raw: Record<string, unknown>,
): Promise<CallToolResult> {
  const parsed = parse(name, raw);
  return (await Promise.resolve(
    toolOf(name).handler(parsed as never),
  )) as CallToolResult;
}

describe("wire-coercion: booleans (coerceBoolean)", () => {
  // "true"/"false" strings and native booleans must be equivalent. Expected
  // dedupe output computed independently: distinct lines, sorted ascending.
  it("text sort-lines: unique 'true' and true both dedupe", async () => {
    const input = "b\na\nc\na\nb";
    const expected = "a\nb\nc";
    const fromString = await run("text", {
      action: "sort-lines",
      input,
      unique: "true",
    });
    const fromBool = await run("text", {
      action: "sort-lines",
      input,
      unique: true,
    });
    expect((fromString.structuredContent as { result: string }).result).toBe(
      expected,
    );
    expect((fromBool.structuredContent as { result: string }).result).toBe(
      expected,
    );
  });

  it("text sort-lines: unique 'false' keeps duplicates (like native false)", () => {
    expect(
      parse("text", { action: "sort-lines", unique: "false" }),
    ).toMatchObject({ unique: false });
    expect(
      parse("text", { action: "sort-lines", unique: false }),
    ).toMatchObject({ unique: false });
  });

  it("text sort-lines: numeric 'true' coerces", () => {
    expect(
      parse("text", { action: "sort-lines", numeric: "true" }),
    ).toMatchObject({ numeric: true });
  });

  // csvDynamicTyping:"false" must be honoured — a leading-zero cell stays a
  // string instead of being coerced to the number 7.
  it("convert-data: csvDynamicTyping 'false' preserves cells as strings", async () => {
    const res = await run("convert-data", {
      from: "csv",
      to: "json",
      input: "id\n007",
      csvDynamicTyping: "false",
    });
    const parsed = JSON.parse(
      (res.structuredContent as { result: string }).result,
    );
    expect(parsed).toEqual([{ id: "007" }]);
  });

  it("convert-data: csvDynamicTyping 'true' still coerces numbers", async () => {
    const res = await run("convert-data", {
      from: "csv",
      to: "json",
      input: "id\n7",
      csvDynamicTyping: "true",
    });
    const parsed = JSON.parse(
      (res.structuredContent as { result: string }).result,
    );
    expect(parsed).toEqual([{ id: 7 }]);
  });

  // Only the literal strings coerce. Typos and numbers must stay loud so a
  // garbled flag never silently reads as `false`.
  const REJECTED: Array<[string, unknown]> = [
    ["yes", "yes"],
    ["string 1", "1"],
    ["number 1", 1],
    ["number 0", 0],
    ["True (capitalised)", "True"],
  ];
  it.each(REJECTED)("text unique rejects %s", (_label, value) => {
    expect(() =>
      parse("text", { action: "sort-lines", unique: value }),
    ).toThrow();
  });

  it("boolean default is applied when the field is omitted", () => {
    expect(parse("text", { action: "sort-lines" })).toMatchObject({
      unique: false,
      numeric: false,
    });
    expect(
      parse("convert-data", { from: "csv", to: "json", input: "a\n1" }),
    ).toMatchObject({ csvHeaders: true, csvDynamicTyping: true });
  });
});

describe("wire-coercion: single-or-array (singleOrArray / singleOrBatch)", () => {
  // A JSON-stringified array must parse to the same value as the native array,
  // producing the batch envelope (results[] + failures[]) with one entry each.
  it('hash: input \'["a","b","c"]\' matches the native array form', async () => {
    const fromString = await run("hash", {
      algorithm: "sha256",
      input: '["a","b","c"]',
    });
    const fromArray = await run("hash", {
      algorithm: "sha256",
      input: ["a", "b", "c"],
    });
    const sc = fromString.structuredContent as {
      results: { digest: string }[];
      failures: unknown[];
    };
    expect(sc.results).toHaveLength(3);
    expect(sc.failures).toHaveLength(0);
    expect(fromString.structuredContent).toEqual(fromArray.structuredContent);
  });

  it("hash: a plain string stays a single (non-batch) input", async () => {
    const res = await run("hash", { algorithm: "sha256", input: "abc" });
    // sha256("abc"), computed independently (RFC test vector).
    expect(res.structuredContent).toMatchObject({
      digest:
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    });
  });

  // dns is network-only, so we assert the coercion at the schema boundary: the
  // stringified array must parse to the same value as the native array.
  it('dns: type \'["CAA","NS"]\' coerces to the native array', () => {
    expect(
      parse("dns", { host: "example.com", type: '["CAA","NS"]' }),
    ).toMatchObject({ type: ["CAA", "NS"] });
    expect(
      parse("dns", { host: "example.com", type: ["CAA", "NS"] }),
    ).toMatchObject({ type: ["CAA", "NS"] });
  });

  it("dns: a single type string stays a single value", () => {
    expect(parse("dns", { host: "example.com", type: "MX" })).toMatchObject({
      type: "MX",
    });
  });

  // A `[`-prefixed string that isn't valid JSON falls through untouched so the
  // union reports the real type error (here: not a valid record type).
  it("dns: an unparseable '[' string is passed through and rejected", () => {
    expect(() =>
      parse("dns", { host: "example.com", type: "[oops" }),
    ).toThrow();
  });

  it("singleOrBatch: empty stringified array is rejected (min 1)", () => {
    expect(() => parse("hash", { algorithm: "sha256", input: "[]" })).toThrow();
  });

  // jwt.algorithms is passed to jose, which requires a real array. All three
  // wire forms (stringified array, native array, bare single string) must
  // verify the same HS256 token, and a mismatched restriction must reject.
  it("jwt verify: algorithms accepts string / array / stringified-array forms", async () => {
    const signed = await run("jwt", {
      action: "sign",
      key: "secret",
      payload: { sub: "x" },
    });
    const token = (signed.structuredContent as { token: string }).token;
    for (const algorithms of ['["HS256"]', ["HS256"], "HS256"]) {
      const res = await run("jwt", {
        action: "verify",
        input: token,
        key: "secret",
        algorithms,
      });
      expect(
        res.structuredContent,
        `algorithms=${JSON.stringify(algorithms)}`,
      ).toMatchObject({ valid: true });
    }
    // negative: restricting to a different alg must fail the token.
    const mismatch = await run("jwt", {
      action: "verify",
      input: token,
      key: "secret",
      algorithms: '["RS256"]',
    });
    expect(mismatch.structuredContent).toMatchObject({ valid: false });
  });
});

describe("wire-coercion: script.trace", () => {
  it("trace 'true' coerces and runs like native true", async () => {
    expect(
      parse("script", { source: "return 1+1", trace: "true" }),
    ).toMatchObject({ trace: true });
    // trace true emits a `trace` array (empty here — no tool calls); native
    // false omits it. durationMs is non-deterministic so we assert the fields
    // the coercion actually governs, not the whole envelope.
    const traced = await run("script", { source: "return 1+1", trace: "true" });
    const untraced = await run("script", {
      source: "return 1+1",
      trace: false,
    });
    expect(traced.isError).toBeFalsy();
    expect((traced.structuredContent as { result: unknown }).result).toBe(2);
    expect(
      Array.isArray((traced.structuredContent as { trace?: unknown }).trace),
    ).toBe(true);
    expect(
      (untraced.structuredContent as { trace?: unknown }).trace,
    ).toBeUndefined();
  });

  it("trace 'false' coerces; a typo like 'yes' is rejected", () => {
    expect(
      parse("script", { source: "return 1", trace: "false" }),
    ).toMatchObject({ trace: false });
    expect(() =>
      parse("script", { source: "return 1", trace: "yes" }),
    ).toThrow();
  });
});
