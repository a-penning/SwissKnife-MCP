import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";
import { regexTool } from "../../src/tools/regex.js";

type Args = Parameters<typeof regexTool.handler>[0];

async function run(args: Partial<Args>): Promise<CallToolResult> {
  return (await regexTool.handler({
    flags: "g",
    ...args,
  } as Args)) as CallToolResult;
}

async function structured(
  args: Partial<Args>,
): Promise<Record<string, unknown>> {
  const res = await run(args);
  expect(res.isError, JSON.stringify(res.content)).toBeFalsy();
  return res.structuredContent as Record<string, unknown>;
}

describe("regex: match", () => {
  it("returns all matches with index and groups", async () => {
    const out = await structured({
      action: "match",
      pattern: "(\\w+)@(\\w+)\\.com",
      input: "mail a@x.com and b@y.com today",
    });
    expect(out.count).toBe(2);
    const matches = out.matches as Array<Record<string, unknown>>;
    expect(matches[0]).toMatchObject({
      match: "a@x.com",
      index: 5,
      // Positional captures are surfaced as `captures` (was `groups`).
      captures: ["a", "x"],
    });
    expect(matches[1]).toMatchObject({ match: "b@y.com", index: 17 });
  });
  // Range of pattern/input pairs; expected matches+captures reasoned from JS
  // RegExp semantics (g-flag, left-to-right, non-overlapping).
  it.each([
    [
      "\\d+",
      "a1b22c333",
      [
        { match: "1", index: 1, captures: [] },
        { match: "22", index: 3, captures: [] },
        { match: "333", index: 6, captures: [] },
      ],
    ],
    [
      "(\\w)(\\w)",
      "abcd",
      [
        { match: "ab", index: 0, captures: ["a", "b"] },
        { match: "cd", index: 2, captures: ["c", "d"] },
      ],
    ],
    [
      "o",
      "foo boo",
      [
        { match: "o", index: 1, captures: [] },
        { match: "o", index: 2, captures: [] },
        { match: "o", index: 5, captures: [] },
        { match: "o", index: 6, captures: [] },
      ],
    ],
    [
      "\\bcat\\b",
      "cat category cat",
      [
        { match: "cat", index: 0, captures: [] },
        { match: "cat", index: 13, captures: [] },
      ],
    ],
  ])("match %j over %j yields the expected matches", async (pattern, input, expected) => {
    const out = await structured({ action: "match", pattern, input });
    expect(out.count).toBe(expected.length);
    const matches = out.matches as Array<Record<string, unknown>>;
    for (let i = 0; i < expected.length; i++) {
      expect(matches[i]).toMatchObject(expected[i] as Record<string, unknown>);
    }
  });
  it("supports named groups via the `groups` object (RegExpMatchArray convention)", async () => {
    const out = await structured({
      action: "match",
      pattern: "(?<year>\\d{4})-(?<month>\\d{2})",
      input: "released 2024-03",
    });
    const matches = out.matches as Array<{
      groups: Record<string, string>;
      captures: (string | null)[];
    }>;
    // `groups` is the named-keys object (matches `RegExpMatchArray.groups`).
    expect(matches[0]?.groups).toEqual({ year: "2024", month: "03" });
    // Positional captures still flow into `captures`.
    expect(matches[0]?.captures).toEqual(["2024", "03"]);
  });
  it("returns only the first match without the g flag", async () => {
    const out = await structured({
      action: "match",
      pattern: "\\d+",
      flags: "",
      input: "1 2 3",
    });
    expect(out.count).toBe(1);
  });
  it("handles zero-length matches without hanging", async () => {
    const out = await structured({
      action: "match",
      pattern: "a*",
      input: "bb",
    });
    expect(out.count).toBeGreaterThan(0);
  });
  it.each([
    "(unclosed",
    "[a-",
    "a{2,1}", // quantifier out of order
    "*invalid",
    "(?<>x)", // empty group name
    "(?<n>a)(?<n>b)", // duplicate group name
  ])("rejects invalid pattern %j with the compile error", async (pattern) => {
    const res = await run({ action: "match", pattern, input: "x" });
    expect(res.isError).toBe(true);
  });
});

describe("regex: replace", () => {
  // Range of replacement-token forms (positional $1, named $<n>, $&), global
  // and non-global. Results computed from native String.prototype.replace.
  it.each([
    ["(\\w+)=(\\w+)", "a=1 b=2", "$2:$1", "g", "1:a 2:b", 2],
    ["(\\d)", "x1y2", "[$1]", "g", "x[1]y[2]", 2],
    ["\\d", "1 2 3", "x", "", "x 2 3", 1],
    ["o", "foo", "0", "g", "f00", 2],
    ["(?<y>\\d{4})", "2024", "[$<y>]", "g", "[2024]", 1],
    ["a", "banana", "X", "g", "bXnXnX", 3],
    ["(\\w)(\\w)", "ab", "$&!", "", "ab!", 1],
    ["z", "abc", "Q", "g", "abc", 0], // no match -> unchanged, 0 replacements
  ])("replace %j in %j with %j (flags %j)", async (pattern, input, replacement, flags, result, replacements) => {
    const out = await structured({
      action: "replace",
      pattern,
      input,
      replacement,
      flags,
    });
    expect(out.result).toBe(result);
    expect(out.replacements).toBe(replacements);
  });
  it.each([
    [{ pattern: "(unclosed", input: "x", replacement: "y" }], // bad pattern
    [{ pattern: "a", input: "a" }], // missing replacement
    [{ pattern: "a", input: "a", replacement: "x", flags: "gg" }], // dup flag
  ])("replace rejects bad inputs %j", async (args) => {
    const res = await run({ action: "replace", ...args });
    expect(res.isError).toBe(true);
  });
});

describe("regex: split", () => {
  // Range covering limit, capturing-group interleaving, and whitespace.
  // Expected parts from native String.prototype.split semantics.
  it.each([
    [",\\s*", "a, b,c , d", 3, ["a", "b", "c "]],
    [",", "a,b,c", undefined, ["a", "b", "c"]],
    ["(,)", "a,b,c", undefined, ["a", ",", "b", ",", "c"]], // capture interleaves
    ["\\s+", "one two  three", undefined, ["one", "two", "three"]],
    ["x", "axbxc", 2, ["a", "b"]], // limit truncates
  ])("split %j over %j (limit %s)", async (pattern, input, limit, parts) => {
    const out = await structured({ action: "split", pattern, input, limit });
    expect(out.parts).toEqual(parts);
  });
  it.each([
    [{ pattern: "[", input: "a" }], // bad pattern
    [{ pattern: "a", input: "a", flags: "zz" }], // invalid flags (z not allowed)
  ])("split rejects bad inputs %j", async (args) => {
    const res = await run({ action: "split", ...args });
    expect(res.isError).toBe(true);
  });
});

describe("regex: unicode and sticky-flag edges", () => {
  it("does NOT hang on zero-width pattern with u flag over astral input", async () => {
    // Zero-width matches must advance by whole code points under the u flag:
    // a per-UTF-16-unit lastIndex++ lands mid-surrogate and the scan never
    // terminates, surfacing as a bogus catastrophic-backtracking timeout.
    const out = await structured({
      action: "match",
      pattern: "(?:)",
      flags: "gu",
      input: "😀",
    });
    // Per AdvanceStringIndex: 2 zero-width matches (at code-point boundaries 0 and 2)
    expect(out.count).toBe(2);
  }, 5000);

  it("replace with zero-width pattern + u flag inserts at code-point boundaries", async () => {
    const out = await structured({
      action: "replace",
      pattern: "(?:)",
      flags: "gu",
      input: "😀",
      replacement: "-",
    });
    // Native: "😀".replace(/(?:)/gu, "-") === "-😀-"
    expect(out.result).toBe("-😀-");
    expect(out.replacements).toBe(2);
  }, 5000);

  it("replace with sticky-only `y` flag targets position 0, not the position test() left", async () => {
    // A sticky (non-global) replace must target position 0: calling re.test()
    // beforehand advances lastIndex, so the subsequent replace would otherwise
    // start matching mid-string and rewrite the wrong occurrence.
    const out = await structured({
      action: "replace",
      pattern: "a",
      flags: "y",
      input: "aa",
      replacement: "X",
    });
    expect(out.result).toBe("Xa");
    expect(out.replacements).toBe(1);
  });
});

describe("regex: flag validation", () => {
  it("reports duplicate flags as a flags problem, not 'invalid pattern'", async () => {
    const res = await run({
      action: "match",
      pattern: "a",
      flags: "gg",
      input: "aaa",
    });
    expect(res.isError).toBe(true);
    const msg = JSON.stringify(res.content);
    expect(msg).toMatch(/invalid flags/);
    expect(msg).not.toMatch(/invalid pattern/);
  });

  it("rejects u+v combination up front with a precise message", async () => {
    const res = await run({
      action: "match",
      pattern: "a",
      flags: "uv",
      input: "abc",
    });
    expect(res.isError).toBe(true);
    const msg = JSON.stringify(res.content);
    expect(msg).toMatch(/mutually exclusive/);
    // Error must report the user's flags, not the internally-appended 'g'.
    expect(msg).not.toMatch(/uvg/);
  });
});

describe("regex: match metadata across a range of inputs", () => {
  // Broadens coverage: every match in a multi-hit scan must carry a correct
  // `index` (start offset), for varied spacing/positions.
  it.each([
    ["\\d+", "1 22 333", [0, 2, 5]],
    ["x", "axbxc", [1, 3]],
    ["\\bword\\b", "word a word", [0, 7]],
  ])("%j over %j reports the right start indices", async (pattern, input, expected) => {
    const out = await structured({ action: "match", pattern, input });
    const matches = out.matches as Array<{ index: number }>;
    expect(matches.map((m) => m.index)).toEqual(expected);
  });

  it("surfaces match indices when the `d` flag is set", async () => {
    // The `d` (hasIndices) flag adds per-match and per-capture-group [start, end)
    // ranges to each match. Pin that the flag is wired through end-to-end
    // (a previous regression had `d` validating at the schema but silently
    // doing nothing in the worker).
    const out = await structured({
      action: "match",
      pattern: "(\\d)(\\d)",
      flags: "gd",
      input: "ab 42 cd",
    });
    const m = (out.matches as Array<{ indices?: unknown }>)[0];
    expect(m?.indices, "d flag should expose match indices").toBeDefined();
  });
});

describe("regex: safety", () => {
  it("terminates catastrophic backtracking instead of hanging", async () => {
    const res = await run({
      action: "match",
      pattern: "(a+)+$",
      input: `${"a".repeat(40)}!`,
    });
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res.content)).toContain("budget");
  }, 10_000);
  it("rejects oversized input up front", async () => {
    const res = await run({
      action: "match",
      pattern: "x",
      input: "x".repeat(2_000_001),
    });
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res.content)).toContain("too large");
  });
});
