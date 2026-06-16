import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";
import { diffTool } from "../../src/tools/diff.js";

type Args = Parameters<typeof diffTool.handler>[0];

async function run(args: Partial<Args>): Promise<CallToolResult> {
  return (await diffTool.handler({
    mode: "lines",
    context: 3,
    aLabel: "a",
    bLabel: "b",
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

describe("diff: lines", () => {
  it("produces a unified diff with counts", async () => {
    const out = await structured({
      a: "line one\nline two\nline three\n",
      b: "line one\nline 2\nline three\nline four\n",
    });
    expect(out.diff).toContain("-line two");
    expect(out.diff).toContain("+line 2");
    expect(out.diff).toContain("+line four");
    expect(out.additions).toBe(2);
    expect(out.deletions).toBe(1);
    expect(out.identical).toBe(false);
  });

  // A range of single-line edits, each with independently-counted additions
  // and deletions. A pure insert adds 1; a pure delete removes 1; an
  // in-place change is 1 delete + 1 add.
  it.each([
    ["pure insert", "x\n", "x\ny\n", 1, 0],
    ["pure delete", "x\ny\n", "x\n", 0, 1],
    ["in-place change", "x\n", "y\n", 1, 1],
    ["two inserts", "x\n", "x\ny\nz\n", 2, 0],
    ["replace and append", "a\nb\n", "a\nB\nc\n", 2, 1],
  ])("lines mode counts %s correctly", async (_name, a, b, additions, deletions) => {
    const out = await structured({ a, b });
    expect(out.additions).toBe(additions);
    expect(out.deletions).toBe(deletions);
    expect(out.identical).toBe(false);
  });

  // identical is anchored to BYTE equality. Whitespace / trailing-newline
  // differences are NOT identical even though they look similar.
  it.each([
    ["byte-equal", "same\n", "same\n", true],
    ["trailing newline", "x", "x\n", false],
    ["internal whitespace", "a b\n", "a  b\n", false],
    ["empty vs empty", "", "", true],
    ["case change", "Foo\n", "foo\n", false],
  ])("lines mode identical=%s for %s", async (_name, a, b, identical) => {
    const out = await structured({ a, b });
    expect(out.identical).toBe(identical);
    if (identical) {
      expect(out.additions).toBe(0);
      expect(out.deletions).toBe(0);
    }
  });
  it("respects context and labels", async () => {
    const lines = Array.from({ length: 20 }, (_, i) => `l${i}`).join("\n");
    const changed = lines.replace("l10", "L10");
    const out = await structured({
      a: lines,
      b: changed,
      context: 1,
      aLabel: "old.txt",
      bLabel: "new.txt",
    });
    expect(out.diff).toContain("old.txt");
    expect(out.diff).toContain("new.txt");
    expect(out.diff).not.toContain("l5");
  });
});

describe("diff: words and chars", () => {
  it("marks word-level changes inline", async () => {
    const out = await structured({
      a: "the quick brown fox",
      b: "the slow brown wolf",
      mode: "words",
    });
    expect(out.diff).toBe("the [-quick-]{+slow+} brown [-fox-]{+wolf+}");
    expect(out.additions).toBe(2);
    expect(out.deletions).toBe(2);
  });

  // Word-level token counts: each \S+ run is one token, regardless of how
  // many words share a contiguous diff hunk.
  it.each([
    ["one word replaced", "the cat", "the dog", 1, 1],
    ["one word added", "the cat", "the big cat", 1, 0],
    ["two words added in one hunk", "the cat", "the big fat cat", 2, 0],
    ["one word removed", "the big cat", "the cat", 0, 1],
    ["whitespace only (no tokens)", "foo bar", "foo  bar", 0, 0],
  ])("words mode counts %s", async (_name, a, b, additions, deletions) => {
    const out = await structured({ a, b, mode: "words" });
    expect(out.additions).toBe(additions);
    expect(out.deletions).toBe(deletions);
  });

  // Char-level: counts code points, and the inline markers wrap the exact
  // changed run.
  it.each([
    ["cat", "car", "ca[-t-]{+r+}", 1, 1],
    ["abc", "xyzabc", "{+xyz+}abc", 3, 0],
    ["xyzabc", "abc", "[-xyz-]abc", 0, 3],
    ["abc", "abc", "abc", 0, 0],
  ])("chars mode %s -> %s", async (a, b, diff, additions, deletions) => {
    const out = await structured({ a, b, mode: "chars" });
    expect(out.diff).toBe(diff);
    expect(out.additions).toBe(additions);
    expect(out.deletions).toBe(deletions);
  });
});

describe("diff: input contract", () => {
  // Each side needs EXACTLY one source. Zero sources, or both inline + URL on
  // the same side, is an error. A valid mix (inline + URL across sides is
  // fine, but supplying both on one side is not).
  it.each([
    ["a missing", { b: "y" }],
    ["b missing", { a: "x" }],
    ["both sides missing", {}],
    ["a has both inline and url", { a: "x", aUrl: "http://x", b: "y" }],
    ["b has both inline and url", { a: "x", b: "y", bUrl: "http://y" }],
  ])("rejects when %s", async (_name, args) => {
    expect((await run(args)).isError).toBe(true);
  });
});

describe("diff: identical, counts, and marker-collision warning", () => {
  it("words mode reports identical:false for whitespace-only differences", async () => {
    const out = await structured({
      a: "foo bar",
      b: "foo  bar",
      mode: "words",
    });
    expect(out.identical).toBe(false);
  });
  it("words mode reports identical:false for a trailing-newline diff", async () => {
    const out = await structured({ a: "x", b: "x\n", mode: "words" });
    expect(out.identical).toBe(false);
  });
  it("words mode counts each added word, not each contiguous hunk", async () => {
    const out = await structured({
      a: "the cat",
      b: "the big fat cat",
      mode: "words",
    });
    // "{+big fat +}" is one hunk but two words.
    expect(out.additions).toBe(2);
    expect(out.deletions).toBe(0);
  });
  it("chars mode counts code points added/removed, not hunks", async () => {
    const out = await structured({ a: "abc", b: "xyzabc", mode: "chars" });
    expect(out.additions).toBe(3);
    expect(out.deletions).toBe(0);
  });
  it("warns when input contains diff-marker sequences", async () => {
    const out = await structured({
      a: "plain text",
      b: "plain [-text-] {+sneaky+}",
      mode: "words",
    });
    expect((out.warnings as string[] | undefined) ?? []).toEqual(
      expect.arrayContaining([expect.stringMatching(/diff-marker sequences/)]),
    );
  });

  it("does NOT warn on half-markers that can't actually form a parsing collision", async () => {
    // arr[-1] and {+1,} contain `[-`/`-]`/`{+`/`+}` substrings but never
    // form a complete `[-X-]` or `{+X+}` pair. The previous warning regex
    // matched halves individually and false-positived on these.
    const out = await structured({ a: "arr[-1]", b: "arr[-2]", mode: "words" });
    expect(out.warnings).toEqual([]);
  });

  it("emits a warning when context/aLabel/bLabel are passed but unused (words/chars modes)", async () => {
    const out = await structured({
      a: "hello",
      b: "world",
      mode: "chars",
      context: 5,
      aLabel: "old",
      bLabel: "new",
    });
    const warns = out.warnings as string[];
    expect(warns.some((w) => w.includes("context"))).toBe(true);
    expect(warns.some((w) => w.includes("aLabel"))).toBe(true);
  });

  it("lines mode does NOT fire the ambiguity warning, even when input contains [-/-] markers", async () => {
    // PV-2 pin: lines-mode output uses `+`/`-` prefixes, not inline
    // [-X-] markers — so the marker check is intentionally scoped to
    // words/chars modes. A line that legitimately contains the marker
    // shouldn't trigger a false alarm.
    const out = await structured({
      a: "regular line\nanother [-bracket-] line\n",
      b: "regular line\nanother {+brace+} line\n",
      mode: "lines",
    });
    const warns = (out.warnings as string[]) ?? [];
    expect(warns.some((w) => /diff-marker sequences/.test(w))).toBe(false);
  });
});
