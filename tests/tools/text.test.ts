import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";
import { textTool } from "../../src/tools/text.js";

type Args = Parameters<typeof textTool.handler>[0];

async function run(args: Partial<Args>): Promise<CallToolResult> {
  return (await textTool.handler({
    separator: "-",
    order: "asc",
    numeric: false,
    unique: false,
    ...args,
  } as Args)) as CallToolResult;
}

async function result(args: Partial<Args>): Promise<string> {
  const res = await run(args);
  expect(res.isError, JSON.stringify(res.content)).toBeFalsy();
  return (res.structuredContent as { result: string }).result;
}

describe("text: case", () => {
  // All nine targets across "swiss_knife McpServer". upper/lower operate on the
  // raw input (no word-splitting), hence they keep the underscore/space.
  const CASES: Array<[Args["target"], string]> = [
    ["camel", "swissKnifeMcpServer"],
    ["pascal", "SwissKnifeMcpServer"],
    ["snake", "swiss_knife_mcp_server"],
    ["screaming-snake", "SWISS_KNIFE_MCP_SERVER"],
    ["kebab", "swiss-knife-mcp-server"],
    ["title", "Swiss Knife Mcp Server"],
    ["sentence", "Swiss knife mcp server"],
    ["upper", "SWISS_KNIFE MCPSERVER"],
    ["lower", "swiss_knife mcpserver"],
  ];
  it.each(CASES)("converts mixed input to %s", async (target, expected) => {
    expect(
      await result({ action: "case", input: "swiss_knife McpServer", target }),
    ).toBe(expected);
  });

  // Acronym/camel-hump splitting across every target. Expected values derived
  // from an independent reimplementation of splitWords.
  const ACRONYM: Array<[Args["target"], string]> = [
    ["camel", "parseHttpResponse"],
    ["pascal", "ParseHttpResponse"],
    ["snake", "parse_http_response"],
    ["screaming-snake", "PARSE_HTTP_RESPONSE"],
    ["kebab", "parse-http-response"],
    ["title", "Parse Http Response"],
    ["sentence", "Parse http response"],
    ["upper", "PARSEHTTPRESPONSE"],
    ["lower", "parsehttpresponse"],
  ];
  it.each(ACRONYM)(
    "splits camel humps/acronyms for %s",
    async (target, expected) => {
      expect(
        await result({ action: "case", input: "parseHTTPResponse", target }),
      ).toBe(expected);
    },
  );

  // case requires a target — distinct failure mode.
  it("rejects missing target", async () => {
    expect((await run({ action: "case", input: "anything" })).isError).toBe(
      true,
    );
  });
});

describe("text: slugify", () => {
  // Diacritic transliteration + punctuation stripping with the default "-".
  const DEFAULT_SEP: Array<[string, string]> = [
    ["Crème Brûlée — Recipe!", "creme-brulee-recipe"],
    ["Über Café 123", "uber-cafe-123"],
    ["ABC_def-GHI", "abc-def-ghi"],
    ["Hello World", "hello-world"],
    ["  !!!  ", ""],
  ];
  it.each(DEFAULT_SEP)("slugifies %j to %j", async (input, expected) => {
    expect(await result({ action: "slugify", input })).toBe(expected);
  });

  // Custom separators, including ones that look like regex-replacement
  // patterns ($$, $&) which must be inserted verbatim.
  const SEP_CASES: Array<[string, string, string]> = [
    ["Hello World", "_", "hello_world"],
    ["héllo wörld", "", "helloworld"],
    ["héllo wörld", "$$", "hello$$world"],
    ["héllo wörld", "$&", "hello$&world"],
  ];
  it.each(SEP_CASES)(
    "slugifies %j with separator %j to %j",
    async (input, separator, expected) => {
      expect(await result({ action: "slugify", input, separator })).toBe(
        expected,
      );
    },
  );
});

describe("text: lines", () => {
  // sort-lines across order/numeric/unique combinations. Expected outputs
  // derived from an independent reimplementation.
  const SORT: Array<[string, Partial<Args>, string]> = [
    ["b\na\nc", {}, "a\nb\nc"],
    ["b\na\nc", { order: "desc" }, "c\nb\na"],
    ["10\n9\n2", { numeric: true }, "2\n9\n10"],
    ["10\n9\n2", { numeric: true, order: "desc" }, "10\n9\n2"],
    ["1.5\n1.25\n1.1", { numeric: true }, "1.1\n1.25\n1.5"],
    ["b\na\nb", { unique: true }, "a\nb"],
    // sort + unique: unsorted input with repeats collapses to sorted distinct.
    [
      "banana\napple\ncherry\napple\nbanana",
      { unique: true },
      "apple\nbanana\ncherry",
    ],
    // unique with descending order still drops duplicates.
    ["banana\napple\napple", { unique: true, order: "desc" }, "banana\napple"],
    // negative case: unique on input with no duplicates is a plain sort.
    ["c\nb\na", { unique: true }, "a\nb\nc"],
    // unique without the flag (default false) keeps duplicates.
    ["b\na\nb", {}, "a\nb\nb"],
    ["c\nb\na\n", {}, "a\nb\nc\n"],
    ["c\nb\na", {}, "a\nb\nc"],
  ];
  it.each(SORT)(
    "sort-lines %j with %j gives %j",
    async (input, opts, expected) => {
      expect(await result({ action: "sort-lines", input, ...opts })).toBe(
        expected,
      );
    },
  );

  // dedupe-lines preserving first-seen order. Each case asserts both the
  // result and the count of removed duplicates.
  const DEDUPE: Array<[string, string, number]> = [
    ["x\ny\nx\nz\n", "x\ny\nz\n", 1],
    ["a\na\na", "a", 2],
    ["1\n2\n3", "1\n2\n3", 0],
    ["dup\ndup\nuniq\ndup", "dup\nuniq", 2],
  ];
  it.each(DEDUPE)(
    "dedupe-lines %j gives %j (removed %i)",
    async (input, expected, removed) => {
      const res = await run({ action: "dedupe-lines", input });
      expect((res.structuredContent as { result: string }).result).toBe(
        expected,
      );
      expect((res.structuredContent as { removed: number }).removed).toBe(
        removed,
      );
    },
  );
});

describe("text: count", () => {
  // characters = code points, utf16Units = JS .length, bytes = UTF-8 byte
  // length, words = \S+ runs, lines = non-empty-trailing-aware line count,
  // uniqueLines = distinct lines. All computed independently.
  interface Counts {
    characters: number;
    utf16Units: number;
    bytes: number;
    words: number;
    lines: number;
    uniqueLines: number;
  }
  const CASES: Array<[string, Counts]> = [
    [
      "héllo 🚀\nsecond line\n",
      {
        characters: 20,
        utf16Units: 21,
        bytes: 24,
        words: 4,
        lines: 2,
        uniqueLines: 2,
      },
    ],
    [
      "",
      {
        characters: 0,
        utf16Units: 0,
        bytes: 0,
        words: 0,
        lines: 0,
        uniqueLines: 0,
      },
    ],
    [
      "a",
      {
        characters: 1,
        utf16Units: 1,
        bytes: 1,
        words: 1,
        lines: 1,
        uniqueLines: 1,
      },
    ],
    [
      "alpha beta\ngamma",
      {
        characters: 16,
        utf16Units: 16,
        bytes: 16,
        words: 3,
        lines: 2,
        uniqueLines: 2,
      },
    ],
    [
      "dup\ndup\nx",
      {
        characters: 9,
        utf16Units: 9,
        bytes: 9,
        words: 3,
        lines: 3,
        uniqueLines: 2,
      },
    ],
    [
      // ZWJ-less family of code points: 👍 + skin-tone modifier = 2 code points,
      // 4 UTF-16 units, 8 UTF-8 bytes.
      "👍🏽",
      {
        characters: 2,
        utf16Units: 4,
        bytes: 8,
        words: 1,
        lines: 1,
        uniqueLines: 1,
      },
    ],
  ];
  it.each(CASES)("counts %j correctly", async (input, expected) => {
    const out = (await run({ action: "count", input }))
      .structuredContent as unknown as Counts;
    expect(out).toMatchObject(expected);
  });
});

describe("text: escape / unescape", () => {
  // JSON string-body escaping (JSON.stringify minus the surrounding quotes).
  const JSON_ESCAPE: Array<[string, string]> = [
    ['say "hi"\nplease', 'say \\"hi\\"\\nplease'],
    ["tab\there", "tab\\there"],
    ["back\\slash", "back\\\\slash"],
    ["plain text", "plain text"],
  ];
  it.each(JSON_ESCAPE)("escapes json %j -> %j", async (input, expected) => {
    expect(await result({ action: "escape", input, style: "json" })).toBe(
      expected,
    );
  });

  // JSON escape -> unescape round-trip.
  const JSON_ROUNDTRIP = [
    'say "hi"\nplease',
    "tab\there",
    "back\\slash",
    "emoji 🚀 ok",
  ];
  it.each(JSON_ROUNDTRIP)(
    "json escape/unescape round-trips %j",
    async (orig) => {
      const escaped = await result({
        action: "escape",
        input: orig,
        style: "json",
      });
      expect(
        await result({ action: "unescape", input: escaped, style: "json" }),
      ).toBe(orig);
    },
  );

  // POSIX shell single-quoting.
  const SHELL: Array<[string, string]> = [
    ["it's $HOME", `'it'\\''s $HOME'`],
    ["plain", `'plain'`],
    ["a'b'c", `'a'\\''b'\\''c'`],
  ];
  it.each(SHELL)("escapes shell-posix %j -> %j", async (input, expected) => {
    expect(
      await result({ action: "escape", input, style: "shell-posix" }),
    ).toBe(expected);
  });

  // Regex metacharacter escape, and its round-trip via unescape.
  const REGEX: Array<[string, string]> = [
    ["1+1=2 (maybe?)", "1\\+1=2 \\(maybe\\?\\)"],
    ["a.b[c]", "a\\.b\\[c\\]"],
    ["^$|*", "\\^\\$\\|\\*"],
    ["no meta", "no meta"],
  ];
  it.each(REGEX)("escapes regex %j -> %j", async (input, expected) => {
    expect(await result({ action: "escape", input, style: "regex" })).toBe(
      expected,
    );
  });
  it.each(REGEX)("unescapes regex %j -> %j", async (plain, escaped) => {
    expect(
      await result({ action: "unescape", input: escaped, style: "regex" }),
    ).toBe(plain);
  });

  // Distinct failure modes for escape/unescape.
  const INVALID: Array<[string, Partial<Args>]> = [
    [
      "shell-posix unescape unsupported",
      { action: "unescape", input: "'x'", style: "shell-posix" },
    ],
    ["escape requires style", { action: "escape", input: "x" }],
    ["unescape requires style", { action: "unescape", input: "x" }],
    [
      "json unescape of malformed body",
      { action: "unescape", input: "bad\\q", style: "json" },
    ],
  ];
  it.each(INVALID)("rejects %s", async (_label, args) => {
    expect((await run(args)).isError).toBe(true);
  });
});

describe("text: edge cases", () => {
  it("case conversion preserves non-ASCII letters and emoji-adjacent text", async () => {
    expect(
      await result({
        action: "case",
        input: "café naïve über",
        target: "snake",
      }),
    ).toBe("café_naïve_über");
  });
  it("slugify with empty separator concatenates without crashing", async () => {
    expect(
      await result({
        action: "slugify",
        input: "héllo wörld",
        separator: "",
      }),
    ).toBe("helloworld");
  });
  it("slugify with a $-bearing separator inserts it literally (no replacement-pattern injection)", async () => {
    expect(
      await result({
        action: "slugify",
        input: "héllo wörld",
        separator: "$$",
      }),
    ).toBe("hello$$world");
    expect(
      await result({
        action: "slugify",
        input: "héllo wörld",
        separator: "$&",
      }),
    ).toBe("hello$&world");
  });
  it("dedupe-lines on empty input returns empty (no fabricated newline)", async () => {
    const res = await run({ action: "dedupe-lines", input: "" });
    expect(res.isError).toBeFalsy();
    expect(
      (res.structuredContent as { result: string; lineCount: number }).result,
    ).toBe("");
    expect((res.structuredContent as { lineCount: number }).lineCount).toBe(0);
  });

  it("sort-lines preserves a trailing newline when present (parity with dedupe-lines)", async () => {
    const res = await run({ action: "sort-lines", input: "c\nb\na\n" });
    expect(res.isError).toBeFalsy();
    const s = res.structuredContent as { result: string };
    expect(s.result).toBe("a\nb\nc\n");
  });

  it("sort-lines on input without a trailing newline keeps it absent", async () => {
    const res = await run({ action: "sort-lines", input: "c\nb\na" });
    expect((res.structuredContent as { result: string }).result).toBe(
      "a\nb\nc",
    );
  });

  it("count's structuredContent includes a `result` field (parity with other text actions)", async () => {
    const res = await run({ action: "count", input: "alpha beta\ngamma" });
    expect(res.isError).toBeFalsy();
    const s = res.structuredContent as { result: string; words: number };
    expect(typeof s.result).toBe("string");
    expect(s.words).toBe(3);
  });

  it("normalize NFC collapses decomposed sequences to composed form", async () => {
    // "é" can be composed (U+00E9) or decomposed (U+0065 U+0301). NFC
    // converts to the composed form.
    const decomposed = "é";
    const res = await run({ action: "normalize", input: decomposed });
    expect(res.isError).toBeFalsy();
    expect((res.structuredContent as { result: string }).result).toBe("é");
    expect((res.structuredContent as { result: string }).result.length).toBe(1);
  });

  // trim across both/start/end and a range of whitespace inputs (spaces,
  // tabs, newlines, and the no-op case). Expected values computed via JS
  // trim/trimStart/trimEnd.
  const TRIM: Array<[string, Args["side"] | undefined, string]> = [
    ["  hello  ", undefined, "hello"],
    ["  hello  ", "both", "hello"],
    ["  hello  ", "start", "hello  "],
    ["  hello  ", "end", "  hello"],
    ["\t\n x \t", "both", "x"],
    ["\t\n x \t", "start", "x \t"],
    ["\t\n x \t", "end", "\t\n x"],
    ["no-pad", "both", "no-pad"],
  ];
  it.each(TRIM)("trim %j side=%s gives %j", async (input, side, expected) => {
    const out = await run(
      side === undefined
        ? { action: "trim", input }
        : { action: "trim", input, side },
    );
    expect((out.structuredContent as { result: string }).result).toBe(expected);
  });

  // replace is literal (no regex semantics): `find` is matched verbatim and
  // every occurrence is replaced. result + replacement count derived from a
  // split-based reimplementation.
  const REPLACE: Array<[string, string, string, string, number]> = [
    // `.` is a regex metachar but here matched literally → all dots replaced.
    ["a.b.c", ".", "/", "a/b/c", 2],
    ["aaa", "a", "b", "bbb", 3],
    ["xyz", "q", "z", "xyz", 0],
    ["one two one", "one", "1", "1 two 1", 2],
    ["a.*b", ".*", "X", "aXb", 1],
  ];
  it.each(REPLACE)(
    "replace %j find=%j replacement=%j -> %j (%i)",
    async (input, find, replacement, expected, count) => {
      const out = await run({ action: "replace", input, find, replacement });
      expect((out.structuredContent as { result: string }).result).toBe(
        expected,
      );
      expect(
        (out.structuredContent as { replacements: number }).replacements,
      ).toBe(count);
    },
  );

  // Distinct failure modes for replace: missing find, missing replacement,
  // and empty find.
  const REPLACE_INVALID: Array<[string, Partial<Args>]> = [
    ["missing find and replacement", { action: "replace", input: "x" }],
    ["missing replacement", { action: "replace", input: "x", find: "x" }],
    [
      "empty find",
      { action: "replace", input: "abc", find: "", replacement: "x" },
    ],
  ];
  it.each(REPLACE_INVALID)("replace rejects %s", async (_label, args) => {
    expect((await run(args)).isError).toBe(true);
  });

  it("title-case strips non-alphanumeric punctuation (documented asymmetry vs upper/lower)", async () => {
    // `splitWords` discards everything that isn't a letter or digit before
    // rejoining — so "hello, world!" becomes "Hello World", losing the
    // comma and exclamation. This is undesirable but documented; pin it.
    const res = await run({
      action: "case",
      input: "hello, world!",
      target: "title",
    });
    expect((res.structuredContent as { result: string }).result).toBe(
      "Hello World",
    );
  });
});
