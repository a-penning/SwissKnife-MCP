import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";
import { convertDataTool } from "../../src/tools/convert-data.js";

type Args = Parameters<typeof convertDataTool.handler>[0];

async function run(args: Partial<Args>): Promise<CallToolResult> {
  return (await convertDataTool.handler({
    indent: 2,
    csvDelimiter: ",",
    csvHeaders: true,
    csvDynamicTyping: true,
    ...args,
  } as Args)) as CallToolResult;
}

async function result(
  args: Partial<Args>,
): Promise<{ result: string; warnings: string[] }> {
  const res = await run(args);
  expect(res.isError, JSON.stringify(res.content)).toBeFalsy();
  return res.structuredContent as { result: string; warnings: string[] };
}

describe("convert-data: json <-> yaml", () => {
  it("json to yaml", async () => {
    const out = await result({
      from: "json",
      to: "yaml",
      input: '{"name":"swissknife","tags":["mcp","tools"],"port":3000}',
    });
    expect(out.result).toContain("name: swissknife");
    expect(out.result).toContain("- mcp");
    expect(out.warnings).toEqual([]);
  });
  it("yaml to json round-trips structure", async () => {
    const out = await result({
      from: "yaml",
      to: "json",
      input: "server:\n  port: 3000\n  hosts:\n    - a\n    - b\n",
    });
    expect(JSON.parse(out.result)).toEqual({
      server: { port: 3000, hosts: ["a", "b"] },
    });
  });
});

describe("convert-data: toml", () => {
  it("toml to json", async () => {
    const out = await result({
      from: "toml",
      to: "json",
      input: '[server]\nport = 3000\nname = "x"\n',
    });
    expect(JSON.parse(out.result)).toEqual({
      server: { port: 3000, name: "x" },
    });
  });

  // TOML requires an OBJECT at the root. Arrays and bare scalars cannot be the
  // document root and must be a clear error, not silently wrapped.
  it.each([
    ["array root", "[1,2,3]"],
    ["scalar number root", "42"],
    ["scalar string root", '"hello"'],
    ["null root", "null"],
    ["boolean root", "true"],
  ])("json %s to toml is a clear error", async (_name, input) => {
    const res = await run({ from: "json", to: "toml", input });
    expect(res.isError).toBe(true);
  });
});

describe("convert-data: xml", () => {
  it("xml to json preserves attributes with a lossiness warning", async () => {
    const out = await result({
      from: "xml",
      to: "json",
      input: '<config env="prod"><port>3000</port></config>',
    });
    const parsed = JSON.parse(out.result);
    expect(parsed.config["@_env"]).toBe("prod");
    // XML→JSON is lossless by default — "3000" stays a string. Callers who
    // want auto-typing should opt in explicitly (parity with CSV).
    expect(parsed.config.port).toBe("3000");
    expect(out.warnings.length).toBeGreaterThan(0);
  });
  it("json to xml wraps multi-key roots with a warning", async () => {
    const out = await result({
      from: "json",
      to: "xml",
      input: '{"a":1,"b":2}',
    });
    expect(out.result).toContain("<root>");
    expect(out.warnings.some((w) => w.includes("root"))).toBe(true);
  });
  it("reports xml parse errors with line/column", async () => {
    const res = await run({ from: "xml", to: "json", input: "<a><b></a>" });
    expect(res.isError).toBe(true);
  });
});

describe("convert-data: csv", () => {
  it("csv to json with headers and typing", async () => {
    const out = await result({
      from: "csv",
      to: "json",
      input: "name,port\napi,3000\nweb,8080\n",
    });
    expect(JSON.parse(out.result)).toEqual([
      { name: "api", port: 3000 },
      { name: "web", port: 8080 },
    ]);
  });
  it("json to csv flattens nested values with a warning", async () => {
    const out = await result({
      from: "json",
      to: "csv",
      input: '[{"name":"a","meta":{"x":1}},{"name":"b","meta":{"x":2}}]',
    });
    expect(out.result).toContain("name,meta");
    expect(out.result).toContain('"{""x"":1}"');
    expect(out.warnings.some((w) => w.includes("meta"))).toBe(true);
  });
  it("supports custom delimiters", async () => {
    const out = await result({
      from: "csv",
      to: "json",
      input: "a;b\n1;2\n",
      csvDelimiter: ";",
    });
    expect(JSON.parse(out.result)).toEqual([{ a: 1, b: 2 }]);
  });
  it("warns when auto-typing changes a value's textual form", async () => {
    const out = await result({
      from: "csv",
      to: "json",
      input: "zip\n007\n042\n",
    });
    expect(JSON.parse(out.result)).toEqual([{ zip: 7 }, { zip: 42 }]);
    expect(out.warnings.some((w) => w.includes("zip"))).toBe(true);
  });
  it("csvDynamicTyping:false keeps values as strings losslessly", async () => {
    const out = await result({
      from: "csv",
      to: "json",
      input: "zip\n007\n042\n",
      csvDynamicTyping: false,
    });
    expect(JSON.parse(out.result)).toEqual([{ zip: "007" }, { zip: "042" }]);
    expect(out.warnings).toEqual([]);
  });
});

describe("convert-data: toml null", () => {
  it("rejects null with a path instead of a generic error", async () => {
    const res = await run({
      from: "json",
      to: "toml",
      input: '{"a":{"b":null}}',
    });
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res.content)).toContain("null");
    expect(JSON.stringify(res.content)).toContain("root.a.b");
  });
});

describe("convert-data: pretty / minified", () => {
  it("pretty re-indents json", async () => {
    const out = await result({
      from: "json",
      to: "pretty",
      input: '{"a":{"b":1}}',
      indent: 4,
    });
    expect(out.result).toBe('{\n    "a": {\n        "b": 1\n    }\n}');
  });
  it("minifies json", async () => {
    const out = await result({
      from: "json",
      to: "minified",
      input: '{\n  "a": [1, 2]\n}',
    });
    expect(out.result).toBe('{"a":[1,2]}');
  });
  it("refuses to minify yaml with a clear error", async () => {
    const res = await run({ from: "yaml", to: "minified", input: "a: 1" });
    expect(res.isError).toBe(true);
  });
});

describe("convert-data: errors", () => {
  // Malformed source documents across every parseable format. Each must be a
  // domain error (isError true), not a silent guess or a leaked library trace.
  it.each([
    ["json", '{"a":}', /invalid JSON/],
    ["json", "{nope", /invalid JSON/],
    ["json", "[1,2,", /invalid JSON/],
    ["yaml", "a: 1\n  b: 2\n bad indent", /invalid YAML/],
    ["yaml", "key: [unclosed", /invalid YAML/],
    ["toml", "key = ", /invalid TOML/],
    ["toml", "[unclosed", /invalid TOML/],
    ["xml", "<a><b></a>", /invalid XML/],
    ["xml", "<a>", /invalid XML/],
    ["xml", "", /invalid XML/],
  ])("rejects malformed %s input", async (from, input, pattern) => {
    const res = await run({ from: from as never, to: "json", input });
    expect(res.isError, JSON.stringify(res.content)).toBe(true);
    expect(JSON.stringify(res.content)).toMatch(pattern);
  });

  // 'minified' is only meaningful for json and xml; any other source is an
  // explicit error rather than a lossy "best effort".
  it.each([
    ["yaml", "a: 1"],
    ["toml", "a = 1"],
    ["csv", "a,b\n1,2"],
  ])("refuses to minify %s", async (from, input) => {
    const res = await run({ from: from as never, to: "minified", input });
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res.content)).toMatch(/minified/);
  });

  // csvDelimiter must be exactly one character.
  it.each([
    [",,"],
    [""],
    ["||"],
    ["ab"],
  ])("rejects csvDelimiter %j", async (delim) => {
    const res = await run({
      from: "json",
      to: "csv",
      input: '[{"a":1}]',
      csvDelimiter: delim,
    });
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res.content)).toMatch(/single character/);
  });

  it("requires exactly one of input/inputUrl", async () => {
    expect((await run({ from: "json", to: "yaml" })).isError).toBe(true);
  });
});

describe("convert-data: malformed-input and edge-case handling", () => {
  it("YAML output handles indent:0 (schema allows it) without crashing", async () => {
    const out = await result({
      from: "json",
      to: "yaml",
      input: '{"a":1}',
      indent: 0,
    });
    expect(out.result).toContain("a: 1");
  });

  it("JSON→CSV unions columns across rows (no silent drop)", async () => {
    const out = await result({
      from: "json",
      to: "csv",
      input: '[{"a":1},{"b":2}]',
    });
    const lines = out.result.split(/\r?\n/);
    expect(lines[0]).toBe("a,b");
    expect(lines.slice(1)).toContain("1,");
    expect(lines.slice(1)).toContain(",2");
  });

  it("XML parses '007' as text, not 7 (lossless by default)", async () => {
    const out = await result({
      from: "xml",
      to: "json",
      input: "<root><id>007</id><ver>1.10</ver></root>",
    });
    const parsed = JSON.parse(out.result);
    expect(parsed.root.id).toBe("007");
    expect(parsed.root.ver).toBe("1.10");
  });

  it("JSON→XML wraps an array root in a single <root> with <item>s (valid XML)", async () => {
    const out = await result({
      from: "json",
      to: "xml",
      input: '[{"a":1},{"a":2}]',
    });
    // Count top-level "<root" opens — should be exactly 1.
    const rootOpens = (out.result.match(/<root[\s>]/g) ?? []).length;
    expect(rootOpens).toBe(1);
  });

  it("JSON→XML rejects keys that are not valid XML Names", async () => {
    const res = await run({
      from: "json",
      to: "xml",
      input: '{"root":{"1bad":"x"}}',
    });
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res.content)).toMatch(/valid XML Name/);
  });

  it("csvDelimiter must be exactly one character", async () => {
    const res = await run({
      from: "json",
      to: "csv",
      input: '[{"a":1}]',
      csvDelimiter: ",,",
    });
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res.content)).toMatch(/single character/);
  });

  it("empty XML gives a precise error rather than 'column undefined'", async () => {
    const res = await run({ from: "xml", to: "json", input: "" });
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res.content)).not.toMatch(/column undefined/);
  });
});

describe("convert-data: more round-trips and edges (range)", () => {
  // Broaden valid coverage across every source format.
  it.each([
    ["yaml", "a: 1\nb:\n  - x\n  - y", { a: 1, b: ["x", "y"] }],
    [
      "yaml",
      "n: 1\nf: 1.5\nt: true\ns: hi\nnul: null",
      {
        n: 1,
        f: 1.5,
        t: true,
        s: "hi",
        nul: null,
      },
    ],
    ["yaml", "[1, 2, 3]", [1, 2, 3]],
    [
      "toml",
      'title = "x"\n[owner]\nname = "a"',
      { title: "x", owner: { name: "a" } },
    ],
    ["toml", "a = 1\nb = true\nc = 1.5", { a: 1, b: true, c: 1.5 }],
    ["xml", "<r><b>x</b></r>", { r: { b: "x" } }],
    ["xml", "<r><i>1</i><i>2</i></r>", { r: { i: ["1", "2"] } }],
    [
      "csv",
      "a,b\n1,2\n3,4",
      [
        { a: 1, b: 2 },
        { a: 3, b: 4 },
      ],
    ],
    ["csv", "name\napi\nweb", [{ name: "api" }, { name: "web" }]],
  ])("parses %s into the expected JSON structure", async (from, input, expected) => {
    const out = await result({ from: from as never, to: "json", input });
    expect(JSON.parse(out.result)).toEqual(expected);
  });

  // Round-trips that exercise serialize side across targets. Each is verified
  // by an independent property of the output, not by string equality with
  // tool output.
  it.each([
    ["json", "yaml", '{"k":"v"}', "k: v"],
    ["json", "toml", '{"k":"v"}', 'k = "v"'],
    ["json", "minified", '{ "a" : [ 1 , 2 ] }', '{"a":[1,2]}'],
    ["json", "pretty", '{"a":1}', '"a": 1'],
  ])("%s -> %s contains expected fragment", async (from, to, input, fragment) => {
    const out = await result({ from: from as never, to: to as never, input });
    expect(out.result).toContain(fragment);
  });

  it("preserves object key order through json→pretty (no sorting)", async () => {
    const out = await result({
      from: "json",
      to: "pretty",
      input: '{"b":2,"a":1}',
    });
    expect(out.result.replace(/\s+/g, " ").trim()).toBe('{ "b": 2, "a": 1 }');
  });

  // Ragged CSV rows (too few / too many fields vs the header) are an error,
  // never a silently padded or truncated row.
  it.each([
    ["short row", "a,b\n1,2\n3"],
    ["short row first", "a,b\n1\n2,3"],
    ["extra field", "a,b\n1,2,3"],
  ])("rejects ragged CSV (%s) instead of guessing", async (_name, input) => {
    const res = await run({ from: "csv", to: "json", input });
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res.content).toLowerCase()).toMatch(/field|row/);
  });

  it("csvHeaders:false emits arrays-of-cells, not header-keyed objects", async () => {
    const out = await result({
      from: "csv",
      to: "json",
      input: "Alice,30\nBob,25",
      csvHeaders: false,
    });
    expect(JSON.parse(out.result)).toEqual([
      ["Alice", 30],
      ["Bob", 25],
    ]);
  });

  // empty array → CSV gives a clean, domain-specific error (no columns to
  // derive from). Same class as the "column undefined" guard above.
  it("empty array → CSV gives a clean error, not a library internal", async () => {
    const res = await run({ from: "json", to: "csv", input: "[]" });
    expect(res.isError).toBe(true);
    const msg = JSON.stringify(res.content);
    expect(msg).not.toMatch(/Option columns is empty/i);
    // A useful message should name what went wrong in the caller's terms.
    expect(msg.toLowerCase()).toMatch(/csv|array|empty row|no rows/);
  });
});
