import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";
import { jsonQueryTool } from "../../src/tools/json-query.js";

// The classic Goessner JSONPath example document.
const STORE = JSON.stringify({
  store: {
    book: [
      {
        category: "reference",
        author: "Nigel Rees",
        title: "Sayings of the Century",
        price: 8.95,
      },
      {
        category: "fiction",
        author: "Evelyn Waugh",
        title: "Sword of Honour",
        price: 12.99,
      },
      {
        category: "fiction",
        author: "Herman Melville",
        title: "Moby Dick",
        isbn: "0-553-21311-3",
        price: 8.99,
      },
      {
        category: "fiction",
        author: "J. R. R. Tolkien",
        title: "The Lord of the Rings",
        isbn: "0-395-19395-8",
        price: 22.99,
      },
    ],
    bicycle: { color: "red", price: 19.95 },
  },
});

type Args = Parameters<typeof jsonQueryTool.handler>[0];

async function run(args: Partial<Args>): Promise<CallToolResult> {
  return (await jsonQueryTool.handler({
    limit: 1000,
    input: STORE,
    ...args,
  } as Args)) as CallToolResult;
}

async function structured(args: Partial<Args>): Promise<{
  values: unknown[];
  paths: string[];
  count: number;
  truncated: boolean;
}> {
  const res = await run(args);
  expect(res.isError, JSON.stringify(res.content)).toBeFalsy();
  return res.structuredContent as never;
}

describe("json-query: goessner vectors", () => {
  it("$.store.book[*].author returns all four authors", async () => {
    const out = await structured({ query: "$.store.book[*].author" });
    expect(out.values).toEqual([
      "Nigel Rees",
      "Evelyn Waugh",
      "Herman Melville",
      "J. R. R. Tolkien",
    ]);
  });

  // Wildcards: dot-form, bracket-form, and recursive descent. Derived from
  // the STORE doc: 4 authors, 4 prices on books + 1 bicycle price = 5 prices,
  // store has 2 children (book array, bicycle object).
  it.each([
    ["$..author", 4],
    ["$..price", 5],
    ["$.store.*", 2],
    ["$.store.book[*]", 4],
    ["$.store.book.*", 4],
    ["$.store.book[*].category", 4],
  ])("recursive/wildcard query %s yields count %i", async (query, count) => {
    const out = await structured({ query });
    expect(out.count).toBe(count);
  });

  // Single-index and negative-index access, plain and via recursive descent.
  it.each([
    ["$..book[2]", "Moby Dick"],
    ["$..book[-1].title", "The Lord of the Rings"],
    ["$.store.book[0].title", "Sayings of the Century"],
    ["$.store.book[-2].title", "Moby Dick"],
    ["$['store']['book'][1]['title']", "Sword of Honour"],
  ])("index query %s selects %s", async (query, title) => {
    const out = await structured({ query });
    const v = out.values[0];
    expect(
      typeof v === "object" && v !== null ? (v as { title: string }).title : v,
    ).toBe(title);
  });

  // Indices that fall outside the array are not an error — they just match
  // nothing. (Distinct from a malformed index, which IS an error.)
  it.each([
    ["$.store.book[99].title"],
    ["$.store.book[-99].title"],
  ])("out-of-range index %s is an empty success", async (query) => {
    const out = await structured({ query });
    expect(out.count).toBe(0);
    expect(out.truncated).toBe(false);
  });

  // Slices and unions. Expectations computed by hand against the 4-book array
  // [0:Sayings, 1:Sword, 2:Moby, 3:Rings].
  it.each([
    ["$..book[:2].title", ["Sayings of the Century", "Sword of Honour"]],
    ["$..book[1:3].title", ["Sword of Honour", "Moby Dick"]],
    ["$..book[2:].title", ["Moby Dick", "The Lord of the Rings"]],
    ["$..book[0,3].title", ["Sayings of the Century", "The Lord of the Rings"]],
    ["$..book[::2].title", ["Sayings of the Century", "Moby Dick"]],
    [
      "$..book[::-1].title",
      [
        "The Lord of the Rings",
        "Moby Dick",
        "Sword of Honour",
        "Sayings of the Century",
      ],
    ],
    ["$..book[-2:].title", ["Moby Dick", "The Lord of the Rings"]],
  ])("slice/union %s", async (query, expected) => {
    expect((await structured({ query })).values).toEqual(expected);
  });

  // Filters: existence and every supported comparison operator. Book prices
  // are 8.95, 12.99, 8.99, 22.99; categories reference/fiction; isbn present
  // on books 2 and 3.
  it.each([
    ["$..book[?(@.isbn)].title", ["Moby Dick", "The Lord of the Rings"]],
    ["$..book[?(@.price < 10)].title", ["Sayings of the Century", "Moby Dick"]],
    ["$..book[?(@.price <= 8.95)].title", ["Sayings of the Century"]],
    ["$..book[?(@.price > 20)].title", ["The Lord of the Rings"]],
    [
      "$..book[?(@.price >= 12.99)].title",
      ["Sword of Honour", "The Lord of the Rings"],
    ],
    ["$..book[?(@.category == 'reference')].author", ["Nigel Rees"]],
    ["$..book[?(@.category != 'fiction')].author", ["Nigel Rees"]],
  ])("filter %s", async (query, expected) => {
    expect((await structured({ query })).values).toEqual(expected);
  });

  it("bracket child notation", async () => {
    const out = await structured({ query: "$['store']['bicycle']['color']" });
    expect(out.values).toEqual(["red"]);
  });

  // Normalized paths are always bracket-quoted regardless of the input syntax.
  it.each([
    ["$.store.book[0].title", ["$['store']['book'][0]['title']"]],
    ["$['store']['bicycle']['color']", ["$['store']['bicycle']['color']"]],
    ["$.store.book[-1].author", ["$['store']['book'][3]['author']"]],
  ])("normalizes path of %s", async (query, paths) => {
    expect((await structured({ query })).paths).toEqual(paths);
  });

  // Comparisons never coerce: "5" (string) and 5 (number) are distinct, and
  // ordering comparisons across mismatched types match nothing rather than
  // coercing.
  it.each([
    ["$[?(@.v == 5)]", [{ v: 5 }]],
    ["$[?(@.v == '5')]", [{ v: "5" }]],
    ["$[?(@.v < 6)]", [{ v: 5 }]],
    ["$[?(@.v != 5)]", [{ v: "5" }]],
  ])("comparison %s never coerces types", async (query, expected) => {
    const doc = JSON.stringify([{ v: "5" }, { v: 5 }]);
    const out = await structured({ input: doc, query });
    expect(out.values).toEqual(expected);
  });
});

describe("json-query: limits and errors", () => {
  it("applies limit and reports truncation", async () => {
    const doc = JSON.stringify(Array.from({ length: 10 }, (_, i) => i));
    const out = await structured({ input: doc, query: "$[*]", limit: 3 });
    expect(out.values).toEqual([0, 1, 2]);
    expect(out.count).toBe(10);
    expect(out.truncated).toBe(true);
  });

  // Prototype-chain keys are not own-properties of the parsed document, so
  // traversal must not descend into them (Object.hasOwn, not `in`). Each is a
  // no-match success, never a hit on Object.prototype members.
  it.each([
    ["$.__proto__"],
    ["$['__proto__'].polluted"],
    ["$.constructor"],
    ["$['constructor']['name']"],
    ["$..toString"],
    ["$.hasOwnProperty"],
  ])("does not traverse prototype-chain key %s", async (query) => {
    const out = await structured({ input: JSON.stringify({ a: 1 }), query });
    expect(out.count).toBe(0);
    expect(out.values).toEqual([]);
  });

  // A query that addresses nothing is a SUCCESS with count 0 — distinct from
  // a malformed query, which is an error (covered below).
  it.each([
    ["$.store.nonexistent"],
    ["$.store.book[?(@.price < 0)]"],
    ["$.store.book[?(@.category == 'poetry')]"],
    ["$.store.bicycle.color.nope"],
    ["$..isbn[5]"],
  ])("no-match query %s is a success with count 0", async (query) => {
    const out = await structured({ query });
    expect(out.count).toBe(0);
    expect(out.truncated).toBe(false);
    expect(out.values).toEqual([]);
  });

  // null is a VALUE, not absence: a present-null key matches, an existence
  // filter on it is true, and an == null comparison finds it.
  it.each([
    ["$.a", [null]],
    ["$[?(@.a)]", [{ a: null }]],
    ["$[?(@.a == null)]", [{ a: null }]],
  ])("treats present null as a value (%s)", async (query, expected) => {
    const doc = JSON.stringify({ a: null });
    const arrDoc = JSON.stringify([{ a: null }]);
    const out = await structured({
      input: query === "$.a" ? doc : arrDoc,
      query,
    });
    expect(out.values).toEqual(expected);
  });

  it.each([
    ["{nope", "invalid JSON"],
    ["", "invalid JSON"],
    ["[1,2,", "invalid JSON"],
    ["{'a':1}", "invalid JSON"],
    ["undefined", "invalid JSON"],
  ])("rejects invalid JSON input %s", async (input, contains) => {
    const res = await run({ input, query: "$" });
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res.content)).toContain(contains);
  });

  // Malformed / unsupported JSONPath syntax: each must be a precise error,
  // never a silent guess.
  it.each([
    ["store.book"], // missing $ root
    ["$..book[?(@.price < @.max)]"], // script expression (path on RHS)
    ["$..book[?(@.price < 10 && @.isbn)]"], // boolean connective
    ["$..book[?(@.price || @.isbn)]"], // boolean connective
    ["$.store.book["], // unterminated bracket
    ["$.store.book[]"], // empty brackets
    ["$.store.book[1:2:0]"], // slice step of 0
    ["$.store.book[abc]"], // non-numeric index
    ["$.store.book[1.5]"], // non-integer index
    ["$..book[?(@.price =~ /x/)]"], // regex operator (unsupported)
  ])("rejects malformed/unsupported query %s", async (query) => {
    const res = await run({ query });
    expect(res.isError, `expected error for ${query}`).toBe(true);
  });

  it("reports unsupported-filter errors specifically", async () => {
    const res = await run({ query: "$..book[?(@.price < @.max)]" });
    expect(JSON.stringify(res.content)).toContain("unsupported filter");
  });

  it("requires exactly one of input / inputUrl", async () => {
    expect((await run({ input: undefined, query: "$" })).isError).toBe(true);
    expect(
      (await run({ inputUrl: "http://localhost/x", query: "$" })).isError,
    ).toBe(true);
  });

  it("filters accept bracket-notation steps inside the path expression", async () => {
    const res = await run({
      input: JSON.stringify([{ a: 1, b: 2 }, { a: 3 }]),
      query: "$[?(@['a'] == 1)]",
    });
    expect(res.isError, JSON.stringify(res.content)).toBeFalsy();
    const out = res.structuredContent as { values: unknown[] };
    expect(out.values).toEqual([{ a: 1, b: 2 }]);
  });

  it("filters accept numeric bracket-index steps inside the path expression", async () => {
    const res = await run({
      input: JSON.stringify([{ row: [10] }, { row: [1] }]),
      query: "$[?(@.row[0] == 1)]",
    });
    expect(res.isError, JSON.stringify(res.content)).toBeFalsy();
    const out = res.structuredContent as { values: unknown[] };
    expect(out.values).toEqual([{ row: [1] }]);
  });

  it("recursive descent handles wide (200k-sibling) documents without push-spread overflow", () => {
    // Old descendants used `out.push(...descendants(child))` which is O(N²)
    // for wide nodes and overflows the call stack via spread above ~125k
    // siblings. Iterative form should handle 200k cleanly.
    const root = {
      children: Array.from({ length: 200_000 }, (_, i) => ({ n: i })),
    };
    expect(() =>
      jsonQueryTool.handler({
        input: JSON.stringify(root),
        query: "$..n",
        limit: 1,
      }),
    ).not.toThrow();
  });
});
