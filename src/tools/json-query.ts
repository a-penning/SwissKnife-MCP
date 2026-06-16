import { z } from "zod";
import { toMessage } from "../lib/errors.js";
import { resolveTextInput } from "../lib/input.js";
import { type JsonValue, queryJsonPath } from "../lib/jsonpath.js";
import { defineTool, err, ok } from "./types.js";

export const jsonQueryTool = defineTool({
  name: "json-query",
  title: "JSON query",
  description:
    "Pull values out of a JSON document using a JSONPath expression. Use this when you have a JSON blob and want to extract specific parts (a field, every element in an array, every node matching a filter) without writing code to walk the structure yourself.\n" +
    "\n" +
    "Each match comes back as both the value and its normalised path, so you can tell which entry came from where. The `query` always starts with `$` (the document root).\n" +
    "\n" +
    "Supported syntax: child access (`.name`, `['name']`), indexing (`[0]`, `[-1]`), unions (`[0,2]`, `['a','b']`), slices (`[start:end:step]`), wildcards (`.*`, `[*]`), recursive descent (`..`), existence filters (`[?(@.path)]`), and comparison filters (`[?(@.price < 10)]` with `== != < <= > >=` against string / number / boolean / null literals).\n" +
    "\n" +
    "Examples:\n" +
    '  { "input": "{\\"users\\":[{\\"name\\":\\"ada\\"},{\\"name\\":\\"grace\\"}]}", "query": "$.users[*].name" }\n' +
    '  { "inputUrl": "https://…/data.json", "query": "$.store.book[?(@.price < 10)].title" }\n' +
    '  { "input": "[1,2,3,4,5]", "query": "$[-2:]" }',
  inputSchema: {
    query: z
      .string()
      .regex(/^\$/, "JSONPath must start with $ (the document root)")
      .describe(
        "JSONPath expression, e.g. $.store.book[?(@.price < 10)].title",
      ),
    input: z.string().optional().describe("the JSON document text"),
    inputUrl: z
      .string()
      .optional()
      .describe("fetch the JSON document from this URL"),
    limit: z.coerce
      .number()
      .int()
      .min(1)
      .max(10_000)
      .default(1000)
      .describe("maximum matches to return"),
  },
  outputSchema: {
    values: z.array(z.unknown()).describe("matched values, document order"),
    paths: z
      .array(z.string())
      .describe("normalized path of each match, e.g. $['a'][0]"),
    count: z
      .number()
      .describe(
        "total matches the query produced (before applying `limit`). If `count > limit`, `truncated` is true and `values`/`paths` carry the first `limit` results.",
      ),
    truncated: z.boolean(),
  },
  handler: async (args) => {
    try {
      const text = await resolveTextInput(args.input, args.inputUrl);
      let root: JsonValue;
      try {
        root = JSON.parse(text) as JsonValue;
      } catch (e) {
        return err(`invalid JSON input: ${toMessage(e)}`);
      }
      const matches = queryJsonPath(root, args.query);
      const truncated = matches.length > args.limit;
      const kept = truncated ? matches.slice(0, args.limit) : matches;
      const values = kept.map((m) => m.value);
      // Always render the array form in the text field, even for a single
      // match. The structuredContent.values shape is *always* an array;
      // unwrapping for n=1 in text made callers branch on input length.
      const summary = JSON.stringify(values, null, 2);
      const headline = `${matches.length} match${matches.length === 1 ? "" : "es"}${truncated ? ` (showing first ${args.limit})` : ""}`;
      return ok(`${headline}\n${summary}`, {
        values,
        paths: kept.map((m) => m.path),
        count: matches.length,
        truncated,
      });
    } catch (e) {
      return err(toMessage(e));
    }
  },
});
