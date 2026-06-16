import { z } from "zod";
import { toMessage } from "../lib/errors.js";
import { resolveTextInput } from "../lib/input.js";
import { type RegexResult, runRegex } from "../lib/safe-regex.js";
import { createSemaphore, maxConcurrentFromEnv } from "../lib/semaphore.js";
import { defineTool, err, ok, okJson } from "./types.js";

const TIME_BUDGET_MS = 2000;
const MAX_INPUT_CHARS = 2_000_000;

// Each run spawns a worker thread; cap concurrency so a burst of calls can't
// fork an unbounded number of workers.
const regexSemaphore = createSemaphore(maxConcurrentFromEnv());

export const regexTool = defineTool({
  name: "regex",
  title: "Regex match, replace & split",
  description:
    "Test, replace, or split with a regular expression. Use this when you want to see what a pattern matches in a body of text, when you need to find/replace with capture-group substitution, or when you want to split on a pattern. Patterns use JavaScript (ECMAScript) semantics — supports named groups, lookbehind, and the Unicode `u`/`v` flags. Catastrophic backtracking is bounded by a worker-side timeout so the server doesn't hang.\n" +
    "\n" +
    "Actions:\n" +
    "  • 'match' — every match (or the first, if you omit the `g` flag). Each one comes back as `{ match, index, end, captures, groups }`.\n" +
    "  • 'replace' — substitution with $1..$9, $<name>, $&, $`, $', $$ tokens. Returns the replacement count plus the new string.\n" +
    "  • 'split' — split on the pattern (JS semantics: capturing groups are interleaved into the output).\n" +
    "\n" +
    "Source is inline (`input`) or pulled from a URL (`inputUrl`).\n" +
    "\n" +
    "Examples:\n" +
    '  { "action": "match", "pattern": "\\\\b(\\\\w+)@(\\\\w+)", "input": "alice@example.com, bob@test.org" }\n' +
    '  { "action": "replace", "pattern": "(\\\\w+)@(\\\\w+)", "replacement": "$1 at $2", "input": "alice@example" }\n' +
    '  { "action": "split", "pattern": "\\\\s*,\\\\s*", "input": "a, b ,c,  d" }',
  inputSchema: {
    action: z.enum(["match", "replace", "split"]),
    pattern: z.string(),
    flags: z
      .string()
      .regex(/^[gimsuyvd]*$/, "flags must be a subset of gimsuyvd")
      .default("g")
      .describe(
        "subset of gimsuyvd; defaults to 'g' (match/replace all). Pass '' explicitly for first-match-only semantics.",
      ),
    input: z.string().optional(),
    inputUrl: z
      .string()
      .optional()
      .describe("fetch the text to test against from this URL"),
    replacement: z
      .string()
      .optional()
      .describe(
        "replace (required when action='replace'): supports $1..$9, $<name>, $&, $`, $', $$",
      ),
    limit: z.coerce
      .number()
      .int()
      .min(1)
      .optional()
      .describe(
        "split: max parts (counts every item including captured separators, per JS semantics)",
      ),
  },
  handler: async (args) => {
    try {
      const flagError = validateFlags(args.flags);
      if (flagError) return err(flagError);
      if (args.action === "replace" && args.replacement === undefined) {
        return err("replace requires `replacement`");
      }
      const input = await resolveTextInput(args.input, args.inputUrl);
      if (input.length > MAX_INPUT_CHARS) {
        return err(
          `input too large for regex: ${input.length} chars (limit ${MAX_INPUT_CHARS})`,
        );
      }

      const result: RegexResult = await regexSemaphore.run(() =>
        runRegex(
          {
            action: args.action,
            pattern: args.pattern,
            flags: args.flags,
            input,
            replacement: args.replacement,
            limit: args.limit,
          },
          TIME_BUDGET_MS,
        ),
      );

      switch (args.action) {
        case "match":
          return okJson(result as Record<string, unknown>);
        case "replace": {
          const r = result as { result: string; replacements: number };
          // Surface the replacement count alongside the new text so zero
          // replacements doesn't look like a no-op copy in the text field.
          return ok(`${r.replacements} replacement(s)\n\n${r.result}`, r);
        }
        case "split": {
          const r = result as { parts: string[]; count: number };
          return ok(JSON.stringify(r.parts, null, 2), r);
        }
      }
    } catch (e) {
      return err(toMessage(e));
    }
  },
});

function validateFlags(flags: string): string | undefined {
  const seen = new Set<string>();
  for (const f of flags) {
    if (seen.has(f))
      return `invalid flags ${JSON.stringify(flags)}: ${JSON.stringify(f)} appears more than once`;
    seen.add(f);
  }
  if (seen.has("u") && seen.has("v")) {
    return `invalid flags ${JSON.stringify(flags)}: "u" and "v" are mutually exclusive (pick one)`;
  }
  return undefined;
}
