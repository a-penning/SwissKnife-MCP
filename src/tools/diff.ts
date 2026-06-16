import { diffChars, diffWords, structuredPatch } from "diff";
import { z } from "zod";
import { toMessage } from "../lib/errors.js";
import { resolveTextInput } from "../lib/input.js";
import { defineTool, err, ok } from "./types.js";

export const diffTool = defineTool({
  name: "diff",
  title: "Text comparison",
  description:
    "Compare two pieces of text and see what changed. Use this when you have an 'old' and 'new' version of something — config files, response bodies, two snippets of code — and you want a clear, structured account of the differences plus how many lines/words/chars were added or removed.\n" +
    "\n" +
    "Granularity (`mode`):\n" +
    "  • 'lines' (default) — unified diff with configurable context lines and side labels.\n" +
    "  • 'words' — inline diff: removed runs marked [-like this-], additions marked {+like this+}.\n" +
    "  • 'chars' — same inline marker style, but character-by-character.\n" +
    "\n" +
    "Either side can be inline (`a`, `b`) or fetched from a URL (`aUrl`, `bUrl`) — mix and match.\n" +
    "\n" +
    "Examples:\n" +
    '  { "a": "foo\\nbar\\n", "b": "foo\\nbaz\\n" } → unified diff with counts\n' +
    '  { "a": "hello world", "b": "hello there", "mode": "words" } → "hello [-world-]{+there+}"\n' +
    '  { "aUrl": "https://…/old.json", "bUrl": "https://…/new.json" }',
  inputSchema: {
    a: z.string().optional().describe("left/old text"),
    aUrl: z.string().optional().describe("fetch left/old text from this URL"),
    b: z.string().optional().describe("right/new text"),
    bUrl: z.string().optional().describe("fetch right/new text from this URL"),
    mode: z
      .enum(["lines", "words", "chars"])
      .default("lines")
      .describe(
        "Granularity. 'lines' (default): unified diff with context. 'words': inline word-level diff. 'chars': inline character-level diff. In words/chars mode, additions=0 and deletions=0 with identical=false means only whitespace differs.",
      ),
    context: z.coerce
      .number()
      .int()
      .min(0)
      .max(100)
      .default(3)
      .describe("lines: context lines. Ignored (with warning) in other modes."),
    aLabel: z
      .string()
      .default("a")
      .describe("lines: label for the old side. Ignored in other modes."),
    bLabel: z
      .string()
      .default("b")
      .describe("lines: label for the new side. Ignored in other modes."),
  },
  outputSchema: {
    diff: z.string(),
    additions: z
      .number()
      .describe(
        "added lines (mode:lines) / added word tokens (mode:words) / added chars (mode:chars)",
      ),
    deletions: z.number(),
    identical: z
      .boolean()
      .describe(
        "true when `a` and `b` are byte-identical (independent of whitespace folding done by words mode)",
      ),
    warnings: z.array(z.string()).optional(),
  },
  handler: async (args) => {
    try {
      const [a, b] = await Promise.all([
        resolveTextInput(args.a, args.aUrl, "a"),
        resolveTextInput(args.b, args.bUrl, "b"),
      ]);

      // `identical` is anchored to byte equality so callers can use it as a
      // pure "no change" check. Whitespace-insensitive equivalence in words
      // mode is a separate question (additions/deletions == 0 there can mean
      // "only whitespace changed").
      const identical = a === b;
      const warnings: string[] = [];

      // Surface ignored mode-specific params so callers know `context` /
      // `aLabel` / `bLabel` had no effect in words/chars mode (rather
      // than silently swallowing them).
      if (args.mode !== "lines") {
        if (args.context !== 3) {
          warnings.push(
            `context=${args.context} is only used in mode='lines' — ignored for mode='${args.mode}'`,
          );
        }
        if (args.aLabel !== "a" || args.bLabel !== "b") {
          warnings.push(
            `aLabel/bLabel are only used in mode='lines' — ignored for mode='${args.mode}'`,
          );
        }
      }

      if (args.mode === "lines") {
        // Single structuredPatch + formatPatch — avoid also calling
        // createTwoFilesPatch, which would run structuredPatch a second time.
        const patch = structuredPatch(
          args.aLabel,
          args.bLabel,
          a,
          b,
          undefined,
          undefined,
          { context: args.context },
        );
        let additions = 0;
        let deletions = 0;
        for (const hunk of patch.hunks) {
          for (const line of hunk.lines) {
            if (line.startsWith("+")) additions++;
            else if (line.startsWith("-")) deletions++;
          }
        }
        // Reconstruct the unified-diff text from the patch we already
        // have rather than recomputing it.
        const header = `--- ${args.aLabel}\n+++ ${args.bLabel}\n`;
        const hunks = patch.hunks
          .map((h) => {
            const head = `@@ -${h.oldStart},${h.oldLines} +${h.newStart},${h.newLines} @@`;
            return [head, ...h.lines].join("\n");
          })
          .join("\n");
        const diff = patch.hunks.length === 0 ? header : `${header}${hunks}\n`;
        const structured = { diff, additions, deletions, identical, warnings };
        return ok(diff, structured);
      }

      const parts = args.mode === "words" ? diffWords(a, b) : diffChars(a, b);
      let additions = 0;
      let deletions = 0;
      const marked = parts
        .map((part) => {
          // Count actual tokens (words / code points) added or removed,
          // not contiguous diff hunks — so the units stay consistent with
          // mode:lines (lines added / removed).
          const tokenCount =
            args.mode === "words"
              ? (part.value.match(/\S+/g) ?? []).length
              : [...part.value].length;
          if (part.added) {
            additions += tokenCount;
            return `{+${part.value}+}`;
          }
          if (part.removed) {
            deletions += tokenCount;
            return `[-${part.value}-]`;
          }
          return part.value;
        })
        .join("");
      // Require COMPLETE marker pairs so we don't trip on innocent text:
      // `arr[-1]`, `{+1,}`, `x+}y` were all triggering the warning even
      // though they cannot cause a parsing collision.
      if (
        /\[-[\s\S]+?-\]|\{\+[\s\S]+?\+\}/.test(a) ||
        /\[-[\s\S]+?-\]|\{\+[\s\S]+?\+\}/.test(b)
      ) {
        warnings.push(
          "input contains diff-marker sequences ([-..-] or {+..+}); the inline diff output is ambiguous in those regions",
        );
      }
      const structured = {
        diff: marked,
        additions,
        deletions,
        identical,
        warnings,
      };
      return ok(marked, structured);
    } catch (e) {
      return err(toMessage(e));
    }
  },
});
