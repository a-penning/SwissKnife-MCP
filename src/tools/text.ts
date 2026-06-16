import { Buffer } from "node:buffer";
import { z } from "zod";
import { toMessage } from "../lib/errors.js";
import { resolveTextInput } from "../lib/input.js";
import { coerceBoolean, defineTool, err, ok } from "./types.js";

// Unicode-aware word splitter: preserves accented letters (é, ü, ñ, ...) and
// other scripts (CJK, Cyrillic, ...) as part of words instead of treating them
// as separators. The earlier /[^A-Za-z0-9]+/ split silently deleted any
// non-ASCII letter, so "café" became "caf" and emoji vanished entirely.
function splitWords(input: string): string[] {
  return input
    .replace(/(\p{Ll}|\p{N})(\p{Lu})/gu, "$1 $2")
    .replace(/(\p{Lu}+)(\p{Lu}\p{Ll})/gu, "$1 $2")
    .split(/[^\p{L}\p{N}]+/u)
    .filter(Boolean);
}

const capitalize = (w: string) =>
  (w[0]?.toUpperCase() ?? "") + w.slice(1).toLowerCase();

function convertCase(input: string, target: string): string {
  const words = splitWords(input);
  switch (target) {
    case "camel":
      return words
        .map((w, i) => (i === 0 ? w.toLowerCase() : capitalize(w)))
        .join("");
    case "pascal":
      return words.map(capitalize).join("");
    case "snake":
      return words.map((w) => w.toLowerCase()).join("_");
    case "screaming-snake":
      return words.map((w) => w.toUpperCase()).join("_");
    case "kebab":
      return words.map((w) => w.toLowerCase()).join("-");
    case "title":
      return words.map(capitalize).join(" ");
    case "sentence":
      return words
        .map((w, i) => (i === 0 ? capitalize(w) : w.toLowerCase()))
        .join(" ");
    case "upper":
      return input.toUpperCase();
    case "lower":
      return input.toLowerCase();
    default:
      throw new Error(`unknown case target ${JSON.stringify(target)}`);
  }
}

function slugify(input: string, separator: string): string {
  const stripped = input
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "") // strip Combining Diacritical Marks
    .toLowerCase();
  // Identify runs of word characters; join them with the separator inserted
  // verbatim. Building the result this way means we never have to feed the
  // separator to String.prototype.replace as a replacement (it would
  // otherwise interpret $$ / $& / $' / $` / $n as substitution patterns) and
  // it lets us pass "" through as a "no separator" request without building
  // an unhelpful /^+|+$/g regex from it.
  const parts = stripped.match(/[a-z0-9]+/g);
  return parts ? parts.join(separator) : "";
}

const REGEX_META = /[.*+?^${}()|[\]\\]/g;

export const textTool = defineTool({
  name: "text",
  title: "Text manipulation toolkit",
  description:
    "Common string and line operations on a chunk of text. Use this when you need to rename something in a different case convention, slugify a title for a URL, sort or de-duplicate a block of lines, count words/lines/bytes, normalise Unicode, trim whitespace, do a literal find/replace, or escape text for embedding in JSON / shell / regex.\n" +
    "\n" +
    "Actions:\n" +
    "  • 'case' — convert between camelCase, PascalCase, snake_case, SCREAMING_SNAKE, kebab-case, Title Case, Sentence case, UPPER, lower.\n" +
    "  • 'slugify' — URL-safe slug (transliterates diacritics, joins with a separator of your choice).\n" +
    "  • 'sort-lines' — sort lines asc/desc, optionally numerically, and optionally drop duplicates in the same pass with `unique: true`.\n" +
    "  • 'dedupe-lines' — drop duplicate lines, preserving first-seen order.\n" +
    "  • 'count' — characters (code points), UTF-16 units, UTF-8 bytes, words, lines, unique lines.\n" +
    "  • 'normalize' — Unicode normalisation form NFC / NFD / NFKC / NFKD.\n" +
    "  • 'trim' — strip whitespace from one or both sides.\n" +
    "  • 'replace' — literal find/replace (no regex). For regex, use the `regex` tool.\n" +
    "  • 'escape' / 'unescape' — `style: 'json' | 'shell-posix' | 'regex'` for a JSON string body, POSIX shell single-quoting, or regex metacharacters.\n" +
    "\n" +
    "Source is inline (`input`) or pulled from a URL (`inputUrl`).\n" +
    "\n" +
    "Examples:\n" +
    '  { "action": "case", "target": "kebab", "input": "Hello World" } → "hello-world"\n' +
    '  { "action": "slugify", "input": "Café — résumé" } → "cafe-resume"\n' +
    '  { "action": "replace", "input": "a.b.c", "find": ".", "replacement": "/" } → "a/b/c"\n' +
    '  { "action": "count", "input": "..." } → characters / bytes / words / lines',
  inputSchema: {
    action: z.enum([
      "case",
      "slugify",
      "sort-lines",
      "dedupe-lines",
      "count",
      "normalize",
      "trim",
      "replace",
      "escape",
      "unescape",
    ]),
    input: z.string().optional(),
    inputUrl: z.string().optional().describe("fetch the text from this URL"),
    target: z
      .enum([
        "camel",
        "pascal",
        "snake",
        "screaming-snake",
        "kebab",
        "title",
        "sentence",
        "upper",
        "lower",
      ])
      .optional()
      .describe("case: target convention"),
    separator: z.string().default("-").describe("slugify: separator"),
    order: z.enum(["asc", "desc"]).default("asc").describe("sort-lines"),
    numeric: coerceBoolean(false).describe("sort-lines: compare numerically"),
    unique: coerceBoolean(false).describe("sort-lines: drop duplicates"),
    form: z
      .enum(["NFC", "NFD", "NFKC", "NFKD"])
      .default("NFC")
      .describe("normalize: Unicode normalization form"),
    side: z
      .enum(["both", "start", "end"])
      .default("both")
      .describe("trim: which side(s) to trim whitespace from"),
    find: z
      .string()
      .optional()
      .describe("replace: literal substring to find (no regex semantics)."),
    replacement: z
      .string()
      .optional()
      .describe(
        "replace: literal replacement text (no $1/$& expansion — use the regex tool if you need that).",
      ),
    style: z
      .enum(["json", "shell-posix", "regex"])
      .optional()
      .describe("escape/unescape"),
  },
  refine: (args, ctx) => {
    switch (args.action) {
      case "case":
        if (!args.target) {
          ctx.addIssue({
            code: "custom",
            message: "case requires `target`",
            path: ["target"],
          });
        }
        break;
      case "replace":
        if (args.find === undefined) {
          ctx.addIssue({
            code: "custom",
            message: "replace requires `find` (literal substring)",
            path: ["find"],
          });
        } else if (args.find === "") {
          ctx.addIssue({
            code: "custom",
            message:
              "`find` cannot be empty — use the regex tool for pattern-based replace",
            path: ["find"],
          });
        }
        if (args.replacement === undefined) {
          ctx.addIssue({
            code: "custom",
            message: "replace requires `replacement` (literal text)",
            path: ["replacement"],
          });
        }
        break;
      case "escape":
        if (!args.style) {
          ctx.addIssue({
            code: "custom",
            message: "escape requires `style`",
            path: ["style"],
          });
        }
        break;
      case "unescape":
        if (!args.style) {
          ctx.addIssue({
            code: "custom",
            message: "unescape requires `style`",
            path: ["style"],
          });
        } else if (args.style === "shell-posix") {
          ctx.addIssue({
            code: "custom",
            message:
              "unescape is not supported for shell-posix (quoting is context-dependent)",
            path: ["style"],
          });
        }
        break;
    }
  },
  handler: async (args) => {
    try {
      const input = await resolveTextInput(args.input, args.inputUrl);
      switch (args.action) {
        case "case": {
          if (!args.target) return err("case requires `target`");
          const result = convertCase(input, args.target);
          return ok(result, { result });
        }
        case "slugify": {
          const result = slugify(input, args.separator);
          return ok(result, { result });
        }
        case "sort-lines": {
          let lines = input.split("\n");
          // Preserve the trailing newline if the input had one — both
          // sort and dedupe must be neutral wrt the document's final newline
          // (and consistent with each other).
          const trailing = lines.at(-1) === "";
          if (trailing) lines = lines.slice(0, -1);
          lines.sort((a, b) => {
            if (args.numeric) {
              const na = Number.parseFloat(a);
              const nb = Number.parseFloat(b);
              if (!Number.isNaN(na) && !Number.isNaN(nb)) return na - nb;
            }
            return a < b ? -1 : a > b ? 1 : 0;
          });
          if (args.order === "desc") lines.reverse();
          if (args.unique) lines = [...new Set(lines)];
          const result = lines.join("\n") + (trailing ? "\n" : "");
          return ok(result, { result, lineCount: lines.length });
        }
        case "dedupe-lines": {
          if (input === "") {
            // "".split("\n") yields [""], which the trailing-newline heuristic
            // misreads as "had a trailing newline" and reappends \n — round-
            // tripping "" through dedupe should stay "".
            return ok("", { result: "", removed: 0, lineCount: 0 });
          }
          let lines = input.split("\n");
          const trailing = lines.at(-1) === "";
          if (trailing) lines = lines.slice(0, -1);
          const before = lines.length;
          lines = [...new Set(lines)];
          const result = lines.join("\n") + (trailing ? "\n" : "");
          return ok(result, {
            result,
            removed: before - lines.length,
            lineCount: lines.length,
          });
        }
        case "count": {
          const lines = input === "" ? [] : input.split("\n");
          const effectiveLines =
            lines.at(-1) === "" ? lines.slice(0, -1) : lines;
          const characters = [...input].length;
          const utf16Units = input.length;
          const bytes = Buffer.byteLength(input, "utf8");
          const words = (input.match(/\S+/g) ?? []).length;
          const linesCount = effectiveLines.length;
          const uniqueLines = new Set(effectiveLines).size;
          // Human-readable summary first (so the text field isn't raw JSON).
          // `result` mirrors the summary text so callers can rely on
          // `structuredContent.result` for every text-tool action.
          const result = `${characters} chars (${utf16Units} UTF-16 units), ${bytes} bytes, ${words} words, ${linesCount} lines (${uniqueLines} unique)`;
          return ok(result, {
            result,
            characters,
            // `utf16Units` is `input.length` (the JS string `.length`,
            // i.e. UTF-16 code units, not user-perceived characters).
            // Use this when comparing against APIs that bill on JS length.
            utf16Units,
            bytes,
            words,
            lines: linesCount,
            uniqueLines,
          });
        }
        case "normalize": {
          const result = input.normalize(args.form);
          return ok(result, {
            result,
            form: args.form,
            byteLength: Buffer.byteLength(result, "utf8"),
          });
        }
        case "trim": {
          const result =
            args.side === "start"
              ? input.trimStart()
              : args.side === "end"
                ? input.trimEnd()
                : input.trim();
          return ok(result, {
            result,
            side: args.side,
            removed: input.length - result.length,
          });
        }
        case "replace": {
          if (args.find === undefined) {
            return err("replace requires `find` (literal substring)");
          }
          if (args.replacement === undefined) {
            return err("replace requires `replacement` (literal text)");
          }
          if (args.find === "") {
            return err(
              "`find` cannot be empty — use the regex tool for pattern-based replace",
            );
          }
          // String.prototype.replaceAll with two string args treats both
          // as literal text — no $1/$& expansion, no regex metachars.
          const replacements = input.split(args.find).length - 1;
          const result = input.replaceAll(args.find, args.replacement);
          return ok(`${replacements} replacement(s)\n\n${result}`, {
            result,
            replacements,
          });
        }
        case "escape": {
          if (!args.style) return err("escape requires `style`");
          let result: string;
          if (args.style === "json") {
            result = JSON.stringify(input).slice(1, -1);
          } else if (args.style === "shell-posix") {
            result = `'${input.replaceAll("'", `'\\''`)}'`;
          } else {
            result = input.replace(REGEX_META, "\\$&");
          }
          return ok(result, { result });
        }
        case "unescape": {
          if (!args.style) return err("unescape requires `style`");
          if (args.style === "json") {
            try {
              const result = JSON.parse(`"${input}"`) as string;
              return ok(result, { result });
            } catch (e) {
              return err(`not a valid JSON string body: ${toMessage(e)}`);
            }
          }
          if (args.style === "regex") {
            const result = input.replace(/\\([.*+?^${}()|[\]\\])/g, "$1");
            return ok(result, { result });
          }
          return err(
            "unescape is not supported for shell-posix (quoting is context-dependent)",
          );
        }
      }
    } catch (e) {
      return err(toMessage(e));
    }
  },
});
