import { XMLBuilder, XMLParser, XMLValidator } from "fast-xml-parser";
import Papa from "papaparse";
import { parse as parseToml, stringify as stringifyToml } from "smol-toml";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";
import { z } from "zod";
import { toMessage } from "../lib/errors.js";
import { resolveTextInput } from "../lib/input.js";
import { coerceBoolean, defineTool, err, ok } from "./types.js";

type Format = "json" | "yaml" | "toml" | "xml" | "csv";

interface CsvOptions {
  delimiter: string;
  headers: boolean;
  dynamicTyping: boolean;
}

/** Columns where auto-typing changed a value's textual form (e.g. "007" → 7). */
function lossyTypedColumns(
  typed: unknown,
  raw: unknown,
  headers: boolean,
): string[] {
  const lossy = new Set<string>();
  const tRows = Array.isArray(typed) ? typed : [];
  const rRows = Array.isArray(raw) ? raw : [];
  for (let i = 0; i < tRows.length; i++) {
    const t = tRows[i];
    const r = rRows[i];
    if (headers && isPlainObject(t) && isPlainObject(r)) {
      for (const k of Object.keys(t)) {
        const tv = t[k];
        const rv = r[k];
        if (typeof tv !== "string" && rv != null && String(tv) !== String(rv)) {
          lossy.add(k);
        }
      }
    } else if (Array.isArray(t) && Array.isArray(r)) {
      for (let j = 0; j < t.length; j++) {
        if (typeof t[j] !== "string" && String(t[j]) !== String(r[j])) {
          lossy.add(`column ${j + 1}`);
        }
      }
    }
  }
  return [...lossy];
}

/** TOML has no null type — locate one so the error can point at it. */
function findNullPath(value: unknown, path = "root"): string | undefined {
  if (value === null) return path;
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      const found = findNullPath(value[i], `${path}[${i}]`);
      if (found) return found;
    }
    return undefined;
  }
  if (typeof value === "object") {
    for (const [k, v] of Object.entries(value)) {
      const found = findNullPath(v, `${path}.${k}`);
      if (found) return found;
    }
  }
  return undefined;
}

function parseDocument(
  input: string,
  format: Format,
  csv: CsvOptions,
  warnings: string[],
): unknown {
  switch (format) {
    case "json":
      try {
        return JSON.parse(input);
      } catch (e) {
        throw new Error(`invalid JSON: ${toMessage(e)}`);
      }
    case "yaml":
      try {
        return parseYaml(input, { prettyErrors: true });
      } catch (e) {
        throw new Error(`invalid YAML: ${toMessage(e)}`);
      }
    case "toml":
      try {
        return parseToml(input);
      } catch (e) {
        throw new Error(`invalid TOML: ${toMessage(e)}`);
      }
    case "xml": {
      if (input.trim() === "") {
        throw new Error("invalid XML: input is empty");
      }
      const validation = XMLValidator.validate(input);
      if (validation !== true) {
        const { line, col, msg } = validation.err;
        const location =
          col !== undefined
            ? `line ${line}, column ${col}`
            : line !== undefined
              ? `line ${line}`
              : "the start of the document";
        throw new Error(`invalid XML at ${location}: ${msg}`);
      }
      warnings.push(
        "XML attributes are represented as '@_'-prefixed keys; element order inside mixed content is not preserved",
      );
      // parseTagValue:false stops the parser from coercing "007" → 7 or
      // "1.10" → 1.1 etc.; we expose CSV-style auto-typing only behind the
      // explicit csvDynamicTyping flag, so XML should mirror the same
      // lossless default.
      return new XMLParser({
        ignoreAttributes: false,
        attributeNamePrefix: "@_",
        parseTagValue: false,
        parseAttributeValue: false,
      }).parse(input);
    }
    case "csv": {
      const cleaned = input.replace(/\r?\n$/, "");
      const result = Papa.parse(cleaned, {
        header: csv.headers,
        delimiter: csv.delimiter,
        dynamicTyping: csv.dynamicTyping,
        skipEmptyLines: true,
      });
      if (result.errors.length > 0) {
        const first = result.errors[0] as Papa.ParseError;
        throw new Error(
          `invalid CSV${first.row !== undefined ? ` at row ${first.row}` : ""}: ${first.message}`,
        );
      }
      if (csv.dynamicTyping) {
        const rawParse = Papa.parse(cleaned, {
          header: csv.headers,
          delimiter: csv.delimiter,
          dynamicTyping: false,
          skipEmptyLines: true,
        });
        const lossy = lossyTypedColumns(
          result.data,
          rawParse.data,
          csv.headers,
        );
        if (lossy.length > 0) {
          warnings.push(
            `CSV auto-typing changed the textual form of value(s) in ${lossy.join(", ")} (e.g. leading zeros or large integers); set csvDynamicTyping:false to keep every cell as a string`,
          );
        }
      }
      return result.data;
    }
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

// XML 1.0 Name production (https://www.w3.org/TR/xml/#NT-Name). The full
// character class is huge; this implementation accepts the common ASCII +
// extended-letter subset that real-world generators emit, plus the '@_'
// attribute prefix the parser side uses. It is intentionally strict — silently
// producing malformed XML is worse than failing the conversion.
const XML_NAME_RE = /^[A-Za-z_][A-Za-z0-9_.:-]*$/;

function validateXmlElementNames(value: unknown, path = "root"): void {
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++)
      validateXmlElementNames(value[i], `${path}[${i}]`);
    return;
  }
  if (!isPlainObject(value)) return;
  for (const [k, v] of Object.entries(value)) {
    // `@_foo` is an attribute (the prefix is stripped before emission);
    // `#text` is the text-content sentinel and is allowed verbatim.
    const name = k.startsWith("@_") ? k.slice(2) : k;
    if (k !== "#text" && !XML_NAME_RE.test(name)) {
      throw new Error(
        `cannot emit XML element/attribute name ${JSON.stringify(k)} at ${path}: not a valid XML Name (letters/digits/_/-/./:, starts with letter or _)`,
      );
    }
    validateXmlElementNames(v, `${path}.${k}`);
  }
}

function serializeDocument(
  value: unknown,
  format: Format,
  indent: number,
  csv: CsvOptions,
  warnings: string[],
): string {
  switch (format) {
    case "json":
      return JSON.stringify(value, null, indent);
    case "yaml":
      // The yaml library throws on indent 0 ("Indentation width must be at
      // least 1"); the tool schema allows indent 0 (useful for JSON), so
      // clamp here rather than rejecting the call.
      if (indent === 0) {
        warnings.push(
          "YAML requires indent ≥ 1; clamped indent=0 to indent=1 for this output",
        );
      }
      return stringifyYaml(value, { indent: Math.max(1, indent) });
    case "toml": {
      if (!isPlainObject(value)) {
        throw new Error(
          "TOML output requires an object at the root (not an array or scalar)",
        );
      }
      const nullAt = findNullPath(value);
      if (nullAt !== undefined) {
        throw new Error(
          `TOML has no null type; remove or replace the null value at ${nullAt}`,
        );
      }
      if (indent !== 2) {
        warnings.push(
          "TOML's stringifier has a fixed format; the indent parameter was ignored",
        );
      }
      return stringifyToml(value);
    }
    case "xml": {
      let root: Record<string, unknown>;
      if (isPlainObject(value) && Object.keys(value).length === 1) {
        root = value;
      } else if (Array.isArray(value)) {
        // An array at the document root would emit N top-level elements;
        // XML allows exactly one root, so wrap into <root><item>…</item>…</root>.
        root = { root: { item: value } };
        warnings.push(
          "input was an array; wrapped each element in <item> under a single <root> for XML's one-root-element rule",
        );
      } else {
        root = { root: value };
        warnings.push(
          "input had no single root element; wrapped output in <root>",
        );
      }
      validateXmlElementNames(root);
      return new XMLBuilder({
        ignoreAttributes: false,
        attributeNamePrefix: "@_",
        format: true,
        indentBy: " ".repeat(indent),
      }).build(root) as string;
    }
    case "csv": {
      // An empty array gives PapaParse no columns to work with and it
      // throws "Error: Option columns is empty" — surface a clean,
      // domain-specific error before we hit that path.
      if (Array.isArray(value) && value.length === 0) {
        throw new Error(
          "cannot emit CSV from an empty array — at least one row is required to derive columns",
        );
      }
      const rows = Array.isArray(value) ? value : [value];
      if (!Array.isArray(value)) {
        warnings.push("input was not an array; emitted a single CSV row");
      }
      if (indent !== 2) {
        warnings.push(
          "CSV has no concept of indent; the indent parameter was ignored",
        );
      }
      const flattenable = rows.every(isPlainObject);
      if (flattenable) {
        // Union keys across every row, preserving first-seen order, so a
        // column that only exists in row 5 isn't silently dropped because
        // Papa.unparse defaulted its column list to row 1's keys.
        const columns: string[] = [];
        const seen = new Set<string>();
        const nestedKeys = new Set<string>();
        for (const row of rows as Record<string, unknown>[]) {
          for (const [k, v] of Object.entries(row)) {
            if (!seen.has(k)) {
              seen.add(k);
              columns.push(k);
            }
            if (typeof v === "object" && v !== null) nestedKeys.add(k);
          }
        }
        if (nestedKeys.size > 0) {
          warnings.push(
            `nested values JSON-encoded into cells for column(s): ${[...nestedKeys].join(", ")}`,
          );
        }
        const encoded = (rows as Record<string, unknown>[]).map((row) => {
          const out: Record<string, unknown> = {};
          for (const col of columns) {
            const v = row[col];
            out[col] =
              v === undefined
                ? ""
                : typeof v === "object" && v !== null
                  ? JSON.stringify(v)
                  : v;
          }
          return out;
        });
        return Papa.unparse(encoded, {
          delimiter: csv.delimiter,
          header: csv.headers,
          columns,
        });
      }
      return Papa.unparse(
        rows.map((v) => [v]),
        { delimiter: csv.delimiter, header: false },
      );
    }
  }
}

export const convertDataTool = defineTool({
  name: "convert-data",
  title: "Data format converter",
  description:
    "Convert structured data between JSON, YAML, TOML, XML, and CSV, or reformat a document in place. " +
    "Use it when you have one format and need another (e.g. paste a YAML config and want the JSON, " +
    "or pull a CSV apart into JSON for further processing), or when you want to pretty-print or minify a payload.\n" +
    "\n" +
    "Set `to: 'pretty'` to reformat in the same format with consistent indentation, or `to: 'minified'` to strip " +
    "whitespace (JSON and XML only — the others can't be minified without semantic loss).\n" +
    "\n" +
    "CSV options:\n" +
    "  • `csvDelimiter` — separator character (default ',').\n" +
    "  • `csvHeaders` — treat the first row as column names (default true).\n" +
    "  • `csvDynamicTyping` — auto-coerce numbers and booleans on parse (default true); set false to preserve leading zeros and version strings.\n" +
    "\n" +
    "CSV output is RFC-4180 quoted but NOT formula-escaped: a cell beginning with =, +, -, @, tab, or CR is valid CSV that Excel/LibreOffice will execute as a formula. Treat untrusted CSV output accordingly.\n" +
    "\n" +
    "Lossy conversions (XML attribute encoding, nesting flattened into CSV cells) come back as warnings, not silent drops. " +
    "Source can be inline (`input`) or pulled from a URL (`inputUrl`).\n" +
    "\n" +
    "Examples:\n" +
    '  { "from": "json", "to": "yaml", "input": "{\\"a\\":1}" }\n' +
    '  { "from": "csv", "to": "json", "input": "id,name\\n1,Ada" }\n' +
    '  { "from": "json", "to": "minified", "inputUrl": "https://example.com/data.json" }',
  inputSchema: {
    from: z.enum(["json", "yaml", "toml", "xml", "csv"]),
    to: z.enum(["json", "yaml", "toml", "xml", "csv", "pretty", "minified"]),
    input: z.string().optional(),
    inputUrl: z
      .string()
      .optional()
      .describe("Fetch the source document from this URL."),
    indent: z.coerce
      .number()
      .int()
      .min(0)
      .max(8)
      .default(2)
      .describe("Indentation width for JSON, YAML, and XML output."),
    csvDelimiter: z.string().default(","),
    csvHeaders: coerceBoolean(true).describe(
      "Treat the first CSV row as column headers.",
    ),
    csvDynamicTyping: coerceBoolean(true).describe(
      "Auto-coerce unquoted CSV numbers and booleans on parse. Set false to preserve every cell as a string.",
    ),
  },
  outputSchema: {
    result: z.string(),
    warnings: z.array(z.string()),
  },
  refine: (args, ctx) => {
    if (args.to === "minified" && args.from !== "json" && args.from !== "xml") {
      ctx.addIssue({
        code: "custom",
        message: `minified output is only supported for json and xml, not ${args.from}`,
        path: ["to"],
      });
    }
  },
  handler: async (args) => {
    try {
      if ([...args.csvDelimiter].length !== 1) {
        return err(
          `csvDelimiter must be a single character (got ${JSON.stringify(args.csvDelimiter)})`,
        );
      }
      // Fail BEFORE the fetch when we know the conversion is impossible
      // — saves the inputUrl round-trip on a guaranteed-error path.
      if (
        args.to === "minified" &&
        args.from !== "json" &&
        args.from !== "xml"
      ) {
        return err(
          `minified output is only supported for json and xml, not ${args.from}`,
        );
      }
      const input = await resolveTextInput(args.input, args.inputUrl);
      const warnings: string[] = [];
      const csv: CsvOptions = {
        delimiter: args.csvDelimiter,
        headers: args.csvHeaders,
        dynamicTyping: args.csvDynamicTyping,
      };
      const value = parseDocument(input, args.from, csv, warnings);

      let result: string;
      if (args.to === "minified") {
        if (args.from === "json") {
          result = JSON.stringify(value);
        } else if (args.from === "xml") {
          result = new XMLBuilder({
            ignoreAttributes: false,
            attributeNamePrefix: "@_",
            format: false,
          }).build(value) as string;
        } else {
          return err(
            `minified output is only supported for json and xml, not ${args.from}`,
          );
        }
      } else {
        const target = args.to === "pretty" ? args.from : args.to;
        result = serializeDocument(value, target, args.indent, csv, warnings);
      }
      return ok(result, { result, warnings });
    } catch (e) {
      return err(toMessage(e));
    }
  },
});
