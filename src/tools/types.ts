import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

/**
 * Accept either an `inner`-shaped value or a non-empty array of them. A
 * JSON-stringified array (`'["a","b"]'`) is parsed first because some MCP
 * clients serialise array arguments to a string on the wire; an unparseable
 * `[`-prefixed string (or any other string) is passed through untouched so the
 * wrapped union still reports the real type error and literal single strings
 * stay single.
 */
export function singleOrArray<T extends z.ZodTypeAny>(inner: T) {
  return z.preprocess(
    (v) => {
      if (typeof v === "string" && v.startsWith("[")) {
        try {
          return JSON.parse(v);
        } catch {
          return v;
        }
      }
      return v;
    },
    z.union([inner, z.array(inner).min(1)]),
  );
}

/**
 * A single value or a non-empty array of them — the shape every batch-capable
 * tool's primary input takes (and `jwt`'s `audience`). Shared so the union
 * doesn't drift across tools.
 */
export const singleOrBatch = singleOrArray(z.string());

/**
 * A boolean that also accepts the literal wire strings `"true"` / `"false"`,
 * which MCP clients emit when they stringify a JSON boolean. Only those two
 * strings coerce — `"yes"`, `1`, `"1"` etc. still fail `z.boolean()` so typos
 * stay loud. `def` sets the default applied when the field is omitted.
 */
export function coerceBoolean(def?: boolean) {
  return z
    .preprocess((v) => {
      if (v === "true") return true;
      if (v === "false") return false;
      return v;
    }, z.boolean())
    .default(def ?? false);
}

/**
 * Wrap an object- or array-shaped param so a JSON-string form is accepted too.
 * Some MCP clients (and Claude's tool-call harness) serialise nested
 * object/array arguments to a JSON string at the call boundary — same reason
 * `script`'s `args` and `http`'s `jsonBody` reparse strings; without this, a
 * `z.record(...)` or `z.array(...)` field rejects them as "expected object,
 * received string". An unparseable string is passed through untouched so the
 * wrapped schema reports the real type error. Despite the historical name, the
 * preprocess is structurally generic — use it for arrays too.
 */
export function jsonObjectArg<T extends z.ZodTypeAny>(schema: T) {
  return z.preprocess((v) => {
    if (typeof v === "string") {
      try {
        return JSON.parse(v);
      } catch {
        return v;
      }
    }
    return v;
  }, schema);
}

export interface ToolDef<S extends z.ZodRawShape = z.ZodRawShape> {
  name: string;
  title: string;
  description: string;
  /**
   * The raw Zod shape for the tool's args. The server (`buildServer`) wraps it
   * in a `z.preprocess` that rejects unknown keys (with a rename hint from
   * `RENAMED_PARAMS`) before the object parse, so unknown/typoed/renamed params
   * fail loud at the boundary instead of being silently stripped — individual
   * tool files don't call `.strict()` themselves.
   */
  inputSchema: S;
  outputSchema?: z.ZodRawShape;
  /**
   * Cross-field / action-specific validation applied at the MCP schema
   * boundary (wired into the server's `z.object(inputSchema).superRefine`),
   * so an invalid combination is rejected before the handler runs. Handlers
   * still enforce the same rules — they're also called directly by the
   * `script` gateway and unit tests, which bypass this schema — so treat
   * `refine` as the boundary guard, not the only one.
   */
  refine?: (args: z.infer<z.ZodObject<S>>, ctx: z.core.$RefinementCtx) => void;
  handler: (
    args: z.infer<z.ZodObject<S>>,
  ) => CallToolResult | Promise<CallToolResult>;
}

export function defineTool<S extends z.ZodRawShape>(
  def: ToolDef<S>,
): ToolDef<S> {
  return def;
}

export function ok(
  text: string,
  structured: Record<string, unknown>,
): CallToolResult {
  return {
    content: [{ type: "text", text }],
    structuredContent: structured,
  };
}

/** `ok()` for tools whose readable text is just the pretty-printed structured payload. */
export function okJson(structured: Record<string, unknown>): CallToolResult {
  return ok(JSON.stringify(structured, null, 2), structured);
}

export function err(
  message: string,
  structured?: Record<string, unknown>,
): CallToolResult {
  const base: CallToolResult = {
    isError: true,
    content: [{ type: "text", text: `Error: ${message}` }],
  };
  return structured ? { ...base, structuredContent: structured } : base;
}
