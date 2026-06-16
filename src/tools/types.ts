import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

/**
 * A single value or a non-empty array of them — the shape every batch-capable
 * tool's primary input takes (and `jwt`'s `audience`). Shared so the union
 * doesn't drift across tools.
 */
export const singleOrBatch = z.union([z.string(), z.array(z.string()).min(1)]);

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
