import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { tools } from "./tools/registry.js";

// Replaced at build time by tsup's `define` (see tsup.config.ts) with the
// version from package.json. Falls back to "0.0.0-dev" for `vitest` / `tsx`
// runs that don't go through the bundler.
declare const __SWISSKNIFE_VERSION__: string;
export const VERSION =
  typeof __SWISSKNIFE_VERSION__ !== "undefined"
    ? __SWISSKNIFE_VERSION__
    : "0.0.0-dev";

// Maps from deprecated input-param names to their current names. The MCP
// SDK applies Zod's strip-by-default to unknown keys, which means a caller
// passing the old name gets a silent drop and either confusing
// "missing required field" errors or — worse — undefined behaviour when
// the field they think they're sending is silently ignored. We wrap the
// schemas in `.strict()` to fail loud, then pre-screen for these specific
// renames so the error names the new param explicitly.
const RENAMED_PARAMS: Record<string, Record<string, string>> = {
  http: { bodyEncoding: "requestBodyEncoding" },
  jwt: { token: "input" },
  number: { value: "input" },
};

export function buildServer(): McpServer {
  const server = new McpServer({ name: "swissknife", version: VERSION });
  for (const tool of tools) {
    // Pre-check the raw payload BEFORE Zod runs its strip/parse pass —
    // otherwise either (a) `.strict()` rejects the unknown key with a
    // generic message before we can surface the rename hint, or (b)
    // `.passthrough()` lets the now-missing-required-field error fire
    // first and the refinement on the unknown key never gets a chance.
    const knownKeys = new Set(Object.keys(tool.inputSchema));
    const renames = RENAMED_PARAMS[tool.name] ?? {};
    const objectSchema = z.object(tool.inputSchema);
    // Action-specific / cross-field rules are enforced here so an invalid
    // combination is rejected at the boundary before the handler runs.
    const refined = tool.refine
      ? objectSchema.superRefine(
          tool.refine as (arg: unknown, ctx: z.core.$RefinementCtx) => void,
        )
      : objectSchema;
    const finalInput = z.preprocess((raw) => {
      if (raw && typeof raw === "object" && !Array.isArray(raw)) {
        for (const key of Object.keys(raw as Record<string, unknown>)) {
          if (knownKeys.has(key)) continue;
          const renamed = renames[key];
          throw new Error(
            renamed
              ? `\`${key}\` was renamed to \`${renamed}\` — update your call`
              : `unrecognized key: \`${key}\``,
          );
        }
      }
      return raw;
    }, refined);
    server.registerTool(
      tool.name,
      {
        title: tool.title,
        description: tool.description,
        // biome-ignore lint/suspicious/noExplicitAny: SDK accepts both raw shape and ZodObject
        inputSchema: finalInput as any,
        ...(tool.outputSchema ? { outputSchema: tool.outputSchema } : {}),
      },
      tool.handler,
    );
  }
  return server;
}
