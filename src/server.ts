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
    const renames = RENAMED_PARAMS[tool.name] ?? {};
    // A `.strict()` ZodObject rejects unknown keys (a typo or renamed-away
    // param) instead of silently stripping them, and — unlike the earlier
    // `z.preprocess` wrapper — stays object-typed, so the SDK can introspect
    // its shape and advertise real JSON-Schema properties in `tools/list`
    // (the preprocess wrapper produced an empty schema, hiding every param).
    // The `error` hook rewrites the unknown-key message into a migration hint
    // when the key is a known rename.
    const objectSchema = z
      .object(tool.inputSchema, {
        error: (issue) => {
          if (issue.code === "unrecognized_keys") {
            for (const key of issue.keys ?? []) {
              const renamed = renames[key];
              if (renamed)
                return `\`${key}\` was renamed to \`${renamed}\` — update your call`;
            }
          }
          return undefined;
        },
      })
      .strict();
    // Cross-field / action-specific rules run at the boundary before the
    // handler. Zod 4 refinements keep the schema object-typed, so this does
    // NOT re-break JSON-Schema introspection the way a wrapper would.
    const finalInput = tool.refine
      ? objectSchema.superRefine(
          tool.refine as (arg: unknown, ctx: z.core.$RefinementCtx) => void,
        )
      : objectSchema;
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
