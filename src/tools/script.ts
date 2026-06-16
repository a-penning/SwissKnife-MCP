import { z } from "zod";
import { toMessage } from "../lib/errors.js";
import {
  DEFAULT_TIMEOUT_MS,
  DEFAULT_TOOL_CALL_LIMIT,
  MAX_SOURCE_BYTES,
  MAX_TIMEOUT_MS,
  MAX_TOOL_CALL_LIMIT,
} from "../lib/script/limits.js";
import { runScript } from "../lib/script/runtime.js";
import { createSemaphore, maxConcurrentFromEnv } from "../lib/semaphore.js";
import { coerceBoolean, defineTool, err, ok, type ToolDef } from "./types.js";

// Shared with the regex tool's intent but kept per-tool: bound how many VMs
// can allocate at once so concurrent runs can't collectively exhaust memory.
const scriptSemaphore = createSemaphore(maxConcurrentFromEnv());

const DESCRIPTION = [
  "Run a small JavaScript program in a sandbox that can call every other SwissKnife tool.",
  "Use this whenever a task needs more than one tool call — chaining outputs, looping over a list,",
  "running calls in parallel with Promise.all, conditionally branching, accumulating results, or",
  "retrying a flaky call. One MCP round-trip instead of N, with real control flow.",
  "",
  "Inside the script you have:",
  "  • `tools.<name>(args)` — every other SwissKnife tool, as an async function.",
  "    Both kebab and camelCase are accepted (`tools['json-query']` and `tools.jsonQuery` both work).",
  "  • `args` — whatever you passed as the `args` parameter, JSON-cloned into the VM.",
  "  • `console.log` / `.info` / `.warn` / `.error` / `.debug` — buffered and returned as `logs`.",
  "  • Top-level await. Return a value to surface it (must be JSON-serialisable).",
  "",
  "The sandbox is hermetic: no fs / network / require / fetch / WebAssembly. To make HTTP requests,",
  "go through `tools.http` (which keeps its own SSRF guards and response caps). Tool errors throw",
  "inside the VM — wrap in try/catch to recover. Every run gets a fresh VM; nothing leaks between calls.",
  "",
  `Hard limits per run: ${DEFAULT_TIMEOUT_MS}ms wall-clock (max ${MAX_TIMEOUT_MS}),`,
  `${DEFAULT_TOOL_CALL_LIMIT} tool calls (max ${MAX_TOOL_CALL_LIMIT}), ${MAX_SOURCE_BYTES} bytes of source.`,
  "Hitting a limit returns a structured error, never a crash.",
  "",
  "Nested-tool param shapes (for the most-chained tools — for full schemas, call the MCP `tools/list` method):",
  "  • tools.dns({ host?: string, ip?: string, type?: 'A'|'AAAA'|'MX'|'TXT'|'CNAME'|'NS'|'SOA'|'SRV'|'CAA' (or an array of those), resolver?: string, timeoutMs?: number })",
  "      — omit `type` for parallel fan-out across A/AAAA/MX/TXT/CNAME/NS/SOA; use `ip` for PTR.",
  "  • tools.http({ url: string, method?: 'GET'|'POST'|'PUT'|'PATCH'|'DELETE'|'HEAD'|'OPTIONS', headers?: object, body?: string, jsonBody?: any, timeoutMs?: number })",
  "  • tools.hash({ algorithm: 'sha256'|'sha1'|'md5'|'sha512'|..., input?: string|string[], inputUrl?: string|string[], hmacKey?: string, outputEncoding?: 'hex'|'base64'|'base64url' })",
  "  • tools.inspect({ kind: 'url'|'certificate'|'tls'|'whois', value: string|string[], servername?: string, whoisTarget?: 'domain'|'ip'|'asn', timeoutMs?: number })",
  "  • tools.jwt({ action: 'decode'|'verify'|'sign', input?: string, key?: string, algorithm?: string, payload?: object, expiresIn?: string })",
  "",
  "Validation errors from a nested tool call name the offending param(s) and list the accepted set,",
  "with a 'did you mean' hint when a typo is close enough by edit distance",
  "(e.g. \"dns: unknown parameter 'hots' (did you mean 'host'?). Accepted parameters: host, ip, type, ...\"),",
  "so you can self-correct without exiting the script. Wrap calls in try/catch to recover.",
  "",
  "Examples:",
  '  source: `return await tools.hash({ algorithm: "sha256", input: args.text })`',
  '  args:   { text: "hello" }',
  "",
  "  source: `",
  "    const doc = await tools.http({ url: args.url });",
  '    const q = await tools.jsonQuery({ input: doc.body, query: "$.scopes_supported[*]" });',
  "    return q.values.sort();",
  "  `",
  "",
  "  source: `",
  '    const results = await Promise.all(args.domains.map(d => tools.dns({ host: d, type: "MX" })));',
  "    return results.map(r => r.records).flat();",
  "  `",
].join("\n");

export function buildScriptTool(
  // biome-ignore lint/suspicious/noExplicitAny: heterogeneous tool shapes
  otherTools: ToolDef<any>[],
  // biome-ignore lint/suspicious/noExplicitAny: matches the registry's any-shape contract
): ToolDef<any> {
  return defineTool({
    name: "script",
    title: "JavaScript sandbox for chaining tools",
    description: DESCRIPTION,
    inputSchema: {
      source: z
        .string()
        .describe(
          "JavaScript source. Wrapped in `(async () => { … })()` so top-level await works.",
        ),
      args: z
        .unknown()
        .optional()
        .describe(
          "JSON-cloneable value exposed in the VM as the global `args`.",
        ),
      timeoutMs: z.coerce
        .number()
        .int()
        .min(1)
        .max(MAX_TIMEOUT_MS)
        .default(DEFAULT_TIMEOUT_MS),
      maxToolCalls: z.coerce
        .number()
        .int()
        .min(1)
        .max(MAX_TOOL_CALL_LIMIT)
        .default(DEFAULT_TOOL_CALL_LIMIT),
      trace: coerceBoolean(false).describe(
        "When true, include a per-call trace (tool name, ok flag, durationMs).",
      ),
    },
    outputSchema: {
      result: z.unknown(),
      toolCalls: z.number().int(),
      durationMs: z.number().int(),
      logs: z.array(z.string()),
      trace: z
        .array(
          z.object({
            tool: z.string(),
            ok: z.boolean(),
            durationMs: z.number(),
          }),
        )
        .optional(),
    },
    handler: async (args) => {
      try {
        // jsonBody-style hack: MCP transports sometimes serialise z.unknown()
        // optional fields as the literal string "undefined" (or the JSON
        // string "undefined"). Treat both as absent rather than passing
        // them into the VM verbatim.
        let scriptArgs = args.args;
        if (scriptArgs === "undefined") {
          scriptArgs = undefined;
        } else if (typeof scriptArgs === "string") {
          try {
            scriptArgs = JSON.parse(scriptArgs);
          } catch {
            // string args are fine; leave as-is so the VM sees a string.
          }
        }
        const result = await scriptSemaphore.run(() =>
          runScript({
            source: args.source,
            args: scriptArgs,
            timeoutMs: args.timeoutMs,
            maxToolCalls: args.maxToolCalls,
            trace: args.trace,
            tools: otherTools,
          }),
        );
        if (!result.ok) {
          const location =
            result.line !== undefined ? ` (line ${result.line})` : "";
          // Surface the run metadata callers need to recover from a timeout
          // or tool-call-cap hit: their console output, how far they got,
          // and the wall-clock cost. err() now accepts a structured payload
          // so we don't silently discard the RunScriptResult tail.
          return err(`${result.errorType}: ${result.message}${location}`, {
            errorType: result.errorType,
            message: result.message,
            line: result.line,
            toolCalls: result.toolCalls,
            durationMs: result.durationMs,
            logs: result.logs,
            ...(result.trace ? { trace: result.trace } : {}),
          });
        }
        const summary = `script ok: ${result.toolCalls} tool call(s) in ${result.durationMs}ms`;
        const structured: Record<string, unknown> = {
          result: result.result,
          toolCalls: result.toolCalls,
          durationMs: result.durationMs,
          logs: result.logs,
        };
        if (result.trace) structured.trace = result.trace;
        return ok(summary, structured);
      } catch (e) {
        // runScript bootstrap (wasm init, context alloc) or an unexpected
        // re-throw can land here — honour the errors-as-values contract.
        return err(`script failed: ${toMessage(e)}`);
      }
    },
  });
}
