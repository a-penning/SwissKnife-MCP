import { z } from "zod";
import type { ToolDef } from "../../tools/types.js";
import { ScriptAbort } from "./errors.js";
import { MAX_TRACE_ENTRIES } from "./limits.js";

export interface TraceEntry {
  tool: string;
  ok: boolean;
  durationMs: number;
}

export interface GatewayOptions {
  // The tool registry to dispatch into. `script` itself is intentionally
  // excluded by the caller so a script cannot recursively spawn scripts.
  // biome-ignore lint/suspicious/noExplicitAny: heterogeneous tool shapes
  tools: ToolDef<any>[];
  maxToolCalls: number;
  trace: boolean;
}

// kebab-case ↔ camelCase. The MCP-exposed names are kebab-case
// (`convert-data`, `json-query`) but property names in JS land are
// camelCase. Both forms are accepted from inside the VM so users don't
// have to remember which is which.
function toCamel(name: string): string {
  return name.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
}

export class ToolGateway {
  // biome-ignore lint/suspicious/noExplicitAny: heterogeneous tool shapes
  private readonly byName = new Map<string, ToolDef<any>>();
  private readonly maxToolCalls: number;
  private readonly traceEnabled: boolean;
  private readonly traceLog: TraceEntry[] = [];
  private callCount = 0;

  constructor(opts: GatewayOptions) {
    for (const tool of opts.tools) {
      this.byName.set(tool.name, tool);
      this.byName.set(toCamel(tool.name), tool);
    }
    this.maxToolCalls = opts.maxToolCalls;
    this.traceEnabled = opts.trace;
  }

  get toolNames(): string[] {
    // Each tool is registered under both kebab and camel — return only
    // the kebab originals so callers can iterate uniquely.
    const seen = new Set<string>();
    for (const t of this.byName.values()) seen.add(t.name);
    return [...seen];
  }

  get callsMade(): number {
    return this.callCount;
  }

  get trace(): TraceEntry[] | undefined {
    return this.traceEnabled ? this.traceLog : undefined;
  }

  // Dispatch a single tool invocation from the VM. Throws ScriptAbort for
  // fatal failures (limit exceeded); throws a plain Error for tool-level
  // failures so the user script can `try/catch` and recover.
  //
  // Multiple dispatches may be in flight concurrently — the host runtime
  // uses sync VM functions + deferred VM promises, so Promise.all over
  // tools.* is safe. The call counter is incremented atomically before
  // the handler runs, so the cap applies to concurrent calls too.
  async dispatch(name: string, args: unknown): Promise<unknown> {
    if (this.callCount >= this.maxToolCalls) {
      throw new ScriptAbort(
        "tool-call-limit",
        `tool-call limit reached (${this.maxToolCalls}); refuse '${name}'`,
      );
    }
    const tool = this.byName.get(name);
    if (!tool) {
      throw new Error(`unknown tool '${name}'`);
    }

    // Args from QuickJS arrive as plain JS values via ctx.dump. Run them
    // through the tool's Zod schema in STRICT mode so unknown keys are
    // caught at the boundary rather than silently dropped — a caller who
    // typoed a param name needs to see that, not a downstream handler
    // complaining about a missing field. The error message is enriched
    // with the receiving tool name, the offending key(s), and the schema's
    // accepted keys, so the script can self-correct inside one VM run
    // (no need to leave the VM to look the schema up).
    const acceptedKeys = Object.keys(tool.inputSchema);
    let parsed: unknown;
    try {
      parsed = z
        .object(tool.inputSchema)
        .strict()
        .parse(args ?? {});
    } catch (e) {
      throw new Error(formatGatewayError(name, acceptedKeys, e));
    }

    this.callCount += 1;
    const startedAt = Date.now();
    // biome-ignore lint/suspicious/noExplicitAny: tool handler is typed by Zod elsewhere
    const result = await tool.handler(parsed as any);
    const durationMs = Date.now() - startedAt;
    if (result.isError) {
      const text =
        (result.content?.[0] as { type: string; text?: string } | undefined)
          ?.text ?? "tool reported an error";
      // err() prefixes its text content with "Error: " for human MCP
      // output. When that string is wrapped in `new Error(...)` here, the
      // VM's toString gives "Error: Error: <msg>" — double-prefixed.
      // Strip the leading prefix so the script-side stringification is
      // clean ("Error: <msg>") regardless of how callers stringify it.
      const message = text.startsWith("Error: ") ? text.slice(7) : text;
      this.recordTrace(tool.name, false, durationMs);
      throw new Error(message);
    }
    this.recordTrace(tool.name, true, durationMs);
    return result.structuredContent ?? {};
  }

  private recordTrace(tool: string, ok: boolean, durationMs: number): void {
    if (!this.traceEnabled) return;
    if (this.traceLog.length >= MAX_TRACE_ENTRIES) return;
    this.traceLog.push({ tool, ok, durationMs });
  }
}

// Lightweight Levenshtein for "did you mean" suggestions. Capped at the
// length-2 typo case; anything beyond that isn't a useful hint, just noise.
function suggestKey(input: string, candidates: string[]): string | undefined {
  const lower = input.toLowerCase();
  let best: { key: string; distance: number } | undefined;
  for (const candidate of candidates) {
    const distance = editDistance(lower, candidate.toLowerCase());
    if (distance === 0) continue;
    if (!best || distance < best.distance) best = { key: candidate, distance };
  }
  if (!best) return undefined;
  const threshold = Math.max(1, Math.floor(input.length / 2));
  return best.distance <= threshold ? best.key : undefined;
}

function editDistance(a: string, b: string): number {
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const curr = [i];
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr.push(
        Math.min(
          (curr[j - 1] as number) + 1,
          (prev[j] as number) + 1,
          (prev[j - 1] as number) + cost,
        ),
      );
    }
    prev = curr;
  }
  return prev[b.length] as number;
}

function formatGatewayError(
  toolName: string,
  acceptedKeys: string[],
  err: unknown,
): string {
  if (!(err instanceof z.ZodError)) {
    return `${toolName}: invalid arguments — ${String(err)}`;
  }
  const parts: string[] = [];
  for (const issue of err.issues) {
    if (issue.code === "unrecognized_keys") {
      const unknownKeys = (issue as unknown as { keys: string[] }).keys ?? [];
      for (const key of unknownKeys) {
        const hint = suggestKey(key, acceptedKeys);
        parts.push(
          hint
            ? `unknown parameter '${key}' (did you mean '${hint}'?)`
            : `unknown parameter '${key}'`,
        );
      }
      continue;
    }
    const path = issue.path.length ? `${issue.path.join(".")}: ` : "";
    parts.push(`${path}${issue.message}`);
  }
  const accepted = acceptedKeys.length
    ? ` Accepted parameters: ${acceptedKeys.join(", ")}.`
    : "";
  return `${toolName}: ${parts.join("; ")}.${accepted}`;
}
