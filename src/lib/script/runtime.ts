import {
  getQuickJS,
  type QuickJSContext,
  type QuickJSHandle,
} from "quickjs-emscripten";
import type { ToolDef } from "../../tools/types.js";
import { toMessage } from "../errors.js";
import {
  classifyInternalError,
  ScriptAbort,
  type ScriptErrorType,
} from "./errors.js";
import { ToolGateway, type TraceEntry } from "./gateway.js";
import {
  DEFAULT_TIMEOUT_MS,
  DEFAULT_TOOL_CALL_LIMIT,
  MAX_SOURCE_BYTES,
  MAX_TIMEOUT_MS,
  MAX_TOOL_CALL_LIMIT,
  VM_MEMORY_LIMIT_BYTES,
  VM_STACK_LIMIT_BYTES,
} from "./limits.js";
import { fromHandleChecked, toHandle } from "./serialize.js";

export interface RunScriptOptions {
  source: string;
  args?: unknown;
  timeoutMs?: number;
  maxToolCalls?: number;
  trace?: boolean;
  // biome-ignore lint/suspicious/noExplicitAny: heterogeneous tool shapes
  tools: ToolDef<any>[];
}

export type RunScriptResult =
  | {
      ok: true;
      result: unknown;
      toolCalls: number;
      durationMs: number;
      logs: string[];
      trace?: TraceEntry[];
    }
  | {
      ok: false;
      errorType: ScriptErrorType;
      message: string;
      line?: number;
      toolCalls: number;
      durationMs: number;
      logs: string[];
      trace?: TraceEntry[];
    };

const MAX_LOG_ENTRIES = 64;
const MAX_LOG_ENTRY_LEN = 4096;

interface VmError {
  name?: string;
  message?: string;
  stack?: string;
  lineNumber?: number;
  fileName?: string;
}

// Single entry point. Owns the VM lifecycle; creates a fresh runtime per
// call so two concurrent script runs share no globals, no prototype state,
// and no QuickJS heap.
export async function runScript(
  opts: RunScriptOptions,
): Promise<RunScriptResult> {
  const startedAt = Date.now();
  const logs: string[] = [];

  if (Buffer.byteLength(opts.source, "utf8") > MAX_SOURCE_BYTES) {
    return {
      ok: false,
      errorType: "source-too-large",
      message: `source exceeds ${MAX_SOURCE_BYTES} bytes`,
      toolCalls: 0,
      durationMs: Date.now() - startedAt,
      logs,
    };
  }

  const timeoutMs = clamp(
    opts.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    1,
    MAX_TIMEOUT_MS,
  );
  const maxToolCalls = clamp(
    opts.maxToolCalls ?? DEFAULT_TOOL_CALL_LIMIT,
    1,
    MAX_TOOL_CALL_LIMIT,
  );

  const gateway = new ToolGateway({
    tools: opts.tools,
    maxToolCalls,
    trace: opts.trace ?? false,
  });

  const QuickJS = await getQuickJS();
  const ctx = QuickJS.newContext();
  let abortReason: ScriptAbort | undefined;
  let disposed = false;
  const pending = new Set<Promise<void>>();
  const deadline = startedAt + timeoutMs;

  try {
    ctx.runtime.setMemoryLimit(VM_MEMORY_LIMIT_BYTES);
    ctx.runtime.setMaxStackSize(VM_STACK_LIMIT_BYTES);
    // Interrupt handler fires every few thousand bytecode instructions
    // while the VM is running. Returning true aborts whatever the VM is
    // doing with InternalError "interrupted". We trip on either the
    // wall-clock deadline or a structural abort recorded by a host call.
    ctx.runtime.setInterruptHandler(
      () => Date.now() > deadline || abortReason !== undefined,
    );

    installConsole(ctx, logs);
    installArgs(ctx, opts.args ?? null);
    installTools(
      ctx,
      gateway,
      pending,
      () => disposed,
      (reason) => {
        if (!abortReason) abortReason = reason;
      },
    );

    // Wrap user code in an async IIFE so top-level await and tools.*
    // calls work without ceremony. Trailing newline guards against the
    // last line being a `// comment` that would swallow the `)()`.
    const wrapped = `(async () => {\n${opts.source}\n})()`;
    const evalResult = ctx.evalCode(wrapped);
    if (evalResult.error) {
      const err = ctx.dump(evalResult.error) as VmError;
      evalResult.error.dispose();
      return makeError(err, abortReason, startedAt, gateway, logs);
    }

    // The IIFE returned a Promise handle. Drive both the VM's microtask
    // queue and host-side tool calls until either the outer promise
    // settles, the wall-clock deadline passes, or the gateway aborts.
    const promiseHandle = evalResult.value;
    try {
      ctx.runtime.executePendingJobs();
      while (true) {
        const state = ctx.getPromiseState(promiseHandle);
        if (state.type !== "pending") {
          // Settled: extract value or surface error below.
          if (state.type === "fulfilled") {
            try {
              const dumped = fromHandleChecked(ctx, state.value);
              state.value.dispose();
              return {
                ok: true,
                result: dumped.value,
                toolCalls: gateway.callsMade,
                durationMs: Date.now() - startedAt,
                logs,
                trace: gateway.trace,
              };
            } catch (e) {
              state.value.dispose();
              if (e instanceof ScriptAbort) {
                return {
                  ok: false,
                  errorType: e.errorType,
                  message: e.message,
                  toolCalls: gateway.callsMade,
                  durationMs: Date.now() - startedAt,
                  logs,
                };
              }
              throw e;
            }
          }
          const err = ctx.dump(state.error) as VmError;
          state.error.dispose();
          return makeError(err, abortReason, startedAt, gateway, logs);
        }

        // Still pending. If the wall-clock deadline has passed, force an
        // interrupt by driving jobs once more (the handler will return
        // true) and bail out via the error path.
        if (Date.now() > deadline) {
          // We stop waiting on any in-flight host tool calls and report the
          // timeout now. Those calls are NOT forcibly cancelled — the VM is
          // disposed so no NEW calls can start, and each network tool bounds
          // its own wait with a per-call timeout (http `timeoutMs`, the
          // inputUrl fetcher 10s, tls/whois/RDAP their own `timeoutMs`), so an
          // orphan self-terminates within that window rather than running
          // unbounded. Their results are discarded once `disposed` is set.
          return {
            ok: false,
            errorType: "timeout",
            message: `script exceeded ${timeoutMs}ms wall-clock budget`,
            toolCalls: gateway.callsMade,
            durationMs: Date.now() - startedAt,
            logs,
          };
        }

        if (pending.size === 0) {
          // No outstanding host work AND the VM has nothing to resume —
          // the outer promise can't be resolved by anything reachable.
          // Usual causes: a forgotten `await`, or a `new Promise(...)`
          // body that never calls resolve/reject.
          return {
            ok: false,
            errorType: "runtime",
            message:
              "script returned a Promise with no remaining work to resolve it — check for a missing `await` or a Promise constructor that never calls resolve/reject",
            toolCalls: gateway.callsMade,
            durationMs: Date.now() - startedAt,
            logs,
          };
        }

        // Race the deadline with pending host work so a hung tool call
        // can't outlast the budget.
        const remainingMs = Math.max(0, deadline - Date.now()) + 5;
        await Promise.race([
          Promise.race(pending),
          new Promise<void>((resolve) => setTimeout(resolve, remainingMs)),
        ]);
        ctx.runtime.executePendingJobs();
      }
    } finally {
      promiseHandle.dispose();
    }
  } finally {
    disposed = true;
    ctx.dispose();
  }
}

function clamp(n: number, lo: number, hi: number): number {
  if (!Number.isFinite(n)) return lo;
  return Math.max(lo, Math.min(hi, Math.trunc(n)));
}

function installConsole(ctx: QuickJSContext, logs: string[]): void {
  const consoleObj = ctx.newObject();
  for (const level of ["log", "info", "warn", "error", "debug"]) {
    const fn = ctx.newFunction(level, (...args: QuickJSHandle[]) => {
      if (logs.length >= MAX_LOG_ENTRIES) return ctx.undefined;
      const parts: string[] = [];
      for (const a of args) {
        const v = ctx.dump(a);
        parts.push(stringifyForLog(v));
      }
      let line = `[${level}] ${parts.join(" ")}`;
      if (line.length > MAX_LOG_ENTRY_LEN) {
        line = `${line.slice(0, MAX_LOG_ENTRY_LEN)}…`;
      }
      logs.push(line);
      return ctx.undefined;
    });
    fn.consume((f) => ctx.setProp(consoleObj, level, f));
  }
  ctx.setProp(ctx.global, "console", consoleObj);
  consoleObj.dispose();
}

function stringifyForLog(value: unknown): string {
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value) ?? String(value);
  } catch {
    return String(value);
  }
}

function installArgs(ctx: QuickJSContext, args: unknown): void {
  const handle = toHandle(ctx, args);
  ctx.setProp(ctx.global, "args", handle);
  handle.dispose();
}

function installTools(
  ctx: QuickJSContext,
  gateway: ToolGateway,
  pending: Set<Promise<void>>,
  isDisposed: () => boolean,
  onAbort: (reason: ScriptAbort) => void,
): void {
  const toolsObj = ctx.newObject();
  const installed = new Set<string>();
  for (const kebab of gateway.toolNames) {
    const camel = toCamel(kebab);
    const handler = (argsHandle: QuickJSHandle | undefined): QuickJSHandle =>
      dispatchToolCall(
        ctx,
        gateway,
        kebab,
        argsHandle,
        pending,
        isDisposed,
        onAbort,
      );
    if (!installed.has(camel)) {
      ctx
        .newFunction(camel, handler)
        .consume((fn) => ctx.setProp(toolsObj, camel, fn));
      installed.add(camel);
    }
    if (kebab !== camel && !installed.has(kebab)) {
      ctx
        .newFunction(kebab, handler)
        .consume((fn) => ctx.setProp(toolsObj, kebab, fn));
      installed.add(kebab);
    }
  }
  ctx.setProp(ctx.global, "tools", toolsObj);
  toolsObj.dispose();
}

function dispatchToolCall(
  ctx: QuickJSContext,
  gateway: ToolGateway,
  name: string,
  argsHandle: QuickJSHandle | undefined,
  pending: Set<Promise<void>>,
  isDisposed: () => boolean,
  onAbort: (reason: ScriptAbort) => void,
): QuickJSHandle {
  // Read the host-side JS arguments synchronously. The handle is owned by
  // the VM call frame, so it MUST be dumped before the async tail starts —
  // QuickJS may reuse the slot otherwise.
  let args: unknown;
  try {
    args = argsHandle ? ctx.dump(argsHandle) : undefined;
  } catch (e) {
    const errH = ctx.newString(
      `could not read arguments for '${name}': ${toMessage(e)}`,
    );
    // Convert to a thrown VM exception via a rejected promise constructed
    // synchronously below; falling through to deferred.reject is simpler.
    const deferred = ctx.newPromise();
    deferred.reject(errH);
    errH.dispose();
    deferred.dispose();
    ctx.runtime.executePendingJobs();
    return deferred.handle;
  }

  const deferred = ctx.newPromise();
  const work = (async () => {
    try {
      const result = await gateway.dispatch(name, args);
      if (isDisposed()) return; // VM gone — orphan, drop silently
      const valueHandle = toHandle(ctx, result);
      try {
        deferred.resolve(valueHandle);
      } finally {
        valueHandle.dispose();
      }
    } catch (e) {
      if (isDisposed()) return;
      if (e instanceof ScriptAbort) {
        onAbort(e);
      }
      const message = toMessage(e);
      // Build a VM Error so `try/catch` in the script sees `e instanceof Error`.
      const errCtor = ctx.getProp(ctx.global, "Error");
      const msgHandle = ctx.newString(message);
      let errHandle: QuickJSHandle;
      try {
        const res = ctx.callFunction(errCtor, ctx.undefined, msgHandle);
        if (res.error) {
          // Couldn't construct Error (vanishingly unlikely) — fall back
          // to rejecting with the bare string instead.
          res.error.dispose();
          errHandle = ctx.newString(message);
        } else {
          errHandle = res.value;
        }
      } finally {
        msgHandle.dispose();
        errCtor.dispose();
      }
      try {
        deferred.reject(errHandle);
      } finally {
        errHandle.dispose();
      }
    } finally {
      if (!isDisposed()) {
        try {
          ctx.runtime.executePendingJobs();
        } catch {
          // VM may have been disposed between our check and this call;
          // swallow rather than crash the host.
        }
      }
      deferred.dispose();
    }
  })();
  pending.add(work);
  void work.then(
    () => pending.delete(work),
    () => pending.delete(work),
  );
  return deferred.handle;
}

function toCamel(name: string): string {
  return name.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
}

function makeError(
  vmError: VmError,
  abortReason: ScriptAbort | undefined,
  startedAt: number,
  gateway: ToolGateway,
  logs: string[],
): RunScriptResult {
  // A structural abort recorded during dispatch beats whatever the VM
  // ended up reporting — the gateway has the precise reason.
  if (abortReason) {
    return {
      ok: false,
      errorType: abortReason.errorType,
      message: abortReason.message,
      toolCalls: gateway.callsMade,
      durationMs: Date.now() - startedAt,
      logs,
    };
  }
  let errorType: ScriptErrorType;
  if (vmError.name === "SyntaxError") errorType = "syntax";
  else if (vmError.name === "InternalError")
    errorType = classifyInternalError(vmError.message ?? "");
  else errorType = "runtime";
  const message = vmError.message ?? vmError.name ?? "script failed";
  // User source is wrapped as `(async () => {\n${source}\n})()`. That puts
  // user line 1 at VM line 2, so the VM's reported line is always +1 off
  // from the line the caller wrote. Correct for the wrapper; preserve the
  // raw value when it's 1 (which can only mean the wrapper line itself).
  const rawLine =
    typeof vmError.lineNumber === "number" ? vmError.lineNumber : undefined;
  const line = rawLine !== undefined && rawLine >= 2 ? rawLine - 1 : rawLine;
  return {
    ok: false,
    errorType,
    message,
    line,
    toolCalls: gateway.callsMade,
    durationMs: Date.now() - startedAt,
    logs,
  };
}
