// Single source of truth for the failure modes a script run can produce.
// Every path that aborts a script must map to one of these so callers get a
// stable, structured error type — never a guess.

export type ScriptErrorType =
  | "syntax" // user source did not parse
  | "runtime" // user code threw at runtime
  | "timeout" // wall-clock interrupt fired
  | "memory" // VM heap limit exceeded
  | "stack" // VM call stack exhausted
  | "tool-call-limit" // gateway counter exceeded
  | "tool-error" // an underlying tool returned isError
  | "serialize" // host could not (de)serialise args/result
  | "source-too-large"; // source exceeded MAX_SOURCE_BYTES

export interface ScriptError {
  errorType: ScriptErrorType;
  message: string;
  line?: number;
  column?: number;
}

export class ScriptAbort extends Error {
  readonly errorType: ScriptErrorType;
  constructor(errorType: ScriptErrorType, message: string) {
    super(message);
    this.errorType = errorType;
    this.name = "ScriptAbort";
  }
}

// Map a QuickJS `InternalError` message to one of our error types. The
// engine uses a handful of distinct strings for the conditions we care
// about; everything else falls through to 'runtime'.
export function classifyInternalError(message: string): ScriptErrorType {
  const m = message.toLowerCase();
  if (m.includes("interrupted")) return "timeout";
  if (m.includes("stack overflow")) return "stack";
  if (
    m.includes("out of memory") ||
    m.includes("string too long") ||
    m.includes("array buffer too big")
  )
    return "memory";
  return "runtime";
}
