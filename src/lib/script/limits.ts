// Hard caps applied to every script run. Defaults err on the side of
// "would not block another script for long" rather than "lets the user do as
// much as they like" — the script tool is glue, not a compute engine.

export const DEFAULT_TIMEOUT_MS = 30_000;
export const MAX_TIMEOUT_MS = 60_000;
export const DEFAULT_TOOL_CALL_LIMIT = 100;
export const MAX_TOOL_CALL_LIMIT = 500;

// QuickJS WASM heap. Exceeding this surfaces as `string too long` /
// out-of-memory errors inside the VM, mapped to errorType='memory'.
export const VM_MEMORY_LIMIT_BYTES = 64 * 1024 * 1024;

// QuickJS C-stack budget for the VM. Recursion past this hits a clean
// `stack overflow` InternalError, not a process crash.
export const VM_STACK_LIMIT_BYTES = 256 * 1024;

// User-supplied source length. Generous, but stops a misclient from
// uploading megabytes of code before we look at it.
export const MAX_SOURCE_BYTES = 64 * 1024;

// Cap on the final JSON serialisation of the script's return value. Beyond
// this we surface `serialize` rather than handing a multi-megabyte blob back
// through MCP.
export const MAX_RESULT_BYTES = 1 * 1024 * 1024;

// How many trace entries we keep when trace=true. Each is small but
// unbounded growth would defeat the result cap.
export const MAX_TRACE_ENTRIES = 500;
