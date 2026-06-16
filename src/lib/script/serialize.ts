import type { QuickJSContext, QuickJSHandle } from "quickjs-emscripten";
import { toMessage } from "../errors.js";
import { ScriptAbort } from "./errors.js";
import { MAX_RESULT_BYTES } from "./limits.js";

// Convert a JSON-cloneable host value into a VM handle. The caller owns
// the returned handle and must dispose it (or hand it to the VM which
// takes ownership).
//
// Only JSON-y values are supported. Functions/symbols/undefined property
// values silently mirror JSON.stringify semantics (undefined keys are
// dropped, undefined array entries become null, function/symbol throw).
// Anything weirder is converted to its string representation rather than
// crash the VM bridge.
export function toHandle(ctx: QuickJSContext, value: unknown): QuickJSHandle {
  if (value === null || value === undefined) return ctx.null;
  if (value === true) return ctx.true;
  if (value === false) return ctx.false;
  switch (typeof value) {
    case "number":
      if (!Number.isFinite(value)) {
        throw new ScriptAbort(
          "serialize",
          `cannot pass non-finite number ${value} across the VM boundary`,
        );
      }
      return ctx.newNumber(value);
    case "string":
      return ctx.newString(value);
    case "bigint":
      // No JSON-equivalent for BigInt; reject loudly so callers don't
      // silently lose precision.
      throw new ScriptAbort(
        "serialize",
        "cannot pass BigInt across the VM boundary (not JSON-representable)",
      );
    case "function":
    case "symbol":
      throw new ScriptAbort(
        "serialize",
        `cannot pass ${typeof value} across the VM boundary`,
      );
  }
  if (Array.isArray(value)) {
    const arr = ctx.newArray();
    for (let i = 0; i < value.length; i++) {
      const child = toHandle(ctx, value[i]);
      ctx.setProp(arr, i, child);
      child.dispose();
    }
    return arr;
  }
  if (typeof value === "object") {
    if (value instanceof Date) return ctx.newString(value.toISOString());
    const obj = ctx.newObject();
    for (const [k, v] of Object.entries(value)) {
      if (v === undefined) continue; // JSON-ish: drop undefined keys
      const child = toHandle(ctx, v);
      ctx.setProp(obj, k, child);
      child.dispose();
    }
    return obj;
  }
  // Unreachable in practice; defensive fallback.
  return ctx.newString(String(value));
}

// Read a VM handle back to a plain host value, then validate that it is
// safely JSON-serialisable AND below the result-size cap. The size check
// runs against the final string form so callers see the exact byte count
// that would leave the server.
export function fromHandleChecked(
  ctx: QuickJSContext,
  handle: QuickJSHandle,
): { value: unknown; json: string } {
  // ctx.dump walks the VM value via QuickJS' own JSON-ish conversion. It
  // returns undefined for VM `undefined`, and throws for cyclic values.
  let dumped: unknown;
  try {
    dumped = ctx.dump(handle);
  } catch (e) {
    throw new ScriptAbort(
      "serialize",
      `could not extract return value from VM: ${toMessage(e)}`,
    );
  }

  let json: string;
  try {
    json = JSON.stringify(dumped ?? null);
  } catch (e) {
    throw new ScriptAbort(
      "serialize",
      `return value is not JSON-serialisable: ${toMessage(e)}`,
    );
  }
  if (json === undefined) {
    // JSON.stringify(undefined) === undefined — happens when the VM
    // returns e.g. a function (which ctx.dump returns as undefined too).
    json = "null";
    dumped = null;
  }
  if (Buffer.byteLength(json, "utf8") > MAX_RESULT_BYTES) {
    throw new ScriptAbort(
      "serialize",
      `return value exceeds ${MAX_RESULT_BYTES} bytes when JSON-encoded`,
    );
  }
  // Normalise the host value to "what JSON would carry over the wire" so
  // callers see exactly what MCP delivers. NaN/Infinity collapse to null,
  // unsupported types are dropped from containers — the same contract
  // every other tool's structuredContent follows.
  const value = JSON.parse(json) as unknown;
  return { value, json };
}
