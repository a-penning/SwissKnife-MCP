import { describe, expect, it } from "vitest";
import { runScript } from "../../../src/lib/script/runtime.js";

// Sandbox escape attempts. The QuickJS VM lives in a separate WASM heap
// with no syscalls and no FFI, so most of these are about asserting that
// the obvious "host primitives" really are not reachable.

async function value(source: string) {
  const res = await runScript({ source, tools: [] });
  if (!res.ok)
    throw new Error(`script failed: ${res.errorType} ${res.message}`);
  return res.result;
}

async function run(source: string) {
  return runScript({ source, tools: [] });
}

describe("script runtime: sandbox", () => {
  it("does not expose Node-only globals", async () => {
    expect(
      await value(`
        return {
          process: typeof process,
          require: typeof require,
          Buffer: typeof Buffer,
          global: typeof global,
          fetch: typeof fetch,
          setImmediate: typeof setImmediate,
        };
      `),
    ).toEqual({
      process: "undefined",
      require: "undefined",
      Buffer: "undefined",
      global: "undefined",
      fetch: "undefined",
      setImmediate: "undefined",
    });
  });

  it("does not expose WebAssembly or other host modules", async () => {
    expect(
      await value(`
        return {
          WebAssembly: typeof WebAssembly,
          XMLHttpRequest: typeof XMLHttpRequest,
          WebSocket: typeof WebSocket,
        };
      `),
    ).toEqual({
      WebAssembly: "undefined",
      XMLHttpRequest: "undefined",
      WebSocket: "undefined",
    });
  });

  it("does not allow dynamic import", async () => {
    const res = await run("await import('fs');");
    expect(res.ok).toBe(false);
    if (res.ok) return;
    // QuickJS rejects this as a syntax error (no module resolver) or
    // runtime error (resolver returns nothing). Either is fine, neither
    // is "fs loaded".
    expect(["syntax", "runtime"]).toContain(res.errorType);
  });

  it("eval and new Function do not unlock Node globals", async () => {
    expect(
      await value(`
        return {
          eval: eval("typeof process"),
          newFn: new Function("return typeof process")(),
        };
      `),
    ).toEqual({ eval: "undefined", newFn: "undefined" });
  });

  it("constructor chain on functions does not reach host primitives", async () => {
    // .constructor.constructor escapes the immediate function realm, but
    // in QuickJS that still lands inside the VM's own Function — no host
    // primitive is reachable.
    expect(
      await value(`
        const ctor = (() => {}).constructor.constructor;
        return ctor("return typeof process")();
      `),
    ).toBe("undefined");
  });

  it("globals set in one VM do not leak into the next VM", async () => {
    // Sequential to keep the assertion simple; the same fresh-context
    // guarantee applies to parallel runs since each invocation calls
    // QuickJS.newContext().
    const a = await runScript({
      source: `globalThis.LEAK = 'from-a'; return globalThis.LEAK;`,
      tools: [],
    });
    expect(a.ok && a.result).toBe("from-a");
    const b = await runScript({
      source: `return typeof globalThis.LEAK;`,
      tools: [],
    });
    expect(b.ok && b.result).toBe("undefined");
  });

  it("two scripts run concurrently in separate contexts do not collide", async () => {
    const [a, b] = await Promise.all([
      runScript({
        source: `globalThis.X = 1; for (let i = 0; i < 5000; i++) {} return globalThis.X;`,
        tools: [],
      }),
      runScript({
        source: `globalThis.X = 2; for (let i = 0; i < 5000; i++) {} return globalThis.X;`,
        tools: [],
      }),
    ]);
    expect(a.ok && a.result).toBe(1);
    expect(b.ok && b.result).toBe(2);
  });

  it("prototype pollution inside the VM does not affect the host", async () => {
    await runScript({
      source: `Object.prototype.LEAK = "vm";`,
      tools: [],
    });
    // host check: a fresh object on the host side should not have LEAK
    expect(({} as { LEAK?: unknown }).LEAK).toBeUndefined();
  });

  it("the script tool itself is not reachable from inside the VM", async () => {
    // tools: [] simulates a registry-less call; here we explicitly check
    // that even a name lookup for "script" misses.
    const res = await runScript({
      source: "return typeof tools.script;",
      tools: [],
    });
    expect(res.ok).toBe(true);
    if (res.ok) expect(res.result).toBe("undefined");
  });
});
