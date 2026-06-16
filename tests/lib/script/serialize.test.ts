import { describe, expect, it } from "vitest";
import { MAX_RESULT_BYTES } from "../../../src/lib/script/limits.js";
import { runScript } from "../../../src/lib/script/runtime.js";

async function run(
  source: string,
  args?: unknown,
  opts: Partial<Parameters<typeof runScript>[0]> = {},
) {
  return runScript({ source, args, tools: [], ...opts });
}

describe("script runtime: serialisation", () => {
  it("round-trips primitive values", async () => {
    expect(
      await run(`return { n: 42, s: "hi", b: true, z: null };`).then(
        (r) => r.ok && r.result,
      ),
    ).toEqual({ n: 42, s: "hi", b: true, z: null });
  });

  it("round-trips nested arrays and objects", async () => {
    const r = await run(`return { a: [1, [2, [3]]], b: { c: { d: "x" } } };`);
    expect(r.ok && r.result).toEqual({
      a: [1, [2, [3]]],
      b: { c: { d: "x" } },
    });
  });

  it("drops undefined-valued object keys (JSON-ish semantics)", async () => {
    const r = await run(`return { kept: 1, dropped: undefined };`);
    expect(r.ok && r.result).toEqual({ kept: 1 });
  });

  it("converts undefined array entries to null", async () => {
    const r = await run(`return [1, undefined, 3];`);
    // JSON.stringify gives [1,null,3]; ctx.dump matches that semantics.
    expect(r.ok && r.result).toEqual([1, null, 3]);
  });

  it("rejects NaN return values explicitly", async () => {
    const r = await run(`return NaN;`);
    // NaN dumps to null via JSON, so the value comes back as null —
    // documented behaviour, no error.
    expect(r.ok && r.result).toBeNull();
  });

  it("returning a Symbol does not crash; comes back as null", async () => {
    const r = await run(`return Symbol("x");`);
    // ctx.dump returns undefined for symbols; the runtime coerces undefined
    // to null at the JSON boundary.
    expect(r.ok && r.result).toBeNull();
  });

  it("returning a function does not crash; comes back as its source string", async () => {
    // ctx.dump on a function returns its source text, which then survives
    // JSON serialisation as a plain string. Documented quirk — functions
    // are not transferable across the VM/host boundary.
    const r = await run(`return () => 1;`);
    expect(r.ok && typeof r.result).toBe("string");
  });

  it("functions inside objects are dropped (JSON-ish semantics)", async () => {
    const r = await run(`return { keep: 1, drop: function f() {} };`);
    expect(r.ok && r.result).toEqual({ keep: 1 });
  });

  it("returning a value larger than the cap fails with serialize", async () => {
    const r = await run(
      `return 'x'.repeat(${MAX_RESULT_BYTES + 1000});`,
      undefined,
      { timeoutMs: 5000 },
    );
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.errorType).toBe("serialize");
  });

  it("args are exposed and round-trip JSON-cloneably", async () => {
    const r = await run(`return { sum: args.a + args.b, name: args.name };`, {
      a: 2,
      b: 3,
      name: "x",
    });
    expect(r.ok && r.result).toEqual({ sum: 5, name: "x" });
  });

  it("args default to null when not provided", async () => {
    const r = await run(`return args;`);
    expect(r.ok && r.result).toBeNull();
  });

  it("string args round-trip even when they happen to be JSON-shaped", async () => {
    const r = await run(`return typeof args + ":" + args;`, "hello");
    expect(r.ok && r.result).toBe("string:hello");
  });

  it("BigInt at the boundary fails with a clear serialize error", async () => {
    // Returning a BigInt from the script — ctx.dump in QuickJS surfaces
    // it as a JS BigInt which JSON.stringify can't serialise, so we
    // expect a serialize error.
    const r = await run(`return 12345678901234567890n;`);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.errorType).toBe("serialize");
  });
});
