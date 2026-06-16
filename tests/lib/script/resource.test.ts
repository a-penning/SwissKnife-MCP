import { describe, expect, it } from "vitest";
import { runScript } from "../../../src/lib/script/runtime.js";

// Resource-exhaustion paths. Each case must produce a structured error and
// dispose the VM cleanly — no process abort, no hanging, no later failures
// affecting the next test.

async function run(
  source: string,
  opts: Partial<Parameters<typeof runScript>[0]> = {},
) {
  return runScript({ source, tools: [], ...opts });
}

describe("script runtime: resource limits", () => {
  it("wall-clock timeout interrupts an infinite while loop", async () => {
    const res = await run("while (true) {}", { timeoutMs: 200 });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.errorType).toBe("timeout");
    expect(res.durationMs).toBeGreaterThanOrEqual(150);
    expect(res.durationMs).toBeLessThan(2000);
  });

  it("wall-clock timeout interrupts a CPU-bound for loop", async () => {
    const res = await run("for (let i = 0; i < 1e12; i++) {}", {
      timeoutMs: 200,
    });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.errorType).toBe("timeout");
  });

  it("wall-clock timeout interrupts a microtask flood", async () => {
    const res = await run(
      "for (let i = 0; i < 1e7; i++) await Promise.resolve();",
      { timeoutMs: 200 },
    );
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.errorType).toBe("timeout");
  });

  it("stack overflow on direct recursion is caught", async () => {
    const res = await run("function f(){ f(); } f();");
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.errorType).toBe("stack");
  });

  it("stack overflow on mutual recursion is caught", async () => {
    const res = await run("function a(){ b(); } function b(){ a(); } a();");
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.errorType).toBe("stack");
  });

  it("heap exhaustion via string growth surfaces as memory", async () => {
    const res = await run(
      "let s = 'x'; for (let i = 0; i < 60; i++) s += s; return s.length;",
      { timeoutMs: 5000 },
    );
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.errorType).toBe("memory");
  });

  it("heap exhaustion via array growth surfaces as memory", async () => {
    const res = await run(
      `const a = [];
       while (true) { a.push(new Array(100000).fill(0)); }`,
      { timeoutMs: 5000 },
    );
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.errorType).toBe("memory");
  });

  it("rejects source larger than the source cap", async () => {
    const big = `// ${"x".repeat(80_000)}\nreturn 1;`;
    const res = await run(big);
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.errorType).toBe("source-too-large");
  });

  it("plain syntax errors surface as syntax", async () => {
    const res = await run("return 1 + ;");
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.errorType).toBe("syntax");
  });

  it("user throw surfaces as runtime with the original message", async () => {
    const res = await run("throw new Error('boom');");
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.errorType).toBe("runtime");
    expect(res.message).toContain("boom");
  });

  it("a Promise that never settles fails as runtime (deadlock detection)", async () => {
    const res = await run("await new Promise(() => {});", { timeoutMs: 300 });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    // The polling loop notices no pending host work and refuses to wait
    // forever — could surface as `runtime` (deadlock) OR `timeout`
    // depending on which check fires first. Both are acceptable; the
    // important guarantee is that the script doesn't hang the test runner.
    expect(["runtime", "timeout"]).toContain(res.errorType);
  });
});
