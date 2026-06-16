import { describe, expect, it } from "vitest";
import { z } from "zod";
import { runScript } from "../../../src/lib/script/runtime.js";
import { defineTool, err, ok } from "../../../src/tools/types.js";

// A controllable echo tool used across the gateway tests. Each call
// returns `{ in: <arg> }` so the test can verify pass-through. An
// optional `fail` flag forces an isError response.
const echoTool = defineTool({
  name: "echo",
  title: "echo",
  description: "tests only",
  inputSchema: {
    n: z.number().int(),
    fail: z.boolean().default(false),
    delayMs: z.number().int().min(0).max(1000).default(0),
  },
  handler: async (args) => {
    if (args.delayMs > 0) {
      await new Promise((r) => setTimeout(r, args.delayMs));
    }
    if (args.fail) return err(`echo failed for n=${args.n}`);
    return ok(String(args.n), { in: args.n });
  },
});

// A second tool to exercise multi-tool dispatch and kebab/camel mapping.
const twoWordsTool = defineTool({
  name: "two-words",
  title: "two-words",
  description: "tests only",
  inputSchema: { v: z.number() },
  handler: (args) => ok(String(args.v), { out: args.v * 2 }),
});

describe("script runtime: gateway and concurrency", () => {
  it("exposes a tool under both kebab and camel name", async () => {
    const r1 = await runScript({
      source: `return await tools.twoWords({ v: 7 });`,
      tools: [twoWordsTool],
    });
    expect(r1.ok && r1.result).toEqual({ out: 14 });
    const r2 = await runScript({
      source: `return await tools["two-words"]({ v: 9 });`,
      tools: [twoWordsTool],
    });
    expect(r2.ok && r2.result).toEqual({ out: 18 });
  });

  it("counts every tool call", async () => {
    const r = await runScript({
      source: `
        let sum = 0;
        for (let i = 0; i < 7; i++) {
          const out = await tools.echo({ n: i });
          sum += out.in;
        }
        return sum;
      `,
      tools: [echoTool],
    });
    expect(r.ok && r.result).toBe(0 + 1 + 2 + 3 + 4 + 5 + 6);
    if (r.ok) expect(r.toolCalls).toBe(7);
  });

  it("enforces the maxToolCalls cap", async () => {
    const r = await runScript({
      source: `
        for (let i = 0; i < 10; i++) await tools.echo({ n: i });
        return "should-not-reach";
      `,
      tools: [echoTool],
      maxToolCalls: 3,
    });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.errorType).toBe("tool-call-limit");
    expect(r.toolCalls).toBe(3);
  });

  it("a tool that returns isError throws an Error inside the VM", async () => {
    const r = await runScript({
      source: `
        try {
          await tools.echo({ n: 1, fail: true });
          return "no-throw";
        } catch (e) {
          return { caught: true, msg: e.message };
        }
      `,
      tools: [echoTool],
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.result).toMatchObject({ caught: true });
    expect((r.result as { msg: string }).msg.toLowerCase()).toContain(
      "echo failed",
    );
  });

  it("an unknown tool name throws a catchable TypeError (no such function)", async () => {
    const r = await runScript({
      source: `
        try { await tools.nope({}); return "no-throw"; }
        catch (e) { return { msg: String(e.message) }; }
      `,
      tools: [echoTool],
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    // tools.nope is undefined → calling it throws a VM TypeError. The
    // important thing is that the script catches it and continues.
    expect((r.result as { msg: string }).msg.toLowerCase()).toMatch(
      /not a function|undefined/,
    );
  });

  it("invalid arguments to a tool throw a catchable Error with the tool name and accepted-keys hint", async () => {
    const r = await runScript({
      source: `
        try { await tools.echo({ n: "not a number" }); return "no"; }
        catch (e) { return { msg: e.message }; }
      `,
      tools: [echoTool],
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const msg = (r.result as { msg: string }).msg;
    // Error message must self-document for inside-VM self-correction:
    // names the receiving tool, the offending param, AND the accepted-keys set.
    expect(msg).toContain("echo");
    expect(msg.toLowerCase()).toContain("expected number");
    expect(msg).toContain("Accepted parameters:");
  });

  it("handler errors don't get a double 'Error: Error:' prefix", async () => {
    const r = await runScript({
      source: `
        try { await tools.echo({ n: 1, fail: true }); return "no"; }
        catch (e) { return { msg: String(e), name: e.name }; }
      `,
      tools: [echoTool],
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const { msg, name } = r.result as { msg: string; name: string };
    expect(name).toBe("Error");
    // The handler returns err("echo failed for n=1"). The script gateway
    // must strip the "Error: " prefix from err()'s text content BEFORE
    // wrapping in `new Error(...)`, otherwise `String(e)` produces
    // "Error: Error: echo failed for n=1".
    expect(msg).not.toMatch(/^Error: Error: /);
    expect(msg).toBe("Error: echo failed for n=1");
  });

  it("an unknown parameter name surfaces with a 'did you mean' hint", async () => {
    const r = await runScript({
      source: `
        try { await tools.echo({ nn: 1 }); return "no"; }
        catch (e) { return { msg: e.message }; }
      `,
      tools: [echoTool],
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const msg = (r.result as { msg: string }).msg;
    expect(msg).toContain("unknown parameter 'nn'");
    expect(msg).toContain("did you mean 'n'");
  });

  it("parallel tool calls via Promise.all all complete (sync-context bridge)", async () => {
    const r = await runScript({
      source: `
        const results = await Promise.all([
          tools.echo({ n: 1, delayMs: 20 }),
          tools.echo({ n: 2, delayMs: 20 }),
          tools.echo({ n: 3, delayMs: 20 }),
        ]);
        return results.map(r => r.in);
      `,
      tools: [echoTool],
    });
    expect(r.ok && r.result).toEqual([1, 2, 3]);
    if (r.ok) expect(r.toolCalls).toBe(3);
  });

  it("parallel tool calls share the maxToolCalls budget", async () => {
    const r = await runScript({
      source: `
        const calls = [];
        for (let i = 0; i < 5; i++) calls.push(tools.echo({ n: i }));
        return (await Promise.all(calls)).length;
      `,
      tools: [echoTool],
      maxToolCalls: 3,
    });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.errorType).toBe("tool-call-limit");
  });

  it("two concurrent script runs do not share gateway counters", async () => {
    const [a, b] = await Promise.all([
      runScript({
        source: `
          for (let i = 0; i < 5; i++) await tools.echo({ n: i });
          return "a-done";
        `,
        tools: [echoTool],
        maxToolCalls: 10,
      }),
      runScript({
        source: `
          for (let i = 0; i < 5; i++) await tools.echo({ n: i });
          return "b-done";
        `,
        tools: [echoTool],
        maxToolCalls: 10,
      }),
    ]);
    expect(a.ok && a.result).toBe("a-done");
    expect(b.ok && b.result).toBe("b-done");
    if (a.ok) expect(a.toolCalls).toBe(5);
    if (b.ok) expect(b.toolCalls).toBe(5);
  });

  it("trace=true returns one entry per dispatched call, ok flag per tool result", async () => {
    const r = await runScript({
      source: `
        await tools.echo({ n: 1 });
        try { await tools.echo({ n: 2, fail: true }); } catch {}
        await tools.echo({ n: 3 });
        return "done";
      `,
      tools: [echoTool],
      trace: true,
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.trace).toHaveLength(3);
    expect(r.trace?.map((t) => t.ok)).toEqual([true, false, true]);
    expect(r.trace?.every((t) => t.tool === "echo")).toBe(true);
  });

  it("trace=false (default) omits trace from the result", async () => {
    const r = await runScript({
      source: `await tools.echo({ n: 1 }); return 1;`,
      tools: [echoTool],
    });
    expect(r.ok && r.trace).toBeUndefined();
  });
});
