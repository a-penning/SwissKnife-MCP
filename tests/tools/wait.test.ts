import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MAX_CONCURRENT_WAITS, waitTool } from "../../src/tools/wait.js";

type Args = Parameters<typeof waitTool.handler>[0];

const text = (res: CallToolResult): string =>
  String((res.content?.[0] as { text?: string })?.text ?? "");

// Drive the handler under fake timers so the setTimeout resolves instantly
// (no real waiting) while we control exactly when it fires.
async function runTimed(
  args: Args,
  advanceMs: number,
): Promise<CallToolResult> {
  vi.useFakeTimers();
  try {
    const p = Promise.resolve(waitTool.handler(args));
    await vi.advanceTimersByTimeAsync(advanceMs);
    return await p;
  } finally {
    vi.useRealTimers();
  }
}

afterEach(() => {
  vi.useRealTimers();
});

describe("wait: happy path", () => {
  it("waits the requested duration and echoes it back", async () => {
    const res = await runTimed({ amount: 2, unit: "seconds" }, 2000);
    expect(res.isError).toBeFalsy();
    expect(res.structuredContent).toMatchObject({
      amount: 2,
      unit: "seconds",
      requestedMs: 2000,
    });
  });

  it("converts each unit to milliseconds", async () => {
    const ms = await runTimed({ amount: 250, unit: "milliseconds" }, 250);
    expect(ms.structuredContent).toMatchObject({ requestedMs: 250 });

    const min = await runTimed({ amount: 1, unit: "minutes" }, 60_000);
    expect(min.structuredContent).toMatchObject({ requestedMs: 60_000 });
  });

  it("defaults unit to seconds when omitted", async () => {
    const res = await runTimed({ amount: 1 } as Args, 1000);
    expect(res.structuredContent).toMatchObject({
      unit: "seconds",
      requestedMs: 1000,
    });
  });

  it("allows an arbitrarily long (uncapped) duration", async () => {
    const res = await runTimed({ amount: 30, unit: "minutes" }, 1_800_000);
    expect(res.isError).toBeFalsy();
    expect(res.structuredContent).toMatchObject({ requestedMs: 1_800_000 });
  });

  it("does not resolve before the duration elapses", async () => {
    vi.useFakeTimers();
    try {
      let settled = false;
      const p = Promise.resolve(
        waitTool.handler({ amount: 5, unit: "seconds" }),
      ).then((r) => {
        settled = true;
        return r;
      });
      await vi.advanceTimersByTimeAsync(4999);
      expect(settled).toBe(false);
      await vi.advanceTimersByTimeAsync(1);
      await p;
      expect(settled).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("wait: rejects invalid durations (no actual wait)", () => {
  const bad = async (args: Args): Promise<CallToolResult> =>
    (await waitTool.handler(args)) as CallToolResult;

  it("rejects zero and negative durations", async () => {
    expect((await bad({ amount: 0, unit: "seconds" })).isError).toBe(true);
    expect((await bad({ amount: -5, unit: "seconds" })).isError).toBe(true);
  });
});

describe("wait: concurrency cap", () => {
  it("refuses a wait once the in-flight ceiling is reached, then recovers", async () => {
    vi.useFakeTimers();
    try {
      // Each handler runs synchronously up to `inFlight++` and its first await,
      // so firing MAX in a row fills the ceiling before we probe the next one.
      const inflight = Array.from({ length: MAX_CONCURRENT_WAITS }, () =>
        Promise.resolve(waitTool.handler({ amount: 10, unit: "seconds" })),
      );

      const overflow = (await waitTool.handler({
        amount: 1,
        unit: "seconds",
      })) as CallToolResult;
      expect(overflow.isError).toBe(true);
      expect(text(overflow)).toContain("concurrent");

      // Drain the in-flight waits; the slot frees and new waits work again.
      await vi.advanceTimersByTimeAsync(10_000);
      const drained = await Promise.all(inflight);
      for (const r of drained) {
        expect((r as CallToolResult).isError).toBeFalsy();
      }

      const after = Promise.resolve(
        waitTool.handler({ amount: 1, unit: "seconds" }),
      );
      await vi.advanceTimersByTimeAsync(1000);
      expect(((await after) as CallToolResult).isError).toBeFalsy();
    } finally {
      vi.useRealTimers();
    }
  });
});
