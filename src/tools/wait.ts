import { z } from "zod";
import { parseMaxFromEnv } from "../lib/semaphore.js";
import { defineTool, err, ok } from "./types.js";

const UNIT_MS = {
  milliseconds: 1,
  seconds: 1000,
  minutes: 60_000,
} as const;

// Duration is uncapped (a wait is idle); the guard is a GLOBAL reject-not-queue
// concurrency gate, set at deploy time via SWISSKNIFE_MAX_CONCURRENT_WAITS.
export const MAX_CONCURRENT_WAITS = parseMaxFromEnv(
  "SWISSKNIFE_MAX_CONCURRENT_WAITS",
  8,
);
let inFlight = 0;

export const waitTool = defineTool({
  name: "wait",
  title: "Wait",
  description: `Pause for a fixed duration, then return — \`amount\` in the given \`unit\` (milliseconds, seconds, or minutes). The duration is uncapped, but at most ${MAX_CONCURRENT_WAITS} waits may be in flight at once; a non-positive duration or exceeding that concurrency is rejected.`,
  inputSchema: {
    amount: z.coerce
      .number()
      .describe("How long to wait, in `unit`s. Must be greater than 0."),
    unit: z
      .enum(["milliseconds", "seconds", "minutes"])
      .default("seconds")
      .describe("Time unit for `amount`."),
  },
  handler: async (args) => {
    // `unit` is schema-defaulted at the MCP boundary, but the handler is also
    // invoked directly (the `script` gateway, unit tests) where schema defaults
    // don't apply — so default it here too rather than producing NaN.
    const unit = args.unit ?? "seconds";
    const requestedMs = args.amount * UNIT_MS[unit];
    if (!Number.isFinite(requestedMs) || requestedMs <= 0) {
      return err(
        `amount must be a positive number — got ${args.amount} ${unit}`,
      );
    }
    if (inFlight >= MAX_CONCURRENT_WAITS) {
      return err(
        `too many concurrent waits (max ${MAX_CONCURRENT_WAITS}) — retry once an in-flight wait finishes`,
      );
    }
    inFlight++;
    try {
      await new Promise((resolve) => setTimeout(resolve, requestedMs));
    } finally {
      inFlight--;
    }
    // No measured elapsed in the output: it's wall-clock, so it would break the
    // conformance gateway-parity / determinism invariants (two calls differ).
    return ok(`Waited ${requestedMs}ms.`, {
      amount: args.amount,
      unit,
      requestedMs,
    });
  },
});
