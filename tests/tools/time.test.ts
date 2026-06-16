import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";
import { timeTool } from "../../src/tools/time.js";

type Args = Parameters<typeof timeTool.handler>[0];

function run(args: Partial<Args>): CallToolResult {
  return timeTool.handler({
    inputFormat: "auto",
    timezone: "UTC",
    count: 5,
    ...args,
  } as Args) as CallToolResult;
}

function structured(args: Partial<Args>): Record<string, unknown> {
  const res = run(args);
  expect(res.isError, JSON.stringify(res.content)).toBeFalsy();
  return res.structuredContent as Record<string, unknown>;
}

describe("time: convert", () => {
  // Auto-detect: ≤11-digit integers are unix-seconds. Range of fixed points
  // computed independently via `new Date(n * 1000)`.
  it.each([
    ["1700000000", "2023-11-14T22:13:20.000Z", 1700000000000, "Tue"],
    ["946684800", "2000-01-01T00:00:00.000Z", 946684800000, "Sat"],
    ["1000000000", "2001-09-09T01:46:40.000Z", 1000000000000, "Sun"],
    ["0", "1970-01-01T00:00:00.000Z", 0, "Thu"],
  ])("auto-detects unix seconds %j -> %j", (input, isoUtc, unixMillis, dayOfWeek) => {
    const out = structured({ action: "convert", input });
    expect(out.isoUtc).toBe(isoUtc);
    expect(out.unixMillis).toBe(unixMillis);
    expect(out.dayOfWeek).toBe(dayOfWeek);
  });
  // 12+ digit integers are unix-milliseconds.
  it.each([
    ["1700000000000", "2023-11-14T22:13:20.000Z"],
    ["946684800000", "2000-01-01T00:00:00.000Z"],
    ["1000000000000", "2001-09-09T01:46:40.000Z"],
  ])("auto-detects unix milliseconds %j -> %j", (input, isoUtc) => {
    const out = structured({ action: "convert", input });
    expect(out.isoUtc).toBe(isoUtc);
  });
  // ISO parse plus calendar fields. Day-of-year / iso-week derived from the
  // Gregorian helpers; cross-checked against known calendar facts.
  it.each([
    ["2024-02-29T12:00:00Z", 1709208000, "Thu", 60, 9],
    ["2000-01-01T00:00:00Z", 946684800, "Sat", 1, 52],
    ["2024-12-31T23:59:59Z", 1735689599, "Tue", 366, 1],
    ["2021-01-01T00:00:00Z", 1609459200, "Fri", 1, 53],
  ])("parses ISO %j and reports week/day numbers", (input, unixSeconds, dayOfWeek, doy, week) => {
    const out = structured({ action: "convert", input });
    expect(out.unixSeconds).toBe(unixSeconds);
    expect(out.dayOfWeek).toBe(dayOfWeek);
    expect(out.dayOfYear).toBe(doy);
    expect(out.isoWeek).toBe(week);
  });
  // Same UTC instant, formatted into a range of zones (offsets reasoned from
  // each zone's standard/DST rules for the given date).
  it.each([
    [
      "2021-07-01T12:00:00Z",
      "Europe/London",
      "2021-07-01T13:00:00+01:00",
      "+01:00",
    ],
    [
      "2021-01-01T12:00:00Z",
      "Europe/London",
      "2021-01-01T12:00:00+00:00",
      "+00:00",
    ],
    [
      "2021-07-01T12:00:00Z",
      "America/New_York",
      "2021-07-01T08:00:00-04:00",
      "-04:00",
    ],
    [
      "2021-07-01T12:00:00Z",
      "Asia/Kolkata",
      "2021-07-01T17:30:00+05:30",
      "+05:30",
    ],
    ["2021-07-01T12:00:00Z", "UTC", "2021-07-01T12:00:00+00:00", "+00:00"],
  ])("converts %j into %s with offset", (input, timezone, isoZoned, offset) => {
    const out = structured({ action: "convert", input, timezone });
    expect(out.isoZoned).toBe(isoZoned);
    expect(out.offset).toBe(offset);
  });
  it("handles the Europe/London DST spring-forward boundary", () => {
    const before = structured({
      action: "convert",
      input: "2021-03-28T00:30:00Z",
      timezone: "Europe/London",
    });
    expect(before.isoZoned).toBe("2021-03-28T00:30:00+00:00");
    const after = structured({
      action: "convert",
      input: "2021-03-28T01:30:00Z",
      timezone: "Europe/London",
    });
    expect(after.isoZoned).toBe("2021-03-28T02:30:00+01:00");
  });
  it("ISO week 53 straddling years", () => {
    const out = structured({
      action: "convert",
      input: "2021-01-01T00:00:00Z",
    });
    expect(out.isoWeek).toBe(53);
  });
  it.each([
    "next tuesday-ish",
    "not a date",
    "2024-13-01", // month 13
    "2024-00-10", // month 0
    "tomorrow",
    "", // empty -> "convert requires input"
  ])("rejects unparseable input %j", (input) => {
    const res = run({ action: "convert", input });
    expect(res.isError).toBe(true);
  });
  it.each([
    "Mars/Olympus_Mons",
    "Not/AZone",
    "GMT+25",
    "Europe/Nowhere",
  ])("rejects unknown timezone %j", (timezone) => {
    const res = run({ action: "convert", input: "1700000000", timezone });
    expect(res.isError).toBe(true);
  });
});

describe("time: diff and add", () => {
  // b - a, human form + direction. Each row computed independently from the
  // millisecond delta of the two ISO instants.
  it.each([
    [
      "2024-01-01T00:00:00Z",
      "2024-01-02T01:30:05Z",
      91805000,
      "1d 1h 30m 5s",
      "a → b (b is after a)",
    ],
    [
      "2024-01-01T00:00:00Z",
      "2024-01-01T00:00:00.500Z",
      500,
      "500ms",
      "a → b (b is after a)",
    ],
    [
      "2024-01-02T00:00:00Z",
      "2024-01-01T00:00:00Z",
      -86400000,
      "-1d",
      "b → a (a is after b)",
    ],
    [
      "2024-01-01T00:00:00Z",
      "2025-01-01T00:00:00Z",
      31622400000,
      "366d",
      "a → b (b is after a)",
    ],
    ["2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z", 0, "0ms", "same"],
  ])("computes signed difference %j -> %j", (a, b, milliseconds, human, direction) => {
    const out = structured({ action: "diff", a, b });
    expect(out.milliseconds).toBe(milliseconds);
    expect(out.human).toBe(human);
    expect(out.direction).toBe(direction);
  });
  it.each([
    [{ a: "2024-01-01T00:00:00Z" }], // missing b
    [{ b: "2024-01-01T00:00:00Z" }], // missing a
    [{ a: "garbage", b: "2024-01-01T00:00:00Z" }], // unparseable a
    [{ a: "2024-01-01T00:00:00Z", b: "garbage" }], // unparseable b
  ])("diff rejects bad inputs %j", (args) => {
    const res = run({ action: "diff", ...args });
    expect(res.isError).toBe(true);
  });
  // Date arithmetic across a range of units/signs, incl. month-end clamping
  // and leap years. Expected values from a reference implementation of the
  // same clamp algorithm.
  it.each([
    ["2024-01-01T23:00:00Z", 2, "hours", "2024-01-02T01:00:00.000Z"],
    ["2024-01-31T10:00:00Z", 1, "months", "2024-02-29T10:00:00.000Z"],
    ["2023-01-31T00:00:00Z", 1, "months", "2023-02-28T00:00:00.000Z"],
    ["2024-03-31T00:00:00Z", -1, "months", "2024-02-29T00:00:00.000Z"],
    ["2024-02-29T00:00:00Z", 1, "years", "2025-02-28T00:00:00.000Z"],
    ["2024-01-01T00:00:00Z", 90, "days", "2024-03-31T00:00:00.000Z"],
    ["2024-01-01T00:00:00Z", -1, "weeks", "2023-12-25T00:00:00.000Z"],
    ["2020-12-31T00:00:00Z", 1, "days", "2021-01-01T00:00:00.000Z"],
  ] as const)("add %j %d %s -> %j", (input, amount, unit, isoUtc) => {
    const out = structured({ action: "add", input, amount, unit });
    expect(out.isoUtc).toBe(isoUtc);
  });
  it.each([
    [{ input: "2024-01-01T00:00:00Z", unit: "hours" as const }], // missing amount
    [{ input: "2024-01-01T00:00:00Z", amount: 1 }], // missing unit
    [{ amount: 1, unit: "hours" as const }], // missing input
    [{ input: "garbage", amount: 1, unit: "hours" as const }], // unparseable input
    [{ input: "2024-01-01T00:00:00Z", amount: 1.5, unit: "months" as const }], // fractional months
    [{ input: "2024-01-01T00:00:00Z", amount: 0.5, unit: "years" as const }], // fractional years
  ])("add rejects bad inputs %j", (args) => {
    const res = run({ action: "add", ...args });
    expect(res.isError).toBe(true);
  });
});

describe("time: cron", () => {
  // Next-run schedules from a fixed `from` instant, computed independently
  // with cron-parser using the same options the tool passes (tz UTC,
  // currentDate = from). `next()` is strictly after `from`.
  it.each([
    [
      "*/15 9-17 * * 1-5",
      "2026-01-01T00:00:00Z",
      [
        "2026-01-01T09:00:00.000Z",
        "2026-01-01T09:15:00.000Z",
        "2026-01-01T09:30:00.000Z",
      ],
    ],
    [
      "0 0 * * *",
      "2026-01-01T00:00:00Z",
      [
        "2026-01-02T00:00:00.000Z",
        "2026-01-03T00:00:00.000Z",
        "2026-01-04T00:00:00.000Z",
      ],
    ],
    [
      "* * * * *",
      "2026-01-01T00:00:30Z",
      ["2026-01-01T00:01:00.000Z", "2026-01-01T00:02:00.000Z"],
    ],
    [
      "0 0 1 1 *",
      "2026-06-01T00:00:00Z",
      ["2027-01-01T00:00:00.000Z", "2028-01-01T00:00:00.000Z"],
    ],
    [
      "30 0 0 * * *", // 6-field (seconds)
      "2026-01-01T00:00:00Z",
      ["2026-01-01T00:00:30.000Z", "2026-01-02T00:00:30.000Z"],
    ],
    [
      "0 12 * * 0", // Sundays at noon
      "2026-01-01T00:00:00Z",
      ["2026-01-04T12:00:00.000Z", "2026-01-11T12:00:00.000Z"],
    ],
  ])("lists next runs for %j", (expression, from, expected) => {
    const out = structured({
      action: "cron",
      expression,
      from,
      count: expected.length,
    });
    const runs = out.nextRuns as Array<{ isoUtc: string }>;
    expect(runs.map((r) => r.isoUtc)).toEqual(expected);
  });
  it("is timezone-aware", () => {
    const out = structured({
      action: "cron",
      expression: "0 9 * * *",
      timezone: "America/New_York",
      from: "2026-06-01T00:00:00Z",
      count: 1,
    });
    const runs = out.nextRuns as Array<{ isoUtc: string; isoZoned: string }>;
    expect(runs[0]?.isoZoned).toBe("2026-06-01T09:00:00-04:00");
    expect(runs[0]?.isoUtc).toBe("2026-06-01T13:00:00.000Z");
  });
  it("describes common expressions", () => {
    const out = structured({
      action: "cron",
      expression: "*/15 9-17 * * 1-5",
      from: "2026-01-01T00:00:00Z",
      count: 1,
    });
    const description = String(out.description);
    expect(description).toContain("every 15 minutes");
    expect(description).toContain("9 through 17");
    expect(description).toContain("Mon through Fri");
  });
  it.each([
    "99 * * * *", // minute out of range
    "* 25 * * *", // hour out of range
    "* * 32 * *", // day-of-month out of range
    "* * * 13 *", // month out of range
    "not a cron",
    "", // missing -> "cron requires expression"
  ])("rejects invalid expression %j", (expression) => {
    const res = run({ action: "cron", expression });
    expect(res.isError).toBe(true);
  });

  // cron-parser silently accepts under-/over-specified expressions by padding
  // with defaults. Gate on field count first so a 3-field expression doesn't
  // fabricate a next-run from nothing.
  it.each([
    ["* * *", 3],
    ["* *", 2],
    ["*", 1],
    ["* * * *", 4],
    ["* * * * * * *", 7],
  ])("rejects %j (wrong field count: %i)", (expression, count) => {
    const res = run({ action: "cron", expression });
    expect(res.isError).toBe(true);
    const text = String((res.content?.[0] as { text?: string })?.text ?? "");
    expect(text).toMatch(new RegExp(`got ${count}`));
  });
});

describe("time: now", () => {
  it("returns a consistent instant", () => {
    const out = structured({ action: "now" });
    expect(Math.abs((out.unixMillis as number) - Date.now())).toBeLessThan(
      2000,
    );
    expect(out.unixSeconds).toBe(Math.floor((out.unixMillis as number) / 1000));
  });
});

describe("time: parsing strictness and overflow paths", () => {
  it("naive ISO is interpreted as UTC, not server-local", () => {
    const out = structured({
      action: "convert",
      input: "2024-06-01T12:00:00",
    });
    // 2024-06-01T12:00:00 UTC = unixSeconds 1717243200
    expect(out.unixSeconds).toBe(1717243200);
    expect(String(out.isoUtc)).toBe("2024-06-01T12:00:00.000Z");
  });

  it("Feb 31 (and other invalid day-in-month) is rejected, not silently rolled to Mar", () => {
    const res = run({ action: "convert", input: "2024-02-31" });
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res.content)).toMatch(/invalid day|month has/);
  });

  it("BCE / year-zero ISO inputs are rejected, not silently wrong", () => {
    expect(run({ action: "convert", input: "0000-01-01" }).isError).toBe(true);
    expect(run({ action: "convert", input: "-0001-06-15" }).isError).toBe(true);
  });

  it("diff overflow yields a clean error, not silent NaN + fabricated direction", () => {
    // Build inputs that parse but produce an Invalid Date for arithmetic:
    // unix-ms outside ±8.64e15 is the documented limit.
    const res = run({
      action: "diff",
      a: "9999999999999999999",
      b: "0",
      inputFormat: "unix-ms",
    });
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res.content)).toMatch(/out of representable/);
  });

  it("diff of identical instants reports they're the same (not 'forwards in time')", () => {
    const out = structured({
      action: "diff",
      a: "2024-01-01T00:00:00Z",
      b: "2024-01-01T00:00:00Z",
    });
    expect(out.milliseconds).toBe(0);
    expect(out.direction).toBe("same");
  });

  it("diff direction phrasing is symmetric", () => {
    const fwd = structured({
      action: "diff",
      a: "2024-01-01T00:00:00Z",
      b: "2024-01-02T00:00:00Z",
    });
    const bwd = structured({
      action: "diff",
      a: "2024-01-02T00:00:00Z",
      b: "2024-01-01T00:00:00Z",
    });
    expect(String(fwd.direction)).toMatch(/^a → b/);
    expect(String(bwd.direction)).toMatch(/^b → a/);
  });

  it("add overflow yields a clean error", () => {
    const res = run({
      action: "add",
      input: "2024-01-01T00:00:00Z",
      amount: 999_999_999,
      unit: "years",
    });
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res.content)).toMatch(/overflows/);
  });

  it("cron with overflowing `from` yields a contextual error (not just raw CronDate text)", () => {
    const res = run({
      action: "cron",
      expression: "0 0 * * *",
      from: "9999999999999999999",
      inputFormat: "unix-ms",
    });
    expect(res.isError).toBe(true);
    const msg = JSON.stringify(res.content);
    // Must include the wrapper context that names `from`, not just the raw
    // upstream string from cron-parser.
    expect(msg).toMatch(/cron `from`.*out of representable range/);
  });
});

describe("time: relative parsing (auto mode)", () => {
  it("'now' parses to ~Date.now()", () => {
    const out = structured({ action: "convert", input: "now" });
    const drift = Math.abs((out.unixMillis as number) - Date.now());
    expect(drift).toBeLessThan(2_000);
  });

  it("'in 7 days' parses to ~now+7d", () => {
    const out = structured({ action: "convert", input: "in 7 days" });
    const expected = Date.now() + 7 * 86_400_000;
    expect(Math.abs((out.unixMillis as number) - expected)).toBeLessThan(2_000);
  });

  it("'3 hours ago' parses to ~now-3h", () => {
    const out = structured({ action: "convert", input: "3 hours ago" });
    const expected = Date.now() - 3 * 3_600_000;
    expect(Math.abs((out.unixMillis as number) - expected)).toBeLessThan(2_000);
  });
});
