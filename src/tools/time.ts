import { CronExpressionParser } from "cron-parser";
import { z } from "zod";
import {
  dayOfYear,
  describeCron,
  isoWeek,
  isValidTimeZone,
  parseInstant,
  zonedParts,
} from "../lib/datetime.js";
import { toMessage } from "../lib/errors.js";
import { defineTool, err, okJson } from "./types.js";

function representations(
  date: Date,
  timezone: string,
): Record<string, unknown> {
  if (Number.isNaN(date.getTime())) {
    throw new Error("instant is out of representable range");
  }
  const zoned = zonedParts(date, timezone);
  if (zoned.year <= 0) {
    // ISO 8601 represents BCE as year ≤ 0 with extended notation, but the
    // ISO-week / day-of-year helpers here assume the Gregorian extension and
    // emit subtly-wrong values (off-by-one, missing BCE era marker, etc.).
    // Reject rather than report bad numbers.
    throw new Error(
      `year ${zoned.year} is before the supported range (year 1 onwards); BCE / year-zero dates are not supported`,
    );
  }
  return {
    unixSeconds: Math.floor(date.getTime() / 1000),
    unixMillis: date.getTime(),
    isoUtc: date.toISOString(),
    isoZoned: zoned.iso,
    timezone,
    offset: zoned.offset,
    rfc2822: date.toUTCString(),
    dayOfWeek: zoned.dayOfWeek,
    isoWeek: isoWeek(zoned.year, zoned.month, zoned.day),
    dayOfYear: dayOfYear(zoned.year, zoned.month, zoned.day),
  };
}

function humanizeDuration(ms: number): string {
  const abs = Math.abs(ms);
  const days = Math.floor(abs / 86_400_000);
  const hours = Math.floor((abs % 86_400_000) / 3_600_000);
  const minutes = Math.floor((abs % 3_600_000) / 60_000);
  const seconds = Math.floor((abs % 60_000) / 1000);
  const millis = abs % 1000;
  const parts: string[] = [];
  if (days) parts.push(`${days}d`);
  if (hours) parts.push(`${hours}h`);
  if (minutes) parts.push(`${minutes}m`);
  if (seconds) parts.push(`${seconds}s`);
  if (millis || parts.length === 0) parts.push(`${millis}ms`);
  return `${ms < 0 ? "-" : ""}${parts.join(" ")}`;
}

function addToInstant(date: Date, amount: number, unit: string): Date {
  const result = new Date(date.getTime());
  switch (unit) {
    case "seconds":
      return new Date(date.getTime() + amount * 1000);
    case "minutes":
      return new Date(date.getTime() + amount * 60_000);
    case "hours":
      return new Date(date.getTime() + amount * 3_600_000);
    case "days":
      return new Date(date.getTime() + amount * 86_400_000);
    case "weeks":
      return new Date(date.getTime() + amount * 7 * 86_400_000);
    case "months": {
      const day = result.getUTCDate();
      result.setUTCDate(1);
      result.setUTCMonth(result.getUTCMonth() + amount);
      const daysInMonth = new Date(
        Date.UTC(result.getUTCFullYear(), result.getUTCMonth() + 1, 0),
      ).getUTCDate();
      result.setUTCDate(Math.min(day, daysInMonth)); // clamp: Jan 31 + 1 month = Feb 29/28
      return result;
    }
    case "years":
      return addToInstant(date, amount * 12, "months");
    default:
      throw new Error(`unknown unit ${JSON.stringify(unit)}`);
  }
}

export const timeTool = defineTool({
  name: "time",
  title: "Date, time & cron",
  description:
    "Work with timestamps, durations, and cron expressions. Reach for this when you have a date or time in one form and need it in another, when you need to know the gap between two instants, when you want to add days/months/years to a date, or when you want to know what a cron expression will fire next.\n" +
    "\n" +
    "Actions:\n" +
    "  • 'now' — the current instant in every representation.\n" +
    "  • 'convert' — parse a timestamp and return ISO (UTC and zoned), unix seconds/millis, RFC 2822, day-of-week, ISO week, day-of-year.\n" +
    "  • 'diff' — duration between two instants `a` and `b`, in milliseconds / seconds / human-readable form.\n" +
    "  • 'add' — add or subtract amount+unit on a base instant (months clamp to month-end).\n" +
    "  • 'cron' — explain a cron expression and list its next N run times in a target timezone.\n" +
    "\n" +
    "Inputs accept: unix seconds, unix milliseconds, ISO 8601, RFC 2822, the literal 'now', or relative forms like 'in 7 days' or '3 hours ago'. Timezones are IANA names (e.g. 'Europe/London'). Naive ISO timestamps without offset are treated as UTC.\n" +
    "\n" +
    "Examples:\n" +
    '  { "action": "convert", "input": "1700000000", "timezone": "Europe/London" }\n' +
    '  { "action": "diff", "a": "2024-01-01", "b": "2024-12-31" }\n' +
    '  { "action": "add", "input": "now", "amount": 30, "unit": "days" }\n' +
    '  { "action": "cron", "expression": "0 9 * * MON", "timezone": "Europe/London", "count": 5 }',
  inputSchema: {
    action: z.enum(["now", "convert", "diff", "add", "cron"]),
    input: z
      .string()
      .optional()
      .describe("convert/add: the timestamp to operate on"),
    inputFormat: z
      .enum(["auto", "unix-s", "unix-ms", "iso"])
      .default("auto")
      .describe(
        "How to parse timestamp slots. Applies to ALL slots in the call (input, a, b, `from`) — there is no per-slot override.",
      ),
    timezone: z
      .string()
      .default("UTC")
      .describe("IANA timezone for zoned output"),
    a: z.string().optional().describe("diff: first instant"),
    b: z.string().optional().describe("diff: second instant"),
    amount: z.coerce
      .number()
      .optional()
      .describe(
        "add: how much (negative to subtract). Fractional values OK for seconds/minutes/hours/days/weeks; months/years must be integers (fractional calendar units would be ambiguous).",
      ),
    unit: z
      .enum(["seconds", "minutes", "hours", "days", "weeks", "months", "years"])
      .optional()
      .describe("add: unit"),
    expression: z
      .string()
      .optional()
      .describe("cron: the cron expression (5 or 6 fields)"),
    count: z.coerce
      .number()
      .int()
      .min(1)
      .max(50)
      .default(5)
      .describe("cron: number of next runs"),
    from: z
      .string()
      .optional()
      .describe("cron: compute runs after this instant (default now)"),
  },
  handler: (args) => {
    try {
      if (!isValidTimeZone(args.timezone)) {
        return err(
          `unknown timezone ${JSON.stringify(args.timezone)}: use an IANA name like Europe/London or UTC`,
        );
      }
      switch (args.action) {
        case "now": {
          const structured = representations(new Date(), args.timezone);
          return okJson(structured);
        }
        case "convert": {
          if (!args.input) return err("convert requires `input`");
          const structured = representations(
            parseInstant(args.input, args.inputFormat),
            args.timezone,
          );
          return okJson(structured);
        }
        case "diff": {
          if (!args.a || !args.b) return err("diff requires `a` and `b`");
          const a = parseInstant(args.a, args.inputFormat);
          const b = parseInstant(args.b, args.inputFormat);
          if (Number.isNaN(a.getTime())) {
            return err(`a (${args.a}) is out of representable instant range`);
          }
          if (Number.isNaN(b.getTime())) {
            return err(`b (${args.b}) is out of representable instant range`);
          }
          const milliseconds = b.getTime() - a.getTime();
          // Symmetric phrasing so the two non-equal cases mirror each
          // other word-for-word (previous: "forwards in time" vs "before").
          const direction =
            milliseconds === 0
              ? "same"
              : milliseconds > 0
                ? "a → b (b is after a)"
                : "b → a (a is after b)";
          const structured = {
            milliseconds,
            seconds: milliseconds / 1000,
            human: humanizeDuration(milliseconds),
            direction,
          };
          return okJson(structured);
        }
        case "add": {
          if (!args.input) return err("add requires `input`");
          if (args.amount === undefined || !args.unit) {
            return err("add requires `amount` and `unit`");
          }
          if (
            (args.unit === "months" || args.unit === "years") &&
            !Number.isInteger(args.amount)
          ) {
            return err(
              `amount must be an integer for unit='${args.unit}' (fractional calendar units are ambiguous — use days/hours instead)`,
            );
          }
          const base = parseInstant(args.input, args.inputFormat);
          const result = addToInstant(base, args.amount, args.unit);
          if (Number.isNaN(result.getTime())) {
            return err(
              `adding ${args.amount} ${args.unit} to ${args.input} overflows the representable instant range`,
            );
          }
          const structured = {
            input: base.toISOString(),
            operation: `${args.amount >= 0 ? "+" : ""}${args.amount} ${args.unit}`,
            ...representations(result, args.timezone),
          };
          return okJson(structured);
        }
        case "cron": {
          if (!args.expression) return err("cron requires `expression`");
          // cron-parser silently accepts under-specified expressions
          // (e.g. "* * *") by padding with defaults — silent-success is the
          // worst-case failure mode. Gate on field count BEFORE handing off.
          const fields = args.expression.trim().split(/\s+/);
          if (fields.length !== 5 && fields.length !== 6) {
            return err(
              `cron expression must have 5 fields (minute hour dom month dow) or 6 fields (with leading seconds), got ${fields.length}`,
            );
          }
          let interval: ReturnType<typeof CronExpressionParser.parse>;
          try {
            interval = CronExpressionParser.parse(args.expression, {
              tz: args.timezone,
              ...(args.from
                ? { currentDate: parseInstant(args.from, args.inputFormat) }
                : {}),
            });
          } catch (e) {
            const msg = toMessage(e);
            if (/unhandled timestamp|invalid date/i.test(msg)) {
              return err(
                `cron \`from\` ${JSON.stringify(args.from)} is out of representable range: ${msg}`,
              );
            }
            return err(`invalid cron expression or options: ${msg}`);
          }
          const nextRuns: Array<{ isoUtc: string; isoZoned: string }> = [];
          for (let i = 0; i < args.count; i++) {
            const next = interval.next().toDate();
            nextRuns.push({
              isoUtc: next.toISOString(),
              isoZoned: zonedParts(next, args.timezone).iso,
            });
          }
          const structured = {
            expression: args.expression,
            description: describeCron(args.expression),
            timezone: args.timezone,
            nextRuns,
          };
          return okJson(structured);
        }
      }
    } catch (e) {
      return err(toMessage(e));
    }
  },
});
