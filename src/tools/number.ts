import { z } from "zod";
import { toMessage } from "../lib/errors.js";
import {
  formatBytes,
  formatDuration,
  fromRoman,
  MS_PER,
  parseBytes,
  parseDuration,
  toRoman,
} from "../lib/units.js";
import { defineTool, err, ok } from "./types.js";

export const numberTool = defineTool({
  name: "number",
  title: "Number, byte size, duration & roman",
  description:
    "Convert numbers between human-friendly forms. Use this when you have '1.5 GB' and want bytes (or vice versa), when you need to translate a human duration like '1d 2h' to milliseconds or ISO-8601, when you need a roman numeral, or when you want to render a number with locale-aware grouping or scientific notation.\n" +
    "\n" +
    "Actions:\n" +
    "  • 'bytes' — byte count ↔ human size; returns the exact bytes plus SI (kB, MB — powers of 1000) and IEC (KiB, MiB — powers of 1024).\n" +
    "  • 'duration' — ms ↔ human duration; accepts numbers (with `unit`, default ms), strings ('1d 2h', '90m', '1:30:05'), and ISO 8601 ('PT2H30M'). Returns ms, seconds, human, ISO, and clock forms.\n" +
    "  • 'roman' — integers 1..3999 ↔ roman numerals.\n" +
    "  • 'format' — render a number with locale-aware grouping/precision (Intl): standard, scientific, engineering, or compact notation.\n" +
    "\n" +
    "For number-base conversion (hex / binary / octal / arbitrary radix), use the `encode` tool with `format: 'radix'`.\n" +
    "\n" +
    "Examples:\n" +
    '  { "action": "bytes", "input": "1.5 GiB" } → 1610612736 bytes + SI/IEC strings\n' +
    '  { "action": "duration", "input": "1d 2h 30m" } → ms + seconds + ISO\n' +
    '  { "action": "roman", "input": 2024 } → "MMXXIV"\n' +
    '  { "action": "format", "input": 1234567.89, "locale": "de-DE", "notation": "compact" }',
  inputSchema: {
    action: z.enum(["bytes", "duration", "roman", "format"]),
    input: z
      .union([z.string(), z.number()])
      .describe("the number or string to convert"),
    unit: z
      .enum(["ms", "s", "m", "h", "d", "w"])
      .default("ms")
      .describe(
        "duration: unit of a numeric input. One of ms, s, m, h, d, w. ('min'/'sec' are not accepted — pick the single-letter form.)",
      ),
    locale: z
      .string()
      .default("en-US")
      .describe("format: BCP-47 locale, e.g. en-US, de-DE"),
    notation: z
      .enum(["standard", "scientific", "engineering", "compact"])
      .default("standard")
      .describe("format: Intl notation"),
    minimumFractionDigits: z.coerce.number().int().min(0).max(20).optional(),
    maximumFractionDigits: z.coerce.number().int().min(0).max(20).optional(),
    useGrouping: z
      .boolean()
      .default(true)
      .describe("format: thousands separators"),
  },
  handler: (args) => {
    try {
      switch (args.action) {
        case "bytes": {
          const bytes =
            typeof args.input === "number"
              ? validateByteCount(args.input)
              : parseBytes(args.input);
          const { si, iec } = formatBytes(bytes);
          return ok(`${bytes} bytes = ${si} (SI) = ${iec} (IEC)`, {
            bytes,
            si,
            iec,
          });
        }
        case "duration": {
          let ms: number;
          if (typeof args.input === "number") {
            if (!Number.isFinite(args.input)) {
              return err("duration input must be a finite number");
            }
            ms = args.input * (MS_PER[args.unit] as number);
          } else if (/^\s*-?\d+(?:\.\d+)?\s*$/.test(args.input)) {
            // A numeric-looking string with `unit` set should be treated the
            // same as a JSON number — apply the `unit` instead of erroring
            // with the misleading "bare numbers need the unit parameter".
            ms = Number(args.input.trim()) * (MS_PER[args.unit] as number);
          } else {
            ms = parseDuration(args.input);
          }
          if (!Number.isFinite(ms)) {
            return err(
              `duration input ${JSON.stringify(args.input)} overflows representable milliseconds`,
            );
          }
          const { human, iso, clock } = formatDuration(ms);
          return ok(`${human} (${ms}ms, ${iso}, ${clock})`, {
            ms,
            seconds: ms / 1000,
            human,
            iso,
            clock,
          });
        }
        case "roman": {
          const numeric =
            typeof args.input === "number"
              ? args.input
              : /^\s*\d+\s*$/.test(args.input)
                ? Number(args.input)
                : undefined;
          if (numeric !== undefined) {
            const roman = toRoman(numeric);
            return ok(`${numeric} = ${roman}`, { number: numeric, roman });
          }
          const number = fromRoman(args.input as string);
          const roman = (args.input as string).trim().toUpperCase();
          return ok(`${roman} = ${number}`, { number, roman });
        }
        case "format": {
          let numeric: number;
          if (typeof args.input === "number") {
            numeric = args.input;
          } else {
            const trimmed = args.input.trim();
            if (trimmed === "") {
              return err('cannot parse "" as a number');
            }
            numeric = Number(trimmed);
          }
          if (Number.isNaN(numeric)) {
            return err(
              `cannot parse ${JSON.stringify(args.input)} as a number`,
            );
          }
          if (!Number.isFinite(numeric)) {
            return err(
              `cannot format non-finite input ${JSON.stringify(args.input)}`,
            );
          }
          let formatter: Intl.NumberFormat;
          try {
            formatter = new Intl.NumberFormat(args.locale, {
              notation: args.notation,
              minimumFractionDigits: args.minimumFractionDigits,
              maximumFractionDigits: args.maximumFractionDigits,
              useGrouping: args.useGrouping,
            });
          } catch (e) {
            return err(toMessage(e));
          }
          const formatted = formatter.format(numeric);
          // Echo back the locale + notation + parsed value so callers can
          // verify what was actually applied rather than guess.
          return ok(formatted, {
            formatted,
            number: numeric,
            locale: args.locale,
            notation: args.notation,
          });
        }
      }
    } catch (e) {
      return err(toMessage(e));
    }
  },
});

function validateByteCount(value: number): number {
  if (!Number.isFinite(value) || value < 0) {
    throw new Error("byte count must be a non-negative finite number");
  }
  if (value > Number.MAX_SAFE_INTEGER) {
    throw new Error("byte quantity exceeds Number.MAX_SAFE_INTEGER");
  }
  return Math.round(value);
}
