export function isValidTimeZone(tz: string): boolean {
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: tz });
    return true;
  } catch {
    return false;
  }
}

const MS_PER_DAY = 86_400_000;

/** Whole days from now until `iso` (negative = in the past). Undefined for bad input. */
export function daysFromNow(iso?: string): number | undefined {
  if (!iso) return undefined;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return undefined;
  return Math.floor((t - Date.now()) / MS_PER_DAY);
}

/** Whole days from `iso` until now (negative = in the future). */
export function daysSince(iso?: string): number | undefined {
  if (!iso) return undefined;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return undefined;
  return Math.floor((Date.now() - t) / MS_PER_DAY);
}

export interface ZonedParts {
  iso: string;
  offset: string;
  dayOfWeek: string;
  year: number;
  month: number;
  day: number;
}

export function zonedParts(date: Date, timeZone: string): ZonedParts {
  const dtf = new Intl.DateTimeFormat("en-US", {
    timeZone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
    weekday: "short",
    timeZoneName: "longOffset",
  });
  const parts: Record<string, string> = {};
  for (const part of dtf.formatToParts(date)) {
    parts[part.type] = part.value;
  }
  const rawOffset = (parts.timeZoneName ?? "GMT").replace("GMT", "");
  const offset = rawOffset === "" ? "+00:00" : rawOffset;
  return {
    iso: `${parts.year}-${parts.month}-${parts.day}T${parts.hour}:${parts.minute}:${parts.second}${offset}`,
    offset,
    dayOfWeek: parts.weekday as string,
    year: Number(parts.year),
    month: Number(parts.month),
    day: Number(parts.day),
  };
}

export function isoWeek(year: number, month: number, day: number): number {
  const date = new Date(Date.UTC(year, month - 1, day));
  const dayNum = (date.getUTCDay() + 6) % 7;
  date.setUTCDate(date.getUTCDate() - dayNum + 3);
  const firstThursday = new Date(Date.UTC(date.getUTCFullYear(), 0, 4));
  const firstDayNum = (firstThursday.getUTCDay() + 6) % 7;
  firstThursday.setUTCDate(firstThursday.getUTCDate() - firstDayNum + 3);
  return (
    1 +
    Math.round((date.getTime() - firstThursday.getTime()) / (7 * 86_400_000))
  );
}

export function dayOfYear(year: number, month: number, day: number): number {
  const start = Date.UTC(year, 0, 1);
  const current = Date.UTC(year, month - 1, day);
  return Math.round((current - start) / 86_400_000) + 1;
}

// Date-only ISO matches: 2024-02-31, 2024-02-31T... (validates day-in-month)
const ISO_DATE_RE =
  /^(-?\d{4,})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2}(?:\.\d+)?))?(Z|[+-]\d{2}:?\d{2})?)?$/;

function daysInMonth(year: number, month1Based: number): number {
  return new Date(Date.UTC(year, month1Based, 0)).getUTCDate();
}

function validateIsoComponents(input: string, match: RegExpMatchArray): void {
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  if (year <= 0) {
    throw new Error(
      `${JSON.stringify(input)} has year ${year}: BCE / year-zero are not supported`,
    );
  }
  if (month < 1 || month > 12) {
    throw new Error(`invalid month ${month} in ${JSON.stringify(input)}`);
  }
  const maxDay = daysInMonth(year, month);
  if (day < 1 || day > maxDay) {
    throw new Error(
      `invalid day ${day} for ${year}-${String(month).padStart(2, "0")}: month has ${maxDay} days`,
    );
  }
  if (match[4] !== undefined) {
    const h = Number(match[4]);
    const m = Number(match[5]);
    const s = match[6] === undefined ? 0 : Number(match[6]);
    if (h > 23 || m > 59 || s >= 60) {
      throw new Error(
        `invalid time-of-day ${match[4]}:${match[5]}${match[6] === undefined ? "" : `:${match[6]}`} in ${JSON.stringify(input)}`,
      );
    }
  }
}

export function parseInstant(
  input: string,
  format: "auto" | "unix-s" | "unix-ms" | "iso",
): Date {
  const trimmed = input.trim();
  if (format === "unix-s" || format === "unix-ms") {
    if (!/^-?\d+(\.\d+)?$/.test(trimmed)) {
      throw new Error(
        `not a numeric ${format} timestamp: ${JSON.stringify(input)}`,
      );
    }
    const n = Number(trimmed);
    return new Date(format === "unix-s" ? n * 1000 : n);
  }
  // Fractional unix-seconds (e.g. `1700000000.5`) are valid per the
  // explicit-format path; auto-detect now accepts them too so the two
  // paths agree.
  if (format === "auto" && /^-?\d+\.\d+$/.test(trimmed)) {
    return new Date(Number(trimmed) * 1000);
  }
  if (format === "auto" && /^-?\d+$/.test(trimmed)) {
    // ≤11 digits is treated as unix-seconds (covers ±year 5138); 12+ digits as
    // milliseconds. Callers near the boundary (year ~5138 vs ~1973) should
    // pass inputFormat explicitly — the auto-detect uses digit count, not
    // value, so the threshold is deterministic but coarse.
    const digits = trimmed.replace("-", "").length;
    const n = Number(trimmed);
    return new Date(digits <= 11 ? n * 1000 : n);
  }
  const isoMatch = trimmed.match(ISO_DATE_RE);
  if (isoMatch) {
    validateIsoComponents(input, isoMatch);
    // Naive ISO (no Z and no ±HH:MM) is interpreted as UTC rather than the
    // server's local timezone, so the result doesn't depend on where this
    // tool happens to run.
    const hasTz = isoMatch[7] !== undefined;
    const text = hasTz || isoMatch[4] === undefined ? trimmed : `${trimmed}Z`;
    const ms = Date.parse(text);
    if (Number.isNaN(ms)) {
      throw new Error(`failed to parse ISO timestamp ${JSON.stringify(input)}`);
    }
    return new Date(ms);
  }
  // Relative time: "in 30 days", "3 hours ago", "now". The skill docs and
  // tool description advertise these — implement them in `auto` mode so
  // the call shape matches the docs.
  if (format === "auto") {
    const rel = parseRelative(trimmed);
    if (rel) return rel;
  }
  const ms = Date.parse(trimmed);
  if (Number.isNaN(ms)) {
    throw new Error(
      `cannot parse ${JSON.stringify(input)}: expected unix seconds, unix milliseconds, ISO-8601, RFC 2822, or a relative form like "in 7 days" / "3 hours ago" / "now" — or set inputFormat explicitly`,
    );
  }
  return new Date(ms);
}

// Relative parser supports "now", "in N <unit>", "N <unit> ago" — case
// insensitive, leading/trailing whitespace tolerated. <unit> is a
// human-readable name matching the `add` action's units, plus their
// short forms (s/sec, m/min, h/hr, d, w).
const REL_UNITS: Record<string, number> = {
  ms: 1,
  millisecond: 1,
  milliseconds: 1,
  s: 1000,
  sec: 1000,
  secs: 1000,
  second: 1000,
  seconds: 1000,
  m: 60_000,
  min: 60_000,
  mins: 60_000,
  minute: 60_000,
  minutes: 60_000,
  h: 3_600_000,
  hr: 3_600_000,
  hrs: 3_600_000,
  hour: 3_600_000,
  hours: 3_600_000,
  d: 86_400_000,
  day: 86_400_000,
  days: 86_400_000,
  w: 604_800_000,
  wk: 604_800_000,
  week: 604_800_000,
  weeks: 604_800_000,
};

function parseRelative(text: string): Date | undefined {
  const lower = text.toLowerCase();
  if (lower === "now") return new Date();
  const future = /^in\s+(\d+(?:\.\d+)?)\s+([a-z]+)$/i.exec(lower);
  const past = /^(\d+(?:\.\d+)?)\s+([a-z]+)\s+ago$/i.exec(lower);
  const m = future ?? past;
  if (!m) return undefined;
  const amount = Number(m[1]);
  const unitMs = REL_UNITS[m[2] as string];
  if (!Number.isFinite(amount) || unitMs === undefined) return undefined;
  const sign = future ? 1 : -1;
  return new Date(Date.now() + sign * amount * unitMs);
}

const MONTH_NAMES = [
  "Jan",
  "Feb",
  "Mar",
  "Apr",
  "May",
  "Jun",
  "Jul",
  "Aug",
  "Sep",
  "Oct",
  "Nov",
  "Dec",
];
const DAY_NAMES = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

function describeCronField(
  expr: string,
  singular: string,
  plural: string,
  names?: string[],
  nameBase = 0,
): string | undefined {
  const named = (v: string): string => {
    if (!names) return v;
    const n = Number(v);
    return Number.isInteger(n) && names[n - nameBase] !== undefined
      ? (names[n - nameBase] as string)
      : v;
  };
  if (expr === "*" || expr === "?") return undefined;
  const step = expr.match(/^\*\/(\d+)$/);
  if (step) return `every ${step[1]} ${plural}`;
  const range = expr.match(/^(\w+)-(\w+)$/);
  if (range)
    return `${singular} ${named(range[1] as string)} through ${named(range[2] as string)}`;
  const rangeStep = expr.match(/^(\w+)-(\w+)\/(\d+)$/);
  if (rangeStep)
    return `every ${rangeStep[3]} ${plural} from ${named(rangeStep[1] as string)} through ${named(rangeStep[2] as string)}`;
  if (expr.includes(","))
    return `${plural} ${expr.split(",").map(named).join(", ")}`;
  return `${singular} ${named(expr)}`;
}

export function describeCron(expression: string): string {
  const fields = expression.trim().split(/\s+/);
  if (fields.length < 5 || fields.length > 6) {
    return expression;
  }
  const hasSeconds = fields.length === 6;
  const [sec, min, hour, dom, month, dow] = hasSeconds
    ? (fields as [string, string, string, string, string, string])
    : ["0", ...(fields as [string, string, string, string, string])];
  const pieces = [
    hasSeconds
      ? describeCronField(sec as string, "second", "seconds")
      : undefined,
    describeCronField(min as string, "minute", "minutes") ??
      (min === "*" ? "every minute" : undefined),
    describeCronField(hour as string, "hour", "hours"),
    describeCronField(dom as string, "day of month", "days of month"),
    describeCronField(month as string, "month", "months", MONTH_NAMES, 1),
    describeCronField(
      dow as string,
      "day of week",
      "days of week",
      DAY_NAMES,
      0,
    ),
  ].filter((p): p is string => p !== undefined);
  return pieces.length === 0 ? "every minute" : pieces.join(", ");
}
