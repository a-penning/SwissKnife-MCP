const SI_UNITS = ["B", "kB", "MB", "GB", "TB", "PB"] as const;
const IEC_UNITS = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"] as const;

const BYTE_FACTORS: Record<string, number> = {
  b: 1,
  byte: 1,
  bytes: 1,
  kb: 1000,
  mb: 1000 ** 2,
  gb: 1000 ** 3,
  tb: 1000 ** 4,
  pb: 1000 ** 5,
  kib: 1024,
  mib: 1024 ** 2,
  gib: 1024 ** 3,
  tib: 1024 ** 4,
  pib: 1024 ** 5,
};

// The byte-unit casing convention is "B" (capital). A trailing lowercase "b"
// (the SI/IEC bit symbol) anywhere a byte unit could go — bare "b", "Kb",
// "Gb" — means bits, which this tool does not support. Match the case-
// sensitive form so we can reject before falling back to the lowercase
// factor table.
const BIT_UNIT_RE = /^(?:[kKmMgGtTpP]?b)$/;

/** Parses "1536", "1.5 MiB", "2GB" into a byte count. SI units (kB/MB/…) are powers of 1000; IEC units (KiB/MiB/…) powers of 1024. */
export function parseBytes(input: string): number {
  const match = /^\s*(-?[\d_,]*\.?\d+(?:[eE][+-]?\d+)?)\s*([A-Za-z]*)\s*$/.exec(
    input,
  );
  if (!match) {
    throw new Error(
      `cannot parse ${JSON.stringify(input)} as a byte quantity (expected e.g. "1536" or "1.5 MiB")`,
    );
  }
  const numericRaw = match[1] ?? "";
  // Commas should only appear as thousands separators (every 3 digits left of
  // the decimal). Reject European-style decimal commas like "1,5"; stripping
  // the comma would misread it as 15 — a 10x error.
  if (numericRaw.includes(",")) {
    const groupingMatch =
      /^-?\d{1,3}(?:,\d{3})*(?:\.\d+(?:[eE][+-]?\d+)?)?$/.test(numericRaw);
    if (!groupingMatch) {
      throw new Error(
        `invalid number ${JSON.stringify(numericRaw)}: commas must be thousands separators (every 3 digits)`,
      );
    }
  }
  const amount = Number(numericRaw.replace(/[_,]/g, ""));
  const unitRawCased = match[2] ?? "";
  if (Number.isNaN(amount)) {
    throw new Error(`invalid number ${JSON.stringify(match[1])}`);
  }
  // The single 'B' character is canonical bytes; 'b' alone is bits, and a
  // lowercase 'b' in the size suffix (kb, mb, gb, …) is the SI bit symbol.
  if (unitRawCased !== "" && unitRawCased !== "B") {
    if (BIT_UNIT_RE.test(unitRawCased)) {
      throw new Error(
        `unknown byte unit ${JSON.stringify(unitRawCased)} (use B, kB…PB, KiB…PiB; bits are not supported — did you mean ${unitRawCased.toUpperCase().replace(/B$/, "B")}?)`,
      );
    }
  }
  const unitRaw = unitRawCased.toLowerCase();
  const factor = unitRaw === "" ? 1 : BYTE_FACTORS[unitRaw];
  if (factor === undefined) {
    throw new Error(
      `unknown byte unit ${JSON.stringify(match[2])} (use B, kB…PB, KiB…PiB; bits are not supported)`,
    );
  }
  if (amount < 0) throw new Error("byte quantity cannot be negative");
  const bytes = Math.round(amount * factor);
  if (bytes > Number.MAX_SAFE_INTEGER) {
    throw new Error("byte quantity exceeds Number.MAX_SAFE_INTEGER");
  }
  return bytes;
}

function formatScaled(
  bytes: number,
  base: number,
  units: readonly string[],
): string {
  let value = bytes;
  let unitIndex = 0;
  while (unitIndex < units.length - 1 && value >= base) {
    value /= base;
    unitIndex++;
  }
  // After rounding to 2 decimal places, a value like 999.999 → 1000 — promote
  // to the next unit so we render "1 MB" rather than "1000 kB".
  let rounded = Math.round(value * 100) / 100;
  if (rounded >= base && unitIndex < units.length - 1) {
    rounded /= base;
    unitIndex++;
    rounded = Math.round(rounded * 100) / 100;
  }
  const unit = units[unitIndex] as string;
  const text =
    rounded >= 100 || Number.isInteger(rounded)
      ? String(rounded)
      : rounded.toFixed(2).replace(/0+$/, "").replace(/\.$/, "");
  return `${text} ${unit}`;
}

export function formatBytes(bytes: number): { si: string; iec: string } {
  return {
    si: formatScaled(bytes, 1000, SI_UNITS),
    iec: formatScaled(bytes, 1024, IEC_UNITS),
  };
}

// ---------------------------------------------------------------------------
// Durations

// Exported so the number tool shares this exact table rather than keeping a
// second copy that could drift out of sync.
export const MS_PER: Record<string, number> = {
  ms: 1,
  s: 1000,
  m: 60_000,
  h: 3_600_000,
  d: 86_400_000,
  w: 604_800_000,
};

/**
 * Parses a duration string into milliseconds. Accepts:
 *  - unit tokens: "1d 2h 3m 4.5s 500ms", "90m", "1.5h"
 *  - ISO-8601:    "PT2H30M", "P1DT6H", "PT0.5S" (years/months rejected: not fixed-length)
 *  - clock:       "1:30:05" (h:mm:ss) or "4:30" (m:ss)
 */
export function parseDuration(input: string): number {
  const text = input.trim();
  const negative = text.startsWith("-");
  const body = negative ? text.slice(1).trim() : text;

  let ms: number;
  if (/^p/i.test(body)) ms = parseIsoDuration(body);
  else if (/^\d+(\.\d+)?(:\d{1,2})+$/.test(body)) ms = parseClock(body);
  else ms = parseTokens(body);
  return negative ? -ms : ms;
}

function parseIsoDuration(body: string): number {
  const match =
    /^P(?:(\d+(?:\.\d+)?)Y)?(?:(\d+(?:\.\d+)?)M)?(?:(\d+(?:\.\d+)?)W)?(?:(\d+(?:\.\d+)?)D)?(?:T(?:(\d+(?:\.\d+)?)H)?(?:(\d+(?:\.\d+)?)M)?(?:(\d+(?:\.\d+)?)S)?)?$/i.exec(
      body,
    );
  if (!match || body.length <= 1) {
    throw new Error(`invalid ISO-8601 duration ${JSON.stringify(body)}`);
  }
  const [, years, months, weeks, days, hours, minutes, seconds] = match;
  if (years !== undefined || months !== undefined) {
    throw new Error(
      "years/months are not fixed-length and are not supported; use weeks/days",
    );
  }
  if ([weeks, days, hours, minutes, seconds].every((p) => p === undefined)) {
    throw new Error(`invalid ISO-8601 duration ${JSON.stringify(body)}`);
  }
  return (
    Number(weeks ?? 0) * (MS_PER.w as number) +
    Number(days ?? 0) * (MS_PER.d as number) +
    Number(hours ?? 0) * (MS_PER.h as number) +
    Number(minutes ?? 0) * (MS_PER.m as number) +
    Number(seconds ?? 0) * 1000
  );
}

function parseClock(body: string): number {
  const parts = body.split(":").map(Number);
  if (parts.some(Number.isNaN))
    throw new Error(`invalid clock duration ${body}`);
  // Each mm/ss segment must be 0–59 — fail loud rather than normalise, so a
  // typo like `1:90:05` can't be silently reinterpreted as 2:30:05.
  const checkRange = (n: number, label: string) => {
    if (n < 0 || n > 59 || !Number.isInteger(n)) {
      throw new Error(
        `invalid clock duration ${body}: ${label} segment must be an integer 0..59 (got ${n})`,
      );
    }
  };
  if (parts.length === 2) {
    checkRange(parts[1] as number, "seconds");
    return ((parts[0] as number) * 60 + (parts[1] as number)) * 1000;
  }
  if (parts.length === 3) {
    checkRange(parts[1] as number, "minutes");
    checkRange(parts[2] as number, "seconds");
    return (
      ((parts[0] as number) * 3600 +
        (parts[1] as number) * 60 +
        (parts[2] as number)) *
      1000
    );
  }
  throw new Error(`invalid clock duration ${body} (use m:ss or h:mm:ss)`);
}

function parseTokens(body: string): number {
  const re = /(\d+(?:\.\d+)?)\s*(ms|s|m|h|d|w)\b/gi;
  let total = 0;
  let matchedLength = 0;
  for (const m of body.matchAll(re)) {
    total += Number(m[1]) * (MS_PER[(m[2] as string).toLowerCase()] as number);
    matchedLength += m[0].length;
  }
  const residue = body.replace(re, "").replace(/[\s,]/g, "");
  if (matchedLength === 0 || residue !== "") {
    throw new Error(
      `cannot parse ${JSON.stringify(body)} as a duration (expected e.g. "1d 2h", "90m", "PT2H30M", "1:30:05"; bare numbers need the unit parameter)`,
    );
  }
  return total;
}

export interface FormattedDuration {
  human: string;
  iso: string;
  clock: string;
}

export function formatDuration(msTotal: number): FormattedDuration {
  const sign = msTotal < 0 ? "-" : "";
  let rest = Math.abs(msTotal);
  const days = Math.floor(rest / (MS_PER.d as number));
  rest -= days * (MS_PER.d as number);
  const hours = Math.floor(rest / (MS_PER.h as number));
  rest -= hours * (MS_PER.h as number);
  const minutes = Math.floor(rest / (MS_PER.m as number));
  rest -= minutes * (MS_PER.m as number);
  const seconds = rest / 1000;

  const humanParts: string[] = [];
  if (days) humanParts.push(`${days}d`);
  if (hours) humanParts.push(`${hours}h`);
  if (minutes) humanParts.push(`${minutes}m`);
  if (seconds || humanParts.length === 0) {
    humanParts.push(`${trimNumber(seconds)}s`);
  }

  let iso = "P";
  if (days) iso += `${days}D`;
  if (hours || minutes || seconds || !days) {
    iso += "T";
    if (hours) iso += `${hours}H`;
    if (minutes) iso += `${minutes}M`;
    if (seconds || (!hours && !minutes)) iso += `${trimNumber(seconds)}S`;
  }

  const totalHours = days * 24 + hours;
  const clock = `${totalHours}:${String(minutes).padStart(2, "0")}:${String(Math.floor(seconds)).padStart(2, "0")}`;

  return {
    human: sign + humanParts.join(" "),
    iso: sign + iso,
    clock: sign + clock,
  };
}

function trimNumber(n: number): string {
  // Six decimal places — enough to round-trip sub-millisecond durations
  // through the ISO/human/clock formats without flattening them to "0s".
  return String(Math.round(n * 1_000_000) / 1_000_000);
}

// ---------------------------------------------------------------------------
// Roman numerals

const ROMAN_TABLE: ReadonlyArray<readonly [string, number]> = [
  ["M", 1000],
  ["CM", 900],
  ["D", 500],
  ["CD", 400],
  ["C", 100],
  ["XC", 90],
  ["L", 50],
  ["XL", 40],
  ["X", 10],
  ["IX", 9],
  ["V", 5],
  ["IV", 4],
  ["I", 1],
];

export function toRoman(n: number): string {
  if (!Number.isInteger(n) || n < 1 || n > 3999) {
    throw new Error("roman numerals cover integers 1..3999");
  }
  let rest = n;
  let out = "";
  for (const [symbol, value] of ROMAN_TABLE) {
    while (rest >= value) {
      out += symbol;
      rest -= value;
    }
  }
  return out;
}

export function fromRoman(input: string): number {
  const text = input.trim().toUpperCase();
  if (!/^[MDCLXVI]+$/.test(text)) {
    throw new Error(`invalid roman numeral ${JSON.stringify(input)}`);
  }
  let total = 0;
  let i = 0;
  for (const [symbol, value] of ROMAN_TABLE) {
    while (text.startsWith(symbol, i)) {
      total += value;
      i += symbol.length;
    }
  }
  if (i !== text.length || toRoman(total) !== text) {
    throw new Error(
      `non-canonical roman numeral ${JSON.stringify(input)} (canonical form for ${total || "?"} differs)`,
    );
  }
  return total;
}
