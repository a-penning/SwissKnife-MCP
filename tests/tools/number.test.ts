import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";
import { numberTool } from "../../src/tools/number.js";

type Args = Parameters<typeof numberTool.handler>[0];

async function run(args: Partial<Args>): Promise<CallToolResult> {
  return (await numberTool.handler({
    unit: "ms",
    locale: "en-US",
    notation: "standard",
    useGrouping: true,
    ...args,
  } as Args)) as CallToolResult;
}

async function structured(
  args: Partial<Args>,
): Promise<Record<string, unknown>> {
  const res = await run(args);
  expect(res.isError, JSON.stringify(res.content)).toBeFalsy();
  return res.structuredContent as Record<string, unknown>;
}

describe("number: bytes", () => {
  // Expected SI/IEC renderings derived independently (SI base 1000, IEC base
  // 1024, 2dp rounding with unit promotion).
  const FORMAT_CASES: Array<[number, string, string]> = [
    [0, "0 B", "0 B"],
    [1, "1 B", "1 B"],
    [500, "500 B", "500 B"],
    [1000, "1 kB", "1000 B"],
    [1024, "1.02 kB", "1 KiB"],
    [1536, "1.54 kB", "1.5 KiB"],
    [1_000_000, "1 MB", "976.56 KiB"],
    [1_048_576, "1.05 MB", "1 MiB"],
    [1_234_567_890, "1.23 GB", "1.15 GiB"],
  ];
  it.each(FORMAT_CASES)(
    "formats numeric byte count %i as SI=%s / IEC=%s",
    async (input, si, iec) => {
      expect(await structured({ action: "bytes", input })).toMatchObject({
        bytes: input,
        si,
        iec,
      });
    },
  );

  // Byte string parsing: SI suffixes are powers of 1000, IEC suffixes powers
  // of 1024. Expected byte counts computed independently.
  const PARSE_CASES: Array<[string, number]> = [
    ["1.5 MiB", 1_572_864],
    ["2GB", 2_000_000_000],
    ["1,024", 1024],
    ["3 KiB", 3072],
    ["10 kB", 10_000],
    ["1 PB", 1_000_000_000_000_000],
    ["1 PiB", 1_125_899_906_842_624],
    ["512", 512],
    ["1B", 1],
  ];
  it.each(PARSE_CASES)(
    "parses unit string %s as %i bytes",
    async (input, bytes) => {
      expect(await structured({ action: "bytes", input })).toMatchObject({
        bytes,
      });
    },
  );

  // Distinct failure modes for byte parsing/validation.
  const INVALID: Array<[string, string | number]> = [
    ["unknown unit", "3 parsecs"],
    ["negative numeric", -1],
    ["negative string", "-5 MB"],
    ["European decimal comma", "1,5 MB"],
    ["bit-symbol suffix", "8 Gb"],
    ["empty string", ""],
    ["bare unit, no number", "MB"],
  ];
  it.each(INVALID)("rejects %s (%s)", async (_label, input) => {
    expect((await run({ action: "bytes", input })).isError).toBe(true);
  });
});

describe("number: duration", () => {
  // numeric value + unit. ms/human/iso/clock derived independently.
  const NUMERIC: Array<[number, Args["unit"], number, string, string, string]> =
    [
      [90, "m", 5_400_000, "1h 30m", "PT1H30M", "1:30:00"],
      [2, "h", 7_200_000, "2h", "PT2H", "2:00:00"],
      [500, "ms", 500, "0.5s", "PT0.5S", "0:00:00"],
      [1, "d", 86_400_000, "1d", "P1D", "24:00:00"],
      [3, "s", 3000, "3s", "PT3S", "0:00:03"],
      [1, "w", 604_800_000, "7d", "P7D", "168:00:00"],
    ];
  it.each(NUMERIC)(
    "converts %i %s to %i ms",
    async (input, unit, ms, human, iso, clock) => {
      expect(
        await structured({ action: "duration", input, unit }),
      ).toMatchObject({ ms, seconds: ms / 1000, human, iso, clock });
    },
  );

  // String forms: token, ISO-8601, and clock. ms computed independently.
  const STRINGS: Array<[string, number]> = [
    ["1d 2h", 93_600_000],
    ["90m", 5_400_000],
    ["1.5h", 5_400_000],
    ["PT2H30M", 9_000_000],
    ["P1DT6H", 108_000_000],
    ["1:30:05", 5_405_000],
    ["4:30", 270_000],
    ["0:45", 45_000],
  ];
  it.each(STRINGS)("parses string %s as %i ms", async (input, ms) => {
    expect(await structured({ action: "duration", input })).toMatchObject({
      ms,
    });
  });

  it("echoes human/iso for a token string", async () => {
    expect(
      await structured({ action: "duration", input: "1d 2h" }),
    ).toMatchObject({ human: "1d 2h", iso: "P1DT2H" });
  });

  // Distinct failure modes for duration parsing.
  const INVALID: Array<[string, string]> = [
    ["ISO years", "P1Y"],
    ["ISO months", "P3M"],
    ["garbage tokens", "12345 zorks"],
    ["out-of-range clock minutes", "1:90:05"],
    ["out-of-range clock seconds", "4:75"],
    ["empty ISO marker", "P"],
    ["bare number string (no unit context handling)", "abc"],
  ];
  it.each(INVALID)("rejects %s (%s)", async (_label, input) => {
    expect((await run({ action: "duration", input })).isError).toBe(true);
  });
});

describe("number: roman", () => {
  // integer -> canonical numeral, computed independently via greedy table.
  const TO_ROMAN: Array<[number, string]> = [
    [1, "I"],
    [4, "IV"],
    [9, "IX"],
    [14, "XIV"],
    [40, "XL"],
    [42, "XLII"],
    [90, "XC"],
    [400, "CD"],
    [944, "CMXLIV"],
    [1994, "MCMXCIV"],
    [2023, "MMXXIII"],
    [3888, "MMMDCCCLXXXVIII"],
    [3999, "MMMCMXCIX"],
  ];
  it.each(TO_ROMAN)("converts %i to %s", async (input, roman) => {
    expect(await structured({ action: "roman", input })).toMatchObject({
      number: input,
      roman,
    });
  });

  // numeral string -> number (case-insensitive), and numeric string -> numeral.
  const PARSE: Array<[string, number, string]> = [
    ["mcmxciv", 1994, "MCMXCIV"],
    ["XLII", 42, "XLII"],
    ["iv", 4, "IV"],
    ["mmxxiii", 2023, "MMXXIII"],
    ["42", 42, "XLII"],
    ["1994", 1994, "MCMXCIV"],
  ];
  it.each(PARSE)(
    "parses string %s as number=%i roman=%s",
    async (input, number, roman) => {
      expect(await structured({ action: "roman", input })).toMatchObject({
        number,
        roman,
      });
    },
  );

  // Distinct failure modes: non-canonical numerals, out-of-range integers,
  // and junk.
  const INVALID: Array<[string, string | number]> = [
    ["non-canonical IIII", "IIII"],
    ["non-canonical VV", "VV"],
    ["non-canonical IC", "IC"],
    ["above range integer", 4000],
    ["zero", 0],
    ["negative", -3],
    ["above range numeric string", "4000"],
    ["non-roman letters", "ABC"],
  ];
  it.each(INVALID)("rejects %s", async (_label, input) => {
    expect((await run({ action: "roman", input })).isError).toBe(true);
  });
});

describe("number: format", () => {
  // locale + notation matrix. Expected strings derived from Intl.NumberFormat
  // directly via node (not from the tool). Locales whose grouping separator is
  // a non-breaking/narrow space (e.g. fr-FR) are intentionally omitted to keep
  // the literals robust.
  const FORMAT: Array<[number, Args["locale"], Args["notation"], string]> = [
    [1234567.891, "en-US", "standard", "1,234,567.891"],
    [0, "en-US", "standard", "0"],
    [-42, "en-US", "standard", "-42"],
    [1_200_000, "en-US", "compact", "1.2M"],
    [1500, "en-US", "compact", "1.5K"],
    [123456, "en-US", "engineering", "123.456E3"],
    [123456, "en-US", "scientific", "1.235E5"],
  ];
  it.each(FORMAT)(
    "formats %f (%s/%s) as %s",
    async (input, locale, notation, formatted) => {
      expect(
        await structured({ action: "format", input, locale, notation }),
      ).toMatchObject({ formatted, locale, notation });
    },
  );

  it("respects locale and maximumFractionDigits (de-DE)", async () => {
    expect(
      await structured({
        action: "format",
        input: 1234567.891,
        locale: "de-DE",
        maximumFractionDigits: 2,
      }),
    ).toMatchObject({ formatted: "1.234.567,89" });
  });

  it("honours useGrouping=false", async () => {
    expect(
      await structured({
        action: "format",
        input: 1234567,
        useGrouping: false,
      }),
    ).toMatchObject({ formatted: "1234567" });
  });

  // Numeric strings that JS Number() parses are accepted.
  const PARSE: Array<[string, string]> = [
    ["1e6", "1,000,000"],
    ["42", "42"],
    ["-3.5", "-3.5"],
    ["  1000  ", "1,000"],
  ];
  it.each(PARSE)("parses numeric string %s as %s", async (input, formatted) => {
    expect(await structured({ action: "format", input })).toMatchObject({
      formatted,
    });
  });

  // Distinct failure modes for format.
  const INVALID: Array<[string, string]> = [
    ["non-numeric word", "twelve"],
    ["empty string", ""],
    ["whitespace only", "   "],
    ["Infinity", "Infinity"],
    ["NaN literal", "NaN"],
  ];
  it.each(INVALID)("rejects %s (%s)", async (_label, input) => {
    expect((await run({ action: "format", input })).isError).toBe(true);
  });
});

describe("number: finiteness, rounding, and parse-strictness edges", () => {
  it("duration: numeric overflow returns a clean tool error, not a protocol error", async () => {
    const res = await run({ action: "duration", input: 1e300, unit: "w" });
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res.content)).toMatch(/overflows/);
  });
  it("format: 'Infinity' value is rejected with a clean tool error", async () => {
    const res = await run({ action: "format", input: "Infinity" });
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res.content)).toMatch(/non-finite/);
  });
  it("format: empty / whitespace-only value is rejected, not silently 0", async () => {
    expect((await run({ action: "format", input: "" })).isError).toBe(true);
    expect((await run({ action: "format", input: "   " })).isError).toBe(true);
  });
  it("bytes rendering promotes units after rounding (no '1000 kB' / '1024 KiB')", async () => {
    const out999999 = await structured({ action: "bytes", input: 999999 });
    expect(out999999.si).toBe("1 MB");
    const out1048575 = await structured({ action: "bytes", input: 1048575 });
    expect(out1048575.iec).toBe("1 MiB");
  });
  it("bytes parse rejects ambiguous comma placement (European decimal)", async () => {
    const res = await run({ action: "bytes", input: "1,5 MB" });
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res.content)).toMatch(/thousands separators/);
  });
  it("bytes parse rejects lowercase 'b' bit-symbol suffix instead of silently treating as bytes", async () => {
    const res = await run({ action: "bytes", input: "8 Gb" });
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res.content)).toMatch(/bits are not supported/);
  });
  it("duration: numeric-looking string respects the `unit` parameter", async () => {
    const out = await structured({
      action: "duration",
      input: " 90",
      unit: "m",
    });
    expect(out.ms).toBe(90 * 60 * 1000);
  });
  it("duration: sub-millisecond values are not flattened to PT0S", async () => {
    const out = await structured({
      action: "duration",
      input: 0.4,
      unit: "ms",
    });
    expect(out.ms).toBe(0.4);
    expect(out.iso).toBe("PT0.0004S");
    expect(String(out.human)).not.toBe("0s");
  });
});

describe("number: clock duration bounds", () => {
  it("rejects out-of-range minute/second segments rather than silently renormalising", async () => {
    const res = await run({ action: "duration", input: "1:90:05" });
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res.content)).toMatch(/0\.\.59|0-59/);
  });
  it("accepts a valid clock value", async () => {
    const out = await structured({ action: "duration", input: "1:30:05" });
    expect(out.ms).toBe((1 * 3600 + 30 * 60 + 5) * 1000);
  });
});

describe("number: format echoes back locale + notation", () => {
  it("includes locale and notation so callers can verify what was applied", async () => {
    const out = await structured({
      action: "format",
      input: 1234567,
      locale: "de-DE",
      notation: "compact",
    });
    expect(out.locale).toBe("de-DE");
    expect(out.notation).toBe("compact");
    expect(typeof out.formatted).toBe("string");
  });
});
