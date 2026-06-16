import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";
import { encodeTool } from "../../src/tools/encode.js";

type Args = Parameters<typeof encodeTool.handler>[0];

async function run(args: Partial<Args>): Promise<CallToolResult> {
  return (await encodeTool.handler({
    inputEncoding: "utf8",
    outputEncoding: "utf8",
    maxOutputBytes: 16 * 1024 * 1024,
    ...args,
  } as Args)) as CallToolResult;
}

async function result(args: Partial<Args>): Promise<string> {
  const res = await run(args);
  expect(res.isError, JSON.stringify(res.content)).toBeFalsy();
  return (res.structuredContent as { result: string }).result;
}

function text(res: CallToolResult): string {
  const first = res.content[0];
  return first?.type === "text" ? first.text : "";
}

// RFC 4648 §10 test vectors
const BASE64_VECTORS: Array<[string, string]> = [
  ["", ""],
  ["f", "Zg=="],
  ["fo", "Zm8="],
  ["foo", "Zm9v"],
  ["foob", "Zm9vYg=="],
  ["fooba", "Zm9vYmE="],
  ["foobar", "Zm9vYmFy"],
];

const BASE32_VECTORS: Array<[string, string]> = [
  ["", ""],
  ["f", "MY======"],
  ["fo", "MZXQ===="],
  ["foo", "MZXW6==="],
  ["foob", "MZXW6YQ="],
  ["fooba", "MZXW6YTB"],
  ["foobar", "MZXW6YTBOI======"],
];

describe("encode: base64 (RFC 4648)", () => {
  it.each(BASE64_VECTORS)("encodes %j", async (plain, encoded) => {
    expect(
      await result({ direction: "encode", format: "base64", input: plain }),
    ).toBe(encoded);
  });
  it.each(BASE64_VECTORS)("decodes to %j", async (plain, encoded) => {
    expect(
      await result({ direction: "decode", format: "base64", input: encoded }),
    ).toBe(plain);
  });
  // Illegal characters are reported at the offset of the FIRST bad char.
  it.each([
    ["Zm9v!aaa", 4],
    ["!Zm9v", 0],
    ["Zm@9v", 2],
    ["Zm9v aaa", 4], // space is not in the base64 alphabet
  ])("rejects illegal character in %j at its offset", async (input, offset) => {
    const res = await run({ direction: "decode", format: "base64", input });
    expect(res.isError).toBe(true);
    expect(text(res)).toContain(`offset ${offset}`);
  });
  // Lengths that aren't a multiple of 4 cannot be a valid base64 quantum.
  it.each([
    "Zm9vY",
    "Zm9vYg",
    "A",
    "AB",
  ])("rejects bad padding length %j", async (input) => {
    const res = await run({ direction: "decode", format: "base64", input });
    expect(res.isError).toBe(true);
    expect(text(res)).toContain("multiple of 4");
  });
});

describe("encode: base32 (RFC 4648)", () => {
  it.each(BASE32_VECTORS)("encodes %j", async (plain, encoded) => {
    expect(
      await result({ direction: "encode", format: "base32", input: plain }),
    ).toBe(encoded);
  });
  it.each(BASE32_VECTORS)("decodes to %j", async (plain, encoded) => {
    expect(
      await result({ direction: "decode", format: "base32", input: encoded }),
    ).toBe(plain);
  });
  // Characters outside the RFC 4648 base32 alphabet (A-Z2-7) are rejected,
  // naming the offending character. 0/1/8/9 are the classic excluded digits.
  it.each([
    ["MZ1W6===", '"1"'],
    ["MZ0W6===", '"0"'],
    ["MZ8W6===", '"8"'],
    ["MZ9W6===", '"9"'],
  ])("rejects illegal character in %j", async (input, badChar) => {
    const res = await run({ direction: "decode", format: "base32", input });
    expect(res.isError).toBe(true);
    expect(text(res)).toContain(badChar);
  });
  // Final-quantum lengths of 1/3/6 (after stripping padding) leave stray bits
  // no base32 char could have produced — malformed per RFC 4648 §6.
  it.each([
    "A=======",
    "MZX=====",
    "MZXW6Y==",
  ])("rejects invalid final-quantum length %j", async (input) => {
    const res = await run({ direction: "decode", format: "base32", input });
    expect(res.isError).toBe(true);
    expect(text(res)).toMatch(/final quantum|valid RFC 4648 length/);
  });
});

describe("encode: base64url", () => {
  it("encodes binary-ish text without +/=", async () => {
    expect(
      await result({
        direction: "encode",
        format: "base64url",
        input: "\xfb\xff~",
      }),
    ).toBe("w7vDv34");
  });
  // Round-trip a range of payloads, including ones whose standard-base64 form
  // would contain + and / (so the url variant actually differs).
  it.each([
    "hello world?",
    "",
    "f",
    "foobar",
    "\xff\xfe\xfd", // produces - and _ in base64url
    "subjects?_d=1",
  ])("round-trips %j", async (plain) => {
    const enc = await result({
      direction: "encode",
      format: "base64url",
      input: plain,
    });
    // base64url output must never contain +, / or = padding.
    expect(enc).not.toMatch(/[+/=]/);
    expect(
      await result({ direction: "decode", format: "base64url", input: enc }),
    ).toBe(plain);
  });
  // length % 4 === 1 encodes a fractional byte — rejected, never "decode to
  // empty".
  it.each([
    "A",
    "Zm9vYg==Q",
  ])("rejects %j (cannot encode a whole number of bytes)", async (input) => {
    const res = await run({ direction: "decode", format: "base64url", input });
    expect(res.isError).toBe(true);
  });
});

describe("encode: hex", () => {
  // plain → hex; expected computed with Buffer.from(plain).toString("hex").
  it.each([
    ["foobar", "666f6f626172"],
    ["", ""],
    ["A", "41"],
    ["hi", "6869"],
  ])("encodes %j to %s", async (plain, encoded) => {
    expect(
      await result({ direction: "encode", format: "hex", input: plain }),
    ).toBe(encoded);
  });
  // Decode is case-insensitive (lower/upper/mixed all decode the same).
  it.each([
    ["666f6f", "foo"],
    ["666F6F", "foo"],
    ["666F6f", "foo"],
    ["6869", "hi"],
    ["", ""],
  ])("decodes %j to %j", async (encoded, plain) => {
    expect(
      await result({ direction: "decode", format: "hex", input: encoded }),
    ).toBe(plain);
  });
  it.each(["abc", "f", "12345"])("rejects odd length %j", async (input) => {
    const res = await run({ direction: "decode", format: "hex", input });
    expect(res.isError).toBe(true);
    expect(text(res)).toContain("odd");
  });
  it.each([
    ["ab0x", 3],
    ["xy", 0],
    ["00gg", 2],
  ])("rejects illegal char in %j at offset %i", async (input, offset) => {
    const res = await run({ direction: "decode", format: "hex", input });
    expect(res.isError).toBe(true);
    expect(text(res)).toContain(`offset ${offset}`);
  });
});

describe("encode: url", () => {
  // url-component reserved-char encoding; expected via encodeURIComponent.
  it.each([
    ["a b&c=d?", "a%20b%26c%3Dd%3F"],
    ["100%", "100%25"],
    ["a/b c", "a%2Fb%20c"],
  ])("url-component encodes %j", async (plain, encoded) => {
    expect(
      await result({
        direction: "encode",
        format: "url-component",
        input: plain,
      }),
    ).toBe(encoded);
  });
  // Full-URL encoding preserves structure (encodeURI leaves / ? & = intact).
  it.each([
    ["https://x.io/a b?q=1&r=2", "https://x.io/a%20b?q=1&r=2"],
    ["http://h/p a th", "http://h/p%20a%20th"],
  ])("url keeps full-URL structure for %j", async (plain, encoded) => {
    expect(
      await result({ direction: "encode", format: "url", input: plain }),
    ).toBe(encoded);
  });
  it.each([
    ["a%20b%26c", "a b&c"],
    ["%E2%9C%93", "✓"],
  ])("decodes url-component %j", async (encoded, plain) => {
    expect(
      await result({
        direction: "decode",
        format: "url-component",
        input: encoded,
      }),
    ).toBe(plain);
  });
  // A range of malformed percent-escapes: truncated, non-hex digits.
  it.each([
    "a%2",
    "a%",
    "%G0",
    "%2Q",
  ])("rejects malformed percent-encoding %j", async (input) => {
    const res = await run({
      direction: "decode",
      format: "url-component",
      input,
    });
    expect(res.isError).toBe(true);
  });
});

describe("encode: html", () => {
  // The five characters escapeHtml replaces, individually and combined.
  it.each([
    ['<a href="x">&\'', "&lt;a href=&quot;x&quot;&gt;&amp;&#39;"],
    ["&", "&amp;"],
    ["<", "&lt;"],
    [">", "&gt;"],
    ['"', "&quot;"],
    ["'", "&#39;"],
    ["plain text", "plain text"],
  ])("escapes %j", async (plain, escaped) => {
    expect(
      await result({ direction: "encode", format: "html", input: plain }),
    ).toBe(escaped);
  });
  // Named, decimal and hex (lower/upper x) numeric entities all decode.
  it.each([
    ["&lt;b&gt; &amp; &#65;&#x42;", "<b> & AB"],
    ["&#65;", "A"],
    ["&#x41;", "A"],
    ["&#X41;", "A"],
    ["&amp;&lt;&gt;", "&<>"],
  ])("unescapes %j", async (input, expected) => {
    expect(await result({ direction: "decode", format: "html", input })).toBe(
      expected,
    );
  });
  it("passes through unknown entity unchanged with a warning (no error)", async () => {
    const res = await run({
      direction: "decode",
      format: "html",
      input: "&bogus;",
    });
    expect(res.isError).toBeFalsy();
    const s = res.structuredContent as { result: string; warnings: string[] };
    expect(s.result).toBe("&bogus;");
    expect(s.warnings.some((w) => w.includes("&bogus;"))).toBe(true);
  });
});

describe("encode: unicode-escape", () => {
  // Non-ascii (incl. control chars and astral plane) escape to \uXXXX, with
  // astral code points emitted as a surrogate pair. Expected via an
  // independent escapeUnicode reimplementation.
  it.each([
    ["héllo 🚀", "h\\u00e9llo \\ud83d\\ude80"],
    ["café", "caf\\u00e9"],
    ["\t", "\\u0009"],
    ["😀", "\\ud83d\\ude00"],
    ["plain", "plain"],
  ])("escapes %j", async (plain, escaped) => {
    expect(
      await result({
        direction: "encode",
        format: "unicode-escape",
        input: plain,
      }),
    ).toBe(escaped);
  });
  // Decode accepts both \uXXXX (incl. surrogate pairs) and braced \u{...}.
  it.each([
    ["h\\u00e9llo \\ud83d\\ude80", "héllo 🚀"],
    ["grin \\u{1f600}", "grin 😀"], // braced astral, not truncated to 16 bits
    ["\\u0041\\u0042", "AB"],
    ["\\u{41}", "A"], // short braced form
  ])("unescapes %j", async (input, expected) => {
    expect(
      await result({
        direction: "decode",
        format: "unicode-escape",
        input,
      }),
    ).toBe(expected);
  });
  // A range of malformed escapes: out-of-range code point, non-hex digit,
  // too-short \uXXXX, empty/oversized braces, unterminated brace.
  it.each([
    "\\u{110000}", // > U+10FFFF
    "\\u00G1", // non-hex digit
    "\\u00", // fewer than 4 hex digits
    "\\u{}", // empty braces
    "\\u{1234567}", // > 6 hex digits
    "\\u{12", // missing closing brace
  ])("rejects malformed escape %j", async (input) => {
    const res = await run({
      direction: "decode",
      format: "unicode-escape",
      input,
    });
    expect(res.isError).toBe(true);
  });
});

describe("encode: strict-decode contract holds at boundaries", () => {
  it("base64url rejects length%4==1 inputs instead of returning empty", async () => {
    const res = await run({
      direction: "decode",
      format: "base64url",
      input: "A",
    });
    expect(res.isError).toBe(true);
    expect(text(res)).toMatch(/cannot encode a whole number of bytes/);
  });
  it("base64url accepts standard padded input (RFC 4648 §5 permits padding)", async () => {
    expect(
      await result({
        direction: "decode",
        format: "base64url",
        input: "Zm9vYg==",
      }),
    ).toBe("foob");
  });
  it("base32 rejects 1-char final quantum (5 bits)", async () => {
    const res = await run({
      direction: "decode",
      format: "base32",
      input: "A=======",
    });
    expect(res.isError).toBe(true);
    expect(text(res)).toMatch(/final quantum|valid RFC 4648 length/);
  });
  it("html: '&#abc;' errors precisely instead of crashing on NaN", async () => {
    const res = await run({
      direction: "decode",
      format: "html",
      input: "&#abc;",
    });
    expect(res.isError).toBe(true);
    expect(text(res)).not.toMatch(/NaN/);
  });
  it("html: '&#X41;' (uppercase X) decodes to 'A'", async () => {
    expect(
      await result({ direction: "decode", format: "html", input: "&#X41;" }),
    ).toBe("A");
  });
  it("html: out-of-range numeric entity reports a precise error, not raw RangeError", async () => {
    const res = await run({
      direction: "decode",
      format: "html",
      input: "&#x110000;",
    });
    expect(res.isError).toBe(true);
    expect(text(res)).toMatch(/out of range/);
    expect(text(res)).toMatch(/offset/);
  });
  it("url decode error includes the offset of the bad percent-escape", async () => {
    const res = await run({
      direction: "decode",
      format: "url",
      input: "hello%20world%E0%A4%A",
    });
    expect(res.isError).toBe(true);
    expect(text(res)).toMatch(/offset/);
  });
});

describe("encode: radix", () => {
  // A spread of conversions across bases, incl. negatives, zero, the full
  // base-36 alphabet, and a 128-bit value (BigInt precision). Expected values
  // computed independently with a BigInt reference converter.
  it.each([
    ["255", 10, 16, "ff"],
    ["100000000", 2, 10, "256"],
    ["ff", 16, 2, "11111111"],
    ["777", 8, 10, "511"],
    ["z", 36, 10, "35"],
    ["0", 10, 2, "0"],
    ["-1010", 2, 10, "-10"], // negatives preserved
    [
      "340282366920938463463374607431768211456", // 2^128
      10,
      16,
      "100000000000000000000000000000000",
    ],
  ] as Array<
    [string, number, number, string]
  >)("converts %j base %i → %i", async (input, radixFrom, radixTo, expected) => {
    expect(
      await result({
        direction: "encode",
        format: "radix",
        input,
        radixFrom,
        radixTo,
      }),
    ).toBe(expected);
  });
  // A digit must be valid for the SOURCE base. "129" has a 9 in base 2, "g" is
  // not a base-16 digit, "8" is not octal.
  it.each([
    ["129", 2, "base 2"],
    ["1g", 16, "base 16"],
    ["8", 8, "base 8"],
  ])("rejects digit out of range in %j", async (input, radixFrom, msg) => {
    const res = await run({
      direction: "encode",
      format: "radix",
      input,
      radixFrom,
      radixTo: 10,
    });
    expect(res.isError).toBe(true);
    expect(text(res)).toContain(msg);
  });
  // Both radixFrom and radixTo are required; missing either is an error.
  it.each([
    [{ radixFrom: 10 }],
    [{ radixTo: 16 }],
    [{}],
  ])("requires radixFrom/radixTo (%o)", async (radices) => {
    const res = await run({
      direction: "encode",
      format: "radix",
      input: "255",
      ...radices,
    });
    expect(res.isError).toBe(true);
  });
});

describe("encode: binary chaining", () => {
  // base64 input → hex output. (Zm9vYmFy=base64("foobar"), aGk=base64("hi"))
  it.each([
    ["Zm9vYmFy", "666f6f626172"],
    ["aGk=", "6869"],
  ])("re-encodes base64 %j to hex", async (input, expected) => {
    expect(
      await result({
        direction: "encode",
        format: "hex",
        input,
        inputEncoding: "base64",
      }),
    ).toBe(expected);
  });
  it.each([
    ["666f6f626172", "Zm9vYmFy"],
    ["6869", "aGk="],
  ])("decodes hex %j to base64 via outputEncoding", async (input, expected) => {
    expect(
      await result({
        direction: "decode",
        format: "hex",
        input,
        outputEncoding: "base64",
      }),
    ).toBe(expected);
  });
});

describe("encode: gzip", () => {
  it("round-trips text through gzip + base64", async () => {
    const plain =
      "hello compression world — this should compress well, ".repeat(20);
    // encode → compressed bytes as base64
    const compressed = await result({
      direction: "encode",
      format: "gzip",
      input: plain,
      outputEncoding: "base64",
    });
    // The compressed form should be valid base64 and shorter than the input.
    expect(compressed).toMatch(/^[A-Za-z0-9+/=]+$/);
    expect(compressed.length).toBeLessThan(plain.length);
    // decode → back to the original text
    const decoded = await result({
      direction: "decode",
      format: "gzip",
      input: compressed,
      inputEncoding: "base64",
    });
    expect(decoded).toBe(plain);
  });

  // Inputs that decode to bytes but are not a valid gzip stream: arbitrary
  // text, empty input, and a truncated/garbage header. All must fail cleanly.
  it.each([
    ["ZG9lcyBub3QgZGVjb21wcmVzcw=="], // base64 of plain text
    ["AAAA"], // four zero-ish bytes, no gzip magic
    ["H4s="], // truncated gzip-magic prefix
  ])("rejects a malformed gzip stream %j", async (input) => {
    const res = await run({
      direction: "decode",
      format: "gzip",
      input,
      inputEncoding: "base64",
    });
    expect(res.isError).toBe(true);
    expect(text(res)).toContain("gzip");
  });
});

describe("encode: deflate", () => {
  it("round-trips text through deflate + base64", async () => {
    const plain = "deflate also works, ".repeat(50);
    const compressed = await result({
      direction: "encode",
      format: "deflate",
      input: plain,
      outputEncoding: "base64",
    });
    const decoded = await result({
      direction: "decode",
      format: "deflate",
      input: compressed,
      inputEncoding: "base64",
    });
    expect(decoded).toBe(plain);
  });
});

describe("encode: brotli", () => {
  it("round-trips text through brotli + base64", async () => {
    const plain = "brotli is the squeezier one, ".repeat(50);
    const compressed = await result({
      direction: "encode",
      format: "brotli",
      input: plain,
      outputEncoding: "base64",
    });
    const decoded = await result({
      direction: "decode",
      format: "brotli",
      input: compressed,
      inputEncoding: "base64",
    });
    expect(decoded).toBe(plain);
  });

  it("decompresses a known brotli fixture", async () => {
    // Provenance: produced outside the tool with Node's zlib directly —
    //   require("node:zlib").brotliCompressSync(Buffer.from("Hello")).toString("base64")
    // → "CwKASGVsbG8D". Pinning a concrete vector (not an encode→decode
    // round-trip through this same tool) proves the decoder accepts a brotli
    // stream it didn't itself produce in the same call.
    const fixture = "CwKASGVsbG8D";
    const back = await result({
      direction: "decode",
      format: "brotli",
      input: fixture,
      inputEncoding: "base64",
    });
    expect(back).toBe("Hello");
  });
});

describe("encode: compression bombs are bounded", () => {
  it("refuses to decompress past maxOutputBytes", async () => {
    // 1 KiB of zeros compresses to a tiny payload but expands to 1 KiB.
    const huge = "\0".repeat(1024);
    const compressed = await result({
      direction: "encode",
      format: "gzip",
      input: huge,
      outputEncoding: "base64",
    });
    const res = await run({
      direction: "decode",
      format: "gzip",
      input: compressed,
      inputEncoding: "base64",
      maxOutputBytes: 512, // smaller than the real output
    });
    expect(res.isError).toBe(true);
    expect(text(res).toLowerCase()).toMatch(/maxoutputbytes|too large|buffer/);
  });

  it("allows the same decompression when the cap is raised", async () => {
    const huge = "\0".repeat(1024);
    const compressed = await result({
      direction: "encode",
      format: "gzip",
      input: huge,
      outputEncoding: "base64",
    });
    const decoded = await result({
      direction: "decode",
      format: "gzip",
      input: compressed,
      inputEncoding: "base64",
      maxOutputBytes: 4096,
    });
    expect(decoded).toBe(huge);
  });
});

describe("encode: compression hex output", () => {
  // Every compression format can emit hex; output is pure lowercase hex and
  // round-trips back to the original via hex inputEncoding... well, base64 on
  // decode — here we just assert the hex shape per format.
  it.each(["gzip", "deflate", "brotli"] as Array<
    Args["format"]
  >)("returns compressed bytes as hex for %s", async (format) => {
    const hex = await result({
      direction: "encode",
      format,
      input: "x",
      outputEncoding: "hex",
    });
    expect(hex).toMatch(/^[0-9a-f]+$/);
    expect(hex.length % 2).toBe(0);
  });
});

describe("encode: batch input", () => {
  it("returns results[] when input is an array (base64 encode)", async () => {
    const res = await run({
      direction: "encode",
      format: "base64",
      input: ["foo", "bar"],
    });
    expect(res.isError).toBeFalsy();
    const s = res.structuredContent as {
      results: Array<{ result: string; byteLength: number }>;
    };
    expect(s.results).toHaveLength(2);
    // byteLength now reports OUTPUT bytes ("Zm9v" / "YmFy" are 4 chars).
    expect(s.results[0]).toEqual({ result: "Zm9v", byteLength: 4 });
    expect(s.results[1]).toEqual({ result: "YmFy", byteLength: 4 });
  });

  it("batch works for the radix path too", async () => {
    const res = await run({
      direction: "encode",
      format: "radix",
      input: ["255", "16"],
      radixFrom: 10,
      radixTo: 16,
    });
    expect(res.isError).toBeFalsy();
    const s = res.structuredContent as {
      results: Array<{ result: string }>;
    };
    expect(s.results.map((r) => r.result)).toEqual(["ff", "10"]);
  });

  it("single-string input keeps the flat shape", async () => {
    const res = await run({
      direction: "encode",
      format: "base64",
      input: "foo",
    });
    const s = res.structuredContent as Record<string, unknown>;
    expect(s.result).toBe("Zm9v");
    expect(s.results).toBeUndefined();
  });

  // A bad item is isolated into `failures`; good items still come back in
  // `results`. (Per the conformance contract — batch tools must not lose
  // 99 good results because item #50 was malformed.)
  it.each([
    [["!!!", "Zm9v"], [0]], // bad first
    [["Zm9v", "!!!"], [1]], // bad last
    [["Zm9v", "@@@", "YmFy"], [1]], // bad middle
  ])("batch isolates bad items into failures (input %j, bad %j)", async (input, badIndices) => {
    const res = await run({
      direction: "decode",
      format: "base64",
      input,
    });
    expect(res.isError, JSON.stringify(res.content)).toBeFalsy();
    const s = res.structuredContent as {
      results: unknown[];
      failures: Array<{ index: number }>;
    };
    expect(s.results).toHaveLength(input.length - badIndices.length);
    expect(s.failures.map((f) => f.index).sort()).toEqual(badIndices);
  });
});

describe("encode: compression compatibility guards", () => {
  it("encode + utf8 outputEncoding is rejected for compression formats", async () => {
    const res = await run({
      direction: "encode",
      format: "gzip",
      input: "hello",
      outputEncoding: "utf8",
    });
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res.content)).toMatch(/gzip encode produces binary/);
  });

  it("decode + utf8 inputEncoding is rejected for compression formats", async () => {
    const res = await run({
      direction: "decode",
      format: "gzip",
      input: "anything",
      inputEncoding: "utf8",
    });
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res.content)).toMatch(/gzip decode expects binary/);
  });

  it("the happy round-trip still works (encode → decode via base64)", async () => {
    const enc = await run({
      direction: "encode",
      format: "gzip",
      input: "hello world",
      outputEncoding: "base64",
    });
    expect(enc.isError).toBeFalsy();
    const compressed = (enc.structuredContent as { result: string }).result;
    const dec = await run({
      direction: "decode",
      format: "gzip",
      input: compressed,
      inputEncoding: "base64",
      outputEncoding: "utf8",
    });
    expect(dec.isError).toBeFalsy();
    expect((dec.structuredContent as { result: string }).result).toBe(
      "hello world",
    );
  });
});

describe("encode: byteLength reports OUTPUT bytes (CC-9)", () => {
  // byteLength is the length (in bytes) of the OUTPUT string, not the input.
  // base64("foo")="Zm9v" (4), base64("foobar")="Zm9vYmFy" (8),
  // hex("x")="78" (2), hex("hi")="6869" (4), base32("foo")="MZXW6===" (8).
  it.each([
    ["base64", "foo", 4],
    ["base64", "foobar", 8],
    ["hex", "x", 2],
    ["hex", "hi", 4],
    ["base32", "foo", 8],
  ] as Array<
    [Args["format"], string, number]
  >)("%s encode of %j reports output byteLength %i", async (format, input, expected) => {
    const res = await run({ direction: "encode", format, input });
    expect((res.structuredContent as { byteLength: number }).byteLength).toBe(
      expected,
    );
  });
});

describe("encode: html entity table", () => {
  it("expanded named entities (copy / mdash / hellip / euro / reg) decode", async () => {
    const cases: Array<[string, string]> = [
      ["&copy;", "©"],
      ["&mdash;", "—"],
      ["&hellip;", "…"],
      ["&euro;", "€"],
      ["&reg;", "®"],
    ];
    for (const [entity, expected] of cases) {
      const res = await run({
        direction: "decode",
        format: "html",
        input: entity,
      });
      expect(res.isError, entity).toBeFalsy();
      expect((res.structuredContent as { result: string }).result).toBe(
        expected,
      );
    }
  });

  it("unknown entities pass through unchanged with a warning (not an error)", async () => {
    const res = await run({
      direction: "decode",
      format: "html",
      input: "Look: &xyzzy; ok?",
    });
    expect(res.isError).toBeFalsy();
    const s = res.structuredContent as { result: string; warnings: string[] };
    expect(s.result).toBe("Look: &xyzzy; ok?");
    expect(s.warnings.some((w) => w.includes("xyzzy"))).toBe(true);
  });
});

describe("encode: maxOutputBytes ignored on non-compression formats (CC-8)", () => {
  it("emits a warning when maxOutputBytes is passed with a non-compression format", async () => {
    const res = await run({
      direction: "encode",
      format: "base64",
      input: "x",
      maxOutputBytes: 1024,
    });
    const s = res.structuredContent as { warnings: string[] };
    expect(s.warnings.some((w) => w.includes("maxOutputBytes"))).toBe(true);
  });
  it("no warning when the default is left in place", async () => {
    const res = await run({
      direction: "encode",
      format: "base64",
      input: "x",
    });
    const s = res.structuredContent as { warnings: string[] };
    expect(s.warnings).toEqual([]);
  });
});

describe("encode: base-N decode case-handling is consistent across formats", () => {
  // hex already decodes either case (see "encode: hex" — 666F6F works), so a
  // caller reasonably expects the same leniency from base32. Today base32 only
  // accepts the canonical uppercase alphabet and rejects lowercase, which is an
  // inconsistency *within the same tool*. These pin the consistent contract.

  // Passing: documents that hex is case-insensitive on decode.
  it.each([
    ["48656c6c6f", "Hello"],
    ["48656C6C6F", "Hello"],
    ["48656C6c6F", "Hello"], // mixed case
  ])("hex decodes %j regardless of case", async (input, plain) => {
    expect(await result({ direction: "decode", format: "hex", input })).toBe(
      plain,
    );
  });

  // base32 decode case-folds — RFC 4648's alphabet is uppercase but
  // case-folding on decode is the norm and matches this tool's own hex
  // behaviour. A few representative shapes (short, padded, full, mixed).
  it.each([
    ["foo", "mzxw6==="], // lowercase, padded
    ["fooba", "mzxw6ytb"], // lowercase, no padding
    ["foobar", "mzxw6ytboi======"], // lowercase, full
    ["foobar", "Mzxw6Ytboi======"], // mixed case (realistic copy-paste)
  ])("base32 decodes %j from %j (parity with hex)", async (plain, encoded) => {
    const res = await run({
      direction: "decode",
      format: "base32",
      input: encoded,
    });
    expect(res.isError, JSON.stringify(res.content)).toBeFalsy();
    expect((res.structuredContent as { result: string }).result).toBe(plain);
  });
});
