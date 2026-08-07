import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";
import { hashTool } from "../../src/tools/hash.js";

type Args = Parameters<typeof hashTool.handler>[0];

async function run(args: Partial<Args>): Promise<CallToolResult> {
  return (await hashTool.handler({
    inputEncoding: "utf8",
    hmacKeyEncoding: "utf8",
    outputEncoding: "hex",
    ...args,
  } as Args)) as CallToolResult;
}

async function digest(args: Partial<Args>): Promise<string> {
  const res = await run(args);
  expect(res.isError, JSON.stringify(res.content)).toBeFalsy();
  return (res.structuredContent as { digest: string }).digest;
}

// NIST / RFC reference vectors
describe("hash: digest vectors", () => {
  const VECTORS: Array<[Args["algorithm"], string, string]> = [
    ["md5", "abc", "900150983cd24fb0d6963f7d28e17f72"],
    ["md5", "", "d41d8cd98f00b204e9800998ecf8427e"],
    ["sha1", "abc", "a9993e364706816aba3e25717850c26c9cd0d89d"],
    [
      "sha256",
      "abc",
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    ],
    [
      "sha256",
      "",
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ],
    [
      "sha384",
      "abc",
      "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
    ],
    [
      "sha512",
      "abc",
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    ],
    [
      "sha3-256",
      "abc",
      "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
    ],
    [
      "sha3-512",
      "abc",
      "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
    ],
    [
      "blake2b512",
      "abc",
      "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
    ],
    // Extra reference vectors across the full algorithm matrix and a spread of
    // inputs (empty / short / pangram). Expected digests computed independently
    // with node:crypto, never copied from the tool's own output.
    ["md5", "hello", "5d41402abc4b2a76b9719d911017c592"],
    [
      "md5",
      "The quick brown fox jumps over the lazy dog",
      "9e107d9d372bb6826bd81d3542a419d6",
    ],
    ["sha1", "", "da39a3ee5e6b4b0d3255bfef95601890afd80709"],
    ["sha1", "hello", "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"],
    [
      "sha1",
      "The quick brown fox jumps over the lazy dog",
      "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
    ],
    [
      "sha256",
      "hello",
      "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    ],
    [
      "sha256",
      "The quick brown fox jumps over the lazy dog",
      "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
    ],
    [
      "sha384",
      "",
      "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
    ],
    [
      "sha512",
      "",
      "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    ],
    [
      "sha3-256",
      "",
      "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
    ],
    [
      "sha3-512",
      "",
      "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
    ],
    [
      "blake2b512",
      "",
      "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
    ],
  ];
  it.each(VECTORS)("%s(%j)", async (algorithm, input, expected) => {
    expect(await digest({ algorithm, input })).toBe(expected);
  });
});

describe("hash: crc32", () => {
  // CRC-32 (IEEE 802.3) check values computed independently with a reference
  // bit-reflected implementation; "123456789" → cbf43926 is the canonical
  // CRC-32 check constant.
  it.each([
    ["123456789", "cbf43926"],
    ["", "00000000"],
    ["abc", "352441c2"],
    ["hello", "3610a686"],
    ["The quick brown fox jumps over the lazy dog", "414fa339"],
  ])("crc32(%j) === %s", async (input, expected) => {
    expect(await digest({ algorithm: "crc32", input })).toBe(expected);
  });

  // CRC is not a keyed MAC — any hmacKey (utf8/hex/base64, any length) must
  // be rejected rather than silently ignored.
  it.each([
    ["k", "utf8" as const],
    ["0b0b", "hex" as const],
    ["YWJj", "base64" as const],
  ])("rejects hmacKey %j (%s)", async (hmacKey, hmacKeyEncoding) => {
    const res = await run({
      algorithm: "crc32",
      input: "x",
      hmacKey,
      hmacKeyEncoding,
    });
    expect(res.isError).toBe(true);
  });
});

describe("hash: hmac", () => {
  // RFC 4231 test case 2 (key="Jefe") across the SHA family — digests computed
  // independently with node:crypto's createHmac.
  it.each([
    ["sha1", "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"],
    [
      "sha256",
      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
    ],
    [
      "sha512",
      "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
    ],
  ] as Array<[Args["algorithm"], string]>)(
    "HMAC-%s matches RFC 4231 test case 2",
    async (algorithm, expected) => {
      expect(
        await digest({
          algorithm,
          input: "what do ya want for nothing?",
          hmacKey: "Jefe",
        }),
      ).toBe(expected);
    },
  );
  it("supports hex keys (RFC 4231 test case 1)", async () => {
    expect(
      await digest({
        algorithm: "sha256",
        input: "Hi There",
        hmacKey: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        hmacKeyEncoding: "hex",
      }),
    ).toBe("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
  });
});

describe("hash: encodings and input contract", () => {
  // The same plaintext "abc" expressed via each inputEncoding must yield the
  // canonical SHA-256("abc") digest. "YWJj" is base64("abc"), "616263" is
  // hex("abc").
  it.each([
    ["abc", "utf8" as const],
    ["YWJj", "base64" as const],
    ["616263", "hex" as const],
  ])("digests %j via inputEncoding=%s", async (input, inputEncoding) => {
    expect(await digest({ algorithm: "sha256", input, inputEncoding })).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });
  // Output encodings: each derives the SHA-256("abc") digest bytes re-encoded
  // via Buffer, computed here rather than read from the tool.
  it.each(["hex", "base64", "base64url"] as Array<Args["outputEncoding"]>)(
    "outputs digest as %s",
    async (outputEncoding) => {
      const raw = Buffer.from(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "hex",
      );
      const expected = raw.toString(outputEncoding);
      expect(
        await digest({ algorithm: "sha256", input: "abc", outputEncoding }),
      ).toBe(expected);
    },
  );
  it("rejects both input and inputUrl", async () => {
    const res = await run({
      algorithm: "sha256",
      input: "a",
      inputUrl: "http://x",
    });
    expect(res.isError).toBe(true);
  });
  it("rejects neither input nor inputUrl", async () => {
    const res = await run({ algorithm: "sha256" });
    expect(res.isError).toBe(true);
  });
});

describe("hash: strict input validation", () => {
  // Several distinct malformed base64 inputs — illegal chars and wrong length
  // (% 4 !== 0) — must all be rejected rather than digesting coerced garbage.
  it.each([
    ["!!!not-valid-base64!!!"], // illegal characters
    ["YWJj#"], // trailing illegal char
    ["YWJj="], // length not a multiple of 4
    ["YWJ"], // length 3, not a multiple of 4
  ])("rejects invalid base64 input %j", async (input) => {
    const res = await run({
      algorithm: "sha256",
      input,
      inputEncoding: "base64",
    });
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res.content)).toMatch(/invalid input base64/);
  });

  // Several distinct malformed hex inputs.
  it.each([
    ["zz", "illegal character"],
    ["6g", "illegal character"],
    ["abc", "odd number of digits"],
  ])("rejects invalid hex input %j", async (input) => {
    const res = await run({
      algorithm: "sha256",
      input,
      inputEncoding: "hex",
    });
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res.content)).toMatch(/invalid input hex/);
  });

  it("rejects invalid hex hmacKey rather than computing an empty-key HMAC", async () => {
    const res = await run({
      algorithm: "sha256",
      input: "Hi There",
      hmacKey: "zz-not-hex",
      hmacKeyEncoding: "hex",
    });
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res.content)).toMatch(/invalid hmacKey hex/);
  });

  it("rejects odd-length hex hmacKey rather than silently truncating", async () => {
    const res = await run({
      algorithm: "sha256",
      input: "Hi There",
      hmacKey: "0b0",
      hmacKeyEncoding: "hex",
    });
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res.content)).toMatch(/odd number of digits/);
  });

  it("rejects invalid base64 hmacKey rather than computing an empty-key HMAC", async () => {
    const res = await run({
      algorithm: "sha256",
      input: "Hi There",
      hmacKey: "!!!",
      hmacKeyEncoding: "base64",
    });
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res.content)).toMatch(/invalid hmacKey base64/);
  });
});

describe("hash: batch input", () => {
  it("returns results[] when input is an array", async () => {
    const res = await run({
      algorithm: "sha256",
      input: ["abc", "", "Hi There"],
    });
    expect(res.isError).toBeFalsy();
    const s = res.structuredContent as {
      results: Array<{ digest: string; byteLength: number }>;
      algorithm: string;
    };
    expect(s.algorithm).toBe("sha256");
    expect(s.results).toHaveLength(3);
    // Same digests as a single-item call would produce — batch must be
    // pointwise-equivalent to N single calls.
    expect(s.results[0]).toEqual({
      digest:
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
      byteLength: 3,
    });
    expect(s.results[1]).toEqual({
      digest:
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      byteLength: 0,
    });
    expect(s.results[2]).toEqual({
      digest:
        "cc6d5896d770101ef0280c943a2d3c3f24cd5b11464a5186daf7a238477162ac",
      byteLength: 8,
    });
  });

  it("a single-string input keeps the flat shape (no breaking change)", async () => {
    const res = await run({ algorithm: "sha256", input: "abc" });
    const s = res.structuredContent as Record<string, unknown>;
    expect(s.digest).toBeTruthy();
    expect(s.results).toBeUndefined();
  });

  it("batch isolates a bad item into failures rather than failing the whole call", async () => {
    const res = await run({
      algorithm: "sha256",
      input: ["aGVsbG8=", "!!!"],
      inputEncoding: "base64",
    });
    expect(res.isError, JSON.stringify(res.content)).toBeFalsy();
    const s = res.structuredContent as {
      results: unknown[];
      failures: Array<{ index: number }>;
    };
    expect(s.results).toHaveLength(1);
    expect(s.failures).toHaveLength(1);
    expect(s.failures[0]?.index).toBe(1);
  });

  // The reported index in `failures` must track WHICH item failed,
  // regardless of position in the batch — and good items still come back.
  it.each([
    [["not!", "Zm9v", "aGVsbG8="], 0],
    [["aGVsbG8=", "not!", "Zm9v"], 1],
    [["aGVsbG8=", "Zm9v", "not!"], 2],
  ] as Array<[string[], number]>)(
    "batch failures carry the right index for %j",
    async (input, badIndex) => {
      const res = await run({
        algorithm: "sha256",
        input,
        inputEncoding: "base64",
      });
      expect(res.isError, JSON.stringify(res.content)).toBeFalsy();
      const s = res.structuredContent as {
        results: unknown[];
        failures: Array<{ index: number }>;
      };
      expect(s.results).toHaveLength(2);
      expect(s.failures).toHaveLength(1);
      expect(s.failures[0]?.index).toBe(badIndex);
    },
  );
});

describe("hash: enum / shape niceties", () => {
  it("structuredContent uses the raw algorithm enum + hmac:true flag (round-trippable)", async () => {
    const res = await run({
      algorithm: "sha256",
      input: "abc",
      hmacKey: "k",
    });
    expect(res.isError).toBeFalsy();
    const s = res.structuredContent as { algorithm: string; hmac: boolean };
    expect(s.algorithm).toBe("sha256");
    expect(s.hmac).toBe(true);
  });

  it("supports inputEncoding='hex' (was missing — chains with encode outputEncoding='hex')", async () => {
    // hash of bytes 0x61 0x62 0x63 (== "abc") via hex input.
    const out = structured(
      await run({ algorithm: "sha256", input: "616263", inputEncoding: "hex" }),
    );
    expect((out as { digest: string }).digest).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("supports outputEncoding='base64url' (the JWT signature form)", async () => {
    const digest = await digestVia({
      algorithm: "sha256",
      input: "abc",
      outputEncoding: "base64url",
    });
    // base64url variant of the canonical SHA-256("abc") digest.
    expect(digest).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("rejects an empty hmacKey rather than computing a zero-length-key MAC", async () => {
    const res = await run({ algorithm: "sha256", input: "abc", hmacKey: "" });
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res.content)).toMatch(/empty/);
  });
});

async function digestVia(args: Partial<Args>): Promise<string> {
  const res = await run(args);
  expect(res.isError, JSON.stringify(res.content)).toBeFalsy();
  return (res.structuredContent as { digest: string }).digest;
}

function structured(res: CallToolResult): Record<string, unknown> {
  return res.structuredContent as Record<string, unknown>;
}
