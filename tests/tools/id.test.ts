import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import { idTool } from "../../src/tools/id.js";

type Args = Parameters<typeof idTool.handler>[0];

// The `kind` enum is enforced by Zod at the MCP boundary, not inside the
// handler — so unknown-kind rejection must be checked against the schema.
const idSchema = z.object(idTool.inputSchema as z.ZodRawShape);

function run(args: Partial<Args>): CallToolResult {
  return idTool.handler({
    count: 1,
    outputEncoding: "hex",
    uppercase: true,
    digits: true,
    symbols: true,
    ...args,
  } as Args) as CallToolResult;
}

function values(args: Partial<Args>): string[] {
  const res = run(args);
  expect(res.isError, JSON.stringify(res.content)).toBeFalsy();
  return (res.structuredContent as { values: string[] }).values;
}

function inspect(value: string): Record<string, unknown> {
  const res = run({ action: "inspect", value });
  expect(res.isError).toBeFalsy();
  return res.structuredContent as Record<string, unknown>;
}

const UUID_V4_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

describe("id: generate uuid", () => {
  it("uuid-v4 matches format and is unique across 1000 generations", () => {
    const out = new Set<string>();
    for (let i = 0; i < 10; i++) {
      for (const v of values({
        action: "generate",
        kind: "uuid-v4",
        count: 100,
      })) {
        expect(v).toMatch(UUID_V4_RE);
        out.add(v);
      }
    }
    expect(out.size).toBe(1000);
  });
  // RFC 4122 Appendix B reference vectors (and independently recomputed
  // sha1-based v5 digests) across both named-namespace aliases and a
  // literal-UUID namespace. Deterministic — same input always same output.
  it.each([
    ["dns", "python.org", "886313e1-3b8a-5372-9b90-0c9aee199e5d"],
    ["url", "http://python.org/", "4c565f0d-3f5a-5890-b41b-20cf47701c5e"],
    ["dns", "example.com", "cfbff0d1-9375-5685-968c-48ce8b15ae17"],
    ["dns", "www.example.com", "2ed6657d-e927-568b-95e1-2665a8aea6a2"],
    // namespace given as a literal UUID (the dns namespace UUID itself)
    [
      "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
      "python.org",
      "886313e1-3b8a-5372-9b90-0c9aee199e5d",
    ],
  ])("uuid-v5(%s, %s) === %s", (namespace, name, expected) => {
    const v = values({
      action: "generate",
      kind: "uuid-v5",
      namespace,
      name,
    })[0] as string;
    expect(v).toBe(expected);
    // version nibble is 5, variant nibble is RFC (8..b)
    expect(v[14]).toBe("5");
    expect("89ab").toContain(v[19]);
  });
  // Missing-arg permutations all error — neither namespace nor name may be
  // omitted. (empty-string name IS valid: only `name === undefined` is rejected.)
  it.each<[string, Partial<Args>]>([
    ["neither", { kind: "uuid-v5" }],
    ["no name", { kind: "uuid-v5", namespace: "dns" }],
    ["no namespace", { kind: "uuid-v5", name: "x" }],
  ])("uuid-v5 rejects %s", (_label, extra) => {
    expect(run({ action: "generate", ...extra }).isError).toBe(true);
  });
  it("uuid-v5 accepts an empty-string name (only undefined is rejected)", () => {
    const v = values({
      action: "generate",
      kind: "uuid-v5",
      namespace: "dns",
      name: "",
    })[0] as string;
    expect(v).toMatch(new RegExp(UUID_V4_RE.source.replace("-4", "-5")));
    expect(v[14]).toBe("5");
  });
  it("uuid-v7 has version 7 and an embedded timestamp near now", () => {
    const v = values({ action: "generate", kind: "uuid-v7" })[0] as string;
    expect(v[14]).toBe("7");
    const details = inspect(v);
    const ts = Date.parse(details.timestamp as string);
    expect(Math.abs(ts - Date.now())).toBeLessThan(5000);
  });
});

describe("id: generate other kinds", () => {
  it("ulid is 26 chars and inspectable", () => {
    const v = values({ action: "generate", kind: "ulid" })[0] as string;
    expect(v).toHaveLength(26);
    const details = inspect(v);
    expect(details.kind).toBe("ulid");
    expect(
      Math.abs(Date.parse(details.timestamp as string) - Date.now()),
    ).toBeLessThan(5000);
  });
  // nanoid / random-string honour both length and a custom alphabet across
  // a range of lengths and alphabets (each output char must come from it).
  it.each<["nanoid" | "random-string", number, string]>([
    ["nanoid", 1, "abc123"],
    ["nanoid", 10, "abc123"],
    ["nanoid", 64, "ABCDEF0123456789"],
    ["random-string", 1, "xyz"],
    ["random-string", 50, "xyz"],
    ["random-string", 200, "0123456789abcdef"],
  ])(
    "%s(length=%i, alphabet=%s) draws only from the alphabet",
    (kind, length, alphabet) => {
      const v = values({
        action: "generate",
        kind,
        length,
        alphabet,
      })[0] as string;
      expect([...v]).toHaveLength(length);
      expect([...v].every((c) => alphabet.includes(c))).toBe(true);
    },
  );
  // random-bytes: hex is 2 chars/byte, base64 is ceil(n/3)*4 (with padding).
  it.each<[number, "hex", number]>([
    [1, "hex", 2],
    [16, "hex", 32],
    [32, "hex", 64],
    [64, "hex", 128],
  ])("random-bytes(%i, hex) is %i hex chars", (length, _enc, expectedLen) => {
    const v = values({
      action: "generate",
      kind: "random-bytes",
      length,
      outputEncoding: "hex",
    })[0] as string;
    expect(v).toHaveLength(expectedLen);
    expect(v).toMatch(/^[0-9a-f]+$/);
  });
  it.each<[number, number]>([
    [3, 4],
    [16, 24],
    [32, 44],
    [33, 44],
  ])("random-bytes(%i, base64) is %i base64 chars", (length, expectedLen) => {
    const v = values({
      action: "generate",
      kind: "random-bytes",
      length,
      outputEncoding: "base64",
    })[0] as string;
    expect(v).toHaveLength(expectedLen);
    expect(v).toMatch(/^[A-Za-z0-9+/]+=*$/);
  });
  // password: across a range of lengths, every enabled class is present and
  // the length is exact. Repeat each so the resample loop is exercised.
  it.each([4, 8, 12, 20, 64])(
    "password(length=%i) contains every enabled class",
    (length) => {
      for (let i = 0; i < 20; i++) {
        const v = values({
          action: "generate",
          kind: "password",
          length,
        })[0] as string;
        expect(v).toHaveLength(length);
        expect(v).toMatch(/[a-z]/);
        expect(v).toMatch(/[A-Z]/);
        expect(v).toMatch(/[0-9]/);
        expect(v).toMatch(/[!@#$%^&*()\-_=+[\]{};:,.<>?]/);
      }
    },
  );
  it.each([1, 2, 5, 100])("count=%i returns that many values", (count) => {
    expect(values({ action: "generate", kind: "ulid", count })).toHaveLength(
      count,
    );
  });
  // count is capped at 100 by the schema; anything above must be rejected.
  it.each([0, -1, 101, 1000])("schema rejects count=%i", (count) => {
    expect(
      idSchema.safeParse({ action: "generate", kind: "ulid", count }).success,
    ).toBe(false);
  });
});

describe("id: inspect", () => {
  // One representative UUID per version nibble, plus a ULID. version comes
  // straight from the 13th hex char; these are fixed canonical strings.
  it.each<[string, number]>([
    ["2fac1234-31f8-11b4-a222-08002b34c003", 1],
    ["886313e1-3b8a-5372-9b90-0c9aee199e5d", 5],
    ["f47ac10b-58cc-4372-a567-0e02b2c3d479", 4],
    ["550e8400-e29b-41d4-a716-446655440000", 4],
    ["017f22e2-79b0-7cc3-98c4-dc0c0c07398f", 7],
  ])("identifies UUID %s as version %i", (value, version) => {
    expect(inspect(value)).toMatchObject({
      kind: "uuid",
      valid: true,
      version,
    });
  });
  // Only v1 and v7 carry an embedded timestamp; v4/v5 must NOT.
  it.each<[string, boolean]>([
    ["2fac1234-31f8-11b4-a222-08002b34c003", true], // v1 (2 Oct 1998)
    ["017f22e2-79b0-7cc3-98c4-dc0c0c07398f", true], // v7
    ["f47ac10b-58cc-4372-a567-0e02b2c3d479", false], // v4
    ["886313e1-3b8a-5372-9b90-0c9aee199e5d", false], // v5
  ])("timestamp presence for %s is %s", (value, hasTimestamp) => {
    const details = inspect(value);
    expect(typeof details.timestamp === "string").toBe(hasTimestamp);
  });
  // Variant nibble (19th hex char) → human label, across the full range.
  it.each<[string, string]>([
    ["886313e1-3b8a-5372-9b90-0c9aee199e5d", "RFC 4122/9562"], // 9
    ["f47ac10b-58cc-4372-a567-0e02b2c3d479", "RFC 4122/9562"], // a
    ["00000000-0000-4000-0000-000000000000", "NCS (reserved)"], // 0
    ["00000000-0000-4000-c000-000000000000", "Microsoft (reserved)"], // c
    ["00000000-0000-4000-e000-000000000000", "future (reserved)"], // e
  ])("classifies variant of %s as %s", (value, variant) => {
    expect(inspect(value).variant).toBe(variant);
  });
  // A range of clearly-invalid identifiers — each rejected with a reason.
  it.each([
    "not-an-id",
    "",
    "f47ac10b-58cc-4372-a567", // too short
    "f47ac10b58cc4372a5670e02b2c3d479", // no hyphens
    "g47ac10b-58cc-4372-a567-0e02b2c3d479", // non-hex char
    "f47ac10b-58cc-4372-a567-0e02b2c3d479-extra", // trailing
    "ILOVEILLEGAL0CHARSINULIDXX", // 26 chars but I/L/O/U not in Crockford
  ])("rejects garbage %j with a reason", (value) => {
    const details = inspect(value);
    expect(details.valid).toBe(false);
    expect(typeof details.reason).toBe("string");
    expect((details.reason as string).length).toBeGreaterThan(0);
  });
});

describe("id: errors", () => {
  // Degenerate alphabets (<2 distinct code points) are rejected for both
  // random-string and nanoid.
  it.each<["random-string" | "nanoid", string]>([
    ["random-string", ""],
    ["random-string", "a"],
    ["random-string", "aaa"], // dedupes to 1 distinct
    ["nanoid", ""],
    ["nanoid", "a"],
    ["nanoid", "zzz"],
  ])("%s rejects degenerate alphabet %j", (kind, alphabet) => {
    expect(
      run({ action: "generate", kind, alphabet, length: 10 }).isError,
    ).toBe(true);
  });
  // password length must be >= the number of enabled classes (4 by default).
  it.each([1, 2, 3])(
    "rejects password shorter than its classes (len=%i)",
    (length) => {
      expect(
        run({ action: "generate", kind: "password", length }).isError,
      ).toBe(true);
    },
  );
  it("password of exactly the class count succeeds (boundary, len=4)", () => {
    expect(
      run({ action: "generate", kind: "password", length: 4 }).isError,
    ).toBeFalsy();
  });
  it("generate without a kind errors", () => {
    expect(run({ action: "generate" }).isError).toBe(true);
  });
  it("inspect without a value errors", () => {
    expect(run({ action: "inspect" }).isError).toBe(true);
  });
});

describe("id: nanoid and random-string agree on alphabet validation", () => {
  it("random-string with astral (emoji) alphabet returns the requested code-point count", () => {
    const res = run({
      action: "generate",
      kind: "random-string",
      alphabet: "😀😁😂",
      length: 5,
    });
    expect(res.isError).toBeFalsy();
    const value = (res.structuredContent as { values: string[] })
      .values[0] as string;
    expect([...value]).toHaveLength(5);
  });

  it("nanoid with astral alphabet emits whole code points (no lone surrogates)", () => {
    const res = run({
      action: "generate",
      kind: "nanoid",
      alphabet: "😀😁",
      length: 5,
    });
    expect(res.isError).toBeFalsy();
    const value = (res.structuredContent as { values: string[] })
      .values[0] as string;
    expect([...value]).toHaveLength(5);
    // verify no half-surrogates
    for (let i = 0; i < value.length; i++) {
      const code = value.charCodeAt(i);
      if (code >= 0xd800 && code <= 0xdbff) {
        expect(value.charCodeAt(i + 1)).toBeGreaterThanOrEqual(0xdc00);
        expect(value.charCodeAt(i + 1)).toBeLessThanOrEqual(0xdfff);
        i++;
      } else {
        expect(code).not.toBeGreaterThanOrEqual(0xd800);
      }
    }
  });

  it("nanoid with custom alphabet supports lengths up to the advertised 1024 cap", () => {
    const res = run({
      action: "generate",
      kind: "nanoid",
      alphabet: "abc",
      length: 1024,
    });
    expect(res.isError).toBeFalsy();
    expect(
      ((res.structuredContent as { values: string[] }).values[0] as string)
        .length,
    ).toBe(1024);
  });

  it("nanoid with single-char alphabet is rejected (matches random-string)", () => {
    expect(
      run({
        action: "generate",
        kind: "nanoid",
        alphabet: "a",
        length: 10,
      }).isError,
    ).toBe(true);
  });

  it("nanoid with empty alphabet is rejected (matches random-string)", () => {
    expect(
      run({
        action: "generate",
        kind: "nanoid",
        alphabet: "",
        length: 10,
      }).isError,
    ).toBe(true);
  });

  it("nanoid with duplicate-char alphabet dedupes (matches random-string)", () => {
    // alphabet "aab" should behave as "ab" — each char ~uniform.
    const res = run({
      action: "generate",
      kind: "nanoid",
      alphabet: "aab",
      length: 200,
    });
    expect(res.isError).toBeFalsy();
    const value = (res.structuredContent as { values: string[] })
      .values[0] as string;
    const aCount = [...value].filter((c) => c === "a").length;
    // After dedup, 'a' should be roughly half (~100). The buggy non-deduped
    // distribution biased 'a' to ~2/3 (~133+).
    expect(aCount).toBeGreaterThan(70);
    expect(aCount).toBeLessThan(130);
  });
});

describe("id: boundary and option-validation guards", () => {
  it("action defaults to 'generate' — no need to pass it every call", () => {
    const res = run({
      action: undefined as unknown as "generate",
      kind: "uuid-v4",
    });
    expect(res.isError).toBeFalsy();
  });

  it("inspect accepts an array (batch)", () => {
    const res = run({
      action: "inspect",
      value: ["550e8400-e29b-41d4-a716-446655440000", "not-a-thing"],
    });
    expect(res.isError).toBeFalsy();
    const s = res.structuredContent as {
      results: Array<Record<string, unknown>>;
    };
    expect(s.results).toHaveLength(2);
    expect(s.results[0]?.valid).toBe(true);
    expect(s.results[1]?.valid).toBe(false);
  });

  it("inspect returns the canonical form", () => {
    const res = run({
      action: "inspect",
      value: "550E8400-E29B-41D4-A716-446655440000",
    });
    expect((res.structuredContent as { canonical: string }).canonical).toBe(
      "550e8400-e29b-41d4-a716-446655440000",
    );
  });

  it("random-bytes with base64 outputEncoding is shorter than with hex", () => {
    const hex = (
      run({
        action: "generate",
        kind: "random-bytes",
        length: 32,
        outputEncoding: "hex",
      }).structuredContent as { values: string[] }
    ).values[0] as string;
    const b64 = (
      run({
        action: "generate",
        kind: "random-bytes",
        length: 32,
        outputEncoding: "base64",
      }).structuredContent as { values: string[] }
    ).values[0] as string;
    expect(hex).toHaveLength(64);
    expect(b64.length).toBeLessThan(hex.length);
  });
});

describe("id: supported-kind contract", () => {
  // Locks the exact set of `kind`s the tool actually generates. This is the
  // authority — the SKILL catalog claims "UUIDv1 / v4 / v6 / v7 … short ids",
  // but v1, v6 and "short" are NOT implemented. If a kind is added or removed,
  // this test (and the skill catalog) must be updated together.
  const SUPPORTED: Array<[string, Partial<Args>]> = [
    ["uuid-v4", { kind: "uuid-v4" }],
    ["uuid-v5", { kind: "uuid-v5", namespace: "dns", name: "x" }],
    ["uuid-v7", { kind: "uuid-v7" }],
    ["ulid", { kind: "ulid" }],
    ["nanoid", { kind: "nanoid" }],
    ["random-bytes", { kind: "random-bytes", length: 8 }],
    ["password", { kind: "password", length: 12 }],
  ];

  it.each(SUPPORTED)("generates kind=%s", (_label, extra) => {
    const out = values({ action: "generate", ...extra });
    expect(out).toHaveLength(1);
    expect(typeof out[0]).toBe("string");
    expect((out[0] as string).length).toBeGreaterThan(0);
  });

  // Kinds the docs imply but that don't exist — the schema must reject them,
  // not silently accept. (If you implement one, move it into SUPPORTED above.)
  it.each(["uuid-v1", "uuid-v6", "uuid-v3", "short", "cuid"])(
    "schema rejects unimplemented kind=%s",
    (kind) => {
      const parsed = idSchema.safeParse({ action: "generate", kind });
      expect(parsed.success, `${kind} should be rejected by the schema`).toBe(
        false,
      );
    },
  );
});
