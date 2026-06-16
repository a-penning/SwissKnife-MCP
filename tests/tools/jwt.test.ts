import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { exportPKCS8, exportSPKI, generateKeyPair } from "jose";
import { describe, expect, it } from "vitest";
import { jwtTool } from "../../src/tools/jwt.js";

type Args = Parameters<typeof jwtTool.handler>[0];

async function run(args: Partial<Args>): Promise<CallToolResult> {
  return (await jwtTool.handler({
    algorithm: "HS256",
    ...args,
  } as Args)) as CallToolResult;
}

function structured(res: CallToolResult): Record<string, unknown> {
  expect(res.isError, JSON.stringify(res.content)).toBeFalsy();
  return res.structuredContent as Record<string, unknown>;
}

// jwt.io reference token, secret "your-256-bit-secret"
const KNOWN_TOKEN =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
  "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
  "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
const KNOWN_SECRET = "your-256-bit-secret";

describe("jwt: decode", () => {
  it("decodes header, payload, and derived claims without verification", async () => {
    const out = structured(await run({ action: "decode", input: KNOWN_TOKEN }));
    expect(out.header).toEqual({ alg: "HS256", typ: "JWT" });
    expect((out.payload as Record<string, unknown>).name).toBe("John Doe");
    const derived = out.derived as Record<string, unknown>;
    expect(derived.issuedAt).toBe("2018-01-18T01:30:22.000Z");
    expect(out.verified).toBe(false);
  });
  it("flags expired tokens but still decodes them", async () => {
    const signed = structured(
      await run({
        action: "sign",
        key: "k",
        payload: { sub: "x", exp: 1000000000 }, // 2001
      }),
    );
    const out = structured(
      await run({ action: "decode", input: signed.token as string }),
    );
    expect((out.derived as Record<string, unknown>).expired).toBe(true);
  });
  // A range of inputs that are not 3-part JWS compact tokens — each is a
  // hard error (decode never silently coerces).
  it.each([
    "definitely.not", // 2 parts
    "one-part-only", // 1 part
    "a.b.c.d", // 4 parts
    "", // empty
    "....", // 5 empty parts
  ])("rejects non-JWT input %j with an error", async (input) => {
    expect((await run({ action: "decode", input })).isError).toBe(true);
  });
});

describe("jwt: verify (HMAC)", () => {
  // HS256/384/512 round-trip: sign with each then verify with the right
  // secret succeeds and surfaces the algorithm in the verified header.
  it.each([
    "HS256",
    "HS384",
    "HS512",
  ])("%s round-trips: sign then verify with the right secret", async (algorithm) => {
    const signed = structured(
      await run({
        action: "sign",
        algorithm,
        key: "round-trip-secret",
        payload: { sub: "rt" },
      }),
    );
    const out = structured(
      await run({
        action: "verify",
        input: signed.token as string,
        key: "round-trip-secret",
      }),
    );
    expect(out.valid).toBe(true);
    expect((out.header as Record<string, unknown>).alg).toBe(algorithm);
    expect((out.payload as Record<string, unknown>).sub).toBe("rt");
  });
  // Wrong secret → invalid with a signature failure reason, across algs.
  it.each([
    "HS256",
    "HS384",
    "HS512",
  ])("%s with the WRONG secret is invalid", async (algorithm) => {
    const signed = structured(
      await run({
        action: "sign",
        algorithm,
        key: "correct-secret",
        payload: { sub: "rt" },
      }),
    );
    const out = structured(
      await run({
        action: "verify",
        input: signed.token as string,
        key: "wrong-secret",
      }),
    );
    expect(out.valid).toBe(false);
    expect(typeof out.failureReason).toBe("string");
  });
  it("verifies the known token with the right secret", async () => {
    const out = structured(
      await run({ action: "verify", input: KNOWN_TOKEN, key: KNOWN_SECRET }),
    );
    expect(out.valid).toBe(true);
    expect((out.payload as Record<string, unknown>).sub).toBe("1234567890");
  });
  it("reports tampered signatures as invalid with a reason", async () => {
    const tampered = `${KNOWN_TOKEN.slice(0, -2)}xx`;
    const out = structured(
      await run({ action: "verify", input: tampered, key: KNOWN_SECRET }),
    );
    expect(out.valid).toBe(false);
    expect(String(out.failureReason)).toMatch(/signature/i);
  });
  it("reports expiry with a reason", async () => {
    const signed = structured(
      await run({
        action: "sign",
        key: "k",
        payload: { sub: "x", exp: 1000000000 },
      }),
    );
    const out = structured(
      await run({ action: "verify", input: signed.token as string, key: "k" }),
    );
    expect(out.valid).toBe(false);
    expect(String(out.failureReason)).toMatch(/exp/i);
  });
  // Audience matching: matching aud (string or array member) → valid;
  // mismatching → invalid with an aud reason.
  it.each<[string, string | string[], boolean]>([
    ["service-a", "service-a", true],
    ["service-a", "service-b", false],
    ["service-a", ["service-a", "service-c"], true],
    ["service-a", ["service-b", "service-c"], false],
  ])("aud=%s vs expected=%j → valid:%s", async (aud, expected, shouldBeValid) => {
    const signed = structured(
      await run({ action: "sign", key: "k", payload: { aud } }),
    );
    const out = structured(
      await run({
        action: "verify",
        input: signed.token as string,
        key: "k",
        audience: expected,
      }),
    );
    expect(out.valid).toBe(shouldBeValid);
    if (!shouldBeValid) expect(String(out.failureReason)).toMatch(/aud/i);
  });
  // Issuer matching: matching iss → valid, mismatching → invalid with reason.
  it.each<[string, string, boolean]>([
    ["https://issuer.example", "https://issuer.example", true],
    ["https://issuer.example", "https://other.example", false],
  ])("iss=%s vs expected=%s → valid:%s", async (iss, expected, shouldBeValid) => {
    const signed = structured(
      await run({ action: "sign", key: "k", payload: { iss } }),
    );
    const out = structured(
      await run({
        action: "verify",
        input: signed.token as string,
        key: "k",
        issuer: expected,
      }),
    );
    expect(out.valid).toBe(shouldBeValid);
    if (!shouldBeValid) expect(String(out.failureReason)).toMatch(/iss/i);
  });
  // exp / nbf time-window checks: a token valid only in the past (exp) or
  // only in the future (nbf) is rejected; one inside the window is accepted.
  it.each<[string, Record<string, unknown>, boolean, RegExp]>([
    ["expired", { exp: 1_000_000_000 }, false, /exp/i], // year 2001
    [
      "not-yet-valid",
      { nbf: Math.floor(Date.now() / 1000) + 86_400 },
      false,
      /nbf|not.*before|jwt.*not.*active/i,
    ],
    [
      "within window",
      {
        nbf: Math.floor(Date.now() / 1000) - 60,
        exp: Math.floor(Date.now() / 1000) + 3600,
      },
      true,
      /.*/,
    ],
  ])("time window %s → valid:%s", async (_label, claims, shouldBeValid, re) => {
    const signed = structured(
      await run({ action: "sign", key: "k", payload: { sub: "x", ...claims } }),
    );
    const out = structured(
      await run({
        action: "verify",
        input: signed.token as string,
        key: "k",
      }),
    );
    expect(out.valid).toBe(shouldBeValid);
    if (!shouldBeValid) expect(String(out.failureReason)).toMatch(re);
  });
});

describe("jwt: asymmetric algorithms via PEM", () => {
  // One representative alg per family: RSA (RS/PS), EC (ES), Edwards (EdDSA).
  // Each: sign with PKCS8 private key, verify with SPKI public key → valid;
  // verify against a DIFFERENT keypair's public key → invalid.
  const ALGS = ["RS256", "RS384", "PS256", "ES256", "ES384", "EdDSA"];
  it.each(
    ALGS,
  )("%s signs with PKCS8 and verifies with the matching SPKI key", async (algorithm) => {
    const { publicKey, privateKey } = await generateKeyPair(algorithm, {
      extractable: true,
    });
    const signed = structured(
      await run({
        action: "sign",
        algorithm,
        key: await exportPKCS8(privateKey),
        payload: { sub: `${algorithm}-user` },
        expiresIn: "1h",
      }),
    );
    const out = structured(
      await run({
        action: "verify",
        input: signed.token as string,
        key: await exportSPKI(publicKey),
      }),
    );
    expect(out.valid).toBe(true);
    expect((out.payload as Record<string, unknown>).sub).toBe(
      `${algorithm}-user`,
    );
  });
  it.each(
    ALGS,
  )("%s token verified against the WRONG keypair is invalid", async (algorithm) => {
    const a = await generateKeyPair(algorithm, { extractable: true });
    const b = await generateKeyPair(algorithm, { extractable: true });
    const signed = structured(
      await run({
        action: "sign",
        algorithm,
        key: await exportPKCS8(a.privateKey),
        payload: { sub: "x" },
      }),
    );
    const out = structured(
      await run({
        action: "verify",
        input: signed.token as string,
        key: await exportSPKI(b.publicKey),
      }),
    );
    expect(out.valid).toBe(false);
  });
});

describe("jwt: verify contract — never throws past valid:false", () => {
  // A range of structurally-wrong tokens — none throws; all return
  // valid:false with a part-count reason.
  it.each([
    "abc.def",
    "single",
    "a.b.c.d",
    "",
    ".....",
  ])("returns valid:false (not a thrown error) for %j", async (input) => {
    const out = structured(
      await run({ action: "verify", input, key: "secret" }),
    );
    expect(out.valid).toBe(false);
    expect(String(out.failureReason)).toMatch(/3 dot-separated parts/);
  });

  it("returns valid:false for garbage PEM key", async () => {
    const res = await run({
      action: "verify",
      input: KNOWN_TOKEN,
      key: "-----BEGIN PUBLIC KEY-----\ngarbage\n-----END PUBLIC KEY-----",
    });
    expect(res.isError).toBeFalsy();
    expect((res.structuredContent as { valid: boolean }).valid).toBe(false);
  });

  it("returns valid:false (with parse hint) for invalid JWK JSON", async () => {
    const out = structured(
      await run({
        action: "verify",
        input: KNOWN_TOKEN,
        key: "{not valid json",
      }),
    );
    expect(out.valid).toBe(false);
    expect(String(out.failureReason)).toMatch(/JWK/);
  });

  it("trims surrounding whitespace before verifying", async () => {
    const out = structured(
      await run({
        action: "verify",
        input: `  ${KNOWN_TOKEN}  `,
        key: KNOWN_SECRET,
      }),
    );
    expect(out.valid).toBe(true);
  });

  it("rejects alg:none with a policy-specific reason, not an internal type error", async () => {
    // header {alg:none,typ:JWT}, payload {sub:x}, empty signature
    const algNone = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ4In0.";
    const out = structured(
      await run({ action: "verify", input: algNone, key: "secret" }),
    );
    expect(out.valid).toBe(false);
    expect(String(out.failureReason)).toMatch(/none/i);
    expect(String(out.failureReason)).not.toMatch(/TypeError/);
  });
});

describe("jwt: decode flags malformed exp", () => {
  it("emits expWarning when exp is present but not a NumericDate", async () => {
    // header {alg:HS256,typ:JWT}, payload {sub:x, exp:"9999"} (string)
    const bad =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
      "eyJzdWIiOiJ4IiwiZXhwIjoiOTk5OSJ9." +
      "x";
    const out = structured(await run({ action: "decode", input: bad }));
    const derived = out.derived as Record<string, unknown>;
    expect(derived.expired).toBe(false);
    expect(String(derived.expWarning)).toMatch(/NumericDate/);
  });
});

describe("jwt: sign honours the algorithm param", () => {
  it("rejects a conflicting header.alg instead of silently using it", async () => {
    const res = await run({
      action: "sign",
      key: "secret",
      payload: { sub: "x" },
      algorithm: "HS256",
      header: { alg: "HS512" },
    });
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res.content)).toMatch(/conflicts with algorithm/);
  });

  it("structured algorithm field matches the actually-used algorithm", async () => {
    const signed = structured(
      await run({
        action: "sign",
        key: "secret",
        payload: { sub: "x" },
        algorithm: "HS512",
      }),
    );
    expect(signed.algorithm).toBe("HS512");
    const decoded = structured(
      await run({ action: "decode", input: signed.token as string }),
    );
    expect((decoded.header as Record<string, unknown>).alg).toBe("HS512");
  });
});

describe("jwt: sign", () => {
  it("produces a token that decodes with expected claims and iat", async () => {
    const signed = structured(
      await run({
        action: "sign",
        key: "secret",
        payload: { role: "admin" },
        expiresIn: "2h",
      }),
    );
    const out = structured(
      await run({ action: "decode", input: signed.token as string }),
    );
    const payload = out.payload as Record<string, unknown>;
    expect(payload.role).toBe("admin");
    expect(typeof payload.iat).toBe("number");
    expect(typeof payload.exp).toBe("number");
    expect((out.derived as Record<string, unknown>).expired).toBe(false);
  });
  // sign needs BOTH key and payload — each missing-arg permutation errors.
  it.each<[string, Partial<Args>]>([
    ["no payload", { action: "sign", payload: {} }],
    ["no key", { action: "sign", key: "k" }],
    ["neither", { action: "sign" }],
  ])("requires key and payload (%s)", async (_label, args) => {
    expect((await run(args)).isError).toBe(true);
  });
  // expiresIn values round-trip into a consistent exp/iat delta.
  it.each<[string, number]>([
    ["60s", 60],
    ["5m", 300],
    ["2h", 7200],
    ["1d", 86_400],
  ])("expiresIn=%s sets exp ~%i seconds after iat", async (expiresIn, secs) => {
    const signed = structured(
      await run({ action: "sign", key: "k", payload: { sub: "x" }, expiresIn }),
    );
    const decoded = structured(
      await run({ action: "decode", input: signed.token as string }),
    );
    const p = decoded.payload as Record<string, number>;
    expect((p.exp as number) - (p.iat as number)).toBe(secs);
  });
});

describe("jwt: algorithm-confusion and claim-validation guards", () => {
  it("verify returns the same `derived` block decode does (no second round-trip)", async () => {
    const signed = structured(
      await run({
        action: "sign",
        key: KNOWN_SECRET,
        payload: { sub: "x" },
        expiresIn: "2h",
      }),
    );
    const out = structured(
      await run({
        action: "verify",
        input: signed.token as string,
        key: KNOWN_SECRET,
      }),
    );
    expect(out.valid).toBe(true);
    const d = out.derived as Record<string, unknown>;
    expect(typeof d.issuedAt).toBe("string");
    expect(typeof d.expiresAt).toBe("string");
    expect(d.expired).toBe(false);
    expect(typeof d.secondsUntilExpiry).toBe("number");
  });

  it("decode trims surrounding whitespace before parsing (no confusing jose error)", async () => {
    const out = structured(
      await run({ action: "decode", input: `  ${KNOWN_TOKEN}\n` }),
    );
    expect((out.header as Record<string, unknown>).alg).toBe("HS256");
  });

  it("sign rejects both expiresIn AND payload.exp (silent overwrite is now an error)", async () => {
    const res = await run({
      action: "sign",
      key: "k",
      payload: { sub: "x", exp: Math.floor(Date.now() / 1000) + 1000 },
      expiresIn: "2h",
    });
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res.content)).toMatch(/expiresIn conflicts/);
  });

  it("verify rejects a token whose header has no alg (was silently falling back to RS256)", async () => {
    // Build a token with empty header — { } base64url-encoded.
    const headerB64 = Buffer.from("{}").toString("base64url");
    const payloadB64 = Buffer.from(JSON.stringify({ sub: "x" })).toString(
      "base64url",
    );
    const fake = `${headerB64}.${payloadB64}.signature`;
    const out = structured(
      await run({ action: "verify", input: fake, key: "k" }),
    );
    expect(out.valid).toBe(false);
    expect(String(out.failureReason)).toMatch(/missing the .alg/);
  });

  it("sign rejects SEC1-form EC private keys with a conversion hint", async () => {
    const sec1 =
      "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEE\n-----END EC PRIVATE KEY-----";
    const res = await run({
      action: "sign",
      algorithm: "ES256",
      key: sec1,
      payload: { sub: "x" },
    });
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res.content)).toMatch(/PKCS8.*openssl pkcs8/);
  });

  it("verify accepts an audience array (multi-tenant tokens)", async () => {
    const signed = structured(
      await run({
        action: "sign",
        key: "k",
        payload: { sub: "x", aud: "tenant-2" },
      }),
    );
    const out = structured(
      await run({
        action: "verify",
        input: signed.token as string,
        key: "k",
        audience: ["tenant-1", "tenant-2", "tenant-3"],
      }),
    );
    expect(out.valid).toBe(true);
  });

  it("sign response includes issuedAt / expiresAt ISO strings", async () => {
    const out = structured(
      await run({
        action: "sign",
        key: "k",
        payload: { sub: "x" },
        expiresIn: "5m",
      }),
    );
    expect(typeof out.issuedAt).toBe("string");
    expect(typeof out.expiresAt).toBe("string");
  });
});
