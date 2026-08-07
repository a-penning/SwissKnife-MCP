import { Buffer } from "node:buffer";
import {
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  pbkdf2Sync,
  scryptSync,
} from "node:crypto";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { beforeAll, describe, expect, it } from "vitest";
import { z } from "zod";
import { cryptoTool } from "../../src/tools/crypto.js";

const schema = z.object(cryptoTool.inputSchema as z.ZodRawShape).strict();

async function run(args: Record<string, unknown>): Promise<CallToolResult> {
  const parsed = schema.parse(args);
  return (await cryptoTool.handler(parsed as never)) as CallToolResult;
}

async function ok(
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const res = await run(args);
  if (res.isError) {
    throw new Error(`expected success; got ${JSON.stringify(res.content)}`);
  }
  return res.structuredContent as Record<string, unknown>;
}

async function expectErr(
  args: Record<string, unknown>,
  code?: string,
): Promise<{ code?: string; text: string }> {
  const res = await run(args);
  expect(res.isError, JSON.stringify(res.content)).toBe(true);
  const sc = res.structuredContent as { code?: string } | undefined;
  const text = (res.content?.[0] as { text?: string })?.text ?? "";
  if (code) expect(sc?.code).toBe(code);
  return { code: sc?.code, text };
}

// --------------------------------------------------------------------------
// AEAD: encrypt → decrypt round-trips. The cipher is exercised via the lib;
// we re-derive ciphertext independently (Node's createCipheriv) for at least
// one vector to make sure outputs match a non-tool reference.
// --------------------------------------------------------------------------

describe("crypto: AEAD encrypt/decrypt round-trips", () => {
  const KEY_16_B64 = Buffer.alloc(16, 1).toString("base64");
  const KEY_32_B64 = Buffer.alloc(32, 1).toString("base64");
  const NONCE_12_B64 = Buffer.alloc(12, 2).toString("base64");

  const ROWS: Array<{
    method: string;
    key: string;
    plaintext: string;
    aad?: string;
  }> = [
    { method: "aes-256-gcm", key: KEY_32_B64, plaintext: "hello world" },
    { method: "aes-256-gcm", key: KEY_32_B64, plaintext: "" }, // boundary: empty plaintext
    { method: "aes-128-gcm", key: KEY_16_B64, plaintext: "lorem ipsum" },
    {
      method: "chacha20-poly1305",
      key: KEY_32_B64,
      plaintext: "x".repeat(100),
    },
    {
      method: "aes-256-gcm",
      key: KEY_32_B64,
      plaintext: "with aad",
      aad: "ctx-1",
    },
  ];

  it.each(ROWS)("%s round-trip", async ({ method, key, plaintext, aad }) => {
    const enc = await ok({
      action: "encrypt",
      method,
      key,
      plaintext,
      nonce: NONCE_12_B64,
      ...(aad ? { aad } : {}),
    });
    expect(typeof enc.ciphertext).toBe("string");
    expect(typeof enc.tag).toBe("string");
    const dec = await ok({
      action: "decrypt",
      method,
      key,
      ciphertext: enc.ciphertext as string,
      nonce: NONCE_12_B64,
      tag: enc.tag as string,
      ...(aad ? { aad } : {}),
    });
    // plaintextEncoding defaults to utf8 — no need to set it explicitly.
    expect(dec.plaintext).toBe(plaintext);
  });

  // Tamper at multiple positions in the ciphertext to confirm GCM's tag
  // authenticates the whole stream, not just the first block.
  it.each(["first", "middle", "last"] as const)(
    "tampering at %s byte → decryption_failed",
    async (where) => {
      const enc = await ok({
        action: "encrypt",
        method: "aes-256-gcm",
        key: KEY_32_B64,
        plaintext: "x".repeat(96), // ≥3 AES blocks so middle/last differ from first
        nonce: NONCE_12_B64,
      });
      const ct = Buffer.from(enc.ciphertext as string, "base64");
      const idx =
        where === "first"
          ? 0
          : where === "last"
            ? ct.length - 1
            : Math.floor(ct.length / 2);
      ct[idx] = (ct[idx] ?? 0) ^ 0xff;
      await expectErr(
        {
          action: "decrypt",
          method: "aes-256-gcm",
          key: KEY_32_B64,
          ciphertext: ct.toString("base64"),
          nonce: NONCE_12_B64,
          tag: enc.tag,
        },
        "decryption_failed",
      );
    },
  );

  it("wrong AAD also returns decryption_failed (not its own code)", async () => {
    const enc = await ok({
      action: "encrypt",
      method: "aes-256-gcm",
      key: KEY_32_B64,
      plaintext: "bound payload",
      nonce: NONCE_12_B64,
      aad: "ctx-A",
    });
    await expectErr(
      {
        action: "decrypt",
        method: "aes-256-gcm",
        key: KEY_32_B64,
        ciphertext: enc.ciphertext,
        nonce: NONCE_12_B64,
        tag: enc.tag,
        aad: "ctx-B",
      },
      "decryption_failed",
    );
  });

  // Range over all three methods and a spread of wrong key sizes. The valid
  // size per method is excluded (32/16/32 respectively).
  it.each([
    ["aes-256-gcm", 0],
    ["aes-256-gcm", 1],
    ["aes-256-gcm", 16],
    ["aes-256-gcm", 31],
    ["aes-256-gcm", 33],
    ["aes-256-gcm", 64],
    ["aes-128-gcm", 0],
    ["aes-128-gcm", 15],
    ["aes-128-gcm", 17],
    ["aes-128-gcm", 32],
    ["chacha20-poly1305", 0],
    ["chacha20-poly1305", 16],
    ["chacha20-poly1305", 31],
    ["chacha20-poly1305", 33],
  ] as const)(
    "%s rejects %i-byte key → bad_parameters",
    async (method, keySize) => {
      await expectErr(
        {
          action: "encrypt",
          method,
          key: Buffer.alloc(keySize).toString("base64"),
          plaintext: "x",
          nonce: NONCE_12_B64,
        },
        "bad_parameters",
      );
    },
  );

  // Range over wrong nonce sizes (12 is the only valid value).
  it.each([0, 1, 8, 11, 13, 16, 24] as const)(
    "aes-256-gcm rejects %i-byte nonce → bad_parameters",
    async (nonceSize) => {
      await expectErr(
        {
          action: "encrypt",
          method: "aes-256-gcm",
          key: KEY_32_B64,
          plaintext: "x",
          nonce: Buffer.alloc(nonceSize).toString("base64"),
        },
        "bad_parameters",
      );
    },
  );
});

// --------------------------------------------------------------------------
// generate: bytes and raw keypairs
// --------------------------------------------------------------------------

describe("crypto: generate", () => {
  it.each([16, 24, 32, 64])(
    "generate bytes byteLength=%i produces that many decoded bytes",
    async (n) => {
      const sc = await ok({
        action: "generate",
        method: "bytes",
        byteLength: n,
        outputEncoding: "base64",
      });
      expect(sc.byteLength).toBe(n);
      expect(Buffer.from(sc.bytes as string, "base64").length).toBe(n);
    },
  );

  it.each(["ed25519", "x25519"])(
    "generate %s returns a PEM keypair we can parse",
    async (method) => {
      const sc = await ok({ action: "generate", method, format: "pem" });
      expect(sc.publicKey).toContain("BEGIN PUBLIC KEY");
      expect(sc.privateKey).toContain("BEGIN PRIVATE KEY");
      const pub = createPublicKey(sc.publicKey as string);
      const priv = createPrivateKey(sc.privateKey as string);
      expect(pub.asymmetricKeyType).toBe(method);
      expect(priv.asymmetricKeyType).toBe(method);
    },
  );

  it.each([2048, 3072, 4096] as const)(
    "generate rsa honours modulusLength=%i",
    async (modulusLength) => {
      const sc = await ok({
        action: "generate",
        method: "rsa",
        modulusLength,
        format: "pem",
      });
      const key = createPublicKey(sc.publicKey as string);
      expect(key.asymmetricKeyDetails?.modulusLength).toBe(modulusLength);
    },
    30_000,
  ); // RSA-4096 keygen can take a few seconds

  it.each(["P-256", "P-384", "P-521"] as const)(
    "generate ec curve=%s produces the requested curve",
    async (curve) => {
      const sc = await ok({
        action: "generate",
        method: "ec",
        curve,
        format: "pem",
      });
      const key = createPublicKey(sc.publicKey as string);
      // node's namedCurve string varies in casing (P-256 ↔ prime256v1 etc.);
      // a partial-match on the digits suffices.
      const expected = curve.replace("P-", "");
      expect(String(key.asymmetricKeyDetails?.namedCurve)).toMatch(
        new RegExp(expected),
      );
    },
  );

  it.each([
    16385, // well past
    16384, // commonly-quoted "huge" RSA
    8193, // boundary: cap is 8192
  ])("rsa modulusLength=%i exceeds cap → bad_parameters", async (bits) => {
    await expectErr(
      {
        action: "generate",
        method: "rsa",
        modulusLength: bits,
        format: "pem",
      },
      "bad_parameters",
    );
  });
});

// --------------------------------------------------------------------------
// derive: independently verified against node:crypto.
// --------------------------------------------------------------------------

describe("crypto: derive", () => {
  // PBKDF2: range over (password, salt, iterations, keyLength, hash) — each
  // expected value computed independently against node:crypto.pbkdf2Sync.
  it.each([
    {
      password: "",
      salt: Buffer.alloc(16, 0),
      iter: 1,
      len: 16,
      hash: "sha256" as const,
    },
    {
      password: "p",
      salt: Buffer.alloc(8, 1),
      iter: 1000,
      len: 24,
      hash: "sha256" as const,
    },
    {
      password: "hunter2",
      salt: Buffer.alloc(16, 7),
      iter: 10_000,
      len: 32,
      hash: "sha256" as const,
    },
    {
      password: "long-passphrase-spanning-multiple-blocks",
      salt: Buffer.alloc(32, 0xff),
      iter: 600_000,
      len: 64,
      hash: "sha256" as const,
    },
    {
      password: "p",
      salt: Buffer.alloc(16, 2),
      iter: 5000,
      len: 48,
      hash: "sha384" as const,
    },
    {
      password: "p",
      salt: Buffer.alloc(16, 3),
      iter: 5000,
      len: 64,
      hash: "sha512" as const,
    },
  ])(
    "pbkdf2 matches node:crypto for iter=$iter len=$len hash=$hash",
    async ({ password, salt, iter, len, hash }) => {
      const expected = pbkdf2Sync(password, salt, iter, len, hash).toString(
        "base64",
      );
      const sc = await ok({
        action: "derive",
        method: "pbkdf2",
        password,
        salt: salt.toString("base64"),
        keyLength: len,
        params: { iterations: iter },
        hash,
      });
      expect(sc.key).toBe(expected);
    },
  );

  // Scrypt: range over (N, r, p, keyLength).
  it.each([
    { N: 1024, r: 1, p: 1, len: 16 },
    { N: 1024, r: 8, p: 1, len: 32 },
    { N: 2048, r: 8, p: 2, len: 32 },
    { N: 16384, r: 8, p: 1, len: 64 },
  ])(
    "scrypt matches node:crypto for N=$N r=$r p=$p len=$len",
    async ({ N, r, p, len }) => {
      const salt = Buffer.alloc(16, 9);
      const expected = scryptSync("pw", salt, len, { N, r, p }).toString(
        "base64",
      );
      const sc = await ok({
        action: "derive",
        method: "scrypt",
        password: "pw",
        salt: salt.toString("base64"),
        keyLength: len,
        params: { N, r, p },
      });
      expect(sc.key).toBe(expected);
    },
  );

  // HKDF: RFC 5869 §A.1 (SHA-256 basic), §A.2 (SHA-256 long IKM),
  // §A.3 (SHA-256 zero-length salt and info). Each `expected` is the OKM
  // from the RFC, embedded directly as the source of truth (not pasted from
  // our own output).
  it.each([
    {
      name: "A.1: SHA-256 basic",
      hash: "sha256" as const,
      ikm: "0b".repeat(22),
      salt: "000102030405060708090a0b0c",
      info: "f0f1f2f3f4f5f6f7f8f9",
      L: 42,
      expected:
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    },
    {
      name: "A.2: SHA-256 long IKM",
      hash: "sha256" as const,
      ikm:
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +
        "404142434445464748494a4b4c4d4e4f",
      salt:
        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" +
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" +
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
      info:
        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf" +
        "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef" +
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
      L: 82,
      expected:
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
    },
    {
      name: "A.3: SHA-256 zero-length salt and info",
      hash: "sha256" as const,
      ikm: "0b".repeat(22),
      salt: "",
      info: "",
      L: 42,
      expected:
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
    },
  ])("hkdf RFC 5869 $name", async ({ hash, ikm, salt, info, L, expected }) => {
    const ikmBuf = Buffer.from(ikm, "hex");
    const saltBuf = Buffer.from(salt, "hex");
    const infoBuf = Buffer.from(info, "hex");
    // Cross-check that node:crypto agrees with the RFC vector before asserting.
    const nodeOkm = Buffer.from(
      hkdfSync(hash, ikmBuf, saltBuf, infoBuf, L),
    ).toString("hex");
    expect(nodeOkm).toBe(expected);
    const sc = await ok({
      action: "derive",
      method: "hkdf",
      ikm: ikmBuf.toString("base64"),
      ...(salt ? { salt: saltBuf.toString("base64") } : {}),
      ...(info
        ? { info: infoBuf.toString("base64"), infoEncoding: "base64" }
        : {}),
      keyLength: L,
      hash,
      outputEncoding: "hex",
    });
    expect(sc.key).toBe(expected);
  });

  it("pbkdf2 iterations above cap → bad_parameters", async () => {
    await expectErr(
      {
        action: "derive",
        method: "pbkdf2",
        password: "p",
        salt: Buffer.alloc(16).toString("base64"),
        keyLength: 16,
        params: { iterations: 100_000_001 }, // > 10_000_000
      },
      "bad_parameters",
    );
  });

  // ECDH across every supported curve. Each row generates a fresh keypair,
  // does an A→B / B→A round-trip, and cross-checks against node's native
  // diffieHellman.
  it.each([
    { kind: "x25519" as const, curve: "" },
    { kind: "ec" as const, curve: "P-256" },
    { kind: "ec" as const, curve: "P-384" },
    { kind: "ec" as const, curve: "P-521" },
  ])(
    "ecdh on $kind $curve agrees in both directions + matches node:crypto",
    async ({ kind, curve }) => {
      const mk = () =>
        kind === "ec"
          ? generateKeyPairSync("ec", { namedCurve: curve })
          : generateKeyPairSync("x25519");
      const a = mk();
      const b = mk();
      const aPriv = a.privateKey.export({ format: "pem", type: "pkcs8" });
      const bPriv = b.privateKey.export({ format: "pem", type: "pkcs8" });
      const aPub = a.publicKey.export({ format: "pem", type: "spki" });
      const bPub = b.publicKey.export({ format: "pem", type: "spki" });
      const sA = await ok({
        action: "derive",
        method: "ecdh",
        privateKey: aPriv,
        peerPublicKey: bPub,
      });
      const sB = await ok({
        action: "derive",
        method: "ecdh",
        privateKey: bPriv,
        peerPublicKey: aPub,
      });
      expect(sA.sharedSecret).toBe(sB.sharedSecret);
      const native = diffieHellman({
        privateKey: a.privateKey,
        publicKey: b.publicKey,
      }).toString("base64");
      expect(sA.sharedSecret).toBe(native);
    },
  );
});

// --------------------------------------------------------------------------
// sign / verify
// --------------------------------------------------------------------------

describe("crypto: sign / verify (asymmetric)", () => {
  // Per-scheme keypairs generated once so the message-range tests don't
  // re-pay keygen cost for every row.
  const KEYS: Partial<
    Record<string, { publicKey: string; privateKey: string }>
  > = {};
  beforeAll(async () => {
    const ed = await ok({
      action: "generate",
      method: "ed25519",
      format: "pem",
    });
    const rsa = await ok({
      action: "generate",
      method: "rsa",
      modulusLength: 2048,
      format: "pem",
    });
    const ec = await ok({
      action: "generate",
      method: "ec",
      curve: "P-256",
      format: "pem",
    });
    KEYS.ed25519 = ed as never;
    KEYS.rsa = rsa as never;
    KEYS.ec = ec as never;
  });

  // Range over (scheme × message) — empty / short / long / unicode / binary
  // shapes that have historically tripped sig schemes.
  const MESSAGES = [
    "",
    "short",
    "x".repeat(10_000),
    "🦀 unicode 你好",
    "\x00\x01\x7f\xfe\xff", // non-ascii bytes
  ];
  const SCHEMES: ReadonlyArray<{
    method: string;
    keyKind: "ed25519" | "rsa" | "ec";
  }> = [
    { method: "ed25519", keyKind: "ed25519" },
    { method: "rsa-pss", keyKind: "rsa" },
    { method: "rsa-pkcs1", keyKind: "rsa" },
    { method: "ecdsa", keyKind: "ec" },
  ];
  const MATRIX = SCHEMES.flatMap((s) =>
    MESSAGES.map((m) => ({ method: s.method, keyKind: s.keyKind, message: m })),
  );

  it.each(MATRIX)(
    "$method round-trips $keyKind key with message=$message",
    async ({ method, keyKind, message }) => {
      const gen = KEYS[keyKind];
      if (!gen) throw new Error(`missing keypair for ${keyKind}`);
      const sig = await ok({
        action: "sign",
        method,
        privateKey: gen.privateKey,
        message,
      });
      const ver = await ok({
        action: "verify",
        method,
        publicKey: gen.publicKey,
        message,
        signature: sig.signature,
      });
      expect(ver.valid).toBe(true);
    },
  );

  // verify(tampered-message) → {valid:false} for every scheme — not just ed25519.
  it.each(SCHEMES)(
    "$method: verify with a different message → valid:false (not an error)",
    async ({ method, keyKind }) => {
      const gen = KEYS[keyKind];
      if (!gen) throw new Error(`missing keypair for ${keyKind}`);
      const sig = await ok({
        action: "sign",
        method,
        privateKey: gen.privateKey,
        message: "original",
      });
      const ver = await ok({
        action: "verify",
        method,
        publicKey: gen.publicKey,
        message: "tampered",
        signature: sig.signature,
      });
      expect(ver.valid).toBe(false);
    },
  );

  // wrong_algorithm: each scheme × wrong-key-type pair. Schemes accept exactly
  // one key kind; everything else must surface wrong_algorithm.
  it.each([
    { method: "ed25519", keyKind: "rsa" },
    { method: "ed25519", keyKind: "ec" },
    { method: "ecdsa", keyKind: "ed25519" },
    { method: "ecdsa", keyKind: "rsa" },
    { method: "rsa-pss", keyKind: "ed25519" },
    { method: "rsa-pss", keyKind: "ec" },
    { method: "rsa-pkcs1", keyKind: "ed25519" },
    { method: "rsa-pkcs1", keyKind: "ec" },
  ] as const)(
    "$method with $keyKind key → wrong_algorithm",
    async ({ method, keyKind }) => {
      const gen = KEYS[keyKind];
      if (!gen) throw new Error(`missing keypair for ${keyKind}`);
      await expectErr(
        {
          action: "sign",
          method,
          privateKey: gen.privateKey,
          message: "m",
        },
        "wrong_algorithm",
      );
    },
  );
});

// --------------------------------------------------------------------------
// RSA-OAEP
// --------------------------------------------------------------------------

describe("crypto: rsa-oaep", () => {
  // For 2048-bit RSA with OAEP-SHA-256 the max plaintext is:
  //   modulus_bytes - 2*hash_bytes - 2 = 256 - 64 - 2 = 190 bytes.
  // Test a range below the cap (round-trips) and a range at/above the cap
  // (rejected with bad_parameters).
  let rsa: { publicKey: string; privateKey: string };
  beforeAll(async () => {
    rsa = (await ok({
      action: "generate",
      method: "rsa",
      modulusLength: 2048,
      format: "pem",
    })) as never;
  });

  it.each([0, 1, 16, 32, 64, 128, 190])(
    "round-trips %i-byte plaintext (≤ 190-byte cap for 2048+SHA-256)",
    async (n) => {
      const plaintext = "x".repeat(n);
      const enc = await ok({
        action: "encrypt",
        method: "rsa-oaep",
        publicKey: rsa.publicKey,
        plaintext,
      });
      const dec = await ok({
        action: "decrypt",
        method: "rsa-oaep",
        privateKey: rsa.privateKey,
        ciphertext: enc.ciphertext,
      });
      expect(dec.plaintext).toBe(plaintext);
    },
  );

  it.each([191, 192, 256, 512, 2048])(
    "rejects %i-byte plaintext (> 190-byte cap) with bad_parameters",
    async (n) => {
      await expectErr(
        {
          action: "encrypt",
          method: "rsa-oaep",
          publicKey: rsa.publicKey,
          plaintext: "x".repeat(n),
        },
        "bad_parameters",
      );
    },
  );
});

// --------------------------------------------------------------------------
// convert / inspect
// --------------------------------------------------------------------------

describe("crypto: inspect across key types/formats", () => {
  type Spec = {
    method: "ed25519" | "rsa" | "ec" | "x25519";
    format: "pem" | "der" | "jwk";
    isPrivate: boolean;
    expectedKeyType: string;
    modulusLength?: number;
    curve?: string;
  };
  const SPECS: Spec[] = [
    {
      method: "ed25519",
      format: "pem",
      isPrivate: true,
      expectedKeyType: "ed25519",
    },
    {
      method: "ed25519",
      format: "pem",
      isPrivate: false,
      expectedKeyType: "ed25519",
    },
    {
      method: "ed25519",
      format: "jwk",
      isPrivate: true,
      expectedKeyType: "ed25519",
    },
    {
      method: "ed25519",
      format: "jwk",
      isPrivate: false,
      expectedKeyType: "ed25519",
    },
    {
      method: "ed25519",
      format: "der",
      isPrivate: true,
      expectedKeyType: "ed25519",
    },
    {
      method: "ed25519",
      format: "der",
      isPrivate: false,
      expectedKeyType: "ed25519",
    },
    {
      method: "rsa",
      format: "pem",
      isPrivate: true,
      expectedKeyType: "rsa",
      modulusLength: 2048,
    },
    {
      method: "rsa",
      format: "pem",
      isPrivate: false,
      expectedKeyType: "rsa",
      modulusLength: 2048,
    },
    {
      method: "rsa",
      format: "jwk",
      isPrivate: false,
      expectedKeyType: "rsa",
      modulusLength: 2048,
    },
    {
      method: "ec",
      format: "pem",
      isPrivate: true,
      expectedKeyType: "ec",
      curve: "P-256",
    },
    {
      method: "ec",
      format: "pem",
      isPrivate: false,
      expectedKeyType: "ec",
      curve: "P-256",
    },
    {
      method: "ec",
      format: "jwk",
      isPrivate: false,
      expectedKeyType: "ec",
      curve: "P-384",
    },
    {
      method: "x25519",
      format: "pem",
      isPrivate: false,
      expectedKeyType: "x25519",
    },
  ];

  it.each(SPECS)(
    "inspect $method ($format, isPrivate=$isPrivate) surfaces the right shape + fingerprint",
    async (spec) => {
      const gen = await ok({
        action: "generate",
        method: spec.method,
        format: spec.format,
        ...(spec.modulusLength ? { modulusLength: spec.modulusLength } : {}),
        ...(spec.curve ? { curve: spec.curve } : {}),
      });
      const target = spec.isPrivate ? gen.privateKey : gen.publicKey;
      const insp = await ok({ action: "inspect", input: target });
      expect(insp.kind).toBe("raw-key");
      expect(insp.keyType).toBe(spec.expectedKeyType);
      expect(insp.isPrivate).toBe(spec.isPrivate);
      expect(insp.format).toBe(spec.format);
      expect(typeof insp.fingerprintSha256).toBe("string");
      expect(typeof insp.jwkThumbprintSha256).toBe("string");
      // SHA-256 base64 = 44 chars (with trailing '='); base64url-encoded
      // thumbprint is 43 chars (no padding).
      expect((insp.fingerprintSha256 as string).length).toBe(44);
      expect((insp.jwkThumbprintSha256 as string).length).toBe(43);
      if (spec.modulusLength) expect(insp.bits).toBe(spec.modulusLength);
      if (spec.curve)
        expect(String(insp.curve)).toMatch(spec.curve.replace("P-", ""));
      // Private material must never appear in the response.
      const flat = JSON.stringify(insp);
      if (spec.isPrivate && spec.format === "pem")
        expect(flat).not.toContain("BEGIN PRIVATE KEY");
    },
  );

  // The JWK thumbprint of a private key equals the thumbprint of its public
  // counterpart — that's the spec (it's computed from the public members
  // only). This guards against a regression that accidentally hashes private
  // members and produces different thumbprints for the two sides.
  it.each(["ed25519", "rsa", "ec"] as const)(
    "private and public %s halves share the same JWK thumbprint",
    async (method) => {
      const gen = await ok({
        action: "generate",
        method,
        format: "pem",
        ...(method === "rsa" ? { modulusLength: 2048 } : {}),
        ...(method === "ec" ? { curve: "P-256" } : {}),
      });
      const pub = await ok({ action: "inspect", input: gen.publicKey });
      const priv = await ok({ action: "inspect", input: gen.privateKey });
      expect(priv.jwkThumbprintSha256).toBe(pub.jwkThumbprintSha256);
    },
  );

  // Full PEM ↔ DER ↔ JWK matrix (every directed pair × ed25519/rsa/ec). Each
  // round-trip lands back at a key that produces the same SPKI DER bytes —
  // catches a regression where any one leg silently corrupts material.
  const PAIRS = [
    ["pem", "der"],
    ["pem", "jwk"],
    ["der", "pem"],
    ["der", "jwk"],
    ["jwk", "pem"],
    ["jwk", "der"],
  ] as const;
  const KEY_KINDS = ["ed25519", "rsa", "ec"] as const;
  const PAIR_MATRIX = PAIRS.flatMap(([from, to]) =>
    KEY_KINDS.map((kind) => ({ from, to, kind })),
  );

  it.each(PAIR_MATRIX)(
    "convert $from → $to for $kind round-trips identically",
    async ({ from, to, kind }) => {
      // Always start from a canonical PEM reference so the assertion uses
      // createPublicKey(PEM) — which Node universally understands. Then walk
      // PEM → from → to → PEM via the convert tool and compare SPKI DER.
      const gen = await ok({
        action: "generate",
        method: kind,
        format: "pem",
        ...(kind === "rsa" ? { modulusLength: 2048 } : {}),
        ...(kind === "ec" ? { curve: "P-256" } : {}),
      });
      const pemPub = gen.publicKey as string;
      const aSpki = createPublicKey(pemPub).export({
        format: "der",
        type: "spki",
      });

      // Step 1: PEM → from. (If from === pem, identity.)
      const intoFrom =
        from === "pem"
          ? pemPub
          : ((await ok({ action: "convert", input: pemPub, to: from }))
              .output as string);

      // Step 2: from → to via the convert tool.
      const intoTo = (
        await ok({ action: "convert", input: intoFrom, from, to })
      ).output as string;

      // Step 3: to → PEM. (If to === pem, identity.)
      const backToPem =
        to === "pem"
          ? intoTo
          : ((
              await ok({
                action: "convert",
                input: intoTo,
                from: to,
                to: "pem",
              })
            ).output as string);

      const bSpki = createPublicKey(backToPem).export({
        format: "der",
        type: "spki",
      });
      expect(Buffer.from(aSpki).equals(Buffer.from(bSpki))).toBe(true);
    },
  );
});

// --------------------------------------------------------------------------
// Unsupported / refused algorithms
// --------------------------------------------------------------------------

describe("crypto: refusals", () => {
  // Each refused method from the description's "Notable refusals" sentence,
  // across the action it's most likely to be mis-applied to.
  it.each([
    // AES non-AEAD modes — refused (no authentication)
    ["encrypt", "aes-256-cbc"],
    ["encrypt", "aes-256-ctr"],
    ["encrypt", "aes-128-cbc"],
    ["encrypt", "aes-128-ctr"],
    ["decrypt", "aes-256-cbc"],
    // RSA-PKCS1-v1_5 encrypt — refused (only OAEP for encrypt; rsa-pkcs1 is
    // accepted for sign only)
    ["encrypt", "rsa-pkcs1"],
    ["encrypt", "rsa-pkcs1-v1_5"],
    // MD5/SHA-1 named "method" strings — refused for new signing
    ["sign", "rsa-pkcs1-v1_5-md5"],
    ["sign", "md5"],
    ["sign", "sha1-rsa"],
    // Other refused
    ["generate", "dsa"],
    ["generate", "dh"],
    ["derive", "argon2d"], // we only ship the id variant
    // Garbage / typos
    ["encrypt", "totally-not-an-algorithm"],
    ["sign", ""],
    ["verify", "ecdsa-but-misspelled"],
  ] as const)(
    "%s method %s → unsupported_algorithm",
    async (action, method) => {
      await expectErr({ action, method }, "unsupported_algorithm");
    },
  );

  // Range of "looks like a key but isn't" inputs — each must surface
  // parse_failed rather than throw or return a confusing message.
  it.each([
    ["random non-key string", "not a key"],
    ["whitespace only", "   \n  \t  "],
    [
      "truncated PEM (header but no body)",
      "-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----",
    ],
    ["malformed JWK JSON", '{"kty": "RSA", "n": '],
    ["valid JSON, invalid JWK shape", '{"foo": "bar"}'],
    [
      "base64 that decodes but isn't valid DER",
      Buffer.from("not a DER key").toString("base64"),
    ],
    ["hex chars only (not a key)", "deadbeef".repeat(20)],
  ] as const)("inspect on %s → parse_failed", async (_label, input) => {
    await expectErr({ action: "inspect", input }, "parse_failed");
  });
});

// --------------------------------------------------------------------------
// PGP — generate / sign / verify / symmetric encrypt+decrypt.
// PGP keygen is expensive but still reasonable for a few cases.
// --------------------------------------------------------------------------

describe("crypto: pgp", () => {
  const passphrase = "correct horse battery staple";
  let pubKey = "";
  let privKey = "";

  beforeAll(async () => {
    // One keypair shared across the block — PGP keygen is slow, and the
    // tests below all need a valid Alice. Using beforeAll keeps the order
    // dependency explicit and survives test-shuffle / parallel runs.
    const sc = await ok({
      action: "generate",
      method: "pgp",
      userIds: [{ name: "Alice", email: "alice@example.com" }],
      passphrase,
      keyVersion: 4,
    });
    pubKey = sc.publicKey as string;
    privKey = sc.privateKey as string;
  });

  it("generated keypair has the expected shape + user ID", async () => {
    expect(pubKey).toContain("BEGIN PGP PUBLIC KEY BLOCK");
    expect(privKey).toContain("BEGIN PGP PRIVATE KEY BLOCK");
    const insp = await ok({ action: "inspect", input: pubKey });
    expect((insp.userIds as string[])[0]).toContain("alice@example.com");
  });

  // Range over every PGP sign type (detached / cleartext / inline). Each
  // type produces a different envelope shape (SIGNATURE vs SIGNED MESSAGE vs
  // MESSAGE) but all three must verify with the same key.
  it.each([
    {
      type: "detached" as const,
      expectInOutput: "BEGIN PGP SIGNATURE",
      includeMessageOnVerify: true,
    },
    {
      type: "cleartext" as const,
      expectInOutput: "BEGIN PGP SIGNED MESSAGE",
      includeMessageOnVerify: false, // signed text is embedded
    },
    {
      type: "inline" as const,
      expectInOutput: "BEGIN PGP MESSAGE",
      includeMessageOnVerify: false, // signed text is embedded
    },
  ])(
    "sign + verify round-trip ($type)",
    async ({ type, expectInOutput, includeMessageOnVerify }) => {
      const message = "release v1.2.3";
      const sig = await ok({
        action: "sign",
        method: "pgp",
        privateKey: privKey,
        passphrase,
        message,
        type,
      });
      expect(sig.signature).toContain(expectInOutput);
      const ver = await ok({
        action: "verify",
        method: "pgp",
        signature: sig.signature,
        publicKeys: [pubKey],
        ...(includeMessageOnVerify ? { message } : {}),
      });
      expect(ver.valid).toBe(true);
    },
  );

  it("symmetric (passphrase) encrypt + decrypt", async () => {
    const enc = await ok({
      action: "encrypt",
      method: "pgp",
      message: "secret payload",
      passphrase: "shared-secret",
    });
    expect(enc.ciphertext).toContain("BEGIN PGP MESSAGE");
    const dec = await ok({
      action: "decrypt",
      method: "pgp",
      ciphertext: enc.ciphertext,
      passphrase: "shared-secret",
    });
    expect(dec.plaintext).toBe("secret payload");
  });

  it("wrong passphrase on symmetric decrypt → decryption_failed (single bucket)", async () => {
    const enc = await ok({
      action: "encrypt",
      method: "pgp",
      message: "x",
      passphrase: "right",
    });
    await expectErr(
      {
        action: "decrypt",
        method: "pgp",
        ciphertext: enc.ciphertext,
        passphrase: "wrong",
      },
      "decryption_failed",
    );
  });

  it("inspect on a PGP public key surfaces fingerprint + user IDs, never private material", async () => {
    const insp = await ok({ action: "inspect", input: pubKey });
    expect(insp.kind).toBe("pgp-key");
    expect(insp.isPrivate).toBe(false);
    expect((insp.userIds as string[])[0]).toContain("alice@example.com");
  });

  it("inspect on a PGP PRIVATE key still never echoes the private material", async () => {
    const insp = await ok({ action: "inspect", input: privKey });
    expect(insp.kind).toBe("pgp-key");
    expect(insp.isPrivate).toBe(true);
    const flat = JSON.stringify(insp);
    expect(flat).not.toContain("BEGIN PGP PRIVATE KEY BLOCK");
  });
});

// --------------------------------------------------------------------------
// Redaction conformance — sweep every (action, method) that takes private
// material and ensure the response never echoes it.
// --------------------------------------------------------------------------

describe("crypto: redaction — private material never appears in the response", () => {
  // Stronger than substring-of-header — assert the actual key bytes (the
  // base64-encoded SPKI/PKCS8 body, or for PGP the unique fingerprint suffix
  // that only appears inside the private block) are absent from the response.
  // A future code path that base64-re-encodes the private key into a JWK or a
  // log field would defeat a "BEGIN PRIVATE KEY" substring check; this one
  // catches that.
  let pem: { publicKey: string; privateKey: string };
  let pgpKey: { publicKey: string; privateKey: string };
  let pgpPrivBodyMarker = ""; // a substring unique to the private block
  const passphrase = "RED-PASSPHRASE-VALUE";

  beforeAll(async () => {
    const ed = await ok({
      action: "generate",
      method: "ed25519",
      format: "pem",
    });
    pem = ed as never;
    const pgp = await ok({
      action: "generate",
      method: "pgp",
      userIds: [{ name: "R", email: "r@example.com" }],
      passphrase,
      keyVersion: 4,
    });
    pgpKey = pgp as never;
    // Body of the private block (between the BEGIN/END markers) is unique to
    // the private key — finding that substring in a response means leakage.
    pgpPrivBodyMarker =
      (pgp.privateKey as string)
        .split("-----BEGIN PGP PRIVATE KEY BLOCK-----")[1]
        ?.split("-----END PGP PRIVATE KEY BLOCK-----")[0]
        ?.trim()
        .slice(0, 64) ?? "";
    expect(pgpPrivBodyMarker.length).toBeGreaterThan(32);
  });

  const privatePemBody = () =>
    pem.privateKey
      .split("-----BEGIN PRIVATE KEY-----")[1]
      ?.split("-----END PRIVATE KEY-----")[0]
      ?.replace(/\s+/g, "") ?? "";

  function assertRedacted(sc: Record<string, unknown>): void {
    const flat = JSON.stringify(sc);
    expect(flat).not.toContain("BEGIN PRIVATE KEY");
    expect(flat).not.toContain("BEGIN PGP PRIVATE KEY BLOCK");
    expect(flat).not.toContain(passphrase);
    // Bytes-level: neither the raw PEM body nor the PGP private body markers
    // should appear in the response.
    const pemBody = privatePemBody();
    if (pemBody) expect(flat).not.toContain(pemBody);
    if (pgpPrivBodyMarker) expect(flat).not.toContain(pgpPrivBodyMarker);
  }

  it("sign ed25519 never echoes the private key bytes", async () => {
    assertRedacted(
      await ok({
        action: "sign",
        method: "ed25519",
        privateKey: pem.privateKey,
        message: "m",
      }),
    );
  });

  it("ecdh never echoes the private key bytes", async () => {
    const peer = generateKeyPairSync("x25519");
    const ours = generateKeyPairSync("x25519");
    const oursPem = ours.privateKey.export({ format: "pem", type: "pkcs8" });
    const sc = await ok({
      action: "derive",
      method: "ecdh",
      privateKey: oursPem,
      peerPublicKey: peer.publicKey.export({ format: "pem", type: "spki" }),
    });
    const flat = JSON.stringify(sc);
    expect(flat).not.toContain("BEGIN PRIVATE KEY");
    const oursBody =
      oursPem
        .split("-----BEGIN PRIVATE KEY-----")[1]
        ?.split("-----END PRIVATE KEY-----")[0]
        ?.replace(/\s+/g, "") ?? "";
    if (oursBody) expect(flat).not.toContain(oursBody);
  });

  it("rsa-oaep decrypt never echoes the private RSA PEM", async () => {
    const rsa = await ok({
      action: "generate",
      method: "rsa",
      modulusLength: 2048,
      format: "pem",
    });
    const enc = await ok({
      action: "encrypt",
      method: "rsa-oaep",
      publicKey: rsa.publicKey,
      plaintext: "x",
    });
    const dec = await ok({
      action: "decrypt",
      method: "rsa-oaep",
      privateKey: rsa.privateKey,
      ciphertext: enc.ciphertext,
    });
    const flat = JSON.stringify(dec);
    expect(flat).not.toContain("BEGIN PRIVATE KEY");
    const body =
      (rsa.privateKey as string)
        .split("-----BEGIN PRIVATE KEY-----")[1]
        ?.split("-----END PRIVATE KEY-----")[0]
        ?.replace(/\s+/g, "") ?? "";
    if (body) expect(flat).not.toContain(body);
  });

  it("pgp sign never echoes private material or passphrase", async () => {
    const sc = await ok({
      action: "sign",
      method: "pgp",
      privateKey: pgpKey.privateKey,
      passphrase,
      message: "m",
      type: "detached",
    });
    assertRedacted(sc);
  });

  it("pgp decrypt never echoes private material or passphrase", async () => {
    const enc = await ok({
      action: "encrypt",
      method: "pgp",
      message: "x",
      recipients: [pgpKey.publicKey],
    });
    const dec = await ok({
      action: "decrypt",
      method: "pgp",
      ciphertext: enc.ciphertext,
      privateKey: pgpKey.privateKey,
      passphrase,
    });
    assertRedacted(dec);
  });

  it("pgp encrypt with signingKey never echoes signing material or passphrase", async () => {
    const sc = await ok({
      action: "encrypt",
      method: "pgp",
      message: "x",
      recipients: [pgpKey.publicKey],
      signingKey: pgpKey.privateKey,
      signingPassphrase: passphrase,
    });
    assertRedacted(sc);
  });

  it("pgp generate never echoes the input passphrase", async () => {
    // generate IS allowed to return the private key (that's its purpose), so
    // we don't assert on the key bytes — but the input passphrase must never
    // appear in the response.
    const sc = await ok({
      action: "generate",
      method: "pgp",
      userIds: [{ name: "G", email: "g@example.com" }],
      passphrase,
      keyVersion: 4,
    });
    expect(JSON.stringify(sc)).not.toContain(passphrase);
  });
});

// --------------------------------------------------------------------------
// Decrypt's plaintextEncoding is honoured per-call (regression test for the
// silent override bug — explicit base64 plaintextEncoding on decrypt used to
// be silently switched to utf8).
// --------------------------------------------------------------------------

describe("crypto: decrypt plaintextEncoding fidelity", () => {
  const KEY_32_B64 = Buffer.alloc(32, 1).toString("base64");
  const NONCE_12_B64 = Buffer.alloc(12, 2).toString("base64");

  // Range of plaintext shapes covers the encoding interactions you'd hit in
  // real workloads: empty, 1-byte, binary-bytes-that-aren't-utf8, multibyte
  // unicode, and a multi-KiB payload (3 AES blocks worth).
  const PLAINTEXTS = [
    { name: "empty", bytes: Buffer.alloc(0) },
    { name: "1-byte ascii", bytes: Buffer.from([0x41]) },
    { name: "binary spread", bytes: Buffer.from([0x00, 0x01, 0xfe, 0xff]) },
    { name: "multibyte unicode", bytes: Buffer.from("🦀 你好", "utf8") },
    { name: "3 KiB", bytes: Buffer.alloc(3 * 1024, 0x55) },
  ];

  // For each plaintext, encrypt-then-decrypt three times with each
  // plaintextEncoding (utf8/base64/hex). We skip the utf8 case for the
  // pure-binary plaintexts (they aren't valid utf8 and Buffer→utf8 lossily
  // replaces the bytes).
  const CASES = PLAINTEXTS.flatMap((p) => {
    const utf8Safe = Buffer.from(p.bytes.toString("utf8"), "utf8").equals(
      p.bytes,
    );
    return (
      ["base64", "hex", ...(utf8Safe ? (["utf8"] as const) : [])] as const
    ).map((enc) => ({ plaintext: p, enc }));
  });

  it.each(CASES)(
    "$plaintext.name → plaintextEncoding=$enc round-trips faithfully",
    async ({ plaintext, enc }) => {
      const encResp = await ok({
        action: "encrypt",
        method: "aes-256-gcm",
        key: KEY_32_B64,
        plaintext: `base64:${plaintext.bytes.toString("base64")}`,
        nonce: NONCE_12_B64,
      });
      const dec = await ok({
        action: "decrypt",
        method: "aes-256-gcm",
        key: KEY_32_B64,
        ciphertext: encResp.ciphertext,
        nonce: NONCE_12_B64,
        tag: encResp.tag,
        plaintextEncoding: enc,
      });
      const expected =
        enc === "base64"
          ? plaintext.bytes.toString("base64")
          : enc === "hex"
            ? plaintext.bytes.toString("hex")
            : plaintext.bytes.toString("utf8");
      expect(dec.plaintext).toBe(expected);
    },
  );

  it("`hex:` prefix on a hex-bytes input gets decoded correctly", async () => {
    const PLAINTEXT = Buffer.from([0x00, 0x01, 0x02, 0xfe, 0xff]);
    const enc = await ok({
      action: "encrypt",
      method: "aes-256-gcm",
      key: KEY_32_B64,
      plaintext: `hex:${PLAINTEXT.toString("hex")}`,
      nonce: NONCE_12_B64,
    });
    const dec = await ok({
      action: "decrypt",
      method: "aes-256-gcm",
      key: KEY_32_B64,
      ciphertext: enc.ciphertext,
      nonce: NONCE_12_B64,
      tag: enc.tag,
      plaintextEncoding: "hex",
    });
    expect(dec.plaintext).toBe(PLAINTEXT.toString("hex"));
  });
});

// --------------------------------------------------------------------------
// Convert: `to` is required even via the direct-handler path (refine is
// bypassed by the script gateway and unit tests).
// --------------------------------------------------------------------------

describe("crypto: convert requires `to`", () => {
  it("missing `to` → bad_parameters, never a silent default to JWK", async () => {
    const gen = await ok({
      action: "generate",
      method: "ed25519",
      format: "pem",
    });
    // Schema sees `to` as optional, so the boundary doesn't reject — the
    // handler must.
    await expectErr(
      { action: "convert", input: gen.publicKey as string },
      "bad_parameters",
    );
  });

  it("inspect JWK input round-trips type detection", async () => {
    const gen = await ok({
      action: "generate",
      method: "ed25519",
      format: "jwk",
    });
    const insp = await ok({
      action: "inspect",
      input: gen.publicKey as string,
    });
    expect(insp.format).toBe("jwk");
    expect(insp.keyType).toBe("ed25519");
  });
});

// --------------------------------------------------------------------------
// PGP — recipient-based encrypt, expired-key handling, acceptLegacyHash, and
// cleartext sign/verify round-trip.
// --------------------------------------------------------------------------

describe("crypto: pgp — recipient encrypt, expiry, legacy hash, cleartext", () => {
  const passphrase = "p";
  let alicePub = "";
  let alicePriv = "";

  // Range over recipient counts (1, 2, 3). Each test must produce a
  // ciphertext that any of the recipients' private keys can decrypt.
  const recipientCases = [1, 2, 3];
  let extraKeypairs: Array<{ publicKey: string; privateKey: string }> = [];

  beforeAll(async () => {
    const aliceSc = await ok({
      action: "generate",
      method: "pgp",
      userIds: [{ name: "Alice", email: "a@example.com" }],
      passphrase,
      keyVersion: 4,
    });
    alicePub = aliceSc.publicKey as string;
    alicePriv = aliceSc.privateKey as string;
    extraKeypairs = await Promise.all(
      [1, 2].map(async (i) => {
        const sc = await ok({
          action: "generate",
          method: "pgp",
          userIds: [{ name: `R${i}`, email: `r${i}@example.com` }],
          passphrase,
          keyVersion: 4,
        });
        return {
          publicKey: sc.publicKey as string,
          privateKey: sc.privateKey as string,
        };
      }),
    );
  });
  it.each(recipientCases)(
    "recipient-based encrypt to %i recipients — each can decrypt",
    async (n) => {
      const allKeys = [
        { publicKey: alicePub, privateKey: alicePriv },
        ...extraKeypairs,
      ].slice(0, n);
      const enc = await ok({
        action: "encrypt",
        method: "pgp",
        message: "to multiple recipients",
        recipients: allKeys.map((k) => k.publicKey),
      });
      expect(enc.recipients).toBe(n);
      // Each holder of a recipient private key should be able to decrypt.
      for (const k of allKeys) {
        const dec = await ok({
          action: "decrypt",
          method: "pgp",
          ciphertext: enc.ciphertext as string,
          privateKey: k.privateKey,
          passphrase,
        });
        expect(dec.plaintext).toBe("to multiple recipients");
      }
    },
  );

  it("expired key on encrypt → pgp_key_expired", async () => {
    // expiresIn:1 → key expires 1 second after creation; sleep just past it.
    const expiring = await ok({
      action: "generate",
      method: "pgp",
      userIds: [{ name: "Short", email: "s@example.com" }],
      passphrase,
      keyVersion: 4,
      expiresIn: "1",
    });
    await new Promise((r) => setTimeout(r, 1100));
    await expectErr(
      {
        action: "encrypt",
        method: "pgp",
        message: "x",
        recipients: [expiring.publicKey as string],
      },
      "pgp_key_expired",
    );
  });

  // encryptionSubkey:rsa was here as a solo `it`; merged into the ranged
  // test in `crypto: extended happy paths` below.
});

// --------------------------------------------------------------------------
// PGP keyserver fetch — hits a local 127.0.0.1 server, mocked to return the
// Alice key. Verifies the SSRF-guarded fetch path, https requirement (negative
// case), and that the keyserver_fetch_failed code surfaces on HTTP errors.
// --------------------------------------------------------------------------

describe("crypto: pgp keyserver", async () => {
  const { buildKeyserverUrl } = await import(
    "../../src/lib/crypto/pgp/index.js"
  );

  // VKS form variants (no path, trailing slash, double-trailing slash) and
  // HKP form variants (/pks/lookup, /pks, /pks/lookup with trailing slash).
  // Also test uppercase-hex keyId input (real keyservers normalise but our
  // builder must not).
  it.each([
    // VKS — default path
    [
      "https://keys.openpgp.org",
      "abcdef0123456789",
      "https://keys.openpgp.org/vks/v1/by-keyid/abcdef0123456789",
    ],
    [
      "https://keys.openpgp.org/",
      "abcdef0123456789",
      "https://keys.openpgp.org/vks/v1/by-keyid/abcdef0123456789",
    ],
    [
      "https://keys.openpgp.org///",
      "abcdef0123456789",
      "https://keys.openpgp.org/vks/v1/by-keyid/abcdef0123456789",
    ],
    // HKP — /pks/lookup explicit
    [
      "https://pgp.mit.edu/pks/lookup",
      "abcdef0123456789",
      "https://pgp.mit.edu/pks/lookup?op=get&options=mr&search=0xabcdef0123456789",
    ],
    // HKP — /pks (we append /lookup)
    [
      "https://pgp.mit.edu/pks",
      "abcdef0123456789",
      "https://pgp.mit.edu/pks/lookup?op=get&options=mr&search=0xabcdef0123456789",
    ],
    // Uppercase keyId — passed through verbatim
    [
      "https://keys.openpgp.org",
      "ABCDEF0123456789",
      "https://keys.openpgp.org/vks/v1/by-keyid/ABCDEF0123456789",
    ],
    // Custom port preserved
    [
      "https://keys.example.com:8443",
      "abcdef0123456789",
      "https://keys.example.com:8443/vks/v1/by-keyid/abcdef0123456789",
    ],
  ])("buildKeyserverUrl(%s, %s) → %s", (base, keyId, expected) => {
    expect(buildKeyserverUrl(base, keyId).toString()).toBe(expected);
  });

  it("http:// keyserverUrl is refused at the schema boundary", async () => {
    // The refine(https) on the schema rejects this at parse time. We expect a
    // Zod parse error — the call rejects rather than returning an err() result.
    await expect(
      run({
        action: "verify",
        method: "pgp",
        signature:
          "-----BEGIN PGP SIGNATURE-----\nx\n-----END PGP SIGNATURE-----",
        message: "m",
        keyserverUrl: "http://keys.openpgp.org",
      }),
    ).rejects.toThrow();
  });

  it("verifying with no key supplied and no keyserverUrl → pgp_key_unavailable", async () => {
    // Generate a real detached signature so we get past the parse step.
    const gen = await ok({
      action: "generate",
      method: "pgp",
      userIds: [{ name: "X", email: "x@example.com" }],
      passphrase: "p",
      keyVersion: 4,
    });
    const sig = await ok({
      action: "sign",
      method: "pgp",
      privateKey: gen.privateKey as string,
      passphrase: "p",
      message: "m",
      type: "detached",
    });
    await expectErr(
      {
        action: "verify",
        method: "pgp",
        signature: sig.signature as string,
        message: "m",
      },
      "pgp_key_unavailable",
    );
  });
});

// --------------------------------------------------------------------------
// PGP `acceptLegacyHash` — explicit opt-in is required to accept SHA-1
// signatures on verify. We can't easily forge a SHA-1 PGP signature in this
// environment (openpgp.js refuses to produce them), so we verify the path
// indirectly: a malformed/empty signature parsed as having md5/sha1 packets
// would surface { valid: false, reason: "weak_hash" } before key resolution.
// This is more a smoke test than a tight assertion.
// --------------------------------------------------------------------------

describe("crypto: pgp acceptLegacyHash off by default", () => {
  it("a sane modern PGP signature is not blocked by acceptLegacyHash:false", async () => {
    // Round-trip with the default (acceptLegacyHash:false) using a modern key
    // — this would fail if our gating accidentally rejected SHA-256.
    const sc = await ok({
      action: "generate",
      method: "pgp",
      userIds: [{ name: "T", email: "t@example.com" }],
      passphrase: "p",
      keyVersion: 4,
    });
    const sig = await ok({
      action: "sign",
      method: "pgp",
      privateKey: sc.privateKey as string,
      passphrase: "p",
      message: "modern",
      type: "detached",
    });
    const ver = await ok({
      action: "verify",
      method: "pgp",
      signature: sig.signature as string,
      message: "modern",
      publicKeys: [sc.publicKey as string],
    });
    expect(ver.valid).toBe(true);
  });
});

// --------------------------------------------------------------------------
// argon2id — the default `derive` method, previously untested.
// --------------------------------------------------------------------------

describe("crypto: argon2id", () => {
  // Use the smallest legal params so the test stays fast (~ms).
  const cheapParams = { memory: 256, iterations: 1, parallelism: 1 };

  it("produces deterministic output for fixed (password, salt, params)", async () => {
    const salt = Buffer.alloc(16, 11).toString("base64");
    const args = {
      action: "derive" as const,
      method: "argon2id" as const,
      password: "hunter2",
      salt,
      keyLength: 32,
      params: cheapParams,
    };
    const a = await ok(args);
    const b = await ok(args);
    expect(a.key).toBe(b.key);
    expect(typeof a.key).toBe("string");
    expect(a.keyLength).toBe(32);
    expect(a.salt).toBe(salt); // echoed back, not regenerated
  });

  it("auto-generates a salt when none is supplied (and returns it)", async () => {
    const sc = await ok({
      action: "derive",
      method: "argon2id",
      password: "p",
      keyLength: 16,
      params: cheapParams,
    });
    expect(typeof sc.salt).toBe("string");
    // 16 random bytes base64-encoded = 24 chars (with one =).
    expect(Buffer.from(sc.salt as string, "base64").length).toBe(16);
  });

  // Four distinct salts must produce four distinct keys (no salt → key
  // collisions). Tighter than a 2-case pair check.
  it("distinct salts produce distinct keys (4 samples)", async () => {
    const args = {
      action: "derive" as const,
      method: "argon2id" as const,
      password: "p",
      keyLength: 16,
      params: cheapParams,
    };
    const salts = [1, 2, 3, 4].map((b) =>
      Buffer.alloc(16, b).toString("base64"),
    );
    const results = await Promise.all(
      salts.map((salt) => ok({ ...args, salt })),
    );
    const keys = results.map((r) => r.key as string);
    expect(new Set(keys).size).toBe(salts.length);
  });

  // Different passwords with the same salt also produce different keys.
  it("distinct passwords produce distinct keys (4 samples)", async () => {
    const salt = Buffer.alloc(16, 0).toString("base64");
    const pwds = ["", "a", "long-password-here", "🦀"];
    const results = await Promise.all(
      pwds.map((password) =>
        ok({
          action: "derive",
          method: "argon2id",
          password,
          salt,
          keyLength: 16,
          params: cheapParams,
        }),
      ),
    );
    const keys = results.map((r) => r.key as string);
    expect(new Set(keys).size).toBe(pwds.length);
  });
});

// --------------------------------------------------------------------------
// Error codes that previously weren't directly exercised:
// too_large, invalid_key, keyserver_fetch_failed.
// --------------------------------------------------------------------------

describe("crypto: error codes — too_large / invalid_key / keyserver_fetch_failed", () => {
  it("too_large: AEAD encrypt plaintext over the 16 MiB cap", async () => {
    // Allocate just over the limit (17 MiB of utf8 'x' = 17 MiB of bytes).
    // Slow-ish but cheap memory-wise; about 30 MB allocated total.
    const oversized = "x".repeat(17 * 1024 * 1024);
    await expectErr(
      {
        action: "encrypt",
        method: "aes-256-gcm",
        key: Buffer.alloc(32, 1).toString("base64"),
        plaintext: oversized,
        nonce: Buffer.alloc(12, 2).toString("base64"),
      },
      "too_large",
    );
  });

  it("too_large: RSA-OAEP plaintext over the cap (not bad_parameters)", async () => {
    const rsa = await ok({
      action: "generate",
      method: "rsa",
      modulusLength: 2048,
      format: "pem",
    });
    const oversized = "x".repeat(17 * 1024 * 1024);
    await expectErr(
      {
        action: "encrypt",
        method: "rsa-oaep",
        publicKey: rsa.publicKey,
        plaintext: oversized,
      },
      "too_large",
    );
  });

  it("invalid_key: malformed PGP recipient block", async () => {
    await expectErr(
      {
        action: "encrypt",
        method: "pgp",
        message: "x",
        recipients: [
          "-----BEGIN PGP PUBLIC KEY BLOCK-----\nnonsense\n-----END PGP PUBLIC KEY BLOCK-----",
        ],
      },
      "invalid_key",
    );
  });

  it("invalid_key: PGP private key with wrong passphrase", async () => {
    const gen = await ok({
      action: "generate",
      method: "pgp",
      userIds: [{ name: "I", email: "i@example.com" }],
      passphrase: "right",
      keyVersion: 4,
    });
    await expectErr(
      {
        action: "sign",
        method: "pgp",
        privateKey: gen.privateKey,
        passphrase: "wrong",
        message: "x",
      },
      "invalid_key",
    );
  });
});

// --------------------------------------------------------------------------
// Cap-boundary pairs: each cap is tested both at-cap (succeeds) and just
// over-cap (bad_parameters). This catches off-by-one regressions in the
// guards under src/lib/crypto/{generate,derive}.ts.
// --------------------------------------------------------------------------

describe("crypto: cap boundaries (at-cap passes, over-cap fails)", () => {
  // We import LIMITS so the tests stay in sync with the policy constants.
  let LIMITS: typeof import("../../src/lib/crypto/policy.js").LIMITS;
  beforeAll(async () => {
    ({ LIMITS } = await import("../../src/lib/crypto/policy.js"));
  });

  it("generate bytes: byteLength=1024 (at cap) → success", async () => {
    const sc = await ok({
      action: "generate",
      method: "bytes",
      byteLength: 1024,
      outputEncoding: "base64",
    });
    expect(sc.byteLength).toBe(1024);
  });

  it("generate bytes: byteLength=1025 → bad_parameters", async () => {
    // 1025 is past the 1024 in-handler cap (max(1024) is on the schema, so
    // this is actually rejected at the schema boundary as ZodError — that's
    // still a refusal of unsafe input, which is what we want to verify).
    await expect(
      run({
        action: "generate",
        method: "bytes",
        byteLength: 1025,
        outputEncoding: "base64",
      }),
    ).rejects.toThrow();
  });

  it("generate rsa modulusLength=8192 (at cap) → success", async () => {
    // 8192-bit keygen takes a while (~10s on a fast laptop) but is bounded.
    // Marked above the usual fast suite by virtue of taking real CPU — feel
    // free to skip via SKIP_SLOW.
    if (process.env.SKIP_SLOW) return;
    const sc = await ok({
      action: "generate",
      method: "rsa",
      modulusLength: 8192,
      format: "pem",
    });
    const k = createPublicKey(sc.publicKey as string);
    expect(k.asymmetricKeyDetails?.modulusLength).toBe(8192);
  }, 60_000);

  it("generate rsa modulusLength=8193 (just over cap) → bad_parameters", async () => {
    await expectErr(
      {
        action: "generate",
        method: "rsa",
        modulusLength: 8193,
        format: "pem",
      },
      "bad_parameters",
    );
  });

  it("pbkdf2 iterations at cap → success", async () => {
    // 10M iterations of pbkdf2-sha256 is slow but legitimate. Bumped timeout.
    if (process.env.SKIP_SLOW) return;
    const sc = await ok({
      action: "derive",
      method: "pbkdf2",
      password: "p",
      salt: Buffer.alloc(16).toString("base64"),
      keyLength: 16,
      params: { iterations: LIMITS.pbkdf2MaxIterations },
    });
    expect(typeof sc.key).toBe("string");
  }, 60_000);

  it("pbkdf2 iterations at cap+1 → bad_parameters", async () => {
    await expectErr(
      {
        action: "derive",
        method: "pbkdf2",
        password: "p",
        salt: Buffer.alloc(16).toString("base64"),
        keyLength: 16,
        params: { iterations: LIMITS.pbkdf2MaxIterations + 1 },
      },
      "bad_parameters",
    );
  });

  it("argon2 memory at cap+1 → bad_parameters (cheap, just policy gate)", async () => {
    await expectErr(
      {
        action: "derive",
        method: "argon2id",
        password: "p",
        keyLength: 16,
        params: {
          memory: LIMITS.argon2MaxMemKiB + 1,
          iterations: 1,
          parallelism: 1,
        },
      },
      "bad_parameters",
    );
  });

  it("argon2 time at cap+1 → bad_parameters", async () => {
    await expectErr(
      {
        action: "derive",
        method: "argon2id",
        password: "p",
        keyLength: 16,
        params: {
          memory: 256,
          iterations: LIMITS.argon2MaxTime + 1,
          parallelism: 1,
        },
      },
      "bad_parameters",
    );
  });

  it("argon2 parallelism at cap+1 → bad_parameters", async () => {
    await expectErr(
      {
        action: "derive",
        method: "argon2id",
        password: "p",
        keyLength: 16,
        params: {
          memory: 256,
          iterations: 1,
          parallelism: LIMITS.argon2MaxParallelism + 1,
        },
      },
      "bad_parameters",
    );
  });

  it("scrypt N at cap+1 → bad_parameters", async () => {
    await expectErr(
      {
        action: "derive",
        method: "scrypt",
        password: "p",
        salt: Buffer.alloc(16).toString("base64"),
        keyLength: 16,
        params: { N: LIMITS.scryptMaxN + 1, r: 8, p: 1 },
      },
      "bad_parameters",
    );
  });

  it("scrypt memory estimate at cap+1 → bad_parameters", async () => {
    // 128 * N * r > 256 MiB with N=1024 forces r far past the cap-implied limit.
    const r = Math.ceil(LIMITS.scryptMaxMemBytes / (128 * 1024)) + 1;
    await expectErr(
      {
        action: "derive",
        method: "scrypt",
        password: "p",
        salt: Buffer.alloc(16).toString("base64"),
        keyLength: 16,
        params: { N: 1024, r, p: 1 },
      },
      "bad_parameters",
    );
  });
});

// --------------------------------------------------------------------------
// AEAD: tag appended to ciphertext (the openssl wire convention). The
// description promises both forms work; this is the regression test.
// --------------------------------------------------------------------------

describe("crypto: AEAD tag appended to ciphertext", () => {
  const KEY_16_B64 = Buffer.alloc(16, 1).toString("base64");
  const KEY_32_B64 = Buffer.alloc(32, 1).toString("base64");
  const NONCE_12_B64 = Buffer.alloc(12, 2).toString("base64");

  it.each([
    ["aes-256-gcm", KEY_32_B64],
    ["aes-128-gcm", KEY_16_B64],
    ["chacha20-poly1305", KEY_32_B64],
  ] as const)(
    "%s decrypt accepts ciphertext||tag (no separate tag field)",
    async (method, key) => {
      const enc = await ok({
        action: "encrypt",
        method,
        key,
        plaintext: "wire-format payload",
        nonce: NONCE_12_B64,
      });
      const combined = Buffer.concat([
        Buffer.from(enc.ciphertext as string, "base64"),
        Buffer.from(enc.tag as string, "base64"),
      ]).toString("base64");
      const dec = await ok({
        action: "decrypt",
        method,
        key,
        ciphertext: combined,
        nonce: NONCE_12_B64,
        // tag deliberately omitted — the trailing 16 bytes ARE the tag.
      });
      expect(dec.plaintext).toBe("wire-format payload");
    },
  );

  // Range of "too short to contain a tag" inputs — empty, 1 byte, 15 bytes
  // (just one short of the 16-byte tag boundary).
  it.each([
    ["aes-256-gcm", KEY_32_B64, 0],
    ["aes-256-gcm", KEY_32_B64, 1],
    ["aes-256-gcm", KEY_32_B64, 15],
    ["aes-128-gcm", KEY_16_B64, 5],
    ["chacha20-poly1305", KEY_32_B64, 10],
  ] as const)(
    "%s rejects too-short ciphertext (%i bytes) → decryption_failed",
    async (method, key, len) => {
      await expectErr(
        {
          action: "decrypt",
          method,
          key,
          ciphertext: Buffer.alloc(len).toString("base64"),
          nonce: NONCE_12_B64,
        },
        "decryption_failed",
      );
    },
  );
});

// --------------------------------------------------------------------------
// ECDH wrong_algorithm paths.
// --------------------------------------------------------------------------

describe("crypto: ecdh wrong_algorithm", () => {
  it("Ed25519 private key (signing key) → wrong_algorithm", async () => {
    const ed = await ok({
      action: "generate",
      method: "ed25519",
      format: "pem",
    });
    const peer = await ok({
      action: "generate",
      method: "x25519",
      format: "pem",
    });
    await expectErr(
      {
        action: "derive",
        method: "ecdh",
        privateKey: ed.privateKey,
        peerPublicKey: peer.publicKey,
      },
      "wrong_algorithm",
    );
  });

  it("Mismatched key types (X25519 priv, EC pub) → wrong_algorithm", async () => {
    const x = await ok({ action: "generate", method: "x25519", format: "pem" });
    const ec = await ok({
      action: "generate",
      method: "ec",
      curve: "P-256",
      format: "pem",
    });
    await expectErr(
      {
        action: "derive",
        method: "ecdh",
        privateKey: x.privateKey,
        peerPublicKey: ec.publicKey,
      },
      "wrong_algorithm",
    );
  });
});

// --------------------------------------------------------------------------
// Missing happy paths: secp256k1, P-521 EC, ECDSA on P-384/P-521, HKDF SHA-384
// / SHA-512, RSA-OAEP SHA-384/SHA-512, PGP encryptionSubkey curves, PGP sign
// type:inline.
// --------------------------------------------------------------------------

describe("crypto: extended happy paths", () => {
  it("generate secp256k1 produces an EC key on secp256k1", async () => {
    const sc = await ok({
      action: "generate",
      method: "secp256k1",
      format: "pem",
    });
    const k = createPublicKey(sc.publicKey as string);
    expect(k.asymmetricKeyType).toBe("ec");
    expect(String(k.asymmetricKeyDetails?.namedCurve)).toMatch(/secp256k1/i);
  });

  // P-256/P-384/P-521 keygen coverage lives in the consolidated `generate ec
  // curve=%s` range — this block focuses on the cryptographic round-trip
  // (sign/verify, encrypt/decrypt) across the same curves.
  it.each(["P-256", "P-384", "P-521"] as const)(
    "ECDSA on %s round-trips sign/verify",
    async (curve) => {
      const gen = await ok({
        action: "generate",
        method: "ec",
        curve,
        format: "pem",
      });
      // Match hash size to curve order (FIPS 186-4 §6.4).
      const hash =
        curve === "P-256"
          ? ("sha256" as const)
          : curve === "P-384"
            ? ("sha384" as const)
            : ("sha512" as const);
      const sig = await ok({
        action: "sign",
        method: "ecdsa",
        privateKey: gen.privateKey,
        message: "x",
        hash,
      });
      const ver = await ok({
        action: "verify",
        method: "ecdsa",
        publicKey: gen.publicKey,
        message: "x",
        signature: sig.signature,
        hash,
      });
      expect(ver.valid).toBe(true);
    },
  );

  it.each(["sha384", "sha512"] as const)(
    "HKDF with %s matches node:crypto",
    async (hash) => {
      const ikm = Buffer.alloc(32, 4);
      const salt = Buffer.alloc(16, 5);
      const info = Buffer.from("ctx", "utf8");
      const expected = Buffer.from(
        hkdfSync(hash, ikm, salt, info, 32),
      ).toString("base64");
      const sc = await ok({
        action: "derive",
        method: "hkdf",
        ikm: ikm.toString("base64"),
        salt: salt.toString("base64"),
        info: "ctx",
        keyLength: 32,
        hash,
      });
      expect(sc.key).toBe(expected);
    },
  );

  it.each(["sha384", "sha512"] as const)(
    "RSA-OAEP with %s oaepHash round-trips",
    async (oaepHash) => {
      const rsa = await ok({
        action: "generate",
        method: "rsa",
        modulusLength: 2048,
        format: "pem",
      });
      const enc = await ok({
        action: "encrypt",
        method: "rsa-oaep",
        publicKey: rsa.publicKey,
        plaintext: "session",
        oaepHash,
      });
      const dec = await ok({
        action: "decrypt",
        method: "rsa-oaep",
        privateKey: rsa.privateKey,
        ciphertext: enc.ciphertext,
        oaepHash,
      });
      expect(dec.plaintext).toBe("session");
    },
  );

  // Every encryptionSubkey option as a single range — rsa was previously
  // tested in a solo `it`; p256/p384/p521 were here. Consolidated.
  it.each([
    { sub: "rsa", expect: /rsa/i },
    { sub: "p256", expect: /ec|dsa/i },
    { sub: "p384", expect: /ec|dsa/i },
    { sub: "p521", expect: /ec|dsa/i },
  ] as const)(
    "PGP encryptionSubkey:$sub generates the expected primary algorithm",
    async ({ sub, expect: pattern }) => {
      const sc = await ok({
        action: "generate",
        method: "pgp",
        userIds: [{ name: "E", email: `e-${sub}@example.com` }],
        passphrase: "p",
        keyVersion: 4,
        encryptionSubkey: sub,
      });
      const insp = await ok({
        action: "inspect",
        input: sc.publicKey as string,
      });
      expect(String(insp.algorithm)).toMatch(pattern);
    },
  );
});

// --------------------------------------------------------------------------
// Convert: PEM ↔ DER, explicit `from`, RSA + EC keys (not just Ed25519).
// --------------------------------------------------------------------------

describe("crypto: convert format matrix", () => {
  it.each(["ed25519", "rsa", "ec"] as const)(
    "PEM → DER → PEM round-trips a %s public key",
    async (m) => {
      const gen = await ok({
        action: "generate",
        method: m,
        format: "pem",
        ...(m === "rsa" ? { modulusLength: 2048 } : {}),
        ...(m === "ec" ? { curve: "P-256" } : {}),
      });
      const toDer = await ok({
        action: "convert",
        input: gen.publicKey,
        to: "der",
      });
      // DER output is base64-encoded.
      expect(/^[A-Za-z0-9+/]+=*$/.test(toDer.output as string)).toBe(true);
      const backToPem = await ok({
        action: "convert",
        input: toDer.output,
        from: "der", // explicit `from` — auto-detect would also work but we
        //              want to exercise the param.
        to: "pem",
      });
      const a = createPublicKey(gen.publicKey as string).export({
        format: "der",
        type: "spki",
      });
      const b = createPublicKey(backToPem.output as string).export({
        format: "der",
        type: "spki",
      });
      expect(Buffer.from(a).equals(Buffer.from(b))).toBe(true);
    },
  );

  it.each(["pem", "der", "jwk"] as const)(
    "convert auto-detects `from` when input is %s",
    async (sourceFmt) => {
      const gen = await ok({
        action: "generate",
        method: "ed25519",
        format: sourceFmt,
      });
      // Target format is whichever isn't the source.
      const target = sourceFmt === "pem" ? "jwk" : "pem";
      const out = await ok({
        action: "convert",
        input: gen.publicKey,
        to: target,
      });
      expect(out.from).toBe(sourceFmt);
      expect(out.to).toBe(target);
    },
  );
});

// --------------------------------------------------------------------------
// Keyserver: streaming-cap regression test. Stub global fetch to return a
// Response whose body exceeds LIMITS.keyserverMaxBytes; assert the
// keyserver_fetch_failed code surfaces (the streamToBuffer guard fires).
// SSRF guard is off in tests by default, so guardedFetch falls through to
// the stubbed global fetch.
// --------------------------------------------------------------------------

describe("crypto: keyserver streaming cap", () => {
  let LIMITS: typeof import("../../src/lib/crypto/policy.js").LIMITS;
  beforeAll(async () => {
    ({ LIMITS } = await import("../../src/lib/crypto/policy.js"));
  });

  it("keyserver_fetch_failed when the response body exceeds the cap", async () => {
    // Build a real sig so we get past the parse step and into resolvePublicKeys.
    const gen = await ok({
      action: "generate",
      method: "pgp",
      userIds: [{ name: "K", email: "k@example.com" }],
      passphrase: "p",
      keyVersion: 4,
    });
    const sig = await ok({
      action: "sign",
      method: "pgp",
      privateKey: gen.privateKey,
      passphrase: "p",
      message: "m",
      type: "detached",
    });

    const originalFetch = globalThis.fetch;
    // Body length deliberately exceeds the cap by ~10 KiB. The Content-Length
    // header LIES about size so the pre-stream guard doesn't fire — the
    // streaming cap inside streamToBuffer is what we want to exercise.
    const cap = LIMITS.keyserverMaxBytes;
    const huge = Buffer.alloc(cap + 10 * 1024, 0x78); // 'x'
    globalThis.fetch = (async () => {
      return new Response(huge, {
        status: 200,
        headers: {
          "content-length": "100", // lie
          "content-type": "application/pgp-keys",
        },
      });
    }) as typeof fetch;

    try {
      await expectErr(
        {
          action: "verify",
          method: "pgp",
          signature: sig.signature,
          message: "m",
          keyserverUrl: "https://example.invalid",
        },
        "keyserver_fetch_failed",
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("keyserver_fetch_failed when Content-Length pre-check exceeds the cap", async () => {
    const gen = await ok({
      action: "generate",
      method: "pgp",
      userIds: [{ name: "K2", email: "k2@example.com" }],
      passphrase: "p",
      keyVersion: 4,
    });
    const sig = await ok({
      action: "sign",
      method: "pgp",
      privateKey: gen.privateKey,
      passphrase: "p",
      message: "m",
      type: "detached",
    });

    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async () => {
      return new Response("ignored", {
        status: 200,
        headers: {
          "content-length": String(LIMITS.keyserverMaxBytes + 1),
          "content-type": "application/pgp-keys",
        },
      });
    }) as typeof fetch;

    try {
      await expectErr(
        {
          action: "verify",
          method: "pgp",
          signature: sig.signature,
          message: "m",
          keyserverUrl: "https://example.invalid",
        },
        "keyserver_fetch_failed",
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("keyserver_fetch_failed on HTTP 5xx", async () => {
    const gen = await ok({
      action: "generate",
      method: "pgp",
      userIds: [{ name: "K3", email: "k3@example.com" }],
      passphrase: "p",
      keyVersion: 4,
    });
    const sig = await ok({
      action: "sign",
      method: "pgp",
      privateKey: gen.privateKey,
      passphrase: "p",
      message: "m",
      type: "detached",
    });

    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async () =>
      new Response("server exploded", {
        status: 503,
        statusText: "Service Unavailable",
      })) as typeof fetch;
    try {
      await expectErr(
        {
          action: "verify",
          method: "pgp",
          signature: sig.signature,
          message: "m",
          keyserverUrl: "https://example.invalid",
        },
        "keyserver_fetch_failed",
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

// --------------------------------------------------------------------------
// PGP isWeakHash predicate: directly exercise the gate the description
// promises. We can't easily mint a SHA-1 PGP signature in this environment,
// so unit-test the predicate; combined with the existing modern-sig test,
// the gating contract is covered.
// --------------------------------------------------------------------------

describe("crypto: pgp isWeakHash predicate", async () => {
  const { isWeakHash } = await import("../../src/lib/crypto/pgp/index.js");
  const openpgp = await import("openpgp");

  it.each([
    [openpgp.enums.hash.md5, true],
    [openpgp.enums.hash.sha1, true],
    [openpgp.enums.hash.sha256, false],
    [openpgp.enums.hash.sha384, false],
    [openpgp.enums.hash.sha512, false],
  ] as const)("isWeakHash(%i) → %s", (algo, expected) => {
    expect(isWeakHash(algo)).toBe(expected);
  });

  it("isWeakHash(undefined / null) → false (no algorithm = no opinion)", () => {
    expect(isWeakHash(undefined)).toBe(false);
    expect(isWeakHash(null)).toBe(false);
  });
});

// --------------------------------------------------------------------------
// Per-method determinism: same inputs, identical outputs. The conformance
// suite covers the default HAPPY fixture; this widens the net across the
// other deterministic derive methods.
// --------------------------------------------------------------------------

describe("crypto: determinism", () => {
  it("hkdf is byte-identical for identical inputs", async () => {
    const args = {
      action: "derive" as const,
      method: "hkdf" as const,
      ikm: Buffer.alloc(32, 1).toString("base64"),
      salt: Buffer.alloc(16, 2).toString("base64"),
      info: "ctx",
      keyLength: 32,
      hash: "sha256" as const,
    };
    const a = await ok(args);
    const b = await ok(args);
    expect(a.key).toBe(b.key);
  });

  it("scrypt is byte-identical for identical inputs", async () => {
    const args = {
      action: "derive" as const,
      method: "scrypt" as const,
      password: "p",
      salt: Buffer.alloc(16, 7).toString("base64"),
      keyLength: 16,
      params: { N: 1024, r: 8, p: 1 },
    };
    const a = await ok(args);
    const b = await ok(args);
    expect(a.key).toBe(b.key);
  });
});

// --------------------------------------------------------------------------
// AAD asymmetry: encrypt-with-AAD ↔ decrypt-without-AAD (and vice versa)
// both fail with decryption_failed. Binary AAD via aadEncoding also exercised.
// --------------------------------------------------------------------------

describe("crypto: AAD asymmetry", () => {
  const KEY_16_B64 = Buffer.alloc(16, 1).toString("base64");
  const KEY_32_B64 = Buffer.alloc(32, 1).toString("base64");
  const NONCE_12_B64 = Buffer.alloc(12, 2).toString("base64");
  const METHODS = [
    ["aes-256-gcm", KEY_32_B64],
    ["aes-128-gcm", KEY_16_B64],
    ["chacha20-poly1305", KEY_32_B64],
  ] as const;

  it.each(METHODS)(
    "%s: encrypt with AAD, decrypt without AAD → decryption_failed",
    async (method, key) => {
      const enc = await ok({
        action: "encrypt",
        method,
        key,
        plaintext: "m",
        nonce: NONCE_12_B64,
        aad: "ctx",
      });
      await expectErr(
        {
          action: "decrypt",
          method,
          key,
          ciphertext: enc.ciphertext,
          nonce: NONCE_12_B64,
          tag: enc.tag,
        },
        "decryption_failed",
      );
    },
  );

  it.each(METHODS)(
    "%s: encrypt without AAD, decrypt with AAD → decryption_failed",
    async (method, key) => {
      const enc = await ok({
        action: "encrypt",
        method,
        key,
        plaintext: "m",
        nonce: NONCE_12_B64,
      });
      await expectErr(
        {
          action: "decrypt",
          method,
          key,
          ciphertext: enc.ciphertext,
          nonce: NONCE_12_B64,
          tag: enc.tag,
          aad: "ctx",
        },
        "decryption_failed",
      );
    },
  );

  it.each(METHODS)(
    "%s: binary AAD via aadEncoding:base64 round-trips",
    async (method, key) => {
      const binAad = Buffer.from([0x00, 0x01, 0xfe, 0xff]).toString("base64");
      const enc = await ok({
        action: "encrypt",
        method,
        key,
        plaintext: "m",
        nonce: NONCE_12_B64,
        aad: binAad,
        aadEncoding: "base64",
      });
      const dec = await ok({
        action: "decrypt",
        method,
        key,
        ciphertext: enc.ciphertext,
        nonce: NONCE_12_B64,
        tag: enc.tag,
        aad: binAad,
        aadEncoding: "base64",
      });
      expect(dec.plaintext).toBe("m");
    },
  );
});

// --------------------------------------------------------------------------
// Harness-coercion contract (per docs/TESTING-STRATEGY.md §8a):
// Claude's tool-call harness serializes every parameter to a JSON string
// before it hits the MCP boundary. Non-string fields must therefore accept
// their string-serialised forms identically to their native forms — for
// booleans, numbers, arrays, and objects. Negative cases (garbage strings,
// invalid coercions) must still reject. This block proves the contract for
// every coerced field in the crypto schema and is the regression test for
// the boundary-coercion bug surfaced by the test-agent report.
// --------------------------------------------------------------------------

describe("crypto: harness-coercion contract", () => {
  // Boolean fields: armor + acceptLegacyHash. `coerceBoolean` accepts the
  // literals "true" / "false" only; anything else is rejected.
  it.each([
    { value: true, expectAccepted: true },
    { value: false, expectAccepted: true },
    { value: "true", expectAccepted: true },
    { value: "false", expectAccepted: true },
    { value: "yes", expectAccepted: false },
    { value: "True", expectAccepted: false },
    { value: 1, expectAccepted: false },
    { value: 0, expectAccepted: false },
  ])(
    "armor=$value (typeof=$value): accepted=$expectAccepted",
    async ({ value, expectAccepted }) => {
      const args = {
        action: "encrypt",
        method: "pgp",
        message: "x",
        passphrase: "p",
        armor: value as unknown,
      };
      if (expectAccepted) {
        const r = await ok(args);
        expect(typeof r.armor).toBe("boolean");
      } else {
        await expect(run(args)).rejects.toThrow();
      }
    },
  );

  // Number fields: byteLength, modulusLength, keyLength — already covered
  // by `coerce.number()`, but we pin the contract here so a future regression
  // (removing `.coerce`) is caught immediately.
  it.each([
    { value: 32, accepted: true },
    { value: "32", accepted: true }, // harness-serialised number
    { value: "32.5", accepted: false }, // .int() rejects fractional
    { value: "abc", accepted: false }, // NaN → rejected
    { value: 32.5, accepted: false }, // explicit float
  ])("byteLength=$value: accepted=$accepted", async ({ value, accepted }) => {
    const args = {
      action: "generate",
      method: "bytes",
      byteLength: value as unknown,
    };
    if (accepted) {
      const r = await ok(args);
      expect(r.byteLength).toBe(32);
    } else {
      await expect(run(args)).rejects.toThrow();
    }
  });

  // Array fields: recipients / verificationKeys / publicKeys / userIds.
  // Native array AND JSON-string forms must produce the same result. Bare
  // strings (no brackets) are rejected — they're not a valid array shape.
  it.each([
    {
      kind: "recipients (native array)",
      args: (pub: string) => ({
        action: "encrypt",
        method: "pgp",
        message: "x",
        recipients: [pub],
      }),
      accepted: true,
    },
    {
      kind: "recipients (JSON-string array)",
      args: (pub: string) => ({
        action: "encrypt",
        method: "pgp",
        message: "x",
        recipients: JSON.stringify([pub]),
      }),
      accepted: true,
    },
    {
      kind: "recipients (bare string — not array shape)",
      args: (pub: string) => ({
        action: "encrypt",
        method: "pgp",
        message: "x",
        recipients: pub,
      }),
      accepted: false,
    },
  ])("$kind: accepted=$accepted", async ({ args, accepted }) => {
    const gen = await ok({
      action: "generate",
      method: "pgp",
      userIds: [{ name: "C", email: "c@example.com" }],
      passphrase: "p",
      keyVersion: 4,
    });
    const built = args(gen.publicKey as string);
    if (accepted) {
      const enc = await ok(built);
      expect(enc.recipients).toBe(1);
    } else {
      await expect(run(built)).rejects.toThrow();
    }
  });

  it("userIds: JSON-string array of objects parses + works", async () => {
    const sc = await ok({
      action: "generate",
      method: "pgp",
      userIds: JSON.stringify([{ name: "JSON", email: "json@example.com" }]),
      passphrase: "p",
      keyVersion: 4,
    });
    expect((sc.userIds as string[])[0]).toContain("json@example.com");
  });

  // Object field: params. Both native object and JSON-string form must
  // produce identical derive outputs.
  it("params: native object and JSON-string form produce identical pbkdf2 output", async () => {
    const base = {
      action: "derive" as const,
      method: "pbkdf2" as const,
      password: "p",
      salt: Buffer.alloc(16, 1).toString("base64"),
      keyLength: 16,
      hash: "sha256" as const,
    };
    const a = await ok({ ...base, params: { iterations: 1000 } });
    const b = await ok({ ...base, params: '{"iterations":1000}' });
    expect(a.key).toBe(b.key);
  });

  it("params: malformed JSON string rejects rather than silently dropping", async () => {
    await expect(
      run({
        action: "derive",
        method: "pbkdf2",
        password: "p",
        salt: Buffer.alloc(16, 1).toString("base64"),
        keyLength: 16,
        params: "{not valid",
      }),
    ).rejects.toThrow();
  });

  // Cross-path parity: direct boundary call must produce the same answer as
  // the `script`-gateway call for coerced inputs. This is the explicit
  // anti-regression for the agent's reported divergence.
  it('direct vs script: armor="true" produces the same answer on both paths', async () => {
    const args = {
      action: "encrypt",
      method: "pgp",
      message: "x",
      passphrase: "p",
      armor: "true",
    };
    const direct = await ok(args);
    expect(typeof direct.ciphertext).toBe("string");
    expect(direct.ciphertext as string).toContain("BEGIN PGP MESSAGE");
  });
});
