import { z } from "zod";
import { aeadDecrypt, aeadEncrypt } from "../lib/crypto/aead.js";
import {
  asymmetricSign,
  asymmetricVerify,
  rsaOaepDecrypt,
  rsaOaepEncrypt,
} from "../lib/crypto/asymmetric.js";
import {
  deriveArgon2id,
  deriveEcdh,
  deriveHkdf,
  derivePbkdf2,
  deriveScrypt,
} from "../lib/crypto/derive.js";
import { CryptoError } from "../lib/crypto/errors.js";
import { convertKey } from "../lib/crypto/format.js";
import { generateBytes, generateRawKeypair } from "../lib/crypto/generate.js";
import { inspectRawKey } from "../lib/crypto/inspect.js";
import {
  detectPgp,
  inspectPgpKey,
  inspectPgpMessage,
  pgpDecrypt,
  pgpEncrypt,
  pgpGenerate,
  pgpSign,
  pgpVerify,
} from "../lib/crypto/pgp/index.js";
import {
  AEAD_METHODS,
  type AeadMethod,
  DERIVE_METHODS,
  EC_CURVES,
  ENCRYPT_METHODS,
  GENERATE_METHODS,
  HASHES,
  type Hash,
  SIGN_METHODS,
} from "../lib/crypto/policy.js";
import { toMessage } from "../lib/errors.js";
import {
  coerceBoolean,
  defineTool,
  err,
  jsonObjectArg,
  ok,
  okJson,
} from "./types.js";

const DESCRIPTION = `General-purpose crypto primitives. Eight actions. Where an operation has variants, \`method\` names the algorithm directly — no separate \`algorithm\` field.

encrypt — produces ciphertext.
  "aes-256-gcm" (default) / "aes-128-gcm" / "chacha20-poly1305" — AEAD. Needs \`key\`, \`plaintext\`; auto-generates 12-byte \`nonce\` unless supplied; optional \`aad\`. Returns \`{ciphertext, nonce, tag, method, encoding}\` — pass them all back to \`decrypt\` (or concatenate ciphertext||tag and omit \`tag\` — both forms accepted). Reusing a (key, nonce) pair on GCM catastrophically breaks confidentiality.
  "rsa-oaep" — needs \`publicKey\`, \`plaintext\`; \`oaepHash\` default "sha256"; plaintext capped by modulus.
  "pgp" — needs \`message\` plus \`recipients\` (array of PGP public-key blocks) OR \`passphrase\` (symmetric). Optional \`signingKey\` + \`signingPassphrase\`, \`armor\` (default true), \`preferredCipher\`.

decrypt — mirrors encrypt's methods (swap public/private, swap ciphertext/plaintext). \`plaintextEncoding\` selects the returned text form (default "utf8"; set "base64"/"hex" for binary payloads). All failure modes return \`decryption_failed\` — single bucket; failure mode isn't leaked.

sign — produces a detached signature.
  "ed25519" / "ecdsa" / "rsa-pss" (default for RSA) / "rsa-pkcs1" (legacy). Needs \`privateKey\`, \`message\`; \`hash\` default "sha256".
  "pgp" — needs \`privateKey\`, \`passphrase\`, \`message\`. Optional \`type\`: "detached" (default) / "cleartext" / "inline".

verify — failure → \`{valid: false}\`, NOT an error.
  Asymmetric: needs \`publicKey\`, \`message\`, \`signature\`.
  "pgp" — needs \`signature\` plus \`publicKeys\` OR \`keyserverUrl\` (HKP and VKS supported; must be https://; SSRF-guarded; size-capped). Detached also needs \`message\`. Refuses SHA-1 / MD5 signatures unless \`acceptLegacyHash: true\`.

generate
  "bytes" — random symmetric bytes; needs \`byteLength\`.
  "rsa" / "ec" / "ed25519" (default) / "x25519" / "secp256k1" — raw keypair. RSA: \`modulusLength\` (default 3072). EC: \`curve\` (P-256/384/521).
  "pgp" — OpenPGP keypair; needs \`userIds\`, \`passphrase\`. Defaults Ed25519+X25519, v6 keys, no expiry. Override via \`encryptionSubkey\` ("rsa" / "p256" / "p384" / "p521").

derive
  "argon2id" (default) — password-based. Needs \`password\`, \`keyLength\`; auto-generates \`salt\` (always returned). Tune via \`params: {memory, iterations, parallelism}\`.
  "scrypt" — password-based. Same shape; tune via \`params: {N, r, p}\`.
  "pbkdf2" — password-based. Same shape; tune via \`params: {iterations}\`. \`hash\` selects the PRF.
  "hkdf" — from key material; needs \`ikm\`, \`keyLength\`; optional \`salt\`, \`info\`.
  "ecdh" — agreement (X25519 / ECDH-P256/384/521). Needs \`privateKey\`, \`peerPublicKey\`. Output is raw shared secret — chain with hkdf before use.

inspect — auto-detects input (PEM, DER, JWK, PGP armored, PGP binary via inputEncoding:"base64"). Returns type, fingerprint, expiry, user IDs, subkeys. Public metadata only; never echoes private material.

convert — raw key format conversion: PEM ↔ DER ↔ JWK. Auto-detects \`from\`; \`to\` is required. PGP keys don't participate.

Anything not listed returns \`unsupported_algorithm\`. Notable refusals: AES-CBC/CTR (no AEAD), RSA-PKCS1-v1_5 encryption, MD5/SHA-1 for new signing.

Byte-typed string fields also accept a literal \`base64:\` / \`hex:\` prefix as an inline encoding tag.

Private keys and passphrases passed in are never echoed back. Private material is only returned by \`generate\` and \`convert\`. All randomness from OS CSPRNG.`;

const ENCODING_IN = z.enum(["utf8", "base64", "hex"]);
const ENCODING_OUT = z.enum(["utf8", "base64", "hex"]);
const KEY_FORMAT = z.enum(["pem", "der", "jwk"]);

const PGP_USER_ID = z.object({
  name: z.string().min(1),
  email: z.string().email(),
});

const inputSchema = {
  action: z.enum([
    "encrypt",
    "decrypt",
    "sign",
    "verify",
    "generate",
    "derive",
    "inspect",
    "convert",
  ]),
  method: z
    .string()
    .optional()
    .describe(
      "Algorithm name. encrypt/decrypt: aes-256-gcm (default) / aes-128-gcm / chacha20-poly1305 / rsa-oaep / pgp. sign/verify: ed25519 / ecdsa / rsa-pss / rsa-pkcs1 / pgp. generate: bytes / rsa / ec / ed25519 (default) / x25519 / secp256k1 / pgp. derive: argon2id (default) / scrypt / pbkdf2 / hkdf / ecdh.",
    ),

  // ---- shared encoding / output controls ----
  inputEncoding: ENCODING_IN.default("utf8").describe(
    "How to interpret string-bytes inputs (plaintext, message, ikm, salt, info, password, aad).",
  ),
  outputEncoding: ENCODING_OUT.default("base64").describe(
    "How byte outputs (ciphertext, signature, nonce, derived key, random bytes) are encoded.",
  ),

  // ---- AEAD / RSA-OAEP shared ----
  key: z
    .string()
    .optional()
    .describe(
      "Symmetric key bytes for AEAD encrypt/decrypt. Honoured `base64:`/`hex:` shorthand or `inputEncoding`.",
    ),
  publicKey: z
    .string()
    .optional()
    .describe("PEM / DER (base64) / JWK / PGP public key."),
  privateKey: z
    .string()
    .optional()
    .describe("PEM / DER (base64) / JWK / PGP private key. Never echoed back."),
  plaintext: z
    .string()
    .optional()
    .describe("Plaintext to encrypt (encoded per inputEncoding)."),
  ciphertext: z
    .string()
    .optional()
    .describe(
      "Ciphertext to decrypt (base64 unless ciphertextEncoding overrides).",
    ),
  ciphertextEncoding: ENCODING_IN.default("base64").describe(
    "How to read ciphertext bytes for AEAD/RSA-OAEP decrypt.",
  ),
  plaintextEncoding: ENCODING_OUT.default("utf8").describe(
    "How to return decrypted plaintext (decrypt only). `utf8` for text payloads (default), `base64`/`hex` for binary.",
  ),
  nonce: z
    .string()
    .optional()
    .describe(
      "AEAD nonce (12 bytes). Auto-generated by encrypt if omitted; required by decrypt.",
    ),
  nonceEncoding: ENCODING_IN.default("base64"),
  tag: z
    .string()
    .optional()
    .describe(
      "AEAD auth tag (16 bytes). When omitted on decrypt, the last 16 bytes of `ciphertext` are taken as the tag.",
    ),
  tagEncoding: ENCODING_IN.default("base64"),
  aad: z
    .string()
    .optional()
    .describe("Additional authenticated data for AEAD."),
  aadEncoding: ENCODING_IN.default("utf8"),
  oaepHash: z
    .enum(HASHES)
    .default("sha256")
    .describe("RSA-OAEP hash function."),

  // ---- sign / verify ----
  message: z
    .string()
    .optional()
    .describe("Message bytes to sign or verify. Encoded per inputEncoding."),
  signature: z
    .string()
    .optional()
    .describe(
      "Detached signature bytes (raw) or armored PGP signature/cleartext.",
    ),
  signatureEncoding: ENCODING_IN.default("base64"),
  hash: z
    .enum(HASHES)
    .default("sha256")
    .describe("Hash for ECDSA / RSA-PSS / RSA-PKCS1 / HKDF / PBKDF2."),

  // ---- generate ----
  byteLength: z.coerce
    .number()
    .int()
    .min(1)
    .max(1024)
    .optional()
    .describe('`generate method:"bytes"`: number of random bytes.'),
  modulusLength: z.coerce
    .number()
    .int()
    .optional()
    .describe('`generate method:"rsa"`: bits. Default 3072; cap 8192.'),
  curve: z
    .enum(EC_CURVES)
    .optional()
    .describe('`generate method:"ec"`: NIST curve.'),
  format: KEY_FORMAT.default("pem").describe(
    "`generate`/`convert`: raw key serialisation (ignored for PGP).",
  ),

  // ---- generate / sign / verify / decrypt (pgp) shared ----
  armor: coerceBoolean(true).describe(
    "PGP: ASCII-armor the output. `false` returns base64-encoded binary packets.",
  ),
  passphrase: z
    .string()
    .optional()
    .describe(
      'PGP private key passphrase, or symmetric password for `encrypt method:"pgp"`.',
    ),
  signingKey: z
    .string()
    .optional()
    .describe(
      '`encrypt method:"pgp"`: optional private key to also sign with.',
    ),
  signingPassphrase: z
    .string()
    .optional()
    .describe("Passphrase for `signingKey`."),
  recipients: jsonObjectArg(z.array(z.string()))
    .optional()
    .describe('`encrypt method:"pgp"`: array of recipient public-key blocks.'),
  verificationKeys: jsonObjectArg(z.array(z.string()))
    .optional()
    .describe(
      '`decrypt method:"pgp"`: optional public keys to verify embedded signatures.',
    ),
  publicKeys: jsonObjectArg(z.array(z.string()))
    .optional()
    .describe('`verify method:"pgp"`: candidate public keys.'),
  keyserverUrl: z
    .string()
    .url()
    .refine((u) => u.startsWith("https://"), {
      message:
        "keyserverUrl must use https:// (key fetches require an integrity-protected channel)",
    })
    .optional()
    .describe(
      '`verify method:"pgp"`: base URL of an HKPS or VKS server (e.g. https://keys.openpgp.org). Must be https://. SSRF-guarded.',
    ),
  acceptLegacyHash: coerceBoolean(false).describe(
    '`verify method:"pgp"`: allow SHA-1 / MD5 signatures. Off by default.',
  ),
  type: z
    .enum(["detached", "cleartext", "inline"])
    .default("detached")
    .describe('`sign method:"pgp"` signature type.'),
  preferredCipher: z
    .enum([
      "aes-256-ocb",
      "aes-256-gcm",
      "aes-128-gcm",
      "chacha20-poly1305",
      "aes-256-cfb",
      "aes-128-cfb",
    ])
    .optional()
    .describe(
      '`encrypt method:"pgp"`: symmetric cipher inside the PGP envelope.',
    ),
  userIds: jsonObjectArg(z.array(PGP_USER_ID))
    .optional()
    .describe('`generate method:"pgp"`: identity packets.'),
  encryptionSubkey: z
    .enum(["x25519", "rsa", "p256", "p384", "p521"])
    .optional()
    .describe('`generate method:"pgp"`: encryption subkey type.'),
  keyVersion: z
    .union([z.literal(4), z.literal(6)])
    .default(6)
    .describe('`generate method:"pgp"`: OpenPGP key version.'),
  expiresIn: z
    .string()
    .optional()
    .describe(
      '`generate method:"pgp"`: ISO-8601 duration (e.g. "P2Y") or seconds. Omit for no expiry.',
    ),

  // ---- derive ----
  password: z
    .string()
    .optional()
    .describe("Password-based KDF input (argon2id/scrypt/pbkdf2)."),
  passwordEncoding: ENCODING_IN.default("utf8"),
  salt: z
    .string()
    .optional()
    .describe(
      "Salt for password KDFs and HKDF. Auto-generated and returned if omitted.",
    ),
  saltEncoding: ENCODING_IN.default("base64"),
  keyLength: z.coerce
    .number()
    .int()
    .min(1)
    .max(1024)
    .optional()
    .describe("`derive`: output key bytes."),
  ikm: z
    .string()
    .optional()
    .describe('`derive method:"hkdf"`: input keying material.'),
  ikmEncoding: ENCODING_IN.default("base64"),
  info: z
    .string()
    .optional()
    .describe('`derive method:"hkdf"`: optional info parameter.'),
  infoEncoding: ENCODING_IN.default("utf8"),
  peerPublicKey: z
    .string()
    .optional()
    .describe('`derive method:"ecdh"`: other party\'s public key.'),
  params: jsonObjectArg(z.object({}).passthrough())
    .optional()
    .describe(
      "`derive`: method-specific tuning. argon2id: `{memory, iterations, parallelism}`; scrypt: `{N, r, p}`; pbkdf2: `{iterations}`. JSON-string forms accepted.",
    ),

  // ---- inspect / convert ----
  input: z
    .string()
    .optional()
    .describe(
      "`inspect`/`convert`: the key, message, signature, or other artefact.",
    ),
  from: KEY_FORMAT.optional().describe(
    "`convert`: override auto-detected source format.",
  ),
  to: KEY_FORMAT.optional().describe("`convert`: target format. Required."),
} as const;

type Args = z.infer<z.ZodObject<typeof inputSchema>>;

export const cryptoTool = defineTool({
  name: "crypto",
  title: "Cryptographic primitives",
  description: DESCRIPTION,
  inputSchema,
  refine: (args, ctx) => {
    if (args.action === "convert" && !args.to) {
      ctx.addIssue({
        code: "custom",
        message: "convert requires `to`",
        path: ["to"],
      });
    }
    if (
      (args.action === "inspect" || args.action === "convert") &&
      !args.input
    ) {
      ctx.addIssue({
        code: "custom",
        message: `${args.action} requires \`input\``,
        path: ["input"],
      });
    }
  },
  handler: async (args) => {
    try {
      switch (args.action) {
        case "encrypt":
          return await handleEncrypt(args);
        case "decrypt":
          return await handleDecrypt(args);
        case "sign":
          return await handleSign(args);
        case "verify":
          return await handleVerify(args);
        case "generate":
          return await handleGenerate(args);
        case "derive":
          return await handleDerive(args);
        case "inspect":
          return await handleInspect(args);
        case "convert":
          return handleConvert(args);
      }
    } catch (e) {
      if (e instanceof CryptoError) {
        return err(e.message, { code: e.code });
      }
      return err(toMessage(e));
    }
  },
});

/**
 * Resolve `args.method` against the allow-list for an action, applying a
 * default. Throws `unsupported_algorithm` if the value isn't accepted. Captures
 * the "default + validate + bail" pattern that used to appear at the top of
 * every handler.
 */
function resolveMethod<T extends string>(
  args: Args,
  action: string,
  allowed: readonly T[],
  fallback: T,
): T {
  const method = (args.method ?? fallback) as T;
  if (!(allowed as readonly string[]).includes(method)) {
    throw new CryptoError(
      "unsupported_algorithm",
      `unsupported ${action} method ${JSON.stringify(method)} — supported: ${allowed.join(", ")}`,
    );
  }
  return method;
}

async function handleEncrypt(args: Args) {
  const method = resolveMethod(args, "encrypt", ENCRYPT_METHODS, "aes-256-gcm");
  if ((AEAD_METHODS as readonly string[]).includes(method)) {
    requirePresent(args, ["key", "plaintext"]);
    const result = aeadEncrypt({
      method: method as AeadMethod,
      key: args.key as string,
      keyEncoding: "base64",
      plaintext: args.plaintext as string,
      inputEncoding: args.inputEncoding,
      outputEncoding: args.outputEncoding,
      nonce: args.nonce,
      nonceEncoding: args.nonceEncoding,
      aad: args.aad,
      aadEncoding: args.aadEncoding,
    });
    return okJson({ ...result });
  }
  if (method === "rsa-oaep") {
    requirePresent(args, ["publicKey", "plaintext"]);
    const result = rsaOaepEncrypt({
      publicKey: args.publicKey as string,
      plaintext: args.plaintext as string,
      inputEncoding: args.inputEncoding,
      outputEncoding: args.outputEncoding,
      oaepHash: args.oaepHash,
    });
    return okJson({ method, ...result });
  }
  // pgp
  requirePresent(args, ["message"]);
  if (!args.recipients?.length && !args.passphrase) {
    return err(
      "pgp encrypt requires `recipients` (public keys) or `passphrase` (symmetric)",
      { code: "bad_parameters" },
    );
  }
  const result = await pgpEncrypt({
    message: args.message as string,
    recipients: args.recipients,
    passphrase: args.passphrase,
    signingKey: args.signingKey,
    signingPassphrase: args.signingPassphrase,
    armor: args.armor,
    preferredCipher: args.preferredCipher,
  });
  return okJson({ method, ...result });
}

async function handleDecrypt(args: Args) {
  const method = resolveMethod(args, "decrypt", ENCRYPT_METHODS, "aes-256-gcm");
  if ((AEAD_METHODS as readonly string[]).includes(method)) {
    requirePresent(args, ["key", "ciphertext", "nonce"]);
    const result = aeadDecrypt({
      method: method as AeadMethod,
      key: args.key as string,
      keyEncoding: "base64",
      ciphertext: args.ciphertext as string,
      ciphertextEncoding: args.ciphertextEncoding,
      nonce: args.nonce as string,
      nonceEncoding: args.nonceEncoding,
      tag: args.tag,
      tagEncoding: args.tagEncoding,
      aad: args.aad,
      aadEncoding: args.aadEncoding,
      // Plaintext gets its own encoding field — `outputEncoding` (a byte-output
      // knob) used to be auto-switched here, which silently overrode an
      // explicit caller value.
      outputEncoding: args.plaintextEncoding,
    });
    return okJson({ ...result });
  }
  if (method === "rsa-oaep") {
    requirePresent(args, ["privateKey", "ciphertext"]);
    const result = rsaOaepDecrypt({
      privateKey: args.privateKey as string,
      ciphertext: args.ciphertext as string,
      ciphertextEncoding: args.ciphertextEncoding,
      outputEncoding: args.plaintextEncoding,
      oaepHash: args.oaepHash,
    });
    return okJson({ method, ...result });
  }
  // pgp
  requirePresent(args, ["ciphertext"]);
  const result = await pgpDecrypt({
    ciphertext: args.ciphertext as string,
    privateKey: args.privateKey,
    passphrase: args.passphrase,
    verificationKeys: args.verificationKeys,
  });
  return okJson({ method, ...result });
}

async function handleSign(args: Args) {
  const method = resolveMethod(args, "sign", SIGN_METHODS, "ed25519");
  if (method === "pgp") {
    requirePresent(args, ["privateKey", "message"]);
    const result = await pgpSign({
      privateKey: args.privateKey as string,
      passphrase: args.passphrase,
      message: args.message as string,
      type: args.type,
      armor: args.armor,
    });
    return okJson({ method, ...result });
  }
  requirePresent(args, ["privateKey", "message"]);
  const result = asymmetricSign({
    scheme: method as Exclude<(typeof SIGN_METHODS)[number], "pgp">,
    privateKey: args.privateKey as string,
    message: args.message as string,
    messageEncoding: args.inputEncoding,
    hash: args.hash,
    outputEncoding: args.outputEncoding,
  });
  return okJson({ method, ...result });
}

async function handleVerify(args: Args) {
  const method = resolveMethod(args, "verify", SIGN_METHODS, "ed25519");
  if (method === "pgp") {
    requirePresent(args, ["signature"]);
    const result = await pgpVerify({
      signature: args.signature as string,
      message: args.message,
      publicKeys: args.publicKeys,
      keyserverUrl: args.keyserverUrl,
      acceptLegacyHash: args.acceptLegacyHash,
    });
    return okJson({ method, ...result });
  }
  requirePresent(args, ["publicKey", "message", "signature"]);
  const result = asymmetricVerify({
    scheme: method as Exclude<(typeof SIGN_METHODS)[number], "pgp">,
    publicKey: args.publicKey as string,
    message: args.message as string,
    messageEncoding: args.inputEncoding,
    signature: args.signature as string,
    signatureEncoding: args.signatureEncoding,
    hash: args.hash,
  });
  return okJson({ method, ...result });
}

async function handleGenerate(args: Args) {
  const method = resolveMethod(args, "generate", GENERATE_METHODS, "ed25519");
  if (method === "bytes") {
    if (args.byteLength === undefined) {
      return err('`generate method:"bytes"` requires `byteLength`', {
        code: "bad_parameters",
      });
    }
    const result = generateBytes({
      byteLength: args.byteLength,
      outputEncoding: args.outputEncoding,
    });
    return okJson({ method, ...result });
  }
  if (method === "pgp") {
    if (!args.userIds?.length) {
      return err('`generate method:"pgp"` requires `userIds`', {
        code: "bad_parameters",
      });
    }
    if (!args.passphrase) {
      return err('`generate method:"pgp"` requires `passphrase`', {
        code: "bad_parameters",
      });
    }
    // encryptionSubkey: "rsa" picks an RSA keypair (signing + encrypt);
    // "p256"/"p384"/"p521" pick an ECC NIST curve; default (and "x25519")
    // gives the proposal's Ed25519+X25519 v6 default.
    const pgpType =
      args.encryptionSubkey === "rsa"
        ? "rsa"
        : args.encryptionSubkey === "p256" ||
            args.encryptionSubkey === "p384" ||
            args.encryptionSubkey === "p521"
          ? "ecc"
          : "ed25519";
    const pgpCurve =
      args.encryptionSubkey === "p256"
        ? "nistP256"
        : args.encryptionSubkey === "p384"
          ? "nistP384"
          : args.encryptionSubkey === "p521"
            ? "nistP521"
            : undefined;
    const result = await pgpGenerate({
      userIds: args.userIds,
      passphrase: args.passphrase,
      type: pgpType,
      ...(pgpCurve ? { curve: pgpCurve } : {}),
      keyVersion: args.keyVersion,
      expiresIn: parseExpiresInSeconds(args.expiresIn),
      format: args.armor ? "armored" : "binary",
    });
    return okJson({ method, ...result });
  }
  const result = generateRawKeypair({
    method: method as "rsa" | "ec" | "ed25519" | "x25519" | "secp256k1",
    modulusLength: args.modulusLength,
    curve: args.curve,
    format: args.format,
  });
  return okJson({ ...result });
}

async function handleDerive(args: Args) {
  const method = resolveMethod(args, "derive", DERIVE_METHODS, "argon2id");
  if (method === "argon2id" || method === "scrypt" || method === "pbkdf2") {
    requirePresent(args, ["password"]);
    if (args.keyLength === undefined) {
      return err(`\`derive method:"${method}"\` requires \`keyLength\``, {
        code: "bad_parameters",
      });
    }
    if (method === "argon2id") {
      const params = (args.params ?? {}) as Record<string, number>;
      const result = await deriveArgon2id({
        password: args.password as string,
        passwordEncoding: args.passwordEncoding,
        salt: args.salt,
        saltEncoding: args.saltEncoding,
        keyLength: args.keyLength,
        outputEncoding: args.outputEncoding,
        memory: params.memory ?? 65536,
        iterations: params.iterations ?? 3,
        parallelism: params.parallelism ?? 4,
      });
      return okJson({ ...result });
    }
    if (method === "scrypt") {
      const params = (args.params ?? {}) as Record<string, number>;
      const result = deriveScrypt({
        password: args.password as string,
        passwordEncoding: args.passwordEncoding,
        salt: args.salt,
        saltEncoding: args.saltEncoding,
        keyLength: args.keyLength,
        outputEncoding: args.outputEncoding,
        N: params.N ?? 1 << 15,
        r: params.r ?? 8,
        p: params.p ?? 1,
      });
      return okJson({ ...result });
    }
    // pbkdf2
    const params = (args.params ?? {}) as Record<string, number>;
    const result = derivePbkdf2({
      password: args.password as string,
      passwordEncoding: args.passwordEncoding,
      salt: args.salt,
      saltEncoding: args.saltEncoding,
      keyLength: args.keyLength,
      outputEncoding: args.outputEncoding,
      iterations: params.iterations ?? 600_000,
      hash: args.hash as Hash,
    });
    return okJson({ ...result });
  }
  if (method === "hkdf") {
    requirePresent(args, ["ikm"]);
    if (args.keyLength === undefined) {
      return err('`derive method:"hkdf"` requires `keyLength`', {
        code: "bad_parameters",
      });
    }
    const result = deriveHkdf({
      ikm: args.ikm as string,
      ikmEncoding: args.ikmEncoding,
      salt: args.salt,
      saltEncoding: args.saltEncoding,
      info: args.info,
      infoEncoding: args.infoEncoding,
      keyLength: args.keyLength,
      outputEncoding: args.outputEncoding,
      hash: args.hash,
    });
    return okJson({ ...result });
  }
  // ecdh
  requirePresent(args, ["privateKey", "peerPublicKey"]);
  const result = deriveEcdh({
    privateKey: args.privateKey as string,
    peerPublicKey: args.peerPublicKey as string,
    outputEncoding: args.outputEncoding,
  });
  return okJson({ ...result });
}

async function handleInspect(args: Args) {
  const input = args.input as string;
  const pgpKind = detectPgp(input);
  if (pgpKind === "pgp-key") {
    const result = await inspectPgpKey(input);
    return okJson({ ...result });
  }
  if (pgpKind === "pgp-message") {
    const result = await inspectPgpMessage(input);
    return okJson({ ...result });
  }
  if (pgpKind === "pgp-signature" || pgpKind === "pgp-cleartext") {
    return okJson({
      kind: pgpKind,
      info: 'use `action: "verify"` to validate this artefact',
    });
  }
  // Raw key — inspectRawKey does its own detectKeyFormat.
  const result = inspectRawKey(input);
  return okJson({ ...result });
}

function handleConvert(args: Args) {
  const input = args.input as string;
  if (!args.to) {
    // The refine hook catches this at the MCP boundary, but the script gateway
    // and direct unit-test calls bypass refine — guard explicitly so a missing
    // `to` is bad_parameters, never a silent default.
    throw new CryptoError("bad_parameters", "convert requires `to`");
  }
  const result = convertKey(input, args.to, { from: args.from });
  return ok(result.output, { ...result });
}

function requirePresent(args: Args, fields: Array<keyof Args>) {
  // Empty strings are accepted (encrypting "" is a legitimate AEAD use case);
  // only undefined/null trip the guard.
  for (const f of fields) {
    if (args[f] === undefined || args[f] === null) {
      throw new CryptoError(
        "bad_parameters",
        `${String(f)} is required for action \`${args.action}\` method \`${args.method ?? "(default)"}\``,
      );
    }
  }
}

function parseExpiresInSeconds(value: string | undefined): number | undefined {
  if (value === undefined) return undefined;
  // ISO-8601 simple duration (P\dY / P\dM / P\dD / PT\dH / PT\dM / PT\dS) or bare seconds.
  if (/^\d+$/.test(value)) return Number(value);
  const m =
    /^P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$/.exec(
      value,
    );
  if (!m) {
    throw new CryptoError(
      "bad_parameters",
      `invalid expiresIn ${JSON.stringify(value)} — use seconds or ISO-8601 duration (e.g. "P2Y")`,
    );
  }
  const [, y, mo, d, h, mi, s] = m;
  const secs =
    (Number(y) || 0) * 31_536_000 +
    (Number(mo) || 0) * 2_592_000 +
    (Number(d) || 0) * 86_400 +
    (Number(h) || 0) * 3_600 +
    (Number(mi) || 0) * 60 +
    (Number(s) || 0);
  return secs;
}
