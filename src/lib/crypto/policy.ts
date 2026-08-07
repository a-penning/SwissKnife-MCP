import { bad, CryptoError, unsupported } from "./errors.js";

/** AEAD methods supported for {@link symmetric encrypt / decrypt}. */
export const AEAD_METHODS = [
  "aes-256-gcm",
  "aes-128-gcm",
  "chacha20-poly1305",
] as const;
export type AeadMethod = (typeof AEAD_METHODS)[number];

export const ASYMMETRIC_ENCRYPT_METHODS = ["rsa-oaep"] as const;
export type AsymmetricEncryptMethod =
  (typeof ASYMMETRIC_ENCRYPT_METHODS)[number];

export const ENCRYPT_METHODS = [
  ...AEAD_METHODS,
  ...ASYMMETRIC_ENCRYPT_METHODS,
  "pgp",
] as const;
export type EncryptMethod = (typeof ENCRYPT_METHODS)[number];

export const SIGN_METHODS = [
  "ed25519",
  "ecdsa",
  "rsa-pss",
  "rsa-pkcs1",
  "pgp",
] as const;
export type SignMethod = (typeof SIGN_METHODS)[number];

export const GENERATE_METHODS = [
  "bytes",
  "rsa",
  "ec",
  "ed25519",
  "x25519",
  "secp256k1",
  "pgp",
] as const;
export type GenerateMethod = (typeof GENERATE_METHODS)[number];

export const DERIVE_METHODS = [
  "argon2id",
  "scrypt",
  "pbkdf2",
  "hkdf",
  "ecdh",
] as const;
export type DeriveMethod = (typeof DERIVE_METHODS)[number];

export const HASHES = ["sha256", "sha384", "sha512"] as const;
export type Hash = (typeof HASHES)[number];

/** Curves accepted by `generate method:"ec"`. */
export const EC_CURVES = ["P-256", "P-384", "P-521"] as const;
export type EcCurve = (typeof EC_CURVES)[number];

/** Symmetric AEAD key lengths by method (bytes). */
const AEAD_KEY_BYTES: Record<AeadMethod, number> = {
  "aes-256-gcm": 32,
  "aes-128-gcm": 16,
  "chacha20-poly1305": 32,
};

const AEAD_NONCE_BYTES: Record<AeadMethod, number> = {
  "aes-256-gcm": 12,
  "aes-128-gcm": 12,
  "chacha20-poly1305": 12,
};

export function aeadKeyBytes(method: AeadMethod): number {
  return AEAD_KEY_BYTES[method];
}

export function aeadNonceBytes(method: AeadMethod): number {
  return AEAD_NONCE_BYTES[method];
}

/**
 * Hard limits from the proposal — caps exist to bound DoS via runaway KDF /
 * keygen cost. Hitting a cap returns `bad_parameters` or `too_large`, never a
 * hang. The defaults are conservative; the maximums protect a shared host.
 */
export const LIMITS = {
  maxInputBytes: 16 * 1024 * 1024,
  pgpRecipients: 32,
  pbkdf2MaxIterations: 10_000_000,
  scryptMaxN: 1 << 20,
  scryptMaxMemBytes: 256 * 1024 * 1024,
  argon2MaxMemKiB: 1 * 1024 * 1024,
  argon2MaxTime: 10,
  argon2MaxParallelism: 16,
  rsaMaxModulus: 8192,
  rsaMinModulus: 2048,
  keyserverTimeoutMs: 5_000,
  keyserverMaxBytes: 256 * 1024,
} as const;

export function assertHash(name: string): Hash {
  if ((HASHES as readonly string[]).includes(name)) return name as Hash;
  return unsupported(
    `unsupported hash ${JSON.stringify(name)} — supported: ${HASHES.join(", ")}`,
  );
}

export function assertRsaModulus(bits: number): number {
  if (!Number.isInteger(bits) || bits < 1024) {
    bad(`modulusLength must be an integer ≥ 1024 (got ${bits})`);
  }
  if (bits > LIMITS.rsaMaxModulus) {
    bad(
      `modulusLength ${bits} exceeds cap ${LIMITS.rsaMaxModulus} — keygen would take minutes`,
    );
  }
  return bits;
}

export function assertEcCurve(curve: string): EcCurve {
  if ((EC_CURVES as readonly string[]).includes(curve)) {
    return curve as EcCurve;
  }
  return unsupported(
    `unsupported curve ${JSON.stringify(curve)} — supported: ${EC_CURVES.join(", ")}`,
  );
}

export function assertByteLength(
  bytes: Buffer | Uint8Array,
  expected: number,
  label: string,
): void {
  if (bytes.length !== expected) {
    bad(`${label} must be ${expected} bytes (got ${bytes.length})`);
  }
}

export function assertInputSize(byteLength: number, label = "input"): void {
  if (byteLength > LIMITS.maxInputBytes) {
    throw new CryptoError(
      "too_large",
      `${label} ${byteLength} bytes exceeds cap ${LIMITS.maxInputBytes}`,
    );
  }
}
