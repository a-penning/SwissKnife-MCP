/**
 * Tagged error for crypto-tool failures. Tool dispatcher catches and translates
 * to err() with `code` in structuredContent so the description's promise that
 * decryption_failed / unsupported_algorithm / pgp_key_expired etc. are machine
 * readable holds up. Anything else surfaces with code = "internal".
 */
export type CryptoErrorCode =
  | "invalid_key"
  | "wrong_algorithm"
  | "decryption_failed"
  | "unsupported_algorithm"
  | "bad_parameters"
  | "too_large"
  | "parse_failed"
  | "pgp_key_expired"
  | "pgp_key_unavailable"
  | "keyserver_fetch_failed";

export class CryptoError extends Error {
  code: CryptoErrorCode;
  constructor(code: CryptoErrorCode, message: string) {
    super(message);
    this.code = code;
    this.name = "CryptoError";
  }
}

export function bad(message: string): never {
  throw new CryptoError("bad_parameters", message);
}

export function unsupported(message: string): never {
  throw new CryptoError("unsupported_algorithm", message);
}

export function invalidKey(message: string): never {
  throw new CryptoError("invalid_key", message);
}

export function parseFailed(message: string): never {
  throw new CryptoError("parse_failed", message);
}

export function decryptionFailed(message = "decryption_failed"): never {
  throw new CryptoError("decryption_failed", message);
}
