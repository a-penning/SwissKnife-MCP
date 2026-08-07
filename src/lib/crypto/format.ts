import { Buffer } from "node:buffer";
import { createPrivateKey, createPublicKey, type KeyObject } from "node:crypto";

type JsonWebKey = {
  kty?: string;
  d?: string;
  k?: string;
  [key: string]: unknown;
};

import { toMessage } from "../errors.js";
import { decodeStrictBase64 } from "../strict-codec.js";
import { CryptoError, invalidKey, parseFailed } from "./errors.js";

export type RawKeyFormat = "pem" | "der" | "jwk";

const PEM_RE = /-----BEGIN [^-]+-----[\s\S]+?-----END [^-]+-----/;

export function detectKeyFormat(input: string): RawKeyFormat {
  const trimmed = input.trim();
  if (PEM_RE.test(trimmed)) return "pem";
  if (trimmed.startsWith("{")) return "jwk";
  // Anything else we treat as base64-encoded DER. The conversion will fail
  // loud below if the bytes don't parse.
  return "der";
}

/** Load a private or public key from PEM / DER (base64) / JWK source. */
export function parseKey(
  input: string,
  hint?: { from?: RawKeyFormat; isPrivate?: boolean },
): KeyObject {
  const from = hint?.from ?? detectKeyFormat(input);
  try {
    if (from === "pem") {
      const trimmed = input.trim();
      if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(trimmed)) {
        return createPrivateKey({ key: trimmed, format: "pem" });
      }
      if (
        /-----BEGIN PUBLIC KEY-----/.test(trimmed) ||
        /-----BEGIN CERTIFICATE-----/.test(trimmed) ||
        /-----BEGIN RSA PUBLIC KEY-----/.test(trimmed)
      ) {
        return createPublicKey({ key: trimmed, format: "pem" });
      }
      invalidKey("PEM block is neither a recognised public nor private key");
    }
    if (from === "jwk") {
      const parsed = JSON.parse(input) as JsonWebKey;
      const looksPrivate = jwkLooksPrivate(parsed);
      // biome-ignore lint/suspicious/noExplicitAny: createPrivateKey/createPublicKey jwk overload
      const jwkArg = parsed as any;
      if (looksPrivate) {
        return createPrivateKey({ key: jwkArg, format: "jwk" });
      }
      return createPublicKey({ key: jwkArg, format: "jwk" });
    }
    // DER — base64-encoded.
    const bytes = decodeStrictBase64(input.replace(/\s+/g, ""), "der base64");
    if (hint?.isPrivate) {
      return createPrivateKey({ key: bytes, format: "der", type: "pkcs8" });
    }
    // Try public first; fall back to private (PKCS#8) on failure so callers
    // don't need to declare the side they have.
    try {
      return createPublicKey({ key: bytes, format: "der", type: "spki" });
    } catch {
      return createPrivateKey({ key: bytes, format: "der", type: "pkcs8" });
    }
  } catch (e) {
    if (e instanceof CryptoError) throw e;
    parseFailed(`could not parse key: ${toMessage(e)}`);
  }
}

function jwkLooksPrivate(jwk: JsonWebKey): boolean {
  if (jwk.kty === "RSA") return jwk.d !== undefined;
  if (jwk.kty === "EC") return jwk.d !== undefined;
  if (jwk.kty === "OKP") return jwk.d !== undefined;
  if (jwk.kty === "oct") return jwk.k !== undefined;
  return false;
}

export interface ConvertResult {
  from: RawKeyFormat;
  to: RawKeyFormat;
  output: string;
  isPrivate: boolean;
}

export function convertKey(
  input: string,
  to: RawKeyFormat,
  hint?: { from?: RawKeyFormat },
): ConvertResult {
  const from = hint?.from ?? detectKeyFormat(input);
  const key = parseKey(input, { from });
  const isPrivate = key.type === "private";
  const output = serialiseKey(key, to, isPrivate);
  return { from, to, output, isPrivate };
}

export function serialiseKey(
  key: KeyObject,
  to: RawKeyFormat,
  isPrivate: boolean,
): string {
  if (to === "pem") {
    const exported = isPrivate
      ? key.export({ format: "pem", type: "pkcs8" })
      : key.export({ format: "pem", type: "spki" });
    // PEM is documented as a string in modern Node; coerce defensively in
    // case future versions return Buffer.
    return typeof exported === "string"
      ? exported
      : Buffer.from(exported as Buffer).toString("utf8");
  }
  if (to === "der") {
    const der = isPrivate
      ? key.export({ format: "der", type: "pkcs8" })
      : key.export({ format: "der", type: "spki" });
    return Buffer.from(der as Buffer).toString("base64");
  }
  if (to === "jwk") {
    const jwk = key.export({ format: "jwk" });
    return JSON.stringify(jwk);
  }
  // Defensive: any other value (e.g. an undefined slipping past a direct
  // handler call) is a bug. Fail loud with bad_parameters rather than picking
  // a silent default.
  throw new CryptoError(
    "bad_parameters",
    `convert requires \`to\`; got ${JSON.stringify(to)}`,
  );
}
