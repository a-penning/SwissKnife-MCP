import { Buffer } from "node:buffer";
import { createHash, createPublicKey, type KeyObject } from "node:crypto";
import { toMessage } from "../errors.js";
import { CryptoError, parseFailed } from "./errors.js";
import { detectKeyFormat, parseKey, type RawKeyFormat } from "./format.js";

export interface RawKeyInspection {
  kind: "raw-key";
  format: RawKeyFormat;
  keyType: string;
  isPrivate: boolean;
  bits?: number;
  curve?: string;
  jwkThumbprintSha256: string;
  fingerprintSha256: string;
  details: Record<string, unknown>;
}

export function inspectRawKey(input: string): RawKeyInspection {
  const format = detectKeyFormat(input);
  let key: KeyObject;
  try {
    key = parseKey(input, { from: format });
  } catch (e) {
    if (e instanceof CryptoError) throw e;
    parseFailed(toMessage(e));
  }
  const isPrivate = key.type === "private";
  const details = key.asymmetricKeyDetails ?? {};
  // RFC 7638 JWK thumbprint, base64url-encoded — universal key fingerprint
  // for inspect even when the source isn't a JWK. Computed on the *public*
  // half so the same private/public pair share a thumbprint.
  const pubKey = isPrivate ? createPublicKey(key) : key;
  const jwk = pubKey.export({ format: "jwk" }) as Record<string, unknown> & {
    kty?: string;
  };
  const thumb = jwkThumbprint(jwk);
  // SHA-256 over the SPKI DER — same hash openssl prints for an SPKI pin.
  const derPub = Buffer.from(pubKey.export({ format: "der", type: "spki" }));
  const fingerprint = createHash("sha256").update(derPub).digest("base64");
  return {
    kind: "raw-key",
    format,
    keyType: key.asymmetricKeyType ?? "unknown",
    isPrivate,
    bits: "modulusLength" in details ? details.modulusLength : undefined,
    curve: "namedCurve" in details ? String(details.namedCurve) : undefined,
    jwkThumbprintSha256: thumb,
    fingerprintSha256: fingerprint,
    // Normalise asymmetricKeyDetails to JSON-serialisable values — RSA's
    // `publicExponent` ships as a BigInt which would otherwise throw at
    // serialisation time (the conformance suite's JSON-serialisability gate).
    // BigInts are surfaced as decimal strings, matching the convention
    // `net`'s host counts use.
    details: serialisableDetails(details as Record<string, unknown>),
  };
}

function serialisableDetails(
  details: Record<string, unknown>,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(details)) {
    out[k] = typeof v === "bigint" ? v.toString(10) : v;
  }
  return out;
}

function jwkThumbprint(jwk: { kty?: string; [k: string]: unknown }): string {
  // RFC 7638: pick the required-membership subset of the JWK, lexicographic
  // member order, JSON-serialise with no whitespace, SHA-256, base64url.
  const required: Record<string, string[]> = {
    RSA: ["e", "kty", "n"],
    EC: ["crv", "kty", "x", "y"],
    OKP: ["crv", "kty", "x"],
    oct: ["k", "kty"],
  };
  const members = required[jwk.kty ?? ""];
  if (!members) {
    return "";
  }
  const canonical: Record<string, string> = {};
  for (const m of members) {
    const v = (jwk as unknown as Record<string, unknown>)[m];
    if (typeof v !== "string") {
      parseFailed(
        `jwk thumbprint: missing required member ${JSON.stringify(m)}`,
      );
    }
    canonical[m] = v as string;
  }
  const serialised = JSON.stringify(canonical, members);
  return createHash("sha256").update(serialised).digest("base64url");
}
