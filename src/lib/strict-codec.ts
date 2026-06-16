import { Buffer } from "node:buffer";

const BASE64_RE = /^[A-Za-z0-9+/]*={0,2}$/;
const BASE64_CHAR_RE = /[A-Za-z0-9+/]/;
const BASE64URL_RE = /^[A-Za-z0-9_-]*={0,2}$/;
const BASE64URL_CHAR_RE = /[A-Za-z0-9_-]/;
const HEX_RE = /^[0-9a-fA-F]*$/;
const HEX_CHAR_RE = /[0-9a-fA-F]/;

function firstNonMatchOffset(input: string, allowed: RegExp): number {
  for (let i = 0; i < input.length; i++) {
    if (!allowed.test(input[i] as string)) return i;
  }
  return -1;
}

/**
 * Decode a string to bytes by encoding tag. `label` names the source in error
 * messages (e.g. "input" → "input base64"). Shared by the byte-oriented tools.
 */
export function decodeWithEncoding(
  value: string,
  encoding: "utf8" | "base64" | "hex",
  label: string,
): Buffer {
  switch (encoding) {
    case "base64":
      return decodeStrictBase64(value, `${label} base64`);
    case "hex":
      return decodeStrictHex(value, `${label} hex`);
    default:
      return Buffer.from(value, "utf8");
  }
}

export function decodeStrictBase64(input: string, label = "base64"): Buffer {
  if (!BASE64_RE.test(input)) {
    const offset = firstNonMatchOffset(
      input.replace(/=+$/, ""),
      BASE64_CHAR_RE,
    );
    const idx = offset === -1 ? input.length - 1 : offset;
    throw new Error(
      `invalid ${label}: illegal character ${JSON.stringify(input[idx])} at offset ${idx}`,
    );
  }
  if (input.length % 4 !== 0) {
    throw new Error(
      `invalid ${label}: length must be a multiple of 4 (check padding)`,
    );
  }
  return Buffer.from(input, "base64");
}

export function decodeStrictBase64Url(
  input: string,
  label = "base64url",
): Buffer {
  if (!BASE64URL_RE.test(input)) {
    const offset = firstNonMatchOffset(
      input.replace(/=+$/, ""),
      BASE64URL_CHAR_RE,
    );
    const idx = offset === -1 ? input.length - 1 : offset;
    throw new Error(
      `invalid ${label}: illegal character ${JSON.stringify(input[idx])} at offset ${idx}`,
    );
  }
  // RFC 4648: padding is optional in base64url, but the unpadded length still
  // has to correspond to a whole number of bytes. A length % 4 === 1 input
  // encodes 0 bytes plus 6 stray bits — invalid, not "decode to empty".
  const unpadded = input.replace(/=+$/, "");
  if (unpadded.length % 4 === 1) {
    throw new Error(
      `invalid ${label}: ${unpadded.length} chars cannot encode a whole number of bytes`,
    );
  }
  return Buffer.from(input, "base64url");
}

export function decodeStrictHex(input: string, label = "hex"): Buffer {
  if (!HEX_RE.test(input)) {
    const offset = firstNonMatchOffset(input, HEX_CHAR_RE);
    throw new Error(
      `invalid ${label}: illegal character ${JSON.stringify(input[offset])} at offset ${offset}`,
    );
  }
  if (input.length % 2 !== 0) {
    throw new Error(`invalid ${label}: odd number of digits`);
  }
  return Buffer.from(input, "hex");
}
