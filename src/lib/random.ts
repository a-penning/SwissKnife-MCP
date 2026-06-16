import { randomBytes } from "node:crypto";

export const CHARSETS = {
  lowercase: "abcdefghijklmnopqrstuvwxyz",
  uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  digits: "0123456789",
  symbols: "!@#$%^&*()-_=+[]{};:,.<>?",
} as const;

/** Unbiased sampling via rejection: no modulo bias. */
export function randomChars(alphabet: string, length: number): string {
  // Iterating the string yields code points, so an alphabet of emoji (each
  // 2 UTF-16 units) gives us one set entry per emoji rather than one per
  // half-surrogate. Lone surrogates in the input are rejected.
  for (let i = 0; i < alphabet.length; i++) {
    const code = alphabet.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const trail = alphabet.charCodeAt(i + 1);
      if (!(trail >= 0xdc00 && trail <= 0xdfff)) {
        throw new Error("alphabet contains an unpaired surrogate");
      }
      i++;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new Error("alphabet contains an unpaired surrogate");
    }
  }
  const unique = new Set(alphabet);
  if (unique.size < 2) {
    throw new Error("alphabet must contain at least 2 distinct characters");
  }
  if (unique.size > 256) {
    throw new Error("alphabet must contain at most 256 distinct characters");
  }
  const chars = [...unique];
  const limit = 256 - (256 % chars.length);
  let out = "";
  let produced = 0; // code-point count, not UTF-16 units
  while (produced < length) {
    for (const byte of randomBytes(Math.max(16, length))) {
      if (byte < limit) {
        out += chars[byte % chars.length] as string;
        produced++;
        if (produced === length) break;
      }
    }
  }
  return out;
}
