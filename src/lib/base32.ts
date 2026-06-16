const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(bytes: Uint8Array): string {
  let out = "";
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += ALPHABET[(buffer << (5 - bits)) & 31];
  }
  while (out.length % 8 !== 0) {
    out += "=";
  }
  return out;
}

// RFC 4648 §6: a base32 group is 8 chars encoding 5 bytes. The only valid
// final-quantum lengths (after stripping padding) are 0, 2, 4, 5, 7 — encoding
// 0, 1, 2, 3, 4 bytes respectively. Lengths 1, 3, 6 would leave >= 5 stray
// bits that no base32 character can have produced, so the input is malformed.
const VALID_FINAL_LENGTHS = new Set([0, 2, 4, 5, 7]);

export function base32Decode(input: string): Uint8Array {
  // RFC 4648 §6 alphabet is uppercase, but most implementations (and the
  // hex decoder in this same tool) accept either case on decode. Mirror
  // that — case-folding here lets a lowercase or mixed-case copy-paste
  // decode cleanly instead of erroring on the first lowercase character.
  input = input.toUpperCase();
  const stripped = input.replace(/=+$/, "");
  const padLength = input.length - stripped.length;
  if (input.length % 8 !== 0 && padLength > 0) {
    throw new Error(
      "invalid base32: padded input length must be a multiple of 8",
    );
  }
  if (!VALID_FINAL_LENGTHS.has(stripped.length % 8)) {
    throw new Error(
      `invalid base32: ${stripped.length % 8} chars in final quantum is not a valid RFC 4648 length (expected 0/2/4/5/7)`,
    );
  }
  let buffer = 0;
  let bits = 0;
  const out: number[] = [];
  for (let i = 0; i < stripped.length; i++) {
    const idx = ALPHABET.indexOf(stripped[i] as string);
    if (idx === -1) {
      throw new Error(
        `invalid base32: illegal character ${JSON.stringify(stripped[i])} at offset ${i}`,
      );
    }
    buffer = (buffer << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((buffer >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Uint8Array.from(out);
}
