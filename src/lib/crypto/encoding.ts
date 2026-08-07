import { Buffer } from "node:buffer";
import {
  decodeStrictBase64,
  decodeStrictHex,
  decodeWithEncoding,
} from "../strict-codec.js";

export type InputEncoding = "utf8" | "base64" | "hex";
export type OutputEncoding = "utf8" | "base64" | "hex";

/**
 * Decode the user-supplied bytes form. Extends the shared
 * {@link decodeWithEncoding} from `lib/strict-codec.ts` with `"base64:"` /
 * `"hex:"` prefix shorthands, so callers can mix raw text and binary in JSON
 * without juggling `inputEncoding`. Without a prefix the declared encoding tag
 * wins.
 */
export function decodeBytes(
  value: string,
  encoding: InputEncoding,
  label: string,
): Buffer {
  if (value.startsWith("base64:")) {
    return decodeStrictBase64(value.slice("base64:".length), `${label} base64`);
  }
  if (value.startsWith("hex:")) {
    return decodeStrictHex(value.slice("hex:".length), `${label} hex`);
  }
  return decodeWithEncoding(value, encoding, label);
}

export function encodeBytes(
  bytes: Buffer | Uint8Array,
  encoding: OutputEncoding,
): string {
  const buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  switch (encoding) {
    case "utf8":
      return buf.toString("utf8");
    case "hex":
      return buf.toString("hex");
    default:
      return buf.toString("base64");
  }
}
