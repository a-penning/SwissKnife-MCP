import { Buffer } from "node:buffer";
import { createHash, randomBytes } from "node:crypto";

export const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const NAMED_NAMESPACES: Record<string, string> = {
  dns: "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
  url: "6ba7b811-9dad-11d1-80b4-00c04fd430c8",
  oid: "6ba7b812-9dad-11d1-80b4-00c04fd430c8",
  x500: "6ba7b814-9dad-11d1-80b4-00c04fd430c8",
};

export function uuidToBytes(uuid: string): Buffer {
  if (!UUID_RE.test(uuid)) {
    throw new Error(`not a valid UUID: ${JSON.stringify(uuid)}`);
  }
  return Buffer.from(uuid.replaceAll("-", ""), "hex");
}

export function bytesToUuid(bytes: Buffer): string {
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

export function uuidV5(namespace: string, name: string): string {
  const resolved = NAMED_NAMESPACES[namespace.toLowerCase()] ?? namespace;
  const hash = createHash("sha1")
    .update(Buffer.concat([uuidToBytes(resolved), Buffer.from(name, "utf8")]))
    .digest();
  const bytes = hash.subarray(0, 16);
  bytes[6] = ((bytes[6] as number) & 0x0f) | 0x50;
  bytes[8] = ((bytes[8] as number) & 0x3f) | 0x80;
  return bytesToUuid(bytes);
}

export function uuidV7(): string {
  const bytes = randomBytes(16);
  const ms = BigInt(Date.now());
  for (let i = 0; i < 6; i++) {
    bytes[i] = Number((ms >> BigInt(8 * (5 - i))) & 0xffn);
  }
  bytes[6] = ((bytes[6] as number) & 0x0f) | 0x70;
  bytes[8] = ((bytes[8] as number) & 0x3f) | 0x80;
  return bytesToUuid(bytes);
}

export function uuidVersion(uuid: string): number {
  return Number.parseInt(uuid[14] as string, 16);
}

export function uuidVariant(uuid: string): string {
  const nibble = Number.parseInt(uuid[19] as string, 16);
  if (nibble < 8) return "NCS (reserved)";
  if (nibble < 0xc) return "RFC 4122/9562";
  if (nibble < 0xe) return "Microsoft (reserved)";
  return "future (reserved)";
}

/** Gregorian epoch offset: 1582-10-15 to 1970-01-01 in 100ns intervals. */
const GREGORIAN_OFFSET = 122192928000000000n;

export function uuidTimestamp(uuid: string): string | undefined {
  const version = uuidVersion(uuid);
  const bytes = uuidToBytes(uuid);
  if (version === 7) {
    let ms = 0n;
    for (let i = 0; i < 6; i++) {
      ms = (ms << 8n) | BigInt(bytes[i] as number);
    }
    return new Date(Number(ms)).toISOString();
  }
  if (version === 1) {
    const hex = uuid.replaceAll("-", "");
    const intervals = BigInt(
      `0x${hex.slice(13, 16)}${hex.slice(8, 12)}${hex.slice(0, 8)}`,
    );
    const ms = (intervals - GREGORIAN_OFFSET) / 10000n;
    return new Date(Number(ms)).toISOString();
  }
  return undefined;
}
