import { generateKeyPairSync, randomBytes } from "node:crypto";
import { toMessage } from "../errors.js";
import { encodeBytes, type OutputEncoding } from "./encoding.js";
import { bad, CryptoError } from "./errors.js";
import { type RawKeyFormat, serialiseKey } from "./format.js";
import { assertEcCurve, assertRsaModulus } from "./policy.js";

export interface GenerateBytesArgs {
  byteLength: number;
  outputEncoding: OutputEncoding;
}

export function generateBytes(args: GenerateBytesArgs): {
  bytes: string;
  byteLength: number;
  encoding: OutputEncoding;
} {
  if (!Number.isInteger(args.byteLength) || args.byteLength < 1) {
    bad(`byteLength must be a positive integer (got ${args.byteLength})`);
  }
  if (args.byteLength > 1024) {
    bad(`byteLength ${args.byteLength} exceeds 1024 (use a KDF for more)`);
  }
  const bytes = randomBytes(args.byteLength);
  return {
    bytes: encodeBytes(bytes, args.outputEncoding),
    byteLength: args.byteLength,
    encoding: args.outputEncoding,
  };
}

export type RawKeypairMethod =
  | "rsa"
  | "ec"
  | "ed25519"
  | "x25519"
  | "secp256k1";

export interface GenerateRawKeypairArgs {
  method: RawKeypairMethod;
  modulusLength?: number;
  curve?: string;
  format: RawKeyFormat;
}

export interface RawKeypairResult {
  method: RawKeypairMethod;
  publicKey: string;
  privateKey: string;
  format: RawKeyFormat;
  details: Record<string, unknown>;
}

export function generateRawKeypair(
  args: GenerateRawKeypairArgs,
): RawKeypairResult {
  try {
    switch (args.method) {
      case "rsa": {
        const modulusLength = assertRsaModulus(args.modulusLength ?? 3072);
        const { publicKey, privateKey } = generateKeyPairSync("rsa", {
          modulusLength,
        });
        return {
          method: "rsa",
          publicKey: serialiseKey(publicKey, args.format, false),
          privateKey: serialiseKey(privateKey, args.format, true),
          format: args.format,
          details: { modulusLength },
        };
      }
      case "ec": {
        const curve = assertEcCurve(args.curve ?? "P-256");
        // EC_CURVES values are already the namedCurve strings Node expects.
        const { publicKey, privateKey } = generateKeyPairSync("ec", {
          namedCurve: curve,
        });
        return {
          method: "ec",
          publicKey: serialiseKey(publicKey, args.format, false),
          privateKey: serialiseKey(privateKey, args.format, true),
          format: args.format,
          details: { curve },
        };
      }
      case "ed25519": {
        const { publicKey, privateKey } = generateKeyPairSync("ed25519");
        return {
          method: "ed25519",
          publicKey: serialiseKey(publicKey, args.format, false),
          privateKey: serialiseKey(privateKey, args.format, true),
          format: args.format,
          details: {},
        };
      }
      case "x25519": {
        const { publicKey, privateKey } = generateKeyPairSync("x25519");
        return {
          method: "x25519",
          publicKey: serialiseKey(publicKey, args.format, false),
          privateKey: serialiseKey(privateKey, args.format, true),
          format: args.format,
          details: {},
        };
      }
      case "secp256k1": {
        const { publicKey, privateKey } = generateKeyPairSync("ec", {
          namedCurve: "secp256k1",
        });
        return {
          method: "secp256k1",
          publicKey: serialiseKey(publicKey, args.format, false),
          privateKey: serialiseKey(privateKey, args.format, true),
          format: args.format,
          details: { curve: "secp256k1" },
        };
      }
    }
  } catch (e) {
    if (e instanceof CryptoError) throw e;
    throw new CryptoError("bad_parameters", toMessage(e));
  }
}
