import { Buffer } from "node:buffer";
import {
  diffieHellman,
  hkdfSync,
  pbkdf2Sync,
  randomBytes,
  scryptSync,
} from "node:crypto";
import * as argon2 from "@node-rs/argon2";
import { toMessage } from "../errors.js";
import {
  decodeBytes,
  encodeBytes,
  type InputEncoding,
  type OutputEncoding,
} from "./encoding.js";
import { bad, CryptoError } from "./errors.js";
import { parseKey } from "./format.js";
import { assertHash, type Hash, LIMITS } from "./policy.js";

export interface Argon2Args {
  password: string;
  passwordEncoding: InputEncoding;
  salt?: string;
  saltEncoding: InputEncoding;
  keyLength: number;
  outputEncoding: OutputEncoding;
  memory: number; // KiB
  iterations: number;
  parallelism: number;
}

export interface PasswordKdfResult {
  key: string;
  salt: string;
  keyLength: number;
  encoding: OutputEncoding;
  method: string;
  params: Record<string, unknown>;
}

export async function deriveArgon2id(
  args: Argon2Args,
): Promise<PasswordKdfResult> {
  if (args.memory > LIMITS.argon2MaxMemKiB) {
    bad(
      `argon2 memory ${args.memory} KiB exceeds cap ${LIMITS.argon2MaxMemKiB}`,
    );
  }
  if (args.iterations > LIMITS.argon2MaxTime) {
    bad(
      `argon2 iterations ${args.iterations} exceeds cap ${LIMITS.argon2MaxTime}`,
    );
  }
  if (args.parallelism > LIMITS.argon2MaxParallelism) {
    bad(
      `argon2 parallelism ${args.parallelism} exceeds cap ${LIMITS.argon2MaxParallelism}`,
    );
  }
  if (args.keyLength < 1 || args.keyLength > 1024) {
    bad(`keyLength ${args.keyLength} out of range 1..1024`);
  }
  const password = decodeBytes(
    args.password,
    args.passwordEncoding,
    "password",
  );
  // Empty-string `salt` is an explicit 0-byte salt (rejected below); only
  // undefined triggers auto-generation.
  const salt =
    args.salt !== undefined
      ? decodeBytes(args.salt, args.saltEncoding, "salt")
      : randomBytes(16);
  if (salt.length < 8) {
    bad(`salt must be ≥ 8 bytes (got ${salt.length})`);
  }
  const raw = await argon2.hashRaw(password, {
    salt,
    algorithm: argon2.Algorithm.Argon2id,
    memoryCost: args.memory,
    timeCost: args.iterations,
    parallelism: args.parallelism,
    outputLen: args.keyLength,
  });
  return {
    method: "argon2id",
    key: encodeBytes(raw, args.outputEncoding),
    salt: salt.toString("base64"),
    keyLength: args.keyLength,
    encoding: args.outputEncoding,
    params: {
      memory: args.memory,
      iterations: args.iterations,
      parallelism: args.parallelism,
    },
  };
}

export interface ScryptArgs {
  password: string;
  passwordEncoding: InputEncoding;
  salt?: string;
  saltEncoding: InputEncoding;
  keyLength: number;
  outputEncoding: OutputEncoding;
  N: number;
  r: number;
  p: number;
}

export function deriveScrypt(args: ScryptArgs): PasswordKdfResult {
  if (args.N > LIMITS.scryptMaxN) {
    bad(`scrypt N ${args.N} exceeds cap ${LIMITS.scryptMaxN}`);
  }
  // memory ≈ 128 * N * r bytes
  const estMem = 128 * args.N * args.r;
  if (estMem > LIMITS.scryptMaxMemBytes) {
    bad(
      `scrypt memory estimate ${estMem} bytes exceeds cap ${LIMITS.scryptMaxMemBytes} — reduce N or r`,
    );
  }
  if (args.keyLength < 1 || args.keyLength > 1024) {
    bad(`keyLength ${args.keyLength} out of range 1..1024`);
  }
  const password = decodeBytes(
    args.password,
    args.passwordEncoding,
    "password",
  );
  // Empty-string `salt` is an explicit 0-byte salt (rejected below); only
  // undefined triggers auto-generation.
  const salt =
    args.salt !== undefined
      ? decodeBytes(args.salt, args.saltEncoding, "salt")
      : randomBytes(16);
  if (salt.length < 8) {
    bad(`salt must be ≥ 8 bytes (got ${salt.length})`);
  }
  let raw: Buffer;
  try {
    raw = scryptSync(password, salt, args.keyLength, {
      N: args.N,
      r: args.r,
      p: args.p,
      maxmem: LIMITS.scryptMaxMemBytes + 32 * 1024 * 1024,
    });
  } catch (e) {
    throw new CryptoError("bad_parameters", `scrypt failed: ${toMessage(e)}`);
  }
  return {
    method: "scrypt",
    key: encodeBytes(raw, args.outputEncoding),
    salt: salt.toString("base64"),
    keyLength: args.keyLength,
    encoding: args.outputEncoding,
    params: { N: args.N, r: args.r, p: args.p },
  };
}

export interface Pbkdf2Args {
  password: string;
  passwordEncoding: InputEncoding;
  salt?: string;
  saltEncoding: InputEncoding;
  keyLength: number;
  outputEncoding: OutputEncoding;
  iterations: number;
  hash: Hash;
}

export function derivePbkdf2(args: Pbkdf2Args): PasswordKdfResult {
  if (args.iterations < 1 || args.iterations > LIMITS.pbkdf2MaxIterations) {
    bad(
      `pbkdf2 iterations ${args.iterations} out of range 1..${LIMITS.pbkdf2MaxIterations}`,
    );
  }
  if (args.keyLength < 1 || args.keyLength > 1024) {
    bad(`keyLength ${args.keyLength} out of range 1..1024`);
  }
  assertHash(args.hash);
  const password = decodeBytes(
    args.password,
    args.passwordEncoding,
    "password",
  );
  // Empty-string `salt` is an explicit 0-byte salt (rejected below); only
  // undefined triggers auto-generation.
  const salt =
    args.salt !== undefined
      ? decodeBytes(args.salt, args.saltEncoding, "salt")
      : randomBytes(16);
  if (salt.length < 8) {
    bad(`salt must be ≥ 8 bytes (got ${salt.length})`);
  }
  const raw = pbkdf2Sync(
    password,
    salt,
    args.iterations,
    args.keyLength,
    args.hash,
  );
  return {
    method: "pbkdf2",
    key: encodeBytes(raw, args.outputEncoding),
    salt: salt.toString("base64"),
    keyLength: args.keyLength,
    encoding: args.outputEncoding,
    params: { iterations: args.iterations, hash: args.hash },
  };
}

export interface HkdfArgs {
  ikm: string;
  ikmEncoding: InputEncoding;
  salt?: string;
  saltEncoding: InputEncoding;
  info?: string;
  infoEncoding: InputEncoding;
  keyLength: number;
  outputEncoding: OutputEncoding;
  hash: Hash;
}

export interface HkdfResult {
  method: "hkdf";
  key: string;
  keyLength: number;
  encoding: OutputEncoding;
  hash: Hash;
}

export function deriveHkdf(args: HkdfArgs): HkdfResult {
  assertHash(args.hash);
  if (args.keyLength < 1 || args.keyLength > 1024) {
    bad(`keyLength ${args.keyLength} out of range 1..1024`);
  }
  const ikm = decodeBytes(args.ikm, args.ikmEncoding, "ikm");
  const salt = args.salt
    ? decodeBytes(args.salt, args.saltEncoding, "salt")
    : Buffer.alloc(0);
  const info = args.info
    ? decodeBytes(args.info, args.infoEncoding, "info")
    : Buffer.alloc(0);
  const raw = hkdfSync(args.hash, ikm, salt, info, args.keyLength);
  return {
    method: "hkdf",
    key: encodeBytes(Buffer.from(raw), args.outputEncoding),
    keyLength: args.keyLength,
    encoding: args.outputEncoding,
    hash: args.hash,
  };
}

export interface EcdhArgs {
  privateKey: string;
  peerPublicKey: string;
  outputEncoding: OutputEncoding;
}

export interface EcdhResult {
  method: "ecdh";
  sharedSecret: string;
  byteLength: number;
  encoding: OutputEncoding;
  curve: string;
}

export function deriveEcdh(args: EcdhArgs): EcdhResult {
  const priv = parseKey(args.privateKey, { isPrivate: true });
  const pub = parseKey(args.peerPublicKey, { isPrivate: false });
  if (priv.asymmetricKeyType !== pub.asymmetricKeyType) {
    throw new CryptoError(
      "wrong_algorithm",
      `ecdh: key types must match (private=${priv.asymmetricKeyType} peer=${pub.asymmetricKeyType})`,
    );
  }
  if (
    priv.asymmetricKeyType !== "ec" &&
    priv.asymmetricKeyType !== "x25519" &&
    priv.asymmetricKeyType !== "x448"
  ) {
    throw new CryptoError(
      "wrong_algorithm",
      `ecdh requires EC, X25519, or X448 keys (got ${priv.asymmetricKeyType ?? "unknown"})`,
    );
  }
  const shared = diffieHellman({ privateKey: priv, publicKey: pub });
  const details = priv.asymmetricKeyDetails ?? {};
  const curve =
    priv.asymmetricKeyType === "x25519"
      ? "x25519"
      : ("namedCurve" in details && details.namedCurve) || "unknown";
  return {
    method: "ecdh",
    sharedSecret: encodeBytes(shared, args.outputEncoding),
    byteLength: shared.length,
    encoding: args.outputEncoding,
    curve: String(curve),
  };
}
