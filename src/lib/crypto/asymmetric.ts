import type { Buffer } from "node:buffer";
import {
  type KeyObject,
  constants as nodeCryptoConstants,
  sign as nodeSign,
  verify as nodeVerify,
  privateDecrypt,
  publicEncrypt,
} from "node:crypto";
import { toMessage } from "../errors.js";
import {
  decodeBytes,
  encodeBytes,
  type InputEncoding,
  type OutputEncoding,
} from "./encoding.js";
import { bad, CryptoError, decryptionFailed, unsupported } from "./errors.js";
import { parseKey } from "./format.js";
import { assertHash, type Hash, LIMITS } from "./policy.js";

const RSA_OAEP_PADDING = nodeCryptoConstants.RSA_PKCS1_OAEP_PADDING;
const RSA_PSS_PADDING = nodeCryptoConstants.RSA_PKCS1_PSS_PADDING;
const RSA_PKCS1_PADDING = nodeCryptoConstants.RSA_PKCS1_PADDING;

/** RSA-OAEP. */
export interface RsaOaepEncryptArgs {
  publicKey: string;
  plaintext: string;
  inputEncoding: InputEncoding;
  outputEncoding: OutputEncoding;
  oaepHash: Hash;
}

export function rsaOaepEncrypt(args: RsaOaepEncryptArgs): {
  ciphertext: string;
  encoding: OutputEncoding;
} {
  const key = parseKey(args.publicKey, { isPrivate: false });
  if (key.asymmetricKeyType !== "rsa") {
    throw new CryptoError(
      "wrong_algorithm",
      `rsa-oaep requires an RSA key, got ${key.asymmetricKeyType ?? "unknown"}`,
    );
  }
  const plaintext = decodeBytes(
    args.plaintext,
    args.inputEncoding,
    "plaintext",
  );
  if (plaintext.length > LIMITS.maxInputBytes) {
    throw new CryptoError(
      "too_large",
      `plaintext ${plaintext.length} bytes exceeds cap ${LIMITS.maxInputBytes}`,
    );
  }
  let ct: Buffer;
  try {
    ct = publicEncrypt(
      {
        key,
        padding: RSA_OAEP_PADDING,
        oaepHash: args.oaepHash,
      },
      plaintext,
    );
  } catch (e) {
    const msg = toMessage(e);
    if (/data too large|message too long/i.test(msg)) {
      bad(`plaintext exceeds RSA-OAEP capacity for this modulus: ${msg}`);
    }
    throw new CryptoError("bad_parameters", msg);
  }
  return {
    ciphertext: encodeBytes(ct, args.outputEncoding),
    encoding: args.outputEncoding,
  };
}

export interface RsaOaepDecryptArgs {
  privateKey: string;
  ciphertext: string;
  ciphertextEncoding: InputEncoding;
  outputEncoding: OutputEncoding;
  oaepHash: Hash;
}

export function rsaOaepDecrypt(args: RsaOaepDecryptArgs): {
  plaintext: string;
  encoding: OutputEncoding;
} {
  const key = parseKey(args.privateKey, { isPrivate: true });
  if (key.asymmetricKeyType !== "rsa") {
    throw new CryptoError(
      "wrong_algorithm",
      `rsa-oaep requires an RSA private key, got ${key.asymmetricKeyType ?? "unknown"}`,
    );
  }
  const ct = decodeBytes(
    args.ciphertext,
    args.ciphertextEncoding,
    "ciphertext",
  );
  try {
    const plaintext = privateDecrypt(
      { key, padding: RSA_OAEP_PADDING, oaepHash: args.oaepHash },
      ct,
    );
    return {
      plaintext: encodeBytes(plaintext, args.outputEncoding),
      encoding: args.outputEncoding,
    };
  } catch {
    return decryptionFailed();
  }
}

/** Sign / verify dispatch. */
export type SignatureScheme = "ed25519" | "ecdsa" | "rsa-pss" | "rsa-pkcs1";

export interface SignArgs {
  scheme: SignatureScheme;
  privateKey: string;
  message: string;
  messageEncoding: InputEncoding;
  hash: Hash;
  outputEncoding: OutputEncoding;
}

export function asymmetricSign(args: SignArgs): {
  signature: string;
  encoding: OutputEncoding;
  scheme: SignatureScheme;
  hash?: Hash;
} {
  const key = parseKey(args.privateKey, { isPrivate: true });
  assertSchemeKeyMatch(args.scheme, key);
  const message = decodeBytes(args.message, args.messageEncoding, "message");
  const algo = signatureAlgorithm(args.scheme, args.hash);
  const padding = signaturePadding(args.scheme);
  const sig = nodeSign(algo, message, {
    key,
    ...(padding !== undefined ? { padding } : {}),
  });
  return {
    signature: encodeBytes(sig, args.outputEncoding),
    encoding: args.outputEncoding,
    scheme: args.scheme,
    ...(args.scheme === "ed25519" ? {} : { hash: args.hash }),
  };
}

export interface VerifyArgs {
  scheme: SignatureScheme;
  publicKey: string;
  message: string;
  messageEncoding: InputEncoding;
  signature: string;
  signatureEncoding: InputEncoding;
  hash: Hash;
}

export function asymmetricVerify(args: VerifyArgs): {
  valid: boolean;
  scheme: SignatureScheme;
  hash?: Hash;
} {
  const key = parseKey(args.publicKey, { isPrivate: false });
  // Public key against private-key-requiring scheme also raises wrong_algorithm
  // — the message stays the same shape.
  assertSchemeKeyMatch(args.scheme, key);
  const message = decodeBytes(args.message, args.messageEncoding, "message");
  const sig = decodeBytes(args.signature, args.signatureEncoding, "signature");
  const algo = signatureAlgorithm(args.scheme, args.hash);
  const padding = signaturePadding(args.scheme);
  const valid = nodeVerify(
    algo,
    message,
    {
      key,
      ...(padding !== undefined ? { padding } : {}),
    },
    sig,
  );
  return {
    valid,
    scheme: args.scheme,
    ...(args.scheme === "ed25519" ? {} : { hash: args.hash }),
  };
}

function assertSchemeKeyMatch(scheme: SignatureScheme, key: KeyObject): void {
  const type = key.asymmetricKeyType;
  if (scheme === "ed25519" && type !== "ed25519") {
    throw new CryptoError(
      "wrong_algorithm",
      `scheme ed25519 requires an Ed25519 key, got ${type ?? "unknown"}`,
    );
  }
  if (scheme === "ecdsa" && type !== "ec") {
    throw new CryptoError(
      "wrong_algorithm",
      `scheme ecdsa requires an EC key, got ${type ?? "unknown"}`,
    );
  }
  if (
    (scheme === "rsa-pss" || scheme === "rsa-pkcs1") &&
    type !== "rsa" &&
    type !== "rsa-pss"
  ) {
    throw new CryptoError(
      "wrong_algorithm",
      `scheme ${scheme} requires an RSA key, got ${type ?? "unknown"}`,
    );
  }
}

function signatureAlgorithm(
  scheme: SignatureScheme,
  hash: Hash,
): string | undefined {
  if (scheme === "ed25519") return undefined; // EdDSA: no separate hash.
  assertHash(hash);
  if (scheme === "ecdsa" || scheme === "rsa-pss" || scheme === "rsa-pkcs1") {
    return hash;
  }
  return unsupported(`unsupported scheme ${JSON.stringify(scheme)}`);
}

function signaturePadding(scheme: SignatureScheme): number | undefined {
  if (scheme === "rsa-pss") return RSA_PSS_PADDING;
  if (scheme === "rsa-pkcs1") return RSA_PKCS1_PADDING;
  return undefined;
}
