import { Buffer } from "node:buffer";
import {
  type CipherGCM,
  type CipherGCMOptions,
  createCipheriv,
  createDecipheriv,
  type DecipherGCM,
  randomBytes,
} from "node:crypto";
import {
  decodeBytes,
  encodeBytes,
  type InputEncoding,
  type OutputEncoding,
} from "./encoding.js";
import { CryptoError, decryptionFailed } from "./errors.js";
import {
  type AeadMethod,
  aeadKeyBytes,
  aeadNonceBytes,
  assertByteLength,
  LIMITS,
} from "./policy.js";

const NODE_NAME: Record<AeadMethod, string> = {
  "aes-256-gcm": "aes-256-gcm",
  "aes-128-gcm": "aes-128-gcm",
  "chacha20-poly1305": "chacha20-poly1305",
};

const TAG_BYTES = 16;

export interface AeadEncryptArgs {
  method: AeadMethod;
  key: string;
  keyEncoding: InputEncoding;
  plaintext: string;
  inputEncoding: InputEncoding;
  outputEncoding: OutputEncoding;
  nonce?: string;
  nonceEncoding: InputEncoding;
  aad?: string;
  aadEncoding: InputEncoding;
}

export interface AeadEncryptResult {
  ciphertext: string;
  nonce: string;
  tag: string;
  encoding: OutputEncoding;
  method: AeadMethod;
}

export function aeadEncrypt(args: AeadEncryptArgs): AeadEncryptResult {
  const keyBytes = decodeBytes(args.key, args.keyEncoding, "key");
  assertByteLength(keyBytes, aeadKeyBytes(args.method), `${args.method} key`);

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

  // Empty-string `nonce` is an explicit 0-byte nonce supplied by the caller
  // (decodeBytes will fail the byte-length check below). Only `undefined`
  // triggers auto-generation.
  const nonce =
    args.nonce !== undefined
      ? decodeBytes(args.nonce, args.nonceEncoding, "nonce")
      : randomBytes(aeadNonceBytes(args.method));
  assertByteLength(nonce, aeadNonceBytes(args.method), `${args.method} nonce`);

  const aad = args.aad
    ? decodeBytes(args.aad, args.aadEncoding, "aad")
    : undefined;

  // chacha20-poly1305 mandates `authTagLength`; the GCM ciphers accept the
  // same option. Casting the option object to CipherGCMOptions picks the
  // overload that exposes `setAAD` / `getAuthTag`.
  const cipher = createCipheriv(NODE_NAME[args.method], keyBytes, nonce, {
    authTagLength: TAG_BYTES,
  } as CipherGCMOptions) as CipherGCM;
  if (aad) cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    method: args.method,
    nonce: encodeBytes(nonce, args.outputEncoding),
    ciphertext: encodeBytes(ciphertext, args.outputEncoding),
    tag: encodeBytes(tag, args.outputEncoding),
    encoding: args.outputEncoding,
  };
}

export interface AeadDecryptArgs {
  method: AeadMethod;
  key: string;
  keyEncoding: InputEncoding;
  ciphertext: string;
  ciphertextEncoding: InputEncoding;
  nonce: string;
  nonceEncoding: InputEncoding;
  tag?: string;
  tagEncoding: InputEncoding;
  aad?: string;
  aadEncoding: InputEncoding;
  outputEncoding: OutputEncoding;
}

export interface AeadDecryptResult {
  plaintext: string;
  encoding: OutputEncoding;
  method: AeadMethod;
}

export function aeadDecrypt(args: AeadDecryptArgs): AeadDecryptResult {
  const keyBytes = decodeBytes(args.key, args.keyEncoding, "key");
  assertByteLength(keyBytes, aeadKeyBytes(args.method), `${args.method} key`);

  const nonce = decodeBytes(args.nonce, args.nonceEncoding, "nonce");
  assertByteLength(nonce, aeadNonceBytes(args.method), `${args.method} nonce`);

  let ctBytes = decodeBytes(
    args.ciphertext,
    args.ciphertextEncoding,
    "ciphertext",
  );

  // The handler accepts the auth tag either as a separate `tag` field or
  // appended to the ciphertext (the convention `openssl` and most wire
  // formats follow). Split off the trailing 16 bytes if no explicit tag.
  let tag: Buffer;
  if (args.tag) {
    tag = decodeBytes(args.tag, args.tagEncoding, "tag");
    assertByteLength(tag, TAG_BYTES, "tag");
  } else {
    if (ctBytes.length < TAG_BYTES) {
      decryptionFailed(
        `ciphertext too short to contain an authentication tag (got ${ctBytes.length} bytes, need ≥ ${TAG_BYTES})`,
      );
    }
    tag = ctBytes.subarray(ctBytes.length - TAG_BYTES);
    ctBytes = ctBytes.subarray(0, ctBytes.length - TAG_BYTES);
  }

  const aad = args.aad
    ? decodeBytes(args.aad, args.aadEncoding, "aad")
    : undefined;

  const decipher = createDecipheriv(NODE_NAME[args.method], keyBytes, nonce, {
    authTagLength: TAG_BYTES,
  } as CipherGCMOptions) as DecipherGCM;
  decipher.setAuthTag(tag);
  if (aad) decipher.setAAD(aad);
  try {
    const plaintext = Buffer.concat([
      decipher.update(ctBytes),
      decipher.final(),
    ]);
    return {
      method: args.method,
      plaintext: encodeBytes(plaintext, args.outputEncoding),
      encoding: args.outputEncoding,
    };
  } catch {
    // The proposal pins this single bucket: bad tag / wrong key / wrong nonce
    // / wrong AAD / tampered ct all surface the same way. Failure mode is
    // never leaked.
    return decryptionFailed();
  }
}
