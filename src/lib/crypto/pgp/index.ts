import * as openpgp from "openpgp";
import { toMessage } from "../../errors.js";
import { streamToBuffer } from "../../input.js";
import { assertUrlAllowed, guardedFetch } from "../../ssrf.js";
import { CryptoError } from "../errors.js";
import { LIMITS } from "../policy.js";

/**
 * OpenPGP integration. The proposal pins these constraints, codified here:
 *   • v6 keys by default for new `generate` calls.
 *   • Ed25519 + X25519 by default for a new keypair.
 *   • AEAD (OCB/GCM) preferred over CFB for new ciphertext.
 *   • SHA-1 / MD5 signatures are rejected unless `acceptLegacyHash: true`.
 *   • Signing with SHA-1 / MD5 is never permitted.
 *   • Expired keys → `pgp_key_expired` on encrypt / sign; verify may still
 *     accept a signature made *before* the signing key's expiry and
 *     surfaces `keyExpiredAfterSigning: true`.
 */

export interface PgpEncryptArgs {
  message: string;
  recipients?: string[];
  passphrase?: string;
  signingKey?: string;
  signingPassphrase?: string;
  armor: boolean;
  preferredCipher?:
    | "aes-256-ocb"
    | "aes-256-gcm"
    | "aes-128-gcm"
    | "chacha20-poly1305"
    | "aes-256-cfb"
    | "aes-128-cfb";
}

export interface PgpEncryptResult {
  ciphertext: string;
  armor: boolean;
  recipients: number;
  signed: boolean;
}

export async function pgpEncrypt(
  args: PgpEncryptArgs,
): Promise<PgpEncryptResult> {
  if (!args.recipients?.length && !args.passphrase) {
    throw new CryptoError(
      "bad_parameters",
      "pgp encrypt requires either `recipients` (public keys) or `passphrase` (symmetric)",
    );
  }
  if (args.recipients && args.recipients.length > LIMITS.pgpRecipients) {
    throw new CryptoError(
      "bad_parameters",
      `recipients ${args.recipients.length} exceeds cap ${LIMITS.pgpRecipients}`,
    );
  }
  const message = await openpgp.createMessage({ text: args.message });
  const encryptionKeys = args.recipients
    ? await Promise.all(
        args.recipients.map((r) => readPublicKey(r, "recipient")),
      )
    : undefined;
  if (encryptionKeys) {
    const now = new Date();
    for (const k of encryptionKeys) {
      const expiry = await k.getExpirationTime();
      if (expiry instanceof Date && expiry < now) {
        throw new CryptoError(
          "pgp_key_expired",
          `recipient ${k.getFingerprint()} expired at ${expiry.toISOString()}`,
        );
      }
    }
  }
  let signingKeys: openpgp.PrivateKey[] | undefined;
  if (args.signingKey) {
    signingKeys = [
      await readPrivateKey(
        args.signingKey,
        args.signingPassphrase,
        "signingKey",
      ),
    ];
    const now = new Date();
    for (const k of signingKeys) {
      const expiry = await k.getExpirationTime();
      if (expiry instanceof Date && expiry < now) {
        throw new CryptoError(
          "pgp_key_expired",
          `signing key ${k.getFingerprint()} expired at ${expiry.toISOString()}`,
        );
      }
    }
  }

  const config = preferredCipherConfig(args.preferredCipher);

  try {
    // openpgp.encrypt's overloads pin format to a literal — we pick the
    // branch explicitly rather than passing a union.
    const baseOpts = {
      message,
      ...(encryptionKeys ? { encryptionKeys } : {}),
      ...(args.passphrase ? { passwords: [args.passphrase] } : {}),
      ...(signingKeys ? { signingKeys } : {}),
      ...(config ? { config } : {}),
    };
    const encrypted = args.armor
      ? await openpgp.encrypt({ ...baseOpts, format: "armored" })
      : await openpgp.encrypt({ ...baseOpts, format: "binary" });
    const ciphertext = args.armor
      ? (encrypted as string)
      : Buffer.from(encrypted as Uint8Array).toString("base64");
    return {
      ciphertext,
      armor: args.armor,
      recipients: encryptionKeys?.length ?? 0,
      signed: Boolean(signingKeys),
    };
  } catch (e) {
    // Propagate CryptoError unchanged (e.g. invalid_key surfaced from a
    // recipient parse, pgp_key_expired from an expiry check).
    if (e instanceof CryptoError) throw e;
    // Classify the underlying openpgp failure. Key-shape errors → invalid_key;
    // everything else → bad_parameters with a non-leaky message.
    const msg = toMessage(e);
    if (/key|signature|algorithm not supported/i.test(msg)) {
      throw new CryptoError("invalid_key", `pgp encrypt: ${msg}`);
    }
    throw new CryptoError("bad_parameters", `pgp encrypt failed: ${msg}`);
  }
}

export interface PgpDecryptArgs {
  ciphertext: string;
  privateKey?: string;
  passphrase?: string;
  verificationKeys?: string[];
}

export interface PgpDecryptResult {
  plaintext: string;
  signatures: Array<{
    keyId: string;
    valid: boolean;
    failureReason?: string;
  }>;
}

export async function pgpDecrypt(
  args: PgpDecryptArgs,
): Promise<PgpDecryptResult> {
  const armored = args.ciphertext.includes("-----BEGIN PGP MESSAGE-----");
  let message: openpgp.Message<string>;
  try {
    message = armored
      ? await openpgp.readMessage({ armoredMessage: args.ciphertext })
      : await openpgp.readMessage({
          binaryMessage: Buffer.from(args.ciphertext, "base64"),
        });
  } catch (e) {
    throw new CryptoError("parse_failed", `pgp message: ${toMessage(e)}`);
  }
  let decryptionKeys: openpgp.PrivateKey[] | undefined;
  if (args.privateKey) {
    decryptionKeys = [
      await readPrivateKey(args.privateKey, args.passphrase, "privateKey"),
    ];
  }
  let verificationKeys: openpgp.PublicKey[] | undefined;
  if (args.verificationKeys?.length) {
    verificationKeys = await Promise.all(
      args.verificationKeys.map((k) => readPublicKey(k, "verificationKey")),
    );
  }
  let result: openpgp.DecryptMessageResult;
  try {
    result = await openpgp.decrypt({
      message,
      ...(decryptionKeys ? { decryptionKeys } : {}),
      ...(args.passphrase && !decryptionKeys
        ? { passwords: [args.passphrase] }
        : {}),
      ...(verificationKeys ? { verificationKeys } : {}),
    });
  } catch {
    // Single bucket — failure mode never leaked (proposal §Error model).
    throw new CryptoError("decryption_failed", "decryption_failed");
  }
  const plaintext =
    typeof result.data === "string"
      ? result.data
      : Buffer.from(result.data as Uint8Array).toString("utf8");
  const signatures = await Promise.all(
    (result.signatures ?? []).map(async (s) => {
      try {
        const verified = await s.verified;
        return { keyId: s.keyID.toHex(), valid: verified };
      } catch (e) {
        return {
          keyId: s.keyID.toHex(),
          valid: false,
          failureReason: toMessage(e),
        };
      }
    }),
  );
  return { plaintext, signatures };
}

export interface PgpSignArgs {
  privateKey: string;
  passphrase?: string;
  message: string;
  type: "detached" | "cleartext" | "inline";
  armor: boolean;
}

export async function pgpSign(args: PgpSignArgs): Promise<{
  signature: string;
  type: PgpSignArgs["type"];
  armor: boolean;
  fingerprint: string;
}> {
  const privKey = await readPrivateKey(
    args.privateKey,
    args.passphrase,
    "privateKey",
  );
  const now = new Date();
  const expiry = await privKey.getExpirationTime();
  if (expiry instanceof Date && expiry < now) {
    throw new CryptoError(
      "pgp_key_expired",
      `signing key ${privKey.getFingerprint()} expired at ${expiry.toISOString()}`,
    );
  }

  if (args.type === "cleartext") {
    const cleartextMessage = await openpgp.createCleartextMessage({
      text: args.message,
    });
    const out = await openpgp.sign({
      message: cleartextMessage,
      signingKeys: privKey,
    });
    return {
      signature: out as string,
      type: "cleartext",
      armor: true,
      fingerprint: privKey.getFingerprint(),
    };
  }

  const message = await openpgp.createMessage({ text: args.message });
  const detached = args.type === "detached";
  const baseOpts = { message, signingKeys: privKey, detached };
  const out = args.armor
    ? await openpgp.sign({ ...baseOpts, format: "armored" })
    : await openpgp.sign({ ...baseOpts, format: "binary" });
  const signature = args.armor
    ? (out as string)
    : Buffer.from(out as Uint8Array).toString("base64");
  return {
    signature,
    type: args.type,
    armor: args.armor,
    fingerprint: privKey.getFingerprint(),
  };
}

export interface PgpVerifyArgs {
  signature: string;
  message?: string;
  publicKeys?: string[];
  keyserverUrl?: string;
  acceptLegacyHash: boolean;
}

export interface PgpVerifyResult {
  valid: boolean;
  reason?: string;
  signedBy?: {
    fingerprint: string;
    keyId: string;
    userIds: string[];
    keySource: "supplied" | "keyserver";
    keyFetchedFrom?: string;
  };
  createdAt?: string;
  hash?: string;
  keyExpiredAfterSigning?: boolean;
}

export async function pgpVerify(args: PgpVerifyArgs): Promise<PgpVerifyResult> {
  const looksCleartext = args.signature.includes(
    "-----BEGIN PGP SIGNED MESSAGE-----",
  );
  if (looksCleartext) {
    return await verifyCleartext(args);
  }
  // Inline-signed PGP MESSAGE — sig + signed data live together in one
  // armored envelope. Parse as Message, not Signature.
  const looksInline =
    args.signature.includes("-----BEGIN PGP MESSAGE-----") &&
    !args.signature.includes("-----BEGIN PGP SIGNATURE-----");
  if (looksInline) {
    return await verifyInline(args);
  }
  if (
    !args.message &&
    args.signature.includes("-----BEGIN PGP SIGNATURE-----")
  ) {
    return {
      valid: false,
      reason: "detached signature requires `message` to verify against",
    };
  }
  const armoredSig = args.signature.includes("-----BEGIN PGP SIGNATURE-----");
  let signature: openpgp.Signature;
  try {
    signature = armoredSig
      ? await openpgp.readSignature({ armoredSignature: args.signature })
      : await openpgp.readSignature({
          binarySignature: Buffer.from(args.signature, "base64"),
        });
  } catch (e) {
    return { valid: false, reason: `parse failed: ${toMessage(e)}` };
  }

  const packets = signature.packets;
  for (const pkt of packets) {
    if (isWeakHash(pkt.hashAlgorithm) && !args.acceptLegacyHash) {
      return { valid: false, reason: "weak_hash" };
    }
  }

  const keyIds = packets.map((p: openpgp.SignaturePacket) =>
    p.issuerKeyID.toHex(),
  );
  const { publicKeys, keyFetchedFrom } = await resolvePublicKeys(args, keyIds);
  if (!publicKeys.length) {
    throw new CryptoError(
      "pgp_key_unavailable",
      `no verification key supplied and none found for ${keyIds.join(", ")}`,
    );
  }

  if (!args.message) {
    return {
      valid: false,
      reason: "verifying a non-cleartext signature requires `message`",
    };
  }
  const message = await openpgp.createMessage({ text: args.message });
  const result = await openpgp.verify({
    message,
    signature,
    verificationKeys: publicKeys,
  });
  return await formatVerifyResult(result, publicKeys, keyFetchedFrom);
}

async function verifyInline(args: PgpVerifyArgs): Promise<PgpVerifyResult> {
  let message: openpgp.Message<string>;
  try {
    message = await openpgp.readMessage({ armoredMessage: args.signature });
  } catch (e) {
    return { valid: false, reason: `parse failed: ${toMessage(e)}` };
  }
  // Collect signature packets to gate on weak hashes (same as detached path).
  const sigPackets = message.packets.filterByTag(
    openpgp.enums.packet.signature,
  ) as unknown as openpgp.SignaturePacket[];
  for (const pkt of sigPackets) {
    if (isWeakHash(pkt.hashAlgorithm) && !args.acceptLegacyHash) {
      return { valid: false, reason: "weak_hash" };
    }
  }
  const keyIds = sigPackets.map((p) => p.issuerKeyID.toHex());
  const { publicKeys, keyFetchedFrom } = await resolvePublicKeys(args, keyIds);
  if (!publicKeys.length) {
    throw new CryptoError(
      "pgp_key_unavailable",
      `no verification key supplied and none found for ${keyIds.join(", ")}`,
    );
  }
  const result = await openpgp.verify({
    message,
    verificationKeys: publicKeys,
  });
  return await formatVerifyResult(result, publicKeys, keyFetchedFrom);
}

async function verifyCleartext(args: PgpVerifyArgs): Promise<PgpVerifyResult> {
  let cleartextMessage: openpgp.CleartextMessage;
  try {
    cleartextMessage = await openpgp.readCleartextMessage({
      cleartextMessage: args.signature,
    });
  } catch (e) {
    return { valid: false, reason: `parse failed: ${toMessage(e)}` };
  }
  // The cleartext message's `.signature` is on the runtime object but absent
  // from the v6 typings; cast through unknown.
  const sigContainer = (
    cleartextMessage as unknown as {
      signature: { packets: openpgp.SignaturePacket[] };
    }
  ).signature;
  const signaturePackets = sigContainer.packets;
  for (const pkt of signaturePackets) {
    if (isWeakHash(pkt.hashAlgorithm) && !args.acceptLegacyHash) {
      return { valid: false, reason: "weak_hash" };
    }
  }
  const keyIds = signaturePackets.map((p: openpgp.SignaturePacket) =>
    p.issuerKeyID.toHex(),
  );
  const { publicKeys, keyFetchedFrom } = await resolvePublicKeys(args, keyIds);
  if (!publicKeys.length) {
    throw new CryptoError(
      "pgp_key_unavailable",
      `no verification key supplied and none found for ${keyIds.join(", ")}`,
    );
  }
  const result = await openpgp.verify({
    message: cleartextMessage,
    verificationKeys: publicKeys,
  });
  return await formatVerifyResult(result, publicKeys, keyFetchedFrom);
}

async function formatVerifyResult(
  result: openpgp.VerifyMessageResult,
  publicKeys: openpgp.PublicKey[],
  keyFetchedFrom?: string,
): Promise<PgpVerifyResult> {
  const sig = result.signatures[0];
  if (!sig) return { valid: false, reason: "no signature packets present" };
  let valid: boolean;
  let reason: string | undefined;
  try {
    valid = await sig.verified;
  } catch (e) {
    valid = false;
    reason = toMessage(e);
  }
  const issuerKey =
    publicKeys.find((k) => k.getKeyID().toHex() === sig.keyID.toHex()) ??
    publicKeys[0];
  // Resolve sig.signature once — both the timestamp and the hash algorithm
  // come from the same packet.
  let resolvedPacket: openpgp.SignaturePacket | undefined;
  try {
    const resolved = await sig.signature;
    resolvedPacket = resolved.packets[0];
  } catch {
    resolvedPacket = undefined;
  }
  const created =
    resolvedPacket?.created instanceof Date
      ? resolvedPacket.created
      : undefined;
  const hashAlgorithm =
    typeof resolvedPacket?.hashAlgorithm === "number"
      ? resolvedPacket.hashAlgorithm
      : undefined;
  let keyExpiredAfterSigning = false;
  if (issuerKey && created instanceof Date) {
    const expiry = await issuerKey.getExpirationTime();
    if (expiry instanceof Date && expiry < new Date() && expiry > created) {
      keyExpiredAfterSigning = true;
    }
  }
  return {
    valid,
    ...(reason ? { reason } : {}),
    ...(issuerKey
      ? {
          signedBy: {
            fingerprint: issuerKey.getFingerprint(),
            keyId: sig.keyID.toHex(),
            userIds: issuerKey.getUserIDs(),
            keySource: keyFetchedFrom ? "keyserver" : "supplied",
            ...(keyFetchedFrom ? { keyFetchedFrom } : {}),
          },
        }
      : {}),
    ...(created ? { createdAt: created.toISOString() } : {}),
    ...(hashAlgorithm !== undefined
      ? { hash: String(openpgp.enums.read(openpgp.enums.hash, hashAlgorithm)) }
      : {}),
    ...(keyExpiredAfterSigning ? { keyExpiredAfterSigning: true } : {}),
  };
}

async function resolvePublicKeys(
  args: PgpVerifyArgs,
  keyIds: string[],
): Promise<{ publicKeys: openpgp.PublicKey[]; keyFetchedFrom?: string }> {
  if (args.publicKeys?.length) {
    const keys = await Promise.all(
      args.publicKeys.map((k) => readPublicKey(k, "publicKey")),
    );
    return { publicKeys: keys };
  }
  if (args.keyserverUrl && keyIds[0]) {
    const fetched = await fetchKeyserverKey(args.keyserverUrl, keyIds[0]);
    return { publicKeys: [fetched.key], keyFetchedFrom: fetched.source };
  }
  return { publicKeys: [] };
}

/**
 * Build the lookup URL for a keyserver. The base URL's path is inspected to
 * pick the right protocol:
 *   • path ending in `/pks/lookup` or `/pks` (or no path) and host name
 *     suggests HKP — use the legacy HKP query string.
 *   • otherwise default to VKS (`/vks/v1/by-keyid/...`) — what keys.openpgp.org
 *     and most modern servers expose.
 *
 * Exported solely for direct unit-test coverage of the URL-construction
 * branches — `fetchKeyserverKey` is the production entry point.
 */
export function buildKeyserverUrl(base: string, keyId: string): URL {
  const trimmed = base.replace(/\/+$/, "");
  const parsed = new URL(trimmed);
  const path = parsed.pathname.toLowerCase();
  if (path.endsWith("/pks/lookup") || path.endsWith("/pks")) {
    const root = path.endsWith("/lookup")
      ? trimmed.slice(0, -"/lookup".length)
      : trimmed;
    return new URL(`${root}/lookup?op=get&options=mr&search=0x${keyId}`);
  }
  return new URL(`${trimmed}/vks/v1/by-keyid/${keyId}`);
}

async function fetchKeyserverKey(
  base: string,
  keyId: string,
): Promise<{ key: openpgp.PublicKey; source: string }> {
  let url: URL;
  try {
    url = buildKeyserverUrl(base, keyId);
  } catch (e) {
    throw new CryptoError(
      "keyserver_fetch_failed",
      `invalid keyserverUrl: ${toMessage(e)}`,
    );
  }
  if (url.protocol !== "https:") {
    // Backstop the schema-level https-only check for direct handler callers.
    throw new CryptoError(
      "keyserver_fetch_failed",
      `keyserverUrl must use https (got ${JSON.stringify(url.protocol)})`,
    );
  }
  await assertUrlAllowed(url);
  let res: Response;
  try {
    res = await guardedFetch(url, {
      signal: AbortSignal.timeout(LIMITS.keyserverTimeoutMs),
      headers: { accept: "application/pgp-keys, text/plain" },
    });
  } catch (e) {
    throw new CryptoError(
      "keyserver_fetch_failed",
      `fetch failed for ${url}: ${toMessage(e)}`,
    );
  }
  if (!res.ok) {
    throw new CryptoError(
      "keyserver_fetch_failed",
      `keyserver ${url} returned HTTP ${res.status} ${res.statusText}`,
    );
  }
  // Pre-check Content-Length to refuse pathological responses without reading
  // the body, then stream-cap as a backstop for servers that lie about size.
  const declared = res.headers.get("content-length");
  if (declared && Number(declared) > LIMITS.keyserverMaxBytes) {
    throw new CryptoError(
      "keyserver_fetch_failed",
      `keyserver response ${declared} bytes exceeds cap ${LIMITS.keyserverMaxBytes}`,
    );
  }
  let bodyBuf: Buffer;
  try {
    const { buffer } = await streamToBuffer(
      res.body,
      LIMITS.keyserverMaxBytes,
      "throw",
    );
    bodyBuf = buffer;
  } catch (e) {
    throw new CryptoError(
      "keyserver_fetch_failed",
      `keyserver response too large: ${toMessage(e)}`,
    );
  }
  const text = bodyBuf.toString("utf8");
  try {
    const key = await openpgp.readKey({ armoredKey: text });
    return { key, source: url.toString() };
  } catch (e) {
    throw new CryptoError(
      "keyserver_fetch_failed",
      `keyserver returned unparseable key: ${toMessage(e)}`,
    );
  }
}

export interface PgpGenerateArgs {
  userIds: Array<{ name: string; email: string }>;
  passphrase: string;
  type: "ed25519" | "rsa" | "ecc";
  curve?: string;
  rsaBits?: number;
  keyVersion?: 4 | 6;
  expiresIn?: number; // seconds; 0 = no expiry
  format: "armored" | "binary";
}

export interface PgpGenerateResult {
  publicKey: string;
  privateKey: string;
  revocationCertificate: string;
  fingerprint: string;
  userIds: string[];
  type: PgpGenerateArgs["type"];
  format: PgpGenerateArgs["format"];
}

export async function pgpGenerate(
  args: PgpGenerateArgs,
): Promise<PgpGenerateResult> {
  if (!args.userIds.length) {
    throw new CryptoError(
      "bad_parameters",
      "pgp generate requires at least one userId",
    );
  }
  if (!args.passphrase) {
    throw new CryptoError(
      "bad_parameters",
      "pgp generate requires `passphrase`",
    );
  }
  const config: Partial<openpgp.Config> = {};
  if (args.keyVersion === 6) config.v6Keys = true;
  if (args.keyVersion === 4) config.v6Keys = false;

  const sharedOpts = {
    userIDs: args.userIds,
    passphrase: args.passphrase,
    type:
      args.type === "rsa"
        ? ("rsa" as const)
        : args.type === "ecc"
          ? ("ecc" as const)
          : ("curve25519" as const),
    config,
    ...(args.rsaBits ? { rsaBits: args.rsaBits } : {}),
    ...(args.curve ? { curve: args.curve as openpgp.EllipticCurveName } : {}),
    ...(args.expiresIn !== undefined
      ? { keyExpirationTime: args.expiresIn }
      : {}),
  };

  // openpgp.generateKey's overloads pin format; pick the branch explicitly.
  const result =
    args.format === "armored"
      ? await openpgp.generateKey({ ...sharedOpts, format: "armored" })
      : await openpgp.generateKey({ ...sharedOpts, format: "binary" });
  const publicArmored =
    args.format === "armored"
      ? (result.publicKey as string)
      : Buffer.from(result.publicKey as Uint8Array).toString("base64");
  const privateArmored =
    args.format === "armored"
      ? (result.privateKey as string)
      : Buffer.from(result.privateKey as Uint8Array).toString("base64");
  const inspect =
    args.format === "armored"
      ? await openpgp.readKey({ armoredKey: result.publicKey as string })
      : await openpgp.readKey({
          binaryKey: result.publicKey as Uint8Array,
        });
  return {
    publicKey: publicArmored,
    privateKey: privateArmored,
    revocationCertificate: result.revocationCertificate as string,
    fingerprint: inspect.getFingerprint(),
    userIds: inspect.getUserIDs(),
    type: args.type,
    format: args.format,
  };
}

export interface PgpKeyInspection {
  kind: "pgp-key";
  isPrivate: boolean;
  fingerprint: string;
  keyId: string;
  userIds: string[];
  algorithm: string;
  creationTime?: string;
  expirationTime?: string;
  expired: boolean;
  subkeys: Array<{ keyId: string; algorithm: string; expirationTime?: string }>;
}

export async function inspectPgpKey(input: string): Promise<PgpKeyInspection> {
  const armored = input.includes("-----BEGIN PGP");
  let key: openpgp.Key;
  try {
    key = armored
      ? await openpgp.readKey({ armoredKey: input })
      : await openpgp.readKey({
          binaryKey: Buffer.from(input, "base64"),
        });
  } catch (e) {
    throw new CryptoError("parse_failed", `pgp key: ${toMessage(e)}`);
  }
  const creation = await key.getCreationTime();
  const expiration = await key.getExpirationTime();
  const algo = openpgp.enums.read(
    openpgp.enums.publicKey,
    key.keyPacket.algorithm,
  );
  const subkeys = await Promise.all(
    key.subkeys.map(async (s) => {
      const sExp = await s.getExpirationTime();
      return {
        keyId: s.getKeyID().toHex(),
        algorithm: String(
          openpgp.enums.read(openpgp.enums.publicKey, s.keyPacket.algorithm),
        ),
        ...(sExp instanceof Date ? { expirationTime: sExp.toISOString() } : {}),
      };
    }),
  );
  return {
    kind: "pgp-key",
    isPrivate: key.isPrivate(),
    fingerprint: key.getFingerprint(),
    keyId: key.getKeyID().toHex(),
    userIds: key.getUserIDs(),
    algorithm: String(algo),
    ...(creation instanceof Date
      ? { creationTime: creation.toISOString() }
      : {}),
    ...(expiration instanceof Date
      ? { expirationTime: expiration.toISOString() }
      : {}),
    expired: expiration instanceof Date && expiration < new Date(),
    subkeys,
  };
}

export interface PgpMessageInspection {
  kind: "pgp-message";
  recipients: string[];
  isSymmetric: boolean;
}

export async function inspectPgpMessage(
  input: string,
): Promise<PgpMessageInspection> {
  const armored = input.includes("-----BEGIN PGP MESSAGE-----");
  let message: openpgp.Message<string>;
  try {
    message = armored
      ? await openpgp.readMessage({ armoredMessage: input })
      : await openpgp.readMessage({
          binaryMessage: Buffer.from(input, "base64"),
        });
  } catch (e) {
    throw new CryptoError("parse_failed", `pgp message: ${toMessage(e)}`);
  }
  const recipients = message.getEncryptionKeyIDs().map((id) => id.toHex());
  const isSymmetric = message.packets.some(
    (p) => p instanceof openpgp.SymEncryptedSessionKeyPacket,
  );
  return { kind: "pgp-message", recipients, isSymmetric };
}

async function readPublicKey(
  input: string,
  label: string,
): Promise<openpgp.PublicKey> {
  try {
    const armored = input.includes("-----BEGIN PGP");
    return armored
      ? await openpgp.readKey({ armoredKey: input })
      : await openpgp.readKey({ binaryKey: Buffer.from(input, "base64") });
  } catch (e) {
    throw new CryptoError("invalid_key", `${label}: ${toMessage(e)}`);
  }
}

async function readPrivateKey(
  input: string,
  passphrase: string | undefined,
  label: string,
): Promise<openpgp.PrivateKey> {
  let armoredOrBinary: openpgp.PrivateKey;
  try {
    const armored = input.includes("-----BEGIN PGP");
    armoredOrBinary = armored
      ? await openpgp.readPrivateKey({ armoredKey: input })
      : await openpgp.readPrivateKey({
          binaryKey: Buffer.from(input, "base64"),
        });
  } catch (e) {
    throw new CryptoError("invalid_key", `${label}: ${toMessage(e)}`);
  }
  if (!armoredOrBinary.isPrivate()) {
    throw new CryptoError("invalid_key", `${label} is not a private key`);
  }
  if (!passphrase) {
    if (armoredOrBinary.isDecrypted()) return armoredOrBinary;
    throw new CryptoError(
      "bad_parameters",
      `${label} is encrypted but no passphrase was supplied`,
    );
  }
  try {
    return await openpgp.decryptKey({
      privateKey: armoredOrBinary,
      passphrase,
    });
  } catch (e) {
    throw new CryptoError(
      "invalid_key",
      `${label} passphrase failed: ${toMessage(e)}`,
    );
  }
}

function preferredCipherConfig(
  preferred: PgpEncryptArgs["preferredCipher"],
): Partial<openpgp.Config> | undefined {
  if (!preferred) return undefined;
  // The proposal lists preferredCipher options; we set the AEAD mode + cipher
  // accordingly. CFB falls back to no-AEAD.
  if (preferred === "aes-256-cfb" || preferred === "aes-128-cfb") {
    return {
      preferredSymmetricAlgorithm:
        preferred === "aes-128-cfb"
          ? openpgp.enums.symmetric.aes128
          : openpgp.enums.symmetric.aes256,
      aeadProtect: false,
    };
  }
  const aead =
    preferred === "aes-256-ocb"
      ? openpgp.enums.aead.ocb
      : preferred === "chacha20-poly1305"
        ? openpgp.enums.aead.eax // chacha20 not in node-openpgp aead enum; fall back
        : openpgp.enums.aead.gcm;
  const cipher =
    preferred === "aes-128-gcm"
      ? openpgp.enums.symmetric.aes128
      : openpgp.enums.symmetric.aes256;
  return {
    aeadProtect: true,
    preferredAEADAlgorithm: aead,
    preferredSymmetricAlgorithm: cipher,
  };
}

/**
 * SHA-1 / MD5 — refused by default for verify, never permitted for new
 * signing. Exported for direct unit-test coverage of the gating predicate
 * (synthesizing a real SHA-1 PGP signature requires either an external tool or
 * deep config gymnastics; testing the predicate itself is the next-best).
 */
export function isWeakHash(algorithm: number | null | undefined): boolean {
  if (algorithm === null || algorithm === undefined) return false;
  return (
    algorithm === openpgp.enums.hash.md5 ||
    algorithm === openpgp.enums.hash.sha1
  );
}

/** Detect what kind of PGP artefact a string is, for `inspect`. */
export function detectPgp(
  input: string,
): "pgp-key" | "pgp-message" | "pgp-signature" | "pgp-cleartext" | null {
  if (input.includes("-----BEGIN PGP PRIVATE KEY BLOCK-----")) return "pgp-key";
  if (input.includes("-----BEGIN PGP PUBLIC KEY BLOCK-----")) return "pgp-key";
  if (input.includes("-----BEGIN PGP MESSAGE-----")) return "pgp-message";
  if (input.includes("-----BEGIN PGP SIGNATURE-----")) return "pgp-signature";
  if (input.includes("-----BEGIN PGP SIGNED MESSAGE-----"))
    return "pgp-cleartext";
  return null;
}
