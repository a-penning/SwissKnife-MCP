# Proposal: `crypto` tool

**Status:** Design proposal — not yet implemented. Nothing in this file describes shipped behaviour.

A general-purpose cryptographic primitive tool: symmetric AEAD encrypt/decrypt, asymmetric key generation, signing/verifying, key agreement, password-based key derivation, and key-format conversion.

## Why this tool

SwissKnife's existing crypto surface is fragmentary: `hash` does digests and HMAC, `jwt` does one specific signed-token format, `id` generates passwords and UUIDs. There is no way to:

- Encrypt or decrypt arbitrary data.
- Generate an RSA / EC / Ed25519 / X25519 keypair.
- Sign or verify a blob outside the JWT envelope.
- Derive a key from a password (PBKDF2 / scrypt / argon2).
- Convert a key between PEM, DER, JWK formats.

These are the operations an LLM is most likely to *hallucinate* if not given a tool — wrong nonce sizes, wrong padding modes, made-up base64 ciphertexts. The `script` VM cannot fill this gap: it is sandboxed without `node:crypto` or WebCrypto, so encryption is genuinely unreachable from user code. This is a primitive-capability gap, not an ergonomic one.

## Non-goals

| Capability | Lives in / Reason |
|---|---|
| Plain digests, HMAC | `hash` |
| JWT sign / verify / decode | `jwt` |
| Password & identifier *string* generation | `id` |
| Base64 / hex / radix encoding | `encode` |
| Certificate parsing, TLS handshake inspection, WHOIS | `inspect` |
| OpenPGP / GPG | Out of scope — separate spec, separate world |
| Key storage, key rotation, key vault | Stateful — violates the suite's stateless contract |
| Encrypted-at-rest container formats (age, GPG, jwe-files) | Tier 2 — revisit after v1 lands |
| CSR / X.509 certificate issuance | Tier 2 — possibly subsumes `inspect`'s cert side |
| Custom protocol handshakes (Noise, MLS, Signal) | Out of scope |

## Action surface

One tool, `crypto`, discriminated by `action` — consistent with `id`, `jwt`, `net`, `time`. Eleven actions in four conceptual groups.

| Group | Action | Purpose |
|---|---|---|
| Symmetric | `encrypt` | AEAD encrypt (AES-GCM / ChaCha20-Poly1305). |
| | `decrypt` | AEAD decrypt with authentication. |
| | `generate-key` | Random symmetric key (16 / 24 / 32 bytes). |
| Asymmetric | `generate-keypair` | RSA / EC / Ed25519 / X25519. |
| | `sign` | Detached signature over a message. |
| | `verify` | Verify a detached signature. |
| | `agree` | ECDH / X25519 key agreement → shared secret. |
| Derivation | `derive-key` | Password-based: PBKDF2 / scrypt / argon2id. |
| | `hkdf` | From existing key material. |
| Key handling | `convert-key` | PEM ↔ DER ↔ JWK ↔ raw. |
| | `inspect-key` | Parse and describe a key (public material only). |

No `outputSchema` — like `inspect`, `time`, `net`, the result shape varies per action; a discriminated-union schema would have to track every branch.

## Algorithm matrix

### Symmetric AEAD

| Algorithm | Status | Notes |
|---|---|---|
| AES-128-GCM | Supported | 12-byte nonce, 16-byte tag. |
| AES-256-GCM | Supported (default) | Same nonce / tag sizes. |
| ChaCha20-Poly1305 | Supported | 12-byte nonce, 32-byte key. |
| XChaCha20-Poly1305 | Deferred | Requires libsodium; defer to v2. |
| AES-GCM-SIV | Deferred | Not in `node:crypto`. |
| AES-CBC, AES-CTR (no MAC) | **Refused** | Trivially misused. Error: `unsupported_algorithm`. |
| DES, 3DES, RC4 | **Refused** | Broken or deprecated. |

### Asymmetric key types

| Type | Curves / sizes | Status |
|---|---|---|
| RSA | 2048, 3072, 4096 | Supported. Min 2048; min 3072 *recommended* via response warning. |
| EC | P-256, P-384, P-521 | Supported. |
| Ed25519 | — | Supported. Default for new signing keys. |
| X25519 | — | Supported. Default for new agreement keys. |
| secp256k1 | — | Supported (Bitcoin / Ethereum use cases). |
| RSA < 2048 | — | Refused. |

### Signature schemes

| Algorithm | Status |
|---|---|
| Ed25519 | Supported (default for Ed25519 keys). |
| ECDSA (SHA-256/384/512) | Supported. |
| RSA-PSS (SHA-256/384/512) | Supported (default for new RSA signing). |
| RSA-PKCS1-v1_5 | Supported with response warning — prefer PSS for new code. |
| Anything with MD5 or SHA-1 | Refused. |

### Key derivation

| KDF | Status | Default parameters |
|---|---|---|
| PBKDF2 | Supported | SHA-256, 600,000 iterations (OWASP 2023). |
| scrypt | Supported | N=2^15, r=8, p=1. |
| argon2id | Supported (adds one native dep — see below) | m=64 MiB, t=3, p=4. |
| HKDF (SHA-256/384/512) | Supported | For key material, not passwords. |

### Key agreement

| Algorithm | Status |
|---|---|
| X25519 | Supported (default). |
| ECDH on P-256 / P-384 / P-521 | Supported. |

## API examples

These illustrate the **intended** shape, not committed wire format.

### `encrypt`

```json
{
  "action": "encrypt",
  "algorithm": "aes-256-gcm",
  "key": "base64:7E2j…",
  "plaintext": "hello",
  "aad": "optional associated data",
  "outputEncoding": "base64"
}
```

Returns:

```json
{
  "ciphertext": "9k2L…",
  "nonce": "Yx3a…",       // auto-generated; returned for the caller
  "tag": "embedded",      // GCM appends; documented either way
  "algorithm": "aes-256-gcm",
  "encoding": "base64"
}
```

Nonce is auto-generated from CSPRNG by default. A caller may pass `nonce` for test vectors; the description must scream that GCM nonce reuse is catastrophic.

### `decrypt`

```json
{
  "action": "decrypt",
  "algorithm": "aes-256-gcm",
  "key": "base64:7E2j…",
  "ciphertext": "9k2L…",
  "nonce": "Yx3a…",
  "aad": "optional associated data"
}
```

Returns `{ plaintext, encoding }` on success. On auth failure: a single generic `decryption_failed` error — no distinction between bad tag, bad key, or malformed ciphertext (avoids leaking the failure mode).

### `generate-keypair`

```json
{ "action": "generate-keypair", "type": "ed25519" }
{ "action": "generate-keypair", "type": "rsa", "modulusLength": 3072 }
{ "action": "generate-keypair", "type": "ec",  "curve": "P-256" }
{ "action": "generate-keypair", "type": "x25519" }
```

Returns:

```json
{
  "type": "ed25519",
  "publicKey":  { "pem": "-----BEGIN PUBLIC KEY-----\n…", "jwk": { … } },
  "privateKey": { "pem": "-----BEGIN PRIVATE KEY-----\n…", "jwk": { … } },
  "fingerprint": { "sha256": "SHA256:…", "format": "openssh" }
}
```

Both halves returned only on explicit generation. On every other action, private material passed *in* is never echoed *out*.

### `sign`

```json
{
  "action": "sign",
  "algorithm": "ed25519",
  "privateKey": "-----BEGIN PRIVATE KEY-----\n…",
  "message": "payload to sign",
  "outputEncoding": "base64"
}
```

Returns `{ signature, algorithm, encoding }`.

### `verify`

```json
{
  "action": "verify",
  "algorithm": "ed25519",
  "publicKey": "-----BEGIN PUBLIC KEY-----\n…",
  "message": "payload to sign",
  "signature": "..."
}
```

Returns `{ valid: true|false }`. Verification failure is `valid: false`, **not** an error (mirrors `jwt verify`).

### `derive-key`

```json
{
  "action": "derive-key",
  "kdf": "argon2id",
  "password": "correct horse battery staple",
  "salt": "base64:…",      // optional — auto-generated if absent
  "keyLength": 32,
  "outputEncoding": "base64",
  "params": { "memory": 65536, "iterations": 3, "parallelism": 4 }
}
```

Returns `{ key, salt, kdf, params, encoding }`. Salt is always returned so the caller can store it for re-derivation.

### `hkdf`

```json
{
  "action": "hkdf",
  "hash": "sha256",
  "ikm": "base64:…",       // input key material
  "salt": "base64:…",      // optional
  "info": "app:session-key",
  "keyLength": 32
}
```

### `agree`

```json
{
  "action": "agree",
  "algorithm": "x25519",
  "privateKey": "...",
  "peerPublicKey": "..."
}
```

Returns `{ sharedSecret, encoding }`. Documentation must point at `hkdf` as the next step — raw ECDH output is **not** a key.

### `convert-key`

```json
{
  "action": "convert-key",
  "from": "pem",
  "to":   "jwk",
  "key":  "-----BEGIN PRIVATE KEY-----\n…"
}
```

Format auto-detection on input is permitted; the *output* format is always explicit.

### `inspect-key`

```json
{ "action": "inspect-key", "key": "-----BEGIN PUBLIC KEY-----\n…" }
```

Returns key type, curve / modulus length, fingerprint (SHA-256, OpenSSH-style), whether it's public or private, and the supported operations. **Never echoes private scalar / exponent material**, even when given a private key — only metadata.

## Key handling

### Accepted input formats

Auto-detected on parse:

- **PEM**: PKCS#1, PKCS#8, SEC1, SPKI, X.509-certificate-as-public-key-source.
- **DER**: same containers, base64-encoded via standard `inputEncoding` semantics.
- **JWK**: JSON object — RSA / EC / OKP types.
- **Raw symmetric keys**: bytes via `inputEncoding` (`base64` / `hex` / `utf8`).

### Output formats

Explicit, never auto-chosen. PEM is the suggested default; JWK is supported for everything except raw symmetric.

### Redaction

- Private material passed **into** the tool is never echoed in any response.
- Private material is returned **only** by `generate-keypair` and `convert-key` (where the request explicitly asks for a private-key output).
- `inspect-key` returns metadata only — even if the input was a private key, the response describes the public-key half.
- The `description` field calls this out: callers should not pipe `crypto` output through anything that logs verbatim arguments.

## Error model

Errors are `err()` values, per `docs/TOOLS.md`. Distinct error codes:

| Code | Meaning |
|---|---|
| `invalid_key` | Parse failed, wrong type, unsupported curve. |
| `wrong_algorithm` | Key type does not match requested algorithm (e.g. Ed25519 key with ECDSA). |
| `decryption_failed` | Single bucket for all AEAD failures — bad tag, wrong key, wrong nonce, tampered ciphertext, wrong AAD. |
| `unsupported_algorithm` | Refused by policy (DES, RSA-1024, MD5-signing, …). |
| `bad_parameters` | KDF cost outside allowed range, key length wrong for algorithm, nonce wrong size. |
| `too_large` | Input exceeds the configured cap. |
| `parse_failed` | Generic format-parse failure not covered above. |

Verification failure on `verify` is **not** an error — it's `{ valid: false }`. Same model as `jwt verify`.

## Limits & resource caps

| Operation | Cap | Configurable |
|---|---|---|
| `encrypt` plaintext | 16 MiB | `maxInputBytes` per call, env override. |
| `decrypt` ciphertext | 16 MiB | same. |
| `sign` / `verify` message | 16 MiB | same. |
| PBKDF2 iterations | 10,000,000 | hard cap. |
| scrypt `N` | 2²⁰ | hard cap. |
| scrypt memory | 256 MiB | hard cap (derived from N·r). |
| argon2id memory | 1 GiB | hard cap. |
| argon2id time cost | 10 | hard cap. |
| argon2id parallelism | 16 | hard cap. |
| `generate-keypair` RSA | 8192 bits | hard cap (above this, keygen takes minutes). |
| Wall clock per call | 30 s | matches `script`'s default. |

Caps exist primarily to prevent DoS via runaway KDF / keygen costs. Hitting one returns `bad_parameters` or `too_large`, not a hang.

## Security posture

- **Randomness:** OS CSPRNG only, via `node:crypto.randomBytes`. No userspace PRNG, no seeded random for "reproducibility" — if a caller wants determinism for testing they pass an explicit `nonce` / `salt`.
- **Nonce policy:** auto-generated by default for all AEAD operations. Caller-supplied nonces accepted (test vectors, deterministic encryption) but the tool description must explicitly warn about GCM nonce reuse.
- **Constant-time comparisons** for signature verification and AEAD authentication tags — `crypto.timingSafeEqual`, never `===`.
- **No fallback algorithm negotiation.** The caller specifies the algorithm; we don't pick one based on key type unless the key type leaves exactly one valid choice (Ed25519 → Ed25519 sign).
- **No silent downgrades.** A request for `aes-128-gcm` with a 32-byte key is `bad_parameters`, not "we'll just truncate."
- **AEAD only for symmetric encryption.** No raw block-cipher or stream-cipher modes without authentication.
- **No private-key-in-logs surface.** Tool response never contains private material the caller passed in; the conformance suite asserts this.

## Implementation notes

### Dependencies

The bulk of this tool is `node:crypto` (Node 22 LTS), which already covers:

- AES-GCM, ChaCha20-Poly1305 (`createCipheriv`, `subtle.encrypt`)
- PBKDF2, scrypt, HKDF (`pbkdf2Sync`, `scryptSync`, `hkdfSync`)
- RSA, EC, Ed25519, X25519 keygen (`generateKeyPairSync`)
- Sign / verify (`sign`, `verify`, `KeyObject`)
- ECDH / X25519 agreement (`diffieHellman`)
- PEM ↔ DER ↔ JWK (`KeyObject.export`, `createPrivateKey` / `createPublicKey`)

**One new dependency** to evaluate: argon2id. Options:

| Package | Type | Pros | Cons |
|---|---|---|---|
| `@node-rs/argon2` | Native (NAPI) | Fast, maintained, prebuilt binaries for common targets. | Native binary in `dist/`. |
| `argon2` | Native (node-gyp) | Most-used. | Requires build toolchain on install — bad for the Docker image. |
| `hash-wasm` | WASM | Pure-WASM, no native compile, runs in any Node. | ~5× slower than native. |
| Defer | — | Ship v1 with PBKDF2 + scrypt only. | Argon2 is the 2026-current recommendation; PBKDF2 is "still fine, but…". |

Recommendation: **defer for v1**, ship PBKDF2 + scrypt (both in `node:crypto`). Add argon2id behind a `@node-rs/argon2` dep in v1.1 once the rest of the tool is stable.

### Code shape

Per `TOOLS.md`'s thin-tool / fat-lib convention:

```
src/tools/crypto.ts          # ~150 lines: schema, action dispatch, formatting
src/lib/crypto/
  ├── aead.ts                # AEAD encrypt / decrypt
  ├── keypair.ts             # generate / convert / inspect
  ├── signing.ts             # sign / verify
  ├── kdf.ts                 # PBKDF2 / scrypt / HKDF (and later argon2)
  ├── agreement.ts           # ECDH / X25519
  ├── format.ts              # PEM ↔ DER ↔ JWK normalisation
  └── policy.ts              # algorithm allow/deny lists, parameter validation
```

Each lib file is pure, accepts `KeyObject`s and `Buffer`s, and is unit-tested directly (per `TESTING-STRATEGY.md`).

### `script` integration

`crypto` is wired into the `script` VM the same way every other tool is — via the `build*Tool` factory pattern. This means `script` can compose `crypto.encrypt` → `encode` → `hash` in a single MCP call. The VM still cannot perform crypto itself; it must go through this tool.

## Test strategy

Per `docs/TESTING-STRATEGY.md`:

- **Independently derived vectors.** Test inputs come from RFC test vectors (RFC 7539 ChaCha20-Poly1305, RFC 8032 Ed25519, RFC 6070 PBKDF2, RFC 7914 scrypt, RFC 5869 HKDF), not from running the implementation and pasting its output.
- **Round-trip properties.** For every (algorithm, key-size) pair: `decrypt(encrypt(plaintext)) === plaintext`; `verify(sign(message)) === true`; `parse(serialise(key)) === key`.
- **Negative cases.** Wrong key → `decryption_failed`. Tampered ciphertext → `decryption_failed`. Tampered AAD → `decryption_failed`. Wrong algorithm for key type → `wrong_algorithm`. Refused algorithm → `unsupported_algorithm`. Each is its own test, not a single mega-case.
- **Redaction conformance.** A registry-driven test sweeps every action that accepts a private key, calls it, and asserts the private material does not appear anywhere in `structuredContent` or `content`.
- **Cap enforcement.** Inputs exactly at the cap pass; inputs one byte over the cap fail with `too_large`. KDF iteration counts at the cap pass; one over fail with `bad_parameters`.
- **No timing-attack hooks.** We do not test for constant-time behaviour (impossible to verify reliably under Vitest), but we do test that `crypto.timingSafeEqual` is the only path used for tag/signature comparison — `lib/crypto/aead.ts` exposes no `===` comparison on ciphertext tags. Lint-enforced via a code review item, not a runtime check.

## Open questions

1. **secp256k1 sign/verify.** Node supports keygen on this curve but signature operations have edge cases (low-S enforcement for Ethereum). Ship without ECDSA-on-secp256k1 in v1?
2. **Public-key encryption (RSA-OAEP, ECIES-style).** Useful, but it's a slippery slope toward "implement age." Out of v1; revisit.
3. **Streaming.** Every existing tool is one-shot; encrypt / decrypt could plausibly stream for large inputs. Defer until someone has a real use case — `script`'s 30 s budget and the 16 MiB cap cover most needs.
4. **Algorithm aliases.** Should `aes256gcm`, `AES-256-GCM`, `aes-256-gcm` all parse? Lean strict (one canonical form per algorithm) — saves us from owning a normalisation table.
5. **JWK thumbprint format.** RFC 7638 canonical thumbprint, base64url-encoded. Should `inspect-key` return one even for non-JWK input? Probably yes — it's the universal key fingerprint.
6. **Argon2 timing.** Even with native bindings, argon2id at default params is ~50–200 ms. Does this break the suite's "fast tool call" expectation? Probably acceptable for an explicit KDF call.

## Rollout

- **v1 (this proposal):** all eleven actions, AES-GCM / ChaCha20-Poly1305, PBKDF2 / scrypt / HKDF, RSA / EC / Ed25519 / X25519, PEM / DER / JWK conversion. No new deps.
- **v1.1:** argon2id via `@node-rs/argon2`.
- **v2 (separate proposal):** XChaCha20-Poly1305, AES-GCM-SIV, possibly ECIES / sealed-box. Possibly `age` file-format support if there's demand.

## References

- RFC 7539 — ChaCha20 and Poly1305 for IETF protocols
- RFC 5869 — HKDF
- RFC 6070 — PBKDF2 test vectors
- RFC 7914 — scrypt
- RFC 9106 — argon2
- RFC 8032 — Ed25519 / Ed448
- RFC 7638 — JWK thumbprint
- OWASP — Password Storage Cheat Sheet (KDF parameter recommendations)
- NIST SP 800-38D — GCM (nonce uniqueness)
