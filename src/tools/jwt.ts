import {
  createRemoteJWKSet,
  customFetch,
  decodeJwt,
  decodeProtectedHeader,
  importJWK,
  importPKCS8,
  importSPKI,
  importX509,
  type JWTPayload,
  jwtVerify,
  SignJWT,
} from "jose";
import { z } from "zod";
import { toMessage } from "../lib/errors.js";
import { fetchText } from "../lib/input.js";
import { assertUrlAllowed, guardedFetch } from "../lib/ssrf.js";
import { defineTool, err, ok, okJson, singleOrBatch } from "./types.js";

function isoOrUndefined(seconds: unknown): string | undefined {
  return typeof seconds === "number"
    ? new Date(seconds * 1000).toISOString()
    : undefined;
}

interface DerivedClaims {
  issuedAt?: string;
  expiresAt?: string;
  notBefore?: string;
  expired: boolean;
  expWarning?: string;
  secondsUntilExpiry?: number;
}

// Build the derived-from-claims envelope. Both decode and verify return
// this so a successful verify doesn't force a second decode round-trip
// to format `exp` / `iat` / `nbf` as ISO strings.
function deriveClaims(payload: {
  iat?: unknown;
  exp?: unknown;
  nbf?: unknown;
}): DerivedClaims {
  const nowSeconds = Date.now() / 1000;
  const hasExpClaim = "exp" in payload && payload.exp !== undefined;
  const expNumber = typeof payload.exp === "number" ? payload.exp : undefined;
  const expired = expNumber !== undefined && expNumber < nowSeconds;
  const expWarning =
    hasExpClaim && expNumber === undefined
      ? `exp claim is not a NumericDate (RFC 7519 §2): ${JSON.stringify(payload.exp)}`
      : undefined;
  return {
    issuedAt: isoOrUndefined(payload.iat),
    expiresAt: isoOrUndefined(payload.exp),
    notBefore: isoOrUndefined(payload.nbf),
    expired,
    ...(expWarning ? { expWarning } : {}),
    ...(expNumber !== undefined
      ? { secondsUntilExpiry: Math.round(expNumber - nowSeconds) }
      : {}),
  };
}

// A JWK arrives as a JSON object literal; parse it and hand it to jose.
// Shared by the verify and sign paths so the detection + error wording can't
// drift between them.
async function importJwk(trimmed: string, alg: string) {
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch (e) {
    const detail = toMessage(e);
    throw new Error(`key looked like a JWK but is not valid JSON: ${detail}`);
  }
  return await importJWK(parsed as Parameters<typeof importJWK>[0], alg);
}

async function importVerifyKey(key: string, alg: string) {
  const trimmed = key.trim();
  if (/^https?:\/\//.test(trimmed)) {
    const url = new URL(trimmed);
    // SSRF guard: jose's default fetch ignores our env, so a JWKS URL
    // pointing at cloud metadata / loopback would otherwise be fetched
    // verbatim. We pre-validate once before construction, and again on
    // each fetch via [customFetch] so cache refreshes don't sneak past
    // the guard if the host's resolution changes.
    await assertUrlAllowed(url);
    return createRemoteJWKSet(url, {
      [customFetch]: async (input, init) => {
        await assertUrlAllowed(new URL(input));
        return guardedFetch(input, init);
      },
    });
  }
  if (trimmed.startsWith("-----BEGIN CERTIFICATE-----")) {
    return await importX509(trimmed, alg);
  }
  if (trimmed.startsWith("-----BEGIN PUBLIC KEY-----")) {
    return await importSPKI(trimmed, alg);
  }
  if (trimmed.startsWith("{")) {
    return await importJwk(trimmed, alg);
  }
  return new TextEncoder().encode(key);
}

async function importSignKey(key: string, alg: string) {
  const trimmed = key.trim();
  if (trimmed.startsWith("-----BEGIN PRIVATE KEY-----")) {
    return await importPKCS8(trimmed, alg);
  }
  // SEC1-encoded EC private keys (OpenSSL's default for `ecparam`) used
  // to fall through to the TextEncoder branch below and silently become
  // an HMAC key, producing a "valid" token signed against the wrong
  // algorithm. Fail loud with a copy-pasteable conversion hint.
  if (trimmed.startsWith("-----BEGIN EC PRIVATE KEY-----")) {
    throw new Error(
      "EC private keys must be in PKCS8 (BEGIN PRIVATE KEY) format; convert with: openssl pkcs8 -topk8 -nocrypt -in key.pem",
    );
  }
  if (trimmed.startsWith("-----BEGIN RSA PRIVATE KEY-----")) {
    throw new Error(
      "RSA private keys must be in PKCS8 (BEGIN PRIVATE KEY) format; convert with: openssl pkcs8 -topk8 -nocrypt -in key.pem",
    );
  }
  if (trimmed.startsWith("{")) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmed);
    } catch (e) {
      const detail = toMessage(e);
      throw new Error(`key looked like a JWK but is not valid JSON: ${detail}`);
    }
    return await importJWK(parsed as Parameters<typeof importJWK>[0], alg);
  }
  return new TextEncoder().encode(key);
}

export const jwtTool = defineTool({
  name: "jwt",
  title: "JSON Web Token (JWT)",
  description:
    "Work with JSON Web Tokens. Use this when you have a JWT you want to peek inside, when you need to confirm a token's signature is valid, or when you need to mint a token for testing.\n" +
    "\n" +
    "Actions:\n" +
    "  • 'decode' — inspect header / payload / signature without verifying anything. Works on expired or tampered tokens; comes back with iat/exp/nbf parsed into ISO timestamps and an `expired` flag.\n" +
    "  • 'verify' — cryptographically verify the signature. `key` can be an HMAC secret, a PEM public key or certificate, a JWK JSON object, or an https:// JWKS URL (which the tool fetches). Verification failures return `valid: false` with `failureReason` (not an `isError`).\n" +
    "  • 'sign' — create a token. `key` is an HMAC secret for HS* algorithms, or a PKCS8 PEM private key for RS* / ES* / PS* / EdDSA. Pass standard claims (`sub`, `iss`, `aud`, …) inside `payload`.\n" +
    "\n" +
    "Provide the token as `input` (inline) or `inputUrl` (fetched).\n" +
    "\n" +
    "Examples:\n" +
    '  { "action": "decode", "input": "eyJhbGc…" } → header, payload, expired flag\n' +
    '  { "action": "verify", "input": "eyJhbGc…", "key": "https://example.com/.well-known/jwks.json" }\n' +
    '  { "action": "sign", "key": "secret", "algorithm": "HS256", "payload": { "sub": "user-1" }, "expiresIn": "1h" }',
  inputSchema: {
    action: z.enum(["decode", "verify", "sign"]),
    input: z
      .string()
      .optional()
      .describe("The JWT (decode/verify). Surrounding whitespace is trimmed."),
    inputUrl: z
      .string()
      .url()
      .optional()
      .describe(
        "Fetch the JWT text from this URL (decode/verify). Mutually exclusive with `input`.",
      ),
    key: z.string().optional().describe("secret, PEM, JWK JSON, or JWKS URL"),
    algorithm: z
      .string()
      .default("HS256")
      .describe(
        "sign: alg to use. (verify uses the alg from the token header to pick the key-import branch.)",
      ),
    algorithms: z
      .array(z.string())
      .optional()
      .describe("verify: allowed algs (default: any)"),
    audience: singleOrBatch
      .optional()
      .describe(
        "verify: expected aud claim. Pass an array to accept any of several audiences (multi-tenant tokens).",
      ),
    issuer: z.string().optional(),
    payload: z
      .record(z.string(), z.unknown())
      .optional()
      .describe(
        "sign: JWT claims (sub / iss / aud / jti / nbf / iat / exp etc. — these are payload keys, not separate args)",
      ),
    expiresIn: z
      .string()
      .optional()
      .describe(
        "sign: e.g. '2h', '30m', '7d'. Mutually exclusive with `payload.exp` — pass exactly one.",
      ),
    header: z
      .record(z.string(), z.unknown())
      .optional()
      .describe("sign: extra header fields"),
  },
  refine: (args, ctx) => {
    if (args.action === "sign") {
      if (!args.key) {
        ctx.addIssue({
          code: "custom",
          message: "sign requires `key` (HMAC secret or PKCS8 PEM private key)",
          path: ["key"],
        });
      }
      if (!args.payload) {
        ctx.addIssue({
          code: "custom",
          message: "sign requires `payload` (object of claims)",
          path: ["payload"],
        });
      }
      return;
    }
    const hasInput = args.input !== undefined;
    const hasUrl = args.inputUrl !== undefined;
    if (!hasInput && !hasUrl) {
      ctx.addIssue({
        code: "custom",
        message: `${args.action} requires \`input\` (or \`inputUrl\`)`,
        path: ["input"],
      });
    } else if (hasInput && hasUrl) {
      ctx.addIssue({
        code: "custom",
        message: "provide exactly one of input or inputUrl",
      });
    }
    if (args.action === "verify" && !args.key) {
      ctx.addIssue({
        code: "custom",
        message: "verify requires `key` (secret, PEM, JWK, or JWKS URL)",
        path: ["key"],
      });
    }
  },
  handler: async (args) => {
    try {
      switch (args.action) {
        case "decode": {
          const token = await resolveToken(args);
          if (typeof token !== "string") return token;
          const parts = token.split(".");
          if (parts.length !== 3) {
            return err(
              `not a JWS compact token: expected 3 dot-separated parts, got ${parts.length}`,
            );
          }
          const header = decodeProtectedHeader(token);
          const payload = decodeJwt(token);
          const structured = {
            header,
            payload,
            signature: parts[2],
            derived: deriveClaims(payload),
            verified: false,
          };
          return okJson(structured);
        }
        case "verify": {
          const token = await resolveToken(args);
          if (typeof token !== "string") return token;
          if (!args.key)
            return err("verify requires `key` (secret, PEM, JWK, or JWKS URL)");
          const parts = token.split(".");
          if (parts.length !== 3) {
            return failVerify(
              `not a JWS compact token: expected 3 dot-separated parts, got ${parts.length}`,
            );
          }
          let header: ReturnType<typeof decodeProtectedHeader>;
          try {
            header = decodeProtectedHeader(token);
          } catch (e) {
            return failVerify(`malformed protected header: ${toMessage(e)}`);
          }
          if (header.alg === "none") {
            return failVerify(
              'token uses alg "none" (unsigned tokens cannot be verified)',
            );
          }
          if (!header.alg) {
            return failVerify(
              "token header is missing the `alg` field — refusing to guess RS256 (which would surface as a confusing key-mismatch error)",
            );
          }
          try {
            const key = await importVerifyKey(args.key, header.alg);
            const { payload, protectedHeader } = await jwtVerify(
              token,
              // biome-ignore lint/suspicious/noExplicitAny: jose key union vs JWKS resolver
              key as any,
              {
                ...(args.algorithms ? { algorithms: args.algorithms } : {}),
                ...(args.audience ? { audience: args.audience } : {}),
                ...(args.issuer ? { issuer: args.issuer } : {}),
              },
            );
            const structured = {
              valid: true,
              header: protectedHeader,
              payload,
              derived: deriveClaims(payload),
            };
            return okJson(structured);
          } catch (e) {
            return failVerify(
              e instanceof Error ? `${e.name}: ${e.message}` : String(e),
            );
          }
        }
        case "sign": {
          if (!args.key)
            return err(
              "sign requires `key` (HMAC secret or PKCS8 PEM private key)",
            );
          if (!args.payload)
            return err("sign requires `payload` (object of claims)");
          if (
            args.header &&
            "alg" in args.header &&
            args.header.alg !== args.algorithm
          ) {
            return err(
              `header.alg (${JSON.stringify(args.header.alg)}) conflicts with algorithm param (${JSON.stringify(args.algorithm)}); supply only one`,
            );
          }
          if (args.expiresIn && args.payload.exp !== undefined) {
            return err(
              "expiresIn conflicts with payload.exp — supply only one (expiresIn would silently overwrite the explicit exp claim)",
            );
          }
          const key = await importSignKey(args.key, args.algorithm);
          let builder = new SignJWT(
            args.payload as JWTPayload,
          ).setProtectedHeader({
            ...(args.header ?? {}),
            alg: args.algorithm,
            typ: "JWT",
          });
          if (args.payload.iat === undefined) builder = builder.setIssuedAt();
          if (args.expiresIn)
            builder = builder.setExpirationTime(args.expiresIn);
          const token = await builder.sign(key);
          // decode the just-signed token so the response includes the
          // resolved iat/exp the caller actually got — no second round-trip.
          const issued = decodeJwt(token);
          const structured = {
            token,
            algorithm: args.algorithm,
            issuedAt: isoOrUndefined(issued.iat),
            expiresAt: isoOrUndefined(issued.exp),
          };
          return ok(token, structured);
        }
      }
    } catch (e) {
      return err(toMessage(e));
    }
  },
});

// Resolve the JWT input from `input` (trimmed) or `inputUrl` (fetched +
// trimmed). Returns either the trimmed token string or an error
// CallToolResult that the caller should return directly.
async function resolveToken(args: {
  action: "decode" | "verify" | "sign";
  input?: string;
  inputUrl?: string;
}): Promise<string | ReturnType<typeof err>> {
  if (args.input === undefined && args.inputUrl === undefined) {
    return err(`${args.action} requires \`input\` (or \`inputUrl\`)`);
  }
  if (args.input !== undefined && args.inputUrl !== undefined) {
    return err("provide exactly one of input or inputUrl");
  }
  const raw =
    args.input !== undefined
      ? args.input
      : await fetchText(args.inputUrl as string);
  return raw.trim();
}

function failVerify(reason: string) {
  const structured = { valid: false, failureReason: reason };
  return okJson(structured);
}
