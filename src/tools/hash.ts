import { Buffer } from "node:buffer";
import { createHash, createHmac } from "node:crypto";
import { z } from "zod";
import { batchProcessAsync } from "../lib/batch.js";
import { crc32 } from "../lib/crc32.js";
import { toMessage } from "../lib/errors.js";
import { fetchBytes } from "../lib/input.js";
import { decodeWithEncoding } from "../lib/strict-codec.js";
import { defineTool, err, ok, singleOrBatch } from "./types.js";

const ALGORITHMS = [
  "md5",
  "sha1",
  "sha256",
  "sha384",
  "sha512",
  "sha3-256",
  "sha3-512",
  "blake2b512",
  "crc32",
] as const;

type Algorithm = (typeof ALGORITHMS)[number];

export const hashTool = defineTool({
  name: "hash",
  title: "Hash & HMAC",
  description:
    "Produce a cryptographic or non-cryptographic digest of some text or a remote file. " +
    "Use it to verify a checksum, sign a payload (HMAC), fingerprint a blob, or check a file's integrity against a published digest.\n" +
    "\n" +
    "Supported algorithms: md5, sha1, sha256, sha384, sha512, sha3-256, sha3-512, blake2b512, crc32. " +
    "Provide `hmacKey` to compute an HMAC instead of a plain digest (not valid for crc32). " +
    "Input is inline text or — via `inputUrl` — a remote document the server fetches and digests for you. " +
    "Either field accepts an array to digest many items at once; bad items are isolated per-item, the rest still return.\n" +
    "\n" +
    "Examples:\n" +
    '  { "algorithm": "sha256", "input": "hello" } → digest "2cf24d…"\n' +
    '  { "algorithm": "sha256", "inputUrl": "https://example.com/file.bin" } → digest of the fetched bytes\n' +
    '  { "algorithm": "sha256", "input": "msg", "hmacKey": "secret" } → HMAC-SHA256\n' +
    '  { "algorithm": "sha256", "input": ["a", "b", "c"] } → results[] + failures[]',
  inputSchema: {
    algorithm: z.enum(ALGORITHMS),
    input: singleOrBatch.optional(),
    inputUrl: singleOrBatch
      .optional()
      .describe(
        "Fetch this URL (or array of URLs) and digest the response body.",
      ),
    inputEncoding: z
      .enum(["utf8", "base64", "hex"])
      .default("utf8")
      .describe("How to interpret inline `input` (ignored for `inputUrl`)."),
    hmacKey: z.string().optional(),
    hmacKeyEncoding: z.enum(["utf8", "base64", "hex"]).default("utf8"),
    outputEncoding: z
      .enum(["hex", "base64", "base64url"])
      .default("hex")
      .describe(
        "Digest output encoding. 'base64url' is the form used by JWT signatures.",
      ),
  },
  refine: (args, ctx) => {
    if ((args.input === undefined) === (args.inputUrl === undefined)) {
      ctx.addIssue({
        code: "custom",
        message: "provide exactly one of input or inputUrl",
      });
    }
  },
  handler: async (args) => {
    try {
      if ((args.input === undefined) === (args.inputUrl === undefined)) {
        return err("provide exactly one of input or inputUrl");
      }
      if (args.hmacKey !== undefined && args.hmacKey.length === 0) {
        return err(
          "hmacKey is empty — refusing to compute a zero-length-key HMAC",
        );
      }

      const isHmac = args.hmacKey !== undefined;

      const fromString = (s: string): Buffer =>
        decodeWithEncoding(s, args.inputEncoding, "input");

      const digestOnce = (bytes: Buffer): string => {
        let digestBytes: Buffer;
        if (args.algorithm === "crc32") {
          if (isHmac) {
            throw new Error(
              "hmacKey is not valid with crc32 (CRC is not a keyed MAC)",
            );
          }
          const buf = Buffer.alloc(4);
          buf.writeUInt32BE(crc32(bytes));
          digestBytes = buf;
        } else if (isHmac) {
          const key = decodeHmacKey(
            args.hmacKey as string,
            args.hmacKeyEncoding,
          );
          digestBytes = createHmac(args.algorithm, key).update(bytes).digest();
        } else {
          digestBytes = createHash(args.algorithm).update(bytes).digest();
        }
        return digestBytes.toString(args.outputEncoding);
      };

      const summary = (digest: string, url?: string): string => {
        const label = isHmac ? `hmac-${args.algorithm}` : args.algorithm;
        // sha256sum convention: "<digest>  <path>" — useful when comparing
        // a single inputUrl result against a published checksum line.
        return url
          ? `${digest}  ${url}\n${label}: ${digest}`
          : `${label}: ${digest}`;
      };

      const isBatch = Array.isArray(args.input) || Array.isArray(args.inputUrl);

      if (isBatch) {
        const items: string[] = Array.isArray(args.inputUrl)
          ? args.inputUrl
          : Array.isArray(args.input)
            ? args.input
            : [];
        const fromUrl = args.inputUrl !== undefined;
        const { results, failures } = await batchProcessAsync(
          items,
          async (v) => {
            const bytes = fromUrl ? await fetchBytes(v) : fromString(v);
            return { digest: digestOnce(bytes), byteLength: bytes.length };
          },
        );
        const label = isHmac ? `hmac-${args.algorithm}` : args.algorithm;
        return ok(results.map((d) => `${label}: ${d.digest}`).join("\n"), {
          results,
          failures,
          algorithm: args.algorithm as Algorithm,
          hmac: isHmac,
        });
      }

      const bytes =
        args.inputUrl !== undefined
          ? await fetchBytes(args.inputUrl as string)
          : fromString(args.input as string);
      const digest = digestOnce(bytes);
      return ok(summary(digest, args.inputUrl as string | undefined), {
        digest,
        algorithm: args.algorithm as Algorithm,
        hmac: isHmac,
        byteLength: bytes.length,
      });
    } catch (e) {
      return err(toMessage(e));
    }
  },
});

function decodeHmacKey(
  key: string,
  encoding: "utf8" | "base64" | "hex",
): Buffer {
  return decodeWithEncoding(key, encoding, "hmacKey");
}
