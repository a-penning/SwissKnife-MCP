import { Buffer } from "node:buffer";
import { z } from "zod";
import { base32Decode, base32Encode } from "../lib/base32.js";
import { batchProcess } from "../lib/batch.js";
import {
  COMPRESSION_FORMATS,
  type CompressionFormat,
  compress,
  decodeUrlWithOffset,
  decompress,
  escapeHtml,
  escapeUnicode,
  unescapeHtml,
  unescapeUnicode,
} from "../lib/encode.js";
import { toMessage } from "../lib/errors.js";
import { fetchBytes } from "../lib/input.js";
import { convertRadix } from "../lib/radix.js";
import {
  decodeStrictBase64,
  decodeStrictBase64Url,
  decodeStrictHex,
} from "../lib/strict-codec.js";
import { defineTool, err, ok, singleOrBatch } from "./types.js";

const FORMATS = [
  "base64",
  "base64url",
  "base32",
  "hex",
  "url",
  "url-component",
  "html",
  "unicode-escape",
  "radix",
  "gzip",
  "deflate",
  "brotli",
] as const;
type Format = (typeof FORMATS)[number];

interface EncodeResultItem {
  result: string;
  byteLength: number;
}

interface EncodeArgs {
  direction: "encode" | "decode";
  format: Format;
  inputEncoding: "utf8" | "base64";
  outputEncoding: "utf8" | "base64" | "hex";
  maxOutputBytes: number;
}

export const encodeTool = defineTool({
  name: "encode",
  title: "Encoder / decoder",
  description:
    "Convert text or binary data between common encodings — useful when you need to pass binary through a text channel, " +
    "decode something you've copied off the wire, change a number's base, or compress/decompress a payload.\n" +
    "\n" +
    "Supported formats: base64, base64url, base32, hex, url (encodeURI), url-component (encodeURIComponent), " +
    "html (entity escaping), unicode-escape (\\uXXXX), radix (number-base conversion, 2-36), and the compression " +
    "formats gzip / deflate / brotli (encode compresses, decode decompresses).\n" +
    "\n" +
    "Pass `input` as a single string, or an array to process many items at once with per-item error isolation. " +
    "Use `inputUrl` to pull the source text from a URL instead. `inputEncoding` / `outputEncoding` let you chain " +
    "binary-producing steps together; for compression, output must be base64 or hex on encode and input must be " +
    "base64 on decode.\n" +
    "\n" +
    "Decompression has a configurable bomb cap via `maxOutputBytes` (default 16 MiB, max 64 MiB) — raise it for " +
    "legitimately large payloads, leave the default for untrusted input.\n" +
    "\n" +
    "Examples:\n" +
    '  { "direction": "encode", "format": "base64", "input": "hello" } → "aGVsbG8="\n' +
    '  { "direction": "decode", "format": "hex", "input": "deadbeef" } → "Þ­¾ï"\n' +
    '  { "direction": "encode", "format": "radix", "input": "255", "radixFrom": 10, "radixTo": 16 } → "ff"\n' +
    '  { "direction": "encode", "format": "gzip", "input": "...", "outputEncoding": "base64" } → compressed bytes',
  inputSchema: {
    direction: z.enum(["encode", "decode"]),
    format: z.enum(FORMATS),
    input: singleOrBatch.optional(),
    inputUrl: z
      .string()
      .url()
      .optional()
      .describe(
        "Fetch the source text from this URL instead of supplying it inline.",
      ),
    inputEncoding: z
      .enum(["utf8", "base64"])
      .default("utf8")
      .describe(
        "How to interpret `input` when encoding binary-capable formats. For gzip/deflate/brotli decode, must be 'base64'.",
      ),
    outputEncoding: z
      .enum(["utf8", "base64", "hex"])
      .default("utf8")
      .describe(
        "How to return decoded bytes (for binary-capable decodes). For gzip/deflate/brotli encode, must be 'base64' or 'hex'.",
      ),
    radixFrom: z.coerce.number().int().min(2).max(36).optional(),
    radixTo: z.coerce.number().int().min(2).max(36).optional(),
    maxOutputBytes: z.coerce
      .number()
      .int()
      .min(1)
      .max(64 * 1024 * 1024)
      .default(16 * 1024 * 1024)
      .describe(
        "Cap on the decompressed size, to bound zip-bomb risk. Only used for gzip/deflate/brotli decode.",
      ),
  },
  refine: (args, ctx) => {
    if ((args.input === undefined) === (args.inputUrl === undefined)) {
      ctx.addIssue({
        code: "custom",
        message: "provide exactly one of input or inputUrl",
      });
    }
    if (args.inputUrl !== undefined && args.format === "radix") {
      ctx.addIssue({
        code: "custom",
        message: "format 'radix' is inline-only — pass `input`, not `inputUrl`",
        path: ["inputUrl"],
      });
    }
  },
  handler: async (args) => {
    try {
      if (args.input === undefined && args.inputUrl === undefined) {
        return err("provide exactly one of input or inputUrl");
      }
      if (args.input !== undefined && args.inputUrl !== undefined) {
        return err("provide exactly one of input or inputUrl");
      }
      let inputValue: string | string[];
      if (args.inputUrl !== undefined) {
        if (args.format === "radix") {
          return err(
            "format 'radix' is inline-only — pass `input`, not `inputUrl`",
          );
        }
        inputValue = (await fetchBytes(args.inputUrl)).toString("utf8");
      } else {
        inputValue = args.input as string | string[];
      }

      const warnings: string[] = [];
      if (
        !COMPRESSION_FORMATS.has(args.format) &&
        args.maxOutputBytes !== 16 * 1024 * 1024
      ) {
        warnings.push(
          `maxOutputBytes only applies to gzip/deflate/brotli decode; ignored for format '${args.format}'`,
        );
      }

      if (args.format === "radix") {
        if (args.radixFrom === undefined || args.radixTo === undefined) {
          return err(
            "format 'radix' requires both radixFrom and radixTo (2-36)",
          );
        }
        const radixFrom = args.radixFrom;
        const radixTo = args.radixTo;
        if (Array.isArray(inputValue)) {
          const { results, failures } = batchProcess(inputValue, (s) => {
            const result = convertRadix(s, radixFrom, radixTo);
            return { result, byteLength: Buffer.byteLength(result) };
          });
          return ok(results.map((i) => i.result).join("\n"), {
            results,
            failures,
            warnings,
          });
        }
        const result = convertRadix(inputValue, radixFrom, radixTo);
        return ok(result, {
          result,
          byteLength: Buffer.byteLength(result),
          warnings,
        });
      }

      // Compressed bytes are inherently binary — fail loud rather than
      // fall through to gibberish.
      if (COMPRESSION_FORMATS.has(args.format)) {
        if (args.direction === "encode" && args.outputEncoding === "utf8") {
          return err(
            `${args.format} encode produces binary output — set outputEncoding to 'base64' or 'hex' (utf8 would corrupt the bytes)`,
          );
        }
        if (args.direction === "decode" && args.inputEncoding === "utf8") {
          return err(
            `${args.format} decode expects binary input — set inputEncoding to 'base64' (utf8 would feed raw bytes to the decompressor and produce an opaque header-check error)`,
          );
        }
      }

      const opts: EncodeArgs = {
        direction: args.direction,
        format: args.format,
        inputEncoding: args.inputEncoding,
        outputEncoding: args.outputEncoding,
        maxOutputBytes: args.maxOutputBytes,
      };

      if (Array.isArray(inputValue)) {
        const { results, failures } = batchProcess(inputValue, (s) =>
          processOne(s, opts, warnings),
        );
        return ok(results.map((i) => i.result).join("\n"), {
          results,
          failures,
          warnings,
        });
      }
      const item = processOne(inputValue, opts, warnings);
      return ok(item.result, {
        result: item.result,
        byteLength: item.byteLength,
        warnings,
      });
    } catch (e) {
      return err(toMessage(e));
    }
  },
});

function processOne(
  input: string,
  args: EncodeArgs,
  warnings: string[],
): EncodeResultItem {
  if (args.direction === "encode") {
    const text =
      args.inputEncoding === "base64"
        ? decodeStrictBase64(input).toString("utf8")
        : input;
    const bytes =
      args.inputEncoding === "base64"
        ? decodeStrictBase64(input)
        : Buffer.from(input, "utf8");

    if (COMPRESSION_FORMATS.has(args.format)) {
      const compressed = compress(args.format as CompressionFormat, bytes);
      const result =
        args.outputEncoding === "hex"
          ? compressed.toString("hex")
          : compressed.toString("base64");
      return { result, byteLength: compressed.length };
    }

    let result: string;
    switch (args.format) {
      case "base64":
        result = bytes.toString("base64");
        break;
      case "base64url":
        result = bytes.toString("base64url");
        break;
      case "base32":
        result = base32Encode(bytes);
        break;
      case "hex":
        result = bytes.toString("hex");
        break;
      case "url":
        result = encodeURI(text);
        break;
      case "url-component":
        result = encodeURIComponent(text);
        break;
      case "html":
        result = escapeHtml(text);
        break;
      case "unicode-escape":
        result = escapeUnicode(text);
        break;
      default:
        throw new Error(`unsupported format ${JSON.stringify(args.format)}`);
    }
    return { result, byteLength: Buffer.byteLength(result, "utf8") };
  }

  // decode
  if (COMPRESSION_FORMATS.has(args.format)) {
    const compressedBytes = decodeStrictBase64(input);
    let plain: Buffer;
    try {
      plain = decompress(
        args.format as CompressionFormat,
        compressedBytes,
        args.maxOutputBytes,
      );
    } catch (e) {
      const msg = toMessage(e);
      if (/maxOutputLength|too large|buffer/i.test(msg)) {
        throw new Error(
          `decompressed output would exceed maxOutputBytes (${args.maxOutputBytes}): ${msg}`,
        );
      }
      throw new Error(`${args.format} decode failed: ${msg}`);
    }
    const result =
      args.outputEncoding === "base64"
        ? plain.toString("base64")
        : args.outputEncoding === "hex"
          ? plain.toString("hex")
          : plain.toString("utf8");
    return { result, byteLength: plain.length };
  }

  let bytes: Buffer;
  switch (args.format) {
    case "base64":
      bytes = decodeStrictBase64(input);
      break;
    case "base64url":
      bytes = decodeStrictBase64Url(input);
      break;
    case "base32":
      bytes = Buffer.from(base32Decode(input));
      break;
    case "hex":
      bytes = decodeStrictHex(input);
      break;
    case "url":
      bytes = Buffer.from(decodeUrlWithOffset(input, decodeURI), "utf8");
      break;
    case "url-component":
      bytes = Buffer.from(
        decodeUrlWithOffset(input, decodeURIComponent),
        "utf8",
      );
      break;
    case "html":
      bytes = Buffer.from(unescapeHtml(input, warnings), "utf8");
      break;
    case "unicode-escape":
      bytes = Buffer.from(unescapeUnicode(input), "utf8");
      break;
    default:
      throw new Error(`unsupported format ${JSON.stringify(args.format)}`);
  }
  const result =
    args.outputEncoding === "base64"
      ? bytes.toString("base64")
      : args.outputEncoding === "hex"
        ? bytes.toString("hex")
        : bytes.toString("utf8");
  return { result, byteLength: bytes.length };
}
