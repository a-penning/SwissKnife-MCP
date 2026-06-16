import { randomBytes, randomUUID } from "node:crypto";
import { nanoid } from "nanoid";
import { decodeTime, ulid } from "ulid";
import { z } from "zod";
import { batchProcess } from "../lib/batch.js";
import { toMessage } from "../lib/errors.js";
import { CHARSETS, randomChars } from "../lib/random.js";
import {
  UUID_RE,
  uuidTimestamp,
  uuidV5,
  uuidV7,
  uuidVariant,
  uuidVersion,
} from "../lib/uuid.js";
import { defineTool, err, ok, okJson, singleOrBatch } from "./types.js";

const ULID_RE = /^[0-9ABCDEFGHJKMNPQRSTVWXYZ]{26}$/;

type GenerateArgs = {
  kind:
    | "uuid-v4"
    | "uuid-v5"
    | "uuid-v7"
    | "ulid"
    | "nanoid"
    | "random-string"
    | "random-bytes"
    | "password";
  namespace?: string;
  name?: string;
  length?: number;
  alphabet?: string;
  outputEncoding?: "hex" | "base64";
  uppercase?: boolean;
  digits?: boolean;
  symbols?: boolean;
};

function generateOne(args: GenerateArgs): string {
  switch (args.kind) {
    case "uuid-v4":
      return randomUUID();
    case "uuid-v5": {
      if (!args.namespace || args.name === undefined) {
        throw new Error(
          "uuid-v5 requires `namespace` (a UUID or one of dns/url/oid/x500) and `name`",
        );
      }
      return uuidV5(args.namespace, args.name);
    }
    case "uuid-v7":
      return uuidV7();
    case "ulid":
      return ulid();
    case "nanoid":
      return args.alphabet !== undefined
        ? randomChars(args.alphabet, args.length ?? 21)
        : nanoid(args.length ?? 21);
    case "random-string":
      return randomChars(
        args.alphabet ??
          CHARSETS.lowercase + CHARSETS.uppercase + CHARSETS.digits,
        args.length ?? 32,
      );
    case "random-bytes":
      return randomBytes(args.length ?? 32).toString(
        args.outputEncoding === "base64" ? "base64" : "hex",
      );
    case "password": {
      const classes = [CHARSETS.lowercase as string];
      if (args.uppercase !== false) classes.push(CHARSETS.uppercase);
      if (args.digits !== false) classes.push(CHARSETS.digits);
      if (args.symbols !== false) classes.push(CHARSETS.symbols);
      const length = args.length ?? 20;
      if (length < classes.length) {
        throw new Error(
          `password length ${length} cannot cover ${classes.length} character classes`,
        );
      }
      const alphabet = classes.join("");
      // resample until every enabled class is represented (unbiased, terminates
      // fast since length >= classes.length); capped to avoid an unbounded loop.
      for (let attempt = 0; attempt < 10_000; attempt++) {
        const candidate = randomChars(alphabet, length);
        if (
          classes.every((cls) => [...candidate].some((ch) => cls.includes(ch)))
        ) {
          return candidate;
        }
      }
      throw new Error(
        "could not generate a password covering all character classes; increase length",
      );
    }
  }
}

function inspectOne(value: string): Record<string, unknown> {
  if (UUID_RE.test(value)) {
    const lower = value.toLowerCase();
    const ts = uuidTimestamp(lower);
    return {
      kind: "uuid",
      valid: true,
      canonical: lower,
      version: uuidVersion(lower),
      variant: uuidVariant(lower),
      ...(ts ? { timestamp: ts } : {}),
    };
  }
  if (ULID_RE.test(value.toUpperCase())) {
    const upper = value.toUpperCase();
    try {
      const ms = decodeTime(upper);
      return {
        kind: "ulid",
        valid: true,
        canonical: upper,
        timestamp: new Date(ms).toISOString(),
      };
    } catch (e) {
      return {
        kind: "ulid",
        valid: false,
        reason: toMessage(e),
      };
    }
  }
  return {
    kind: "unknown",
    valid: false,
    reason: "not a UUID (8-4-4-4-12 hex) or ULID (26 Crockford base32 chars)",
  };
}

export const idTool = defineTool({
  name: "id",
  title: "ID & secret generator",
  description:
    "Generate unique identifiers and random secrets, or inspect an existing identifier to see what it actually is.\n" +
    "\n" +
    "Use `action: 'generate'` to produce UUIDs (v4 random, v5 deterministic from a name, v7 time-ordered), ULIDs, nanoids, " +
    "random strings, random bytes, or strong passwords with guaranteed character-class coverage. All randomness comes from the OS CSPRNG.\n" +
    "\n" +
    "Use `action: 'inspect'` to validate a UUID or ULID and pull out its version, variant, canonical form, and embedded timestamp " +
    "(UUID v1/v7 and ULID). An un-parseable value is a successful answer (`valid: false`), not an error.\n" +
    "\n" +
    "Examples:\n" +
    '  { "action": "generate", "kind": "uuid-v7", "count": 5 }\n' +
    '  { "action": "generate", "kind": "password", "length": 24 }\n' +
    '  { "action": "generate", "kind": "uuid-v5", "namespace": "dns", "name": "example.com" }\n' +
    '  { "action": "inspect", "value": "01HZX5Y2P3J4K5M6N7P8Q9R0S1" } → ulid + timestamp',
  inputSchema: {
    action: z.enum(["generate", "inspect"]).default("generate"),
    kind: z
      .enum([
        "uuid-v4",
        "uuid-v5",
        "uuid-v7",
        "ulid",
        "nanoid",
        "random-string",
        "random-bytes",
        "password",
      ])
      .optional()
      .describe("generate: what kind of identifier to produce."),
    count: z.coerce
      .number()
      .int()
      .min(1)
      .max(100)
      .default(1)
      .describe("generate: how many values to produce (max 100)."),
    length: z.coerce
      .number()
      .int()
      .min(1)
      .max(1024)
      .optional()
      .describe(
        "Length for nanoid / random-string / random-bytes / password. For random-bytes this is the byte count BEFORE encoding.",
      ),
    alphabet: z
      .string()
      .optional()
      .describe("Custom alphabet for nanoid or random-string."),
    namespace: z
      .string()
      .optional()
      .describe(
        "uuid-v5: a UUID or one of the named namespaces 'dns', 'url', 'oid', 'x500'.",
      ),
    name: z.string().optional().describe("uuid-v5: the name to hash."),
    outputEncoding: z
      .enum(["hex", "base64"])
      .optional()
      .describe("random-bytes only: how to encode the bytes (default 'hex')."),
    uppercase: z
      .boolean()
      .default(true)
      .describe("password: include uppercase letters."),
    digits: z.boolean().default(true).describe("password: include digits."),
    symbols: z
      .boolean()
      .default(true)
      .describe("password: include symbols (set: !@#$%^&*()-_=+[]{};:,.<>?)."),
    value: singleOrBatch
      .optional()
      .describe(
        "inspect: the identifier (or array of identifiers) to validate.",
      ),
  },
  handler: (args) => {
    try {
      if (args.action === "inspect") {
        if (args.value === undefined) return err("inspect requires `value`");
        if (Array.isArray(args.value)) {
          const { results, failures } = batchProcess(args.value, (v) => ({
            value: v,
            ...inspectOne(v),
          }));
          return ok(JSON.stringify({ results, failures }, null, 2), {
            results,
            failures,
          });
        }
        const details = inspectOne(args.value);
        return okJson(details);
      }
      const kind = args.kind;
      if (!kind) return err("generate requires `kind`");
      const effective = {
        ...args,
        kind,
        outputEncoding: args.outputEncoding ?? "hex",
      } as GenerateArgs;
      const values = Array.from({ length: args.count }, () =>
        generateOne(effective),
      );
      return ok(values.join("\n"), { values, count: values.length });
    } catch (e) {
      return err(toMessage(e));
    }
  },
});
