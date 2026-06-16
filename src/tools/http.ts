import type { Buffer } from "node:buffer";
import { z } from "zod";
import { parseHttpUrl, streamToBuffer } from "../lib/input.js";
import {
  assertUrlAllowed,
  guardedFetch,
  ssrfGuardEnabled,
} from "../lib/ssrf.js";
import { decodeStrictBase64 } from "../lib/strict-codec.js";
import { defineTool, err, ok } from "./types.js";

const MAX_RESPONSE_BYTES = 5 * 1024 * 1024;
const TEXT_PREVIEW_CHARS = 2048;

const METHODS = [
  "GET",
  "HEAD",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "OPTIONS",
] as const;

export const httpTool = defineTool({
  name: "http",
  title: "HTTP request",
  description:
    "Make a real HTTP(S) request and get back the status, headers, timing, and body. Use this when you want to probe an endpoint, call a REST API, check a health route, or inspect exactly what a server returns for a given request — the things curl and a browser DevTools panel let you do, but as structured data the model can read.\n" +
    "\n" +
    "Supply the request body inline with `body` (text or base64 via `requestBodyEncoding`) or as a JSON value via `jsonBody` (the tool will serialise it and set `content-type: application/json`). GET and HEAD can't carry a body; POST/PUT/PATCH/DELETE/OPTIONS can.\n" +
    "\n" +
    "Response bodies are capped at `maxResponseBytes` (default 256 KiB, max 5 MiB) and come back with `truncated: true` if they exceed it. Non-UTF-8 bodies are returned base64-encoded with `responseBodyEncoding: 'base64'`. JSON responses are additionally parsed into a structured `json` field. Set-Cookie headers are preserved in a separate array (not flattened).\n" +
    "\n" +
    "Examples:\n" +
    '  { "url": "https://api.example.com/health" }\n' +
    '  { "url": "https://api.example.com/users", "method": "POST", "jsonBody": { "name": "ada" } }\n' +
    '  { "url": "https://example.com/", "headers": { "user-agent": "swissknife" } }',
  inputSchema: {
    url: z.string().describe("http(s) URL to request"),
    method: z.enum(METHODS).default("GET"),
    headers: z
      .record(z.string(), z.string())
      .optional()
      .describe("request headers"),
    body: z
      .string()
      .optional()
      .describe(
        "request body. Only valid for POST/PUT/PATCH/DELETE/OPTIONS — GET and HEAD are rejected.",
      ),
    requestBodyEncoding: z
      .enum(["utf8", "base64"])
      .default("utf8")
      .describe(
        "how to interpret the inbound `body` you're sending. The corresponding response field is `responseBodyEncoding` — input and output never share a name.",
      ),
    jsonBody: z
      .unknown()
      .optional()
      .describe(
        "JSON value to send as the body (alternative to `body`; sets content-type application/json unless overridden)",
      ),
    timeoutMs: z.coerce.number().int().min(1).max(60_000).default(10_000),
    redirect: z
      .enum(["follow", "manual", "error"])
      .default("follow")
      .describe(
        "What to do with 3xx redirects. 'follow' (default) follows them; 'manual' returns the 3xx response as-is; 'error' fails on any redirect.",
      ),
    maxResponseBytes: z.coerce
      .number()
      .int()
      .min(1)
      .max(MAX_RESPONSE_BYTES)
      .default(256 * 1024),
    responseEncoding: z
      .enum(["auto", "utf8", "base64"])
      .default("auto")
      .describe(
        "auto: utf8 when the body is valid UTF-8, base64 otherwise; or force one",
      ),
  },
  outputSchema: {
    status: z.number(),
    statusText: z.string(),
    ok: z.boolean().describe("status in the 200-299 range"),
    headers: z.record(z.string(), z.string()),
    body: z.string(),
    responseBodyEncoding: z
      .enum(["utf8", "base64"])
      .describe(
        "how the body field is encoded ('utf8' or 'base64' for non-text payloads). Mirror image of the input `requestBodyEncoding`.",
      ),
    bodyBytes: z.number().describe("bytes kept after the cap"),
    truncated: z.boolean(),
    durationMs: z.number(),
    finalUrl: z.string().describe("URL after redirects"),
    redirected: z.boolean(),
    setCookies: z
      .array(z.string())
      .optional()
      .describe("Set-Cookie headers, preserved separately (not comma-joined)"),
    json: z
      .unknown()
      .optional()
      .describe("parsed body when the response is JSON and not truncated"),
    warnings: z
      .array(z.string())
      .optional()
      .describe(
        "non-fatal advisories (e.g. SSRF guard forcing redirect=manual)",
      ),
  },
  refine: (args, ctx) => {
    if (args.body !== undefined && args.jsonBody !== undefined) {
      ctx.addIssue({
        code: "custom",
        message: "provide at most one of body or jsonBody",
      });
    }
  },
  handler: async (args) => {
    let parsed: URL;
    try {
      parsed = parseHttpUrl(args.url);
    } catch (e) {
      return err(e instanceof Error ? e.message : String(e));
    }
    try {
      await assertUrlAllowed(parsed);
    } catch (e) {
      return err(e instanceof Error ? e.message : String(e));
    }
    if (args.body !== undefined && args.jsonBody !== undefined) {
      return err("provide at most one of body or jsonBody");
    }
    const hasBody = args.body !== undefined || args.jsonBody !== undefined;
    if (hasBody && (args.method === "GET" || args.method === "HEAD")) {
      return err(`${args.method} requests cannot carry a body`);
    }
    const redirectMode: "follow" | "manual" | "error" = args.redirect;

    let headers: Headers;
    try {
      headers = new Headers(args.headers ?? {});
    } catch (e) {
      return err(
        `invalid request headers: ${e instanceof Error ? e.message : String(e)}`,
      );
    }
    let requestBody: string | Buffer | undefined;
    if (args.jsonBody !== undefined) {
      // MCP transport often serialises `jsonBody` as a string because its
      // schema is z.unknown() and has no type. If it arrives as a string,
      // try to parse it as JSON first so we don't double-encode the body
      // into a quoted string. Non-JSON strings are still valid JSON values
      // (a JSON string), so we surface that intent loudly via the error.
      let value = args.jsonBody;
      if (typeof value === "string") {
        try {
          value = JSON.parse(value);
        } catch {
          return err(
            "jsonBody was passed as a string but is not valid JSON; pass a JSON object/array/etc., or use `body` to send a literal string",
          );
        }
      }
      requestBody = JSON.stringify(value);
      if (!headers.has("content-type")) {
        headers.set("content-type", "application/json");
      }
    } else if (args.body !== undefined) {
      if (args.requestBodyEncoding === "base64") {
        try {
          requestBody = decodeStrictBase64(args.body, "body base64");
        } catch (e) {
          return err(e instanceof Error ? e.message : String(e));
        }
      } else {
        requestBody = args.body;
      }
    }

    // Under the SSRF guard we never auto-follow: a redirect could point at a
    // private address that was not pre-validated. The 3xx is returned as-is.
    const redirectDowngraded = ssrfGuardEnabled() && redirectMode !== "manual";
    const redirect = ssrfGuardEnabled() ? "manual" : redirectMode;

    const startedAt = Date.now();
    let res: Response;
    try {
      res = await guardedFetch(parsed, {
        method: args.method,
        headers,
        body: requestBody,
        redirect,
        signal: AbortSignal.timeout(args.timeoutMs),
      });
    } catch (e) {
      if (e instanceof DOMException && e.name === "TimeoutError") {
        return err(`request timed out after ${args.timeoutMs}ms: ${args.url}`);
      }
      const reason =
        e instanceof Error
          ? e.cause instanceof Error
            ? e.cause.message
            : e.message
          : String(e);
      return err(`request failed for ${args.url}: ${reason}`);
    }

    let bodyBuffer: Buffer;
    let truncated: boolean;
    try {
      ({ buffer: bodyBuffer, truncated } = await streamToBuffer(
        res.body,
        args.maxResponseBytes,
        "truncate",
      ));
    } catch (e) {
      // The fetch() AbortSignal can also fire after headers have arrived
      // (while we're still pulling the body) — map that the same way as the
      // pre-headers timeout so the caller sees a single, precise message.
      if (e instanceof DOMException && e.name === "TimeoutError") {
        return err(
          `request timed out after ${args.timeoutMs}ms while reading body: ${args.url}`,
        );
      }
      return err(
        `failed to read response body for ${args.url}: ${e instanceof Error ? e.message : String(e)}`,
      );
    }
    const durationMs = Date.now() - startedAt;

    let responseBodyEncoding: "utf8" | "base64";
    let bodyText: string;
    if (args.responseEncoding === "base64") {
      responseBodyEncoding = "base64";
      bodyText = bodyBuffer.toString("base64");
    } else if (args.responseEncoding === "utf8") {
      responseBodyEncoding = "utf8";
      bodyText = bodyBuffer.toString("utf8");
    } else {
      try {
        bodyText = new TextDecoder("utf-8", { fatal: true }).decode(bodyBuffer);
        responseBodyEncoding = "utf8";
      } catch {
        bodyText = bodyBuffer.toString("base64");
        responseBodyEncoding = "base64";
      }
    }

    const responseHeaders = Object.fromEntries(res.headers.entries());
    // Headers.entries() comma-joins duplicate Set-Cookie into one value, which
    // mangles multiple cookies; expose them intact for endpoint inspection.
    const setCookies = res.headers.getSetCookie?.() ?? [];
    const contentType = res.headers.get("content-type") ?? "";
    let json: unknown;
    let jsonTruncationWarning: string | undefined;
    if (
      responseBodyEncoding === "utf8" &&
      !truncated &&
      /\bjson\b/i.test(contentType)
    ) {
      try {
        json = JSON.parse(bodyText);
      } catch {
        // leave json undefined — body field still carries the raw text
      }
    } else if (
      truncated &&
      /\bjson\b/i.test(contentType) &&
      responseBodyEncoding === "utf8"
    ) {
      // Surface this explicitly so callers don't think they can rely on
      // an undefined `json` field when they sent a truncating cap.
      jsonTruncationWarning = `response is JSON but was truncated at ${args.maxResponseBytes} bytes — \`json\` field omitted; raise maxResponseBytes if you need the parsed form`;
    }

    const warnings: string[] = [];
    if (redirectDowngraded) {
      warnings.push(
        `SSRF guard active: requested redirect=${redirectMode} downgraded to manual (each hop would need re-validation)`,
      );
    }
    if (jsonTruncationWarning) warnings.push(jsonTruncationWarning);

    const statusLine = `${args.method} ${res.url || args.url} -> ${res.status} ${res.statusText} (${durationMs}ms, ${bodyBuffer.length} bytes${truncated ? ", truncated" : ""})`;
    const headerLines = Object.entries(responseHeaders)
      .map(([k, v]) => `${k}: ${v}`)
      .join("\n");
    // For base64 bodies the raw payload is opaque text — label it so the
    // caller doesn't have to recognise base64 by eye.
    let preview: string;
    if (responseBodyEncoding === "base64") {
      preview = `[binary body — base64 in structuredContent.body, ${bodyBuffer.length} bytes]`;
    } else if (bodyText.length > TEXT_PREVIEW_CHARS) {
      preview = `${bodyText.slice(0, TEXT_PREVIEW_CHARS)}\n… [preview truncated; full body in structuredContent]`;
    } else {
      preview = bodyText;
    }
    const warningBlock =
      warnings.length > 0
        ? `\n\n[warnings]\n${warnings.map((w) => `- ${w}`).join("\n")}`
        : "";
    const text = `${statusLine}\n${headerLines}\n\n${preview}${warningBlock}`;

    const structured: Record<string, unknown> = {
      status: res.status,
      statusText: res.statusText,
      ok: res.ok,
      headers: responseHeaders,
      body: bodyText,
      responseBodyEncoding,
      bodyBytes: bodyBuffer.length,
      truncated,
      durationMs,
      finalUrl: res.url || args.url,
      redirected: res.redirected,
    };
    if (setCookies.length > 0) structured.setCookies = setCookies;
    if (json !== undefined) structured.json = json;
    if (warnings.length > 0) structured.warnings = warnings;
    return ok(text, structured);
  },
});
