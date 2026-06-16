import { Buffer } from "node:buffer";
import { toMessage } from "./errors.js";
import { assertUrlAllowed, guardedFetch, ssrfGuardEnabled } from "./ssrf.js";

const MAX_BYTES = 5 * 1024 * 1024;
const TIMEOUT_MS = 10_000;

/** Parse an http(s) URL, throwing a precise error on a bad/unsupported scheme. */
export function parseHttpUrl(url: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`invalid URL: ${JSON.stringify(url)}`);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(
      `unsupported URL protocol ${JSON.stringify(parsed.protocol)} (http/https only)`,
    );
  }
  return parsed;
}

/** Throws unless exactly one of an inline value / its `*Url` counterpart is set. */
export function assertExactlyOneOf(
  inline: unknown,
  url: unknown,
  name = "input",
): void {
  if ((inline === undefined) === (url === undefined)) {
    throw new Error(`provide exactly one of ${name} or ${name}Url`);
  }
}

/**
 * Drain a fetch body into a Buffer under a byte cap. `onOverflow: 'throw'`
 * aborts past the cap (remote input); `'truncate'` keeps the first `maxBytes`
 * and flags it (the http tool, which returns partial bodies).
 */
export async function streamToBuffer(
  body: ReadableStream<Uint8Array> | null,
  maxBytes: number,
  onOverflow: "throw" | "truncate",
): Promise<{ buffer: Buffer; truncated: boolean }> {
  if (!body) return { buffer: Buffer.alloc(0), truncated: false };
  const chunks: Buffer[] = [];
  let total = 0;
  const reader = body.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      if (onOverflow === "throw") {
        void reader.cancel();
        throw new Error(`remote input too large: exceeds ${maxBytes} bytes`);
      }
      const keep = value.byteLength - (total - maxBytes);
      chunks.push(Buffer.from(value.slice(0, keep)));
      void reader.cancel();
      return { buffer: Buffer.concat(chunks), truncated: true };
    }
    chunks.push(Buffer.from(value));
  }
  return { buffer: Buffer.concat(chunks), truncated: false };
}

export async function fetchBytes(url: string): Promise<Buffer> {
  const parsed = parseHttpUrl(url);
  await assertUrlAllowed(parsed);
  // Under the SSRF guard, redirects are not auto-followed: each hop would need
  // re-validation before a connection is made, so we refuse rather than guess.
  const redirect = ssrfGuardEnabled() ? "manual" : "follow";
  let res: Response;
  try {
    res = await guardedFetch(parsed, {
      signal: AbortSignal.timeout(TIMEOUT_MS),
      redirect,
    });
  } catch (e) {
    const reason = toMessage(e);
    throw new Error(`fetch failed for ${url}: ${reason}`);
  }
  if (redirect === "manual" && res.status >= 300 && res.status < 400) {
    throw new Error(
      `fetch failed for ${url}: redirect to ${JSON.stringify(res.headers.get("location") ?? "?")} is not followed while the SSRF guard is on`,
    );
  }
  if (!res.ok) {
    throw new Error(
      `fetch failed for ${url}: HTTP ${res.status} ${res.statusText}`,
    );
  }
  const declared = res.headers.get("content-length");
  if (declared && Number(declared) > MAX_BYTES) {
    throw new Error(
      `remote input too large: ${declared} bytes (limit ${MAX_BYTES})`,
    );
  }
  const { buffer } = await streamToBuffer(res.body, MAX_BYTES, "throw");
  return buffer;
}

export async function fetchText(url: string): Promise<string> {
  return (await fetchBytes(url)).toString("utf8");
}

/** Enforces the exactly-one-of contract for input / inputUrl parameter pairs. */
export async function resolveTextInput(
  inline: string | undefined,
  url: string | undefined,
  name = "input",
): Promise<string> {
  assertExactlyOneOf(inline, url, name);
  return inline !== undefined ? inline : await fetchText(url as string);
}
