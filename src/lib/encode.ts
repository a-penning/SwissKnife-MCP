import type { Buffer } from "node:buffer";
import {
  brotliCompressSync,
  brotliDecompressSync,
  deflateSync,
  gunzipSync,
  gzipSync,
  inflateSync,
} from "node:zlib";
import { toMessage } from "./errors.js";

export function escapeHtml(text: string): string {
  return text
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

// Common HTML4/5 named entities. Not exhaustive (HTML5 ships ~2,231), but
// covers what real-world text actually uses: punctuation, currency,
// copy/trademark marks, common math symbols, Greek letters, named arrows.
// nbsp is U+00A0 (non-breaking space), not U+0020. Anything outside this
// table is passed through unchanged with a warning rather than throwing —
// it's better for a caller to see the raw entity in their result than to
// have the whole call fail because the table is incomplete.
const NAMED_ENTITIES: Record<string, string> = {
  amp: "&",
  lt: "<",
  gt: ">",
  quot: '"',
  apos: "'",
  nbsp: " ",
  ensp: " ",
  emsp: " ",
  thinsp: " ",
  zwnj: "‌",
  zwj: "‍",
  ndash: "–",
  mdash: "—",
  lsquo: "‘",
  rsquo: "’",
  sbquo: "‚",
  ldquo: "“",
  rdquo: "”",
  bdquo: "„",
  laquo: "«",
  raquo: "»",
  hellip: "…",
  bull: "•",
  middot: "·",
  iexcl: "¡",
  iquest: "¿",
  sect: "§",
  para: "¶",
  dagger: "†",
  Dagger: "‡",
  cent: "¢",
  pound: "£",
  yen: "¥",
  euro: "€",
  curren: "¤",
  copy: "©",
  reg: "®",
  trade: "™",
  deg: "°",
  plusmn: "±",
  times: "×",
  divide: "÷",
  micro: "µ",
  permil: "‰",
  minus: "−",
  asymp: "≈",
  ne: "≠",
  le: "≤",
  ge: "≥",
  infin: "∞",
  radic: "√",
  sum: "∑",
  prod: "∏",
  int: "∫",
  part: "∂",
  forall: "∀",
  exist: "∃",
  empty: "∅",
  isin: "∈",
  notin: "∉",
  larr: "←",
  uarr: "↑",
  rarr: "→",
  darr: "↓",
  harr: "↔",
  lArr: "⇐",
  uArr: "⇑",
  rArr: "⇒",
  dArr: "⇓",
  hArr: "⇔",
  alpha: "α",
  beta: "β",
  gamma: "γ",
  delta: "δ",
  epsilon: "ε",
  zeta: "ζ",
  eta: "η",
  theta: "θ",
  iota: "ι",
  kappa: "κ",
  lambda: "λ",
  mu: "μ",
  nu: "ν",
  xi: "ξ",
  omicron: "ο",
  pi: "π",
  rho: "ρ",
  sigma: "σ",
  tau: "τ",
  upsilon: "υ",
  phi: "φ",
  chi: "χ",
  psi: "ψ",
  omega: "ω",
};

function decodeHtmlCodePoint(
  cp: number,
  whole: string,
  offset: number,
): string {
  if (!Number.isFinite(cp) || cp < 0 || cp > 0x10ffff) {
    throw new Error(
      `invalid HTML entity ${JSON.stringify(whole)} at offset ${offset}: code point out of range (0..0x10FFFF)`,
    );
  }
  return String.fromCodePoint(cp);
}

// Match every "&...;" run and classify the body explicitly. The earlier
// single-alternation regex shared a [0-9a-fA-F]+ class across the decimal and
// hex branches, so "&#abc;" matched the decimal arm and crashed in
// fromCodePoint(NaN), while bodies that didn't match any branch (like #abc)
// silently passed through. The #X branch was also dead code because /#x?/
// only matched lowercase.
//
// Unknown named entities are passed through unchanged with a warning,
// not thrown — this table covers ~100 common HTML4/5 entities but HTML5
// ships ~2,231 and we'd rather not block a real-world document on a
// rarely-used entity (`&boxh;`, `&Aogon;`, …). The original text in the
// output is the safe fallback.
export function unescapeHtml(text: string, warnings: string[]): string {
  return text.replace(
    /&([^;&\s]+);/g,
    (whole, body: string, offset: number) => {
      if (/^#[xX][0-9a-fA-F]+$/.test(body)) {
        return decodeHtmlCodePoint(
          Number.parseInt(body.slice(2), 16),
          whole,
          offset,
        );
      }
      if (/^#[0-9]+$/.test(body)) {
        return decodeHtmlCodePoint(
          Number.parseInt(body.slice(1), 10),
          whole,
          offset,
        );
      }
      if (/^[a-zA-Z][a-zA-Z0-9]*$/.test(body)) {
        const named = NAMED_ENTITIES[body.toLowerCase()];
        if (named === undefined) {
          warnings.push(
            `unknown HTML entity ${JSON.stringify(whole)} at offset ${offset} — passed through unchanged`,
          );
          return whole;
        }
        return named;
      }
      throw new Error(
        `invalid HTML entity ${JSON.stringify(whole)} at offset ${offset}`,
      );
    },
  );
}

export function escapeUnicode(text: string): string {
  let out = "";
  for (const unit of text) {
    const cp = unit.codePointAt(0) as number;
    if (cp >= 0x20 && cp <= 0x7e) {
      out += unit;
    } else if (cp > 0xffff) {
      // emit as a surrogate pair of \uXXXX escapes for maximum compatibility
      const high = 0xd800 + ((cp - 0x10000) >> 10);
      const low = 0xdc00 + ((cp - 0x10000) & 0x3ff);
      out += `\\u${high.toString(16).padStart(4, "0")}\\u${low.toString(16).padStart(4, "0")}`;
    } else {
      out += `\\u${cp.toString(16).padStart(4, "0")}`;
    }
  }
  return out;
}

export function unescapeUnicode(text: string): string {
  let out = "";
  let i = 0;
  while (i < text.length) {
    if (text[i] !== "\\" || text[i + 1] !== "u") {
      out += text[i] as string;
      i++;
      continue;
    }
    // \u{HEX}
    if (text[i + 2] === "{") {
      const close = text.indexOf("}", i + 3);
      if (close === -1) {
        throw new Error(
          `malformed unicode escape at offset ${i}: missing closing brace`,
        );
      }
      const digits = text.slice(i + 3, close);
      if (
        digits.length === 0 ||
        digits.length > 6 ||
        !/^[0-9a-fA-F]+$/.test(digits)
      ) {
        throw new Error(
          `malformed unicode escape at offset ${i}: \\u{${digits}} (1-6 hex digits required)`,
        );
      }
      const cp = Number.parseInt(digits, 16);
      if (cp > 0x10ffff) {
        throw new Error(
          `unicode code point U+${cp.toString(16)} is out of range`,
        );
      }
      out += String.fromCodePoint(cp);
      i = close + 1;
      continue;
    }
    // \uHHHH (exactly 4 hex digits)
    const digits = text.slice(i + 2, i + 6);
    if (digits.length < 4 || !/^[0-9a-fA-F]{4}$/.test(digits)) {
      throw new Error(
        `malformed unicode escape at offset ${i}: expected \\uHHHH (4 hex digits) or \\u{H...H}`,
      );
    }
    out += String.fromCodePoint(Number.parseInt(digits, 16));
    i += 6;
  }
  return out;
}

export type CompressionFormat = "gzip" | "deflate" | "brotli";

export const COMPRESSION_FORMATS: ReadonlySet<string> = new Set([
  "gzip",
  "deflate",
  "brotli",
]);

export function compress(format: CompressionFormat, bytes: Buffer): Buffer {
  switch (format) {
    case "gzip":
      return gzipSync(bytes);
    case "deflate":
      return deflateSync(bytes);
    case "brotli":
      return brotliCompressSync(bytes);
  }
}

// maxOutputLength is enforced by zlib natively (Node 17+) — exceeding it
// throws ERR_BUFFER_TOO_LARGE / RangeError before allocating the full
// output. That's what makes this a meaningful zip-bomb guard rather than
// a post-hoc length check.
export function decompress(
  format: CompressionFormat,
  bytes: Buffer,
  maxOutputBytes: number,
): Buffer {
  switch (format) {
    case "gzip":
      return gunzipSync(bytes, { maxOutputLength: maxOutputBytes });
    case "deflate":
      return inflateSync(bytes, { maxOutputLength: maxOutputBytes });
    case "brotli":
      return brotliDecompressSync(bytes, { maxOutputLength: maxOutputBytes });
  }
}

// decodeURI/decodeURIComponent throw URIError with no position info. Surface
// the first invalid %-escape's offset so the caller knows where to look.
export function decodeUrlWithOffset(
  input: string,
  decoder: (s: string) => string,
): string {
  try {
    return decoder(input);
  } catch (e) {
    const detail = toMessage(e);
    for (let i = 0; i < input.length; i++) {
      if (input[i] === "%") {
        const triplet = input.slice(i, i + 3);
        if (!/^%[0-9a-fA-F]{2}$/.test(triplet)) {
          throw new Error(
            `${detail} at offset ${i}: invalid percent-escape ${JSON.stringify(triplet)}`,
          );
        }
      }
    }
    // Couldn't pin a bad triplet (e.g. unpaired surrogate from a valid triplet) —
    // re-throw with the original message untouched so the caller at least sees
    // the underlying URIError text.
    throw e;
  }
}
