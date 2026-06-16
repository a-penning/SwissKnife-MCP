export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

export interface JsonPathMatch {
  value: JsonValue;
  /** Normalized path, e.g. $['store']['book'][0]['title'] */
  path: string;
}

type ComparisonOp = "==" | "!=" | "<" | "<=" | ">" | ">=";

interface FilterStep {
  kind: "key" | "index";
  key?: string;
  index?: number;
}

interface FilterExpr {
  steps: FilterStep[];
  op?: ComparisonOp;
  literal?: JsonValue;
}

type Segment =
  | { kind: "keys"; keys: string[] }
  | { kind: "indices"; indices: number[] }
  | { kind: "wildcard" }
  | { kind: "slice"; start?: number; end?: number; step: number }
  | { kind: "filter"; expr: FilterExpr }
  | { kind: "recursive"; inner: Segment };

class PathError extends Error {}

function fail(message: string, pos?: number): never {
  throw new PathError(
    pos === undefined ? message : `${message} (at position ${pos})`,
  );
}

/**
 * Parser for the supported JSONPath subset:
 *   $  .name  ['name']  ["a","b"]  [0]  [-1]  [0,2]  [start:end:step]
 *   .* [*]  ..name  ..*  ..[...]  [?(@.path op literal)]  [?(@.path)]
 * Filters support ==, !=, <, <=, >, >= against string/number/boolean/null
 * literals — no script expressions, no boolean connectives.
 */
function parsePath(path: string): Segment[] {
  const src = path.trim();
  if (!src.startsWith("$")) fail("path must start with $");
  const segments: Segment[] = [];
  let i = 1;

  while (i < src.length) {
    const ch = src[i];
    if (ch === ".") {
      if (src[i + 1] === ".") {
        i += 2;
        if (src[i] === "[") {
          const [seg, next] = parseBracket(src, i);
          segments.push({ kind: "recursive", inner: seg });
          i = next;
        } else {
          const [seg, next] = parseDotName(src, i);
          segments.push({ kind: "recursive", inner: seg });
          i = next;
        }
      } else {
        const [seg, next] = parseDotName(src, i + 1);
        segments.push(seg);
        i = next;
      }
    } else if (ch === "[") {
      const [seg, next] = parseBracket(src, i);
      segments.push(seg);
      i = next;
    } else {
      fail(`unexpected character ${JSON.stringify(ch)}`, i);
    }
  }
  return segments;
}

function parseDotName(src: string, start: number): [Segment, number] {
  if (src[start] === "*") return [{ kind: "wildcard" }, start + 1];
  const match = /^[\w$][\w$-]*/.exec(src.slice(start));
  if (!match) {
    // Dot notation is ASCII-only by design. Pointer the caller at the
    // bracket-quoted form which DOES support arbitrary keys.
    fail(
      "expected property name or *. Dot notation only accepts [A-Za-z0-9_$-]; for Unicode / spaces / punctuation keys, use bracket-quoted notation, e.g. $['café'] or $['has space'].",
      start,
    );
  }
  return [{ kind: "keys", keys: [match[0]] }, start + match[0].length];
}

/** Parses a [...] group starting at `open` (which must point at '['). */
function parseBracket(src: string, open: number): [Segment, number] {
  const [inner, close] = readBracketBody(src, open);
  const body = inner.trim();
  if (body === "") fail("empty brackets", open);
  if (body === "*") return [{ kind: "wildcard" }, close];
  if (body.startsWith("?")) return [parseFilter(body, open), close];
  if (body.startsWith("'") || body.startsWith('"')) {
    return [{ kind: "keys", keys: parseQuotedUnion(body, open) }, close];
  }
  if (hasTopLevelColon(body)) return [parseSlice(body, open), close];
  const indices = body.split(",").map((part) => {
    const n = part.trim();
    if (!/^-?\d+$/.test(n)) fail(`invalid array index ${JSON.stringify(n)}`);
    return Number.parseInt(n, 10);
  });
  return [{ kind: "indices", indices }, close];
}

/**
 * Returns [body, indexAfterClosingBracket]. Honours quoted strings and
 * balances nested brackets so filter expressions like `[?(@['a'] == 1)]`
 * or `[?(@[0] == 1)]` parse correctly — the inner `]` for `'a'` belongs
 * to a nested step, not to the outer filter.
 */
function readBracketBody(src: string, open: number): [string, number] {
  let i = open + 1;
  let quote: string | undefined;
  let depth = 0;
  for (; i < src.length; i++) {
    const ch = src[i];
    if (quote !== undefined) {
      if (ch === "\\") i++;
      else if (ch === quote) quote = undefined;
    } else if (ch === "'" || ch === '"') {
      quote = ch;
    } else if (ch === "[") {
      depth++;
    } else if (ch === "]") {
      if (depth > 0) {
        depth--;
      } else {
        return [src.slice(open + 1, i), i + 1];
      }
    }
  }
  fail("unterminated [", open);
}

function hasTopLevelColon(body: string): boolean {
  return body.includes(":");
}

function parseSlice(body: string, pos: number): Segment {
  const parts = body.split(":").map((p) => p.trim());
  if (parts.length > 3) fail("slice has too many parts", pos);
  const nums = parts.map((p) => {
    if (p === "") return undefined;
    if (!/^-?\d+$/.test(p))
      fail(`invalid slice component ${JSON.stringify(p)}`);
    return Number.parseInt(p, 10);
  });
  const step = nums[2] ?? 1;
  if (step === 0) fail("slice step cannot be 0", pos);
  return { kind: "slice", start: nums[0], end: nums[1], step };
}

// JSON-grade string escape decoder. Covers the full RFC 8259 §7 set
// (\b \f \n \r \t \\ \/ \" plus \uXXXX) so callers can address keys that
// legitimately contain newlines, tabs, or non-ASCII via \uHHHH escapes —
// the previous "only \\ and \quote" set rejected those with a misleading
// "unsupported escape" message.
function decodeJsonEscape(
  source: string,
  start: number,
  quote: string,
  pos: number,
): { value: string; nextIndex: number } {
  let i = start;
  let value = "";
  while (i < source.length && source[i] !== quote) {
    if (source[i] === "\\") {
      i++;
      const c = source[i];
      switch (c) {
        case '"':
        case "'":
        case "\\":
        case "/":
          value += c;
          i++;
          break;
        case "b":
          value += "\b";
          i++;
          break;
        case "f":
          value += "\f";
          i++;
          break;
        case "n":
          value += "\n";
          i++;
          break;
        case "r":
          value += "\r";
          i++;
          break;
        case "t":
          value += "\t";
          i++;
          break;
        case "u": {
          const hex = source.slice(i + 1, i + 5);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) {
            fail(`malformed \\uXXXX escape: \\u${hex}`, pos);
          }
          value += String.fromCharCode(Number.parseInt(hex, 16));
          i += 5;
          break;
        }
        default:
          fail(`unsupported escape \\${c}`, pos);
      }
    } else {
      value += source[i];
      i++;
    }
  }
  return { value, nextIndex: i };
}

function parseQuotedUnion(body: string, pos: number): string[] {
  const keys: string[] = [];
  let i = 0;
  for (;;) {
    while (body[i] === " ") i++;
    const quote = body[i];
    if (quote !== "'" && quote !== '"') fail("expected quoted key", pos);
    i++;
    const { value, nextIndex } = decodeJsonEscape(body, i, quote, pos);
    i = nextIndex;
    if (i >= body.length) fail("unterminated string", pos);
    i++; // past closing quote
    keys.push(value);
    while (body[i] === " ") i++;
    if (i >= body.length) return keys;
    if (body[i] !== ",") fail("expected , between keys", pos);
    i++;
  }
}

const FILTER_RE =
  /^\?\(\s*@((?:\.[\w$][\w$-]*|\[\s*'(?:[^'\\]|\\.)*'\s*\]|\[\s*"(?:[^"\\]|\\.)*"\s*\]|\[\s*-?\d+\s*\])*)\s*(?:(==|!=|<=|>=|<|>)\s*(.+?)\s*)?\)$/;

function parseFilter(body: string, pos: number): Segment {
  const match = FILTER_RE.exec(body);
  if (!match) {
    fail(
      "unsupported filter: expected [?(@.path)] or [?(@.path op literal)] with ops == != < <= > >=",
      pos,
    );
  }
  const [, rawSteps, op, rawLiteral] = match;
  const steps: FilterStep[] = [];
  const stepRe =
    /\.([\w$][\w$-]*)|\[\s*'((?:[^'\\]|\\.)*)'\s*\]|\[\s*"((?:[^"\\]|\\.)*)"\s*\]|\[\s*(-?\d+)\s*\]/g;
  for (const m of (rawSteps ?? "").matchAll(stepRe)) {
    if (m[1] !== undefined) steps.push({ kind: "key", key: m[1] });
    else if (m[2] !== undefined)
      steps.push({ kind: "key", key: unescapeQuoted(m[2]) });
    else if (m[3] !== undefined)
      steps.push({ kind: "key", key: unescapeQuoted(m[3]) });
    else
      steps.push({ kind: "index", index: Number.parseInt(m[4] as string, 10) });
  }
  const expr: FilterExpr = { steps };
  if (op !== undefined) {
    expr.op = op as ComparisonOp;
    expr.literal = parseLiteral(rawLiteral as string, pos);
  }
  return { kind: "filter", expr };
}

function unescapeQuoted(raw: string): string {
  return raw.replace(/\\(.)/g, "$1");
}

function parseLiteral(raw: string, pos: number): JsonValue {
  if (raw === "true") return true;
  if (raw === "false") return false;
  if (raw === "null") return null;
  if (/^-?\d+(\.\d+)?([eE][+-]?\d+)?$/.test(raw)) return Number(raw);
  if (
    (raw.startsWith("'") && raw.endsWith("'") && raw.length >= 2) ||
    (raw.startsWith('"') && raw.endsWith('"') && raw.length >= 2)
  ) {
    return unescapeQuoted(raw.slice(1, -1));
  }
  fail(
    `unsupported filter literal ${JSON.stringify(raw)} (string, number, boolean or null)`,
    pos,
  );
}

// ---------------------------------------------------------------------------
// Evaluation

interface Node {
  value: JsonValue;
  path: string;
}

function escapeKey(key: string): string {
  return key.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
}

function childPath(parent: string, key: string | number): string {
  return typeof key === "number"
    ? `${parent}[${key}]`
    : `${parent}['${escapeKey(key)}']`;
}

function isObject(v: JsonValue): v is { [key: string]: JsonValue } {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function children(node: Node): Node[] {
  if (Array.isArray(node.value)) {
    return node.value.map((v, i) => ({
      value: v,
      path: childPath(node.path, i),
    }));
  }
  if (isObject(node.value)) {
    return Object.entries(node.value).map(([k, v]) => ({
      value: v,
      path: childPath(node.path, k),
    }));
  }
  return [];
}

/**
 * node + all descendants, document order. Iterative to avoid blowing the
 * call stack on deep documents (recursion would O(depth)) and to avoid
 * push-spread O(N²) blow-ups on wide documents.
 */
function descendants(node: Node): Node[] {
  const out: Node[] = [];
  const stack: Node[] = [node];
  while (stack.length > 0) {
    const current = stack.pop() as Node;
    out.push(current);
    const kids = children(current);
    for (let i = kids.length - 1; i >= 0; i--) {
      stack.push(kids[i] as Node);
    }
  }
  return out;
}

function sliceIndices(
  len: number,
  startRaw: number | undefined,
  endRaw: number | undefined,
  step: number,
): number[] {
  const out: number[] = [];
  if (step > 0) {
    const start =
      startRaw === undefined
        ? 0
        : startRaw < 0
          ? Math.max(len + startRaw, 0)
          : Math.min(startRaw, len);
    const end =
      endRaw === undefined
        ? len
        : endRaw < 0
          ? Math.max(len + endRaw, 0)
          : Math.min(endRaw, len);
    for (let i = start; i < end; i += step) out.push(i);
  } else {
    const start =
      startRaw === undefined
        ? len - 1
        : startRaw < 0
          ? Math.max(len + startRaw, -1)
          : Math.min(startRaw, len - 1);
    const end =
      endRaw === undefined
        ? -1
        : endRaw < 0
          ? Math.max(len + endRaw, -1)
          : Math.min(endRaw, len - 1);
    for (let i = start; i > end; i += step) out.push(i);
  }
  return out;
}

function resolveFilterPath(
  value: JsonValue,
  steps: FilterStep[],
): { found: boolean; value?: JsonValue } {
  let current = value;
  for (const step of steps) {
    if (step.kind === "key") {
      if (!isObject(current) || !Object.hasOwn(current, step.key as string)) {
        return { found: false };
      }
      current = current[step.key as string] as JsonValue;
    } else {
      if (!Array.isArray(current)) return { found: false };
      const index =
        (step.index as number) < 0
          ? current.length + (step.index as number)
          : (step.index as number);
      if (index < 0 || index >= current.length) return { found: false };
      current = current[index] as JsonValue;
    }
  }
  return { found: true, value: current };
}

function compare(
  value: JsonValue,
  op: ComparisonOp,
  literal: JsonValue,
): boolean {
  const bothNumbers = typeof value === "number" && typeof literal === "number";
  const bothStrings = typeof value === "string" && typeof literal === "string";
  switch (op) {
    case "==":
      return isPrimitive(value) && value === literal;
    case "!=":
      return !(isPrimitive(value) && value === literal);
    case "<":
      return (
        (bothNumbers || bothStrings) && value < (literal as number | string)
      );
    case "<=":
      return (
        (bothNumbers || bothStrings) && value <= (literal as number | string)
      );
    case ">":
      return (
        (bothNumbers || bothStrings) && value > (literal as number | string)
      );
    case ">=":
      return (
        (bothNumbers || bothStrings) && value >= (literal as number | string)
      );
  }
}

function isPrimitive(v: JsonValue): boolean {
  return v === null || typeof v !== "object";
}

function matchesFilter(value: JsonValue, expr: FilterExpr): boolean {
  const resolved = resolveFilterPath(value, expr.steps);
  if (!resolved.found) return false;
  if (expr.op === undefined) return true;
  return compare(
    resolved.value as JsonValue,
    expr.op,
    expr.literal as JsonValue,
  );
}

function applySegment(node: Node, segment: Segment): Node[] {
  switch (segment.kind) {
    case "keys": {
      if (!isObject(node.value)) return [];
      return segment.keys
        .filter((k) => Object.hasOwn(node.value as object, k))
        .map((k) => ({
          value: (node.value as { [key: string]: JsonValue })[k] as JsonValue,
          path: childPath(node.path, k),
        }));
    }
    case "indices": {
      if (!Array.isArray(node.value)) return [];
      const arr = node.value;
      return segment.indices
        .map((raw) => (raw < 0 ? arr.length + raw : raw))
        .filter((i) => i >= 0 && i < arr.length)
        .map((i) => ({
          value: arr[i] as JsonValue,
          path: childPath(node.path, i),
        }));
    }
    case "wildcard":
      return children(node);
    case "slice": {
      if (!Array.isArray(node.value)) return [];
      const arr = node.value;
      return sliceIndices(
        arr.length,
        segment.start,
        segment.end,
        segment.step,
      ).map((i) => ({
        value: arr[i] as JsonValue,
        path: childPath(node.path, i),
      }));
    }
    case "filter":
      return children(node).filter((child) =>
        matchesFilter(child.value, segment.expr),
      );
    case "recursive":
      return descendants(node).flatMap((n) => applySegment(n, segment.inner));
  }
}

export function queryJsonPath(root: JsonValue, path: string): JsonPathMatch[] {
  const segments = parsePath(path);
  let nodes: Node[] = [{ value: root, path: "$" }];
  for (const segment of segments) {
    nodes = nodes.flatMap((node) => applySegment(node, segment));
    if (nodes.length === 0) break;
  }
  return nodes;
}
