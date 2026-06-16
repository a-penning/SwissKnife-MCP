import { Worker } from "node:worker_threads";

/**
 * Regex execution runs in a worker thread with a hard wall-clock timeout
 * enforced from the parent. A single uninterruptible `RegExp.exec()` call can
 * backtrack catastrophically (e.g. /(a+)+$/ on a long non-matching string);
 * a deadline checked between calls on the main thread can never fire while that
 * native loop is running. Isolating the match in a worker lets the parent call
 * `worker.terminate()` to forcibly kill a runaway thread, which is the only
 * mechanism that actually bounds the work on a shared, unauthenticated server.
 */

export type RegexResult =
  | { count: number; matches: RegexMatch[] }
  | { result: string; replacements: number }
  | { parts: string[]; count: number };

export interface RegexMatch {
  match: string;
  index: number;
  end: number;
  // Positional captures (corresponds to `match[1]..match[n]` on the
  // native RegExpMatchArray). Renamed from `groups` so it doesn't shadow
  // JavaScript's `match.groups` (which carries named groups).
  captures: (string | null)[];
  // Named groups, keyed by name. Matches `match.groups` from the native
  // RegExpMatchArray — what a caller writing `match.groups.foo` expects.
  groups: Record<string, string>;
  // Present only when the `d` flag (hasIndices) is set. `match`/`groups`
  // are [start, end) tuples for the full match and each capture group;
  // `named` mirrors `indices.groups` from the native RegExp API.
  indices?: {
    match: [number, number];
    captures: ([number, number] | null)[];
    groups: Record<string, [number, number]>;
  };
}

export interface RegexPayload {
  action: "match" | "replace" | "split";
  pattern: string;
  flags: string;
  input: string;
  replacement?: string;
  limit?: number;
}

// Plain JS (no TypeScript): executed verbatim inside an eval worker, where
// `require` is available. All regex work — the part that can hang — lives here.
const WORKER_SOURCE = `
const { parentPort, workerData } = require('node:worker_threads');
const { action, pattern, flags, input, replacement, limit } = workerData;

function compile(p, f) {
  try {
    return new RegExp(p, f);
  } catch (e) {
    throw new Error('invalid pattern: ' + (e && e.message ? e.message : String(e)));
  }
}

// AdvanceStringIndex (ECMAScript §22.2.7.3): when stepping past a zero-width
// match under u/v flag, advance by a whole code point so we don't strand
// lastIndex mid-surrogate-pair (where exec() rewinds and the loop spins).
function advanceLastIndex(re, str) {
  var idx = re.lastIndex;
  if (idx + 1 >= str.length || !(re.unicode || re.unicodeSets)) {
    re.lastIndex = idx + 1;
    return;
  }
  var code = str.charCodeAt(idx);
  if (code < 0xD800 || code > 0xDBFF) {
    re.lastIndex = idx + 1;
    return;
  }
  var trail = str.charCodeAt(idx + 1);
  re.lastIndex = (trail >= 0xDC00 && trail <= 0xDFFF) ? idx + 2 : idx + 1;
}

try {
  let result;
  if (action === 'match') {
    const globalFlags = flags.indexOf('g') >= 0 ? flags : flags + 'g';
    const re = compile(pattern, globalFlags);
    const firstOnly = flags.indexOf('g') < 0;
    const matches = [];
    const hasIndices = flags.indexOf('d') >= 0;
    let m = re.exec(input);
    while (m !== null) {
      const entry = {
        match: m[0],
        index: m.index,
        end: m.index + m[0].length,
        // captures = positional groups (was misnamed 'groups' before — which
        // conflicted with the JS RegExpMatchArray convention where .groups
        // is the named-groups object). Now matches native semantics.
        captures: m.slice(1).map(function (g) { return g === undefined ? null : g; }),
        groups: m.groups ? Object.assign({}, m.groups) : {},
      };
      if (hasIndices && m.indices) {
        // m.indices is RegExpIndicesArray-like: [matchStart, matchEnd]
        // at index 0, then each capture group's [start, end] (or
        // undefined for non-participating groups), plus a 'groups'
        // object keyed by name. Mirror that into our shape.
        entry.indices = {
          match: [m.indices[0][0], m.indices[0][1]],
          captures: m.indices.slice(1).map(function (g) {
            return g === undefined ? null : [g[0], g[1]];
          }),
          groups: m.indices.groups
            ? Object.fromEntries(
                Object.entries(m.indices.groups).map(function (kv) {
                  return [kv[0], kv[1] === undefined ? null : [kv[1][0], kv[1][1]]];
                }),
              )
            : {},
        };
      }
      matches.push(entry);
      if (firstOnly) break;
      if (m[0] === '') advanceLastIndex(re, input);
      m = re.exec(input);
    }
    result = { count: matches.length, matches: matches };
  } else if (action === 'replace') {
    const re = compile(pattern, flags);
    let replacements = 0;
    if (flags.indexOf('g') >= 0) {
      const countRe = compile(pattern, flags);
      let x = countRe.exec(input);
      while (x !== null) {
        replacements++;
        if (x[0] === '') advanceLastIndex(countRe, input);
        x = countRe.exec(input);
      }
    } else {
      // Count using a fresh regex so we don't mutate \`re.lastIndex\` — for a
      // sticky-without-global regex that would start the replace at the wrong
      // position. Native String.prototype.replace already returns "did it
      // match?" through the replacement count, so test it on a clean instance.
      const probeRe = compile(pattern, flags);
      replacements = probeRe.test(input) ? 1 : 0;
    }
    result = { result: input.replace(re, replacement), replacements: replacements };
  } else if (action === 'split') {
    const re = compile(pattern, flags);
    const parts = limit === undefined ? input.split(re) : input.split(re, limit);
    result = { parts: parts, count: parts.length };
  } else {
    throw new Error('unknown action ' + action);
  }
  parentPort.postMessage({ ok: true, result: result });
} catch (e) {
  parentPort.postMessage({ ok: false, error: e && e.message ? e.message : String(e) });
}
`;

export function runRegex(
  payload: RegexPayload,
  timeoutMs: number,
): Promise<RegexResult> {
  return new Promise<RegexResult>((resolve, reject) => {
    let worker: Worker;
    try {
      worker = new Worker(WORKER_SOURCE, { eval: true, workerData: payload });
    } catch (e) {
      reject(e instanceof Error ? e : new Error(String(e)));
      return;
    }

    let settled = false;
    const finish = (fn: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      void worker.terminate();
      fn();
    };

    const timer = setTimeout(() => {
      finish(() =>
        reject(
          new Error(
            `pattern exceeded the ${timeoutMs}ms execution budget (possible catastrophic backtracking) — simplify the pattern or reduce the input size`,
          ),
        ),
      );
    }, timeoutMs);
    timer.unref();

    worker.once(
      "message",
      (msg: { ok: boolean; result?: RegexResult; error?: string }) => {
        finish(() =>
          msg.ok && msg.result !== undefined
            ? resolve(msg.result)
            : reject(new Error(msg.error ?? "regex evaluation failed")),
        );
      },
    );
    worker.once("error", (err) => {
      finish(() => reject(err instanceof Error ? err : new Error(String(err))));
    });
    worker.once("exit", (code) => {
      if (!settled) {
        finish(() =>
          reject(new Error(`regex worker exited unexpectedly (code ${code})`)),
        );
      }
    });
  });
}
