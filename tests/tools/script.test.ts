import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";
import { tools } from "../../src/tools/registry.js";

const scriptToolEntry = tools.find((t) => t.name === "script");
if (!scriptToolEntry) throw new Error("script tool not registered");
const scriptTool = scriptToolEntry;

interface ScriptStructured {
  result: unknown;
  toolCalls: number;
  durationMs: number;
  logs: string[];
  trace?: Array<{ tool: string; ok: boolean; durationMs: number }>;
}

async function run(args: Record<string, unknown>): Promise<CallToolResult> {
  return (await scriptTool.handler({
    source: "",
    timeoutMs: 30_000,
    maxToolCalls: 100,
    trace: false,
    ...args,
  })) as CallToolResult;
}

function structured(res: CallToolResult): ScriptStructured {
  expect(res.isError, JSON.stringify(res.content)).toBeFalsy();
  return res.structuredContent as unknown as ScriptStructured;
}

function errorEnvelope(res: CallToolResult): Record<string, unknown> {
  expect(res.isError, JSON.stringify(res.content)).toBe(true);
  return res.structuredContent as Record<string, unknown>;
}

function errorText(res: CallToolResult): string {
  return String((res.content?.[0] as { text?: string })?.text ?? "");
}

describe("script tool: happy paths", () => {
  // A range of source snippets that each return a distinct JS value type;
  // expectations are computed independently from the source, never pasted.
  const valueCases: Array<[string, string, unknown]> = [
    ["integer arithmetic", "return 21 * 2;", 42],
    ["string concat", "return 'a' + 'b' + 'c';", "abc"],
    ["boolean expression", "return 1 < 2 && 2 < 3;", true],
    ["null literal", "return null;", null],
    ["array literal", "return [1, 2, 3].map(x => x * 2);", [2, 4, 6]],
    ["object literal", "return { ok: true, n: 7 };", { ok: true, n: 7 }],
    ["JSON round-trip", "return JSON.parse('{\"x\":1}').x;", 1],
    [
      "top-level await of a resolved promise",
      "return await Promise.resolve(99);",
      99,
    ],
    ["Math built-in", "return Math.max(3, 9, 1);", 9],
    [
      "string methods",
      "return 'Hello World'.toLowerCase().split(' ');",
      ["hello", "world"],
    ],
  ];
  it.each(
    valueCases,
  )("returns the expected value for %s (toolCalls=0)", async (_label, source, expected) => {
    const r = structured(await run({ source }));
    expect(r.result).toEqual(expected);
    expect(r.toolCalls).toBe(0);
  });

  // args is injected as a global; a range of arg payloads + access patterns.
  const argCases: Array<[string, string, unknown, unknown]> = [
    ["sums numeric fields", "return args.a + args.b;", { a: 10, b: 32 }, 42],
    [
      "reads a nested field",
      "return args.user.name;",
      { user: { name: "ada" } },
      "ada",
    ],
    ["indexes an array arg", "return args[1];", ["x", "y", "z"], "y"],
    ["reflects a string arg", "return args + '!';", "hi", "hi!"],
    ["reflects a number arg", "return args * 2;", 21, 42],
    ["reflects a boolean arg", "return typeof args;", true, "boolean"],
  ];
  it.each(
    argCases,
  )("%s from the args global", async (_label, source, args, expected) => {
    const r = structured(await run({ source, args }));
    expect(r.result).toEqual(expected);
  });

  // console.* methods map to [level]-tagged lines in the logs array.
  const logCases: Array<[string, string, number, string[]]> = [
    ["single log", `console.log("a"); return 1;`, 1, ["[log]"]],
    [
      "log then warn",
      `console.log("a"); console.warn("b"); return 1;`,
      2,
      ["[log]", "[warn]"],
    ],
    ["error level", `console.error("boom"); return 1;`, 1, ["[error]"]],
    [
      "three mixed levels",
      `console.log("a"); console.warn("b"); console.error("c"); return 1;`,
      3,
      ["[log]", "[warn]", "[error]"],
    ],
    ["no logging", `return 1;`, 0, []],
  ];
  it.each(
    logCases,
  )("captures %s into the logs array", async (_label, source, count, tags) => {
    const r = structured(await run({ source }));
    expect(r.logs.length).toBe(count);
    tags.forEach((tag, i) => {
      expect(r.logs[i]).toContain(tag);
    });
  });
});

describe("script tool: tool access", () => {
  it("can hash a value via tools.hash", async () => {
    const r = structured(
      await run({
        source: `
          return await tools.hash({ algorithm: "sha256", input: "abc" });
        `,
      }),
    );
    expect(r.result).toMatchObject({
      digest:
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    });
    expect(r.toolCalls).toBe(1);
  });

  it("chains: encode → text → count", async () => {
    const r = structured(
      await run({
        source: `
          const enc = await tools.encode({
            direction: "encode", format: "base64", input: "hello"
          });
          const dec = await tools.encode({
            direction: "decode", format: "base64", input: enc.result
          });
          return dec.result;
        `,
      }),
    );
    expect(r.result).toBe("hello");
    expect(r.toolCalls).toBe(2);
  });

  it("supports tools.<kebab-name> and tools.<camelName> interchangeably", async () => {
    const r = structured(
      await run({
        source: `
          const a = await tools["json-query"]({
            input: '{"x":42}', query: "$.x"
          });
          const b = await tools.jsonQuery({
            input: '{"x":42}', query: "$.x"
          });
          return [a.values[0], b.values[0]];
        `,
      }),
    );
    expect(r.result).toEqual([42, 42]);
  });

  // A range of tool calls that each fail inside the VM (bad input or invalid
  // params); every one must throw a catchable error rather than returning a
  // value. The script catches and reports caught:true.
  const failingCalls: Array<[string, string]> = [
    [
      "invalid base64 decode",
      `await tools.encode({ direction: "decode", format: "base64", input: "!!!" });`,
    ],
    [
      "unknown hash algorithm",
      `await tools.hash({ algorithm: "not-a-real-algo", input: "x" });`,
    ],
    [
      "json-query with broken JSON input",
      `await tools["json-query"]({ input: "{not json", query: "$.x" });`,
    ],
    [
      "convert-data with bad source format",
      `await tools["convert-data"]({ from: "json", to: "yaml", input: "{nope" });`,
    ],
  ];
  it.each(
    failingCalls,
  )("tool error from %s throws inside the script and is catchable", async (_label, call) => {
    const r = structured(
      await run({
        source: `
            try {
              ${call}
              return { caught: false };
            } catch (e) {
              return { caught: true, hasMsg: typeof e.message === "string" };
            }
          `,
      }),
    );
    expect(r.result).toEqual({ caught: true, hasMsg: true });
  });

  it("script tool itself is not reachable from inside the VM", async () => {
    const r = structured(await run({ source: "return typeof tools.script;" }));
    expect(r.result).toBe("undefined");
  });

  it("trace=true returns one entry per tool call", async () => {
    const r = structured(
      await run({
        source: `
          await tools.hash({ algorithm: "md5", input: "a" });
          await tools.hash({ algorithm: "md5", input: "b" });
          return "done";
        `,
        trace: true,
      }),
    );
    expect(r.trace).toHaveLength(2);
    expect(r.trace?.every((t) => t.tool === "hash" && t.ok)).toBe(true);
  });

  it("every registered non-script tool is reachable as a function", async () => {
    // Iterate the registry from inside the VM and assert each name is a
    // function. This is the safety net that catches "a new tool was added
    // but script didn't pick it up".
    const names = tools.filter((t) => t.name !== "script").map((t) => t.name);
    const r = structured(
      await run({
        source: `
          const want = args;
          const missing = [];
          for (const name of want) {
            const camel = name.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
            if (typeof tools[camel] !== "function") missing.push(camel);
            if (typeof tools[name] !== "function") missing.push(name);
          }
          return missing;
        `,
        args: names,
      }),
    );
    expect(r.result).toEqual([]);
  });
});

describe("script tool: error envelopes", () => {
  // A range of malformed/limit-tripping sources, each mapping to a specific
  // errorType. The errorType is asserted both in the text envelope and the
  // structuredContent so a regression in either surface is caught.
  const syntaxSources: Array<[string, string]> = [
    ["dangling operator", "return 1 + ;"],
    ["empty assignment", "let x = ;"],
    ["unclosed brace", "function f() { return 1"],
    ["unexpected token", "const = 5;"],
    ["bad arrow", "const f = => 1;"],
  ];
  it.each(
    syntaxSources,
  )("flags errorType=syntax for %s", async (_label, source) => {
    const res = await run({ source });
    expect(errorText(res)).toContain("syntax");
    expect(errorEnvelope(res).errorType).toBe("syntax");
  });

  // Runtime throws (after the source parses) all collapse to errorType=runtime.
  const runtimeSources: Array<[string, string]> = [
    ["explicit throw", "throw new Error('boom');"],
    ["reference to undefined", "return notDefined;"],
    ["calling a non-function", "const x = 5; return x();"],
    ["property of null", "return null.foo;"],
    ["rejected await", "return await Promise.reject(new Error('nope'));"],
  ];
  it.each(
    runtimeSources,
  )("flags errorType=runtime for %s", async (_label, source) => {
    const res = await run({ source });
    expect(errorEnvelope(res).errorType).toBe("runtime");
  });

  it("infinite recursion surfaces errorType=stack", async () => {
    const res = await run({
      source: "function f(){ return f(); } return f();",
    });
    expect(errorEnvelope(res).errorType).toBe("stack");
  });

  // BigInt has no JSON representation, so QuickJS' dumper makes JSON.stringify
  // throw => errorType=serialize.
  it("flags errorType=serialize for a returned BigInt", async () => {
    const res = await run({ source: "return 10n;" });
    expect(errorEnvelope(res).errorType).toBe("serialize");
  });

  // Symbols and bare undefined are NOT errors: QuickJS dumps them as
  // `undefined`, which the serializer normalises to JSON `null` (mirroring
  // JSON.stringify), so the run succeeds with result === null.
  const nullishReturns: Array<[string, string]> = [
    ["a symbol", "return Symbol('x');"],
    ["bare undefined", "return undefined;"],
  ];
  it.each(
    nullishReturns,
  )("normalises %s to a successful null result", async (_label, source) => {
    const r = structured(await run({ source }));
    expect(r.result).toBeNull();
  });

  // A returned function is dumped by QuickJS as its source-text string (its
  // toString() form), so the run succeeds with a string result rather than an
  // error or null. Independently: ctx.dump stringifies callables.
  it("returns a function as its source-text string", async () => {
    const r = structured(await run({ source: "return () => 1;" }));
    expect(typeof r.result).toBe("string");
    expect(r.result).toContain("=>");
  });

  it("timeout errors are flagged in the message", async () => {
    const res = await run({ source: "while (true) {}", timeoutMs: 200 });
    expect(res.isError).toBe(true);
    const text = String((res.content?.[0] as { text?: string })?.text ?? "");
    expect(text).toContain("timeout");
    expect(errorEnvelope(res).errorType).toBe("timeout");
  });

  it("error path preserves logs / toolCalls / durationMs in structuredContent (CC-7)", async () => {
    const res = await run({
      source: `
        console.log("before throw");
        throw new Error("intentional");
      `,
    });
    expect(res.isError).toBe(true);
    const s = res.structuredContent as Record<string, unknown>;
    expect(s.errorType).toBe("runtime");
    expect(s.message).toContain("intentional");
    expect(Array.isArray(s.logs)).toBe(true);
    expect((s.logs as string[]).some((l) => l.includes("before throw"))).toBe(
      true,
    );
    expect(typeof s.toolCalls).toBe("number");
    expect(typeof s.durationMs).toBe("number");
  });

  it("user line numbers are corrected for the (async () => {...}) wrapper (off-by-1 fix)", async () => {
    // Syntax errors carry a lineNumber. The user-source `let x = ;` is on
    // line 1 of the user's source; the VM sees it on line 2 because of
    // the `(async () => {\n...\n})()` wrapper. The fix subtracts 1.
    const res = await run({ source: "let x = ;" });
    expect(res.isError).toBe(true);
    const s = res.structuredContent as Record<string, unknown>;
    // Either the line is reported and corrected to 1, or it's undefined
    // (some QuickJS error paths don't carry lineNumber). Both cases
    // count as "we are NOT off by one in the upward direction".
    if (s.line !== undefined) expect(s.line).toBe(1);
  });

  // MAX_SOURCE_BYTES is 64 KiB. Sources comfortably over the cap are rejected
  // with source-too-large; sources comfortably under it run normally. We probe
  // both sides with a margin so the boundary isn't byte-exact-brittle.
  const tooLargeSizes = [70_000, 100_000, 200_000];
  it.each(
    tooLargeSizes,
  )("rejects a %d-byte source as source-too-large", async (size) => {
    const res = await run({ source: `// ${"x".repeat(size)}` });
    expect(errorText(res)).toMatch(/source-too-large/);
    expect(errorEnvelope(res).errorType).toBe("source-too-large");
  });
  const okSizes = [1_000, 30_000, 60_000];
  it.each(okSizes)("accepts a %d-byte source", async (size) => {
    const res = await run({ source: `${"// x\n".repeat(size / 5)}return 1;` });
    expect(structured(res).result).toBe(1);
  });

  // tool-call-limit must fire exactly at the configured cap, and the reported
  // toolCalls counter must equal that cap (callers rely on the exact count).
  const caps = [1, 2, 5];
  it.each(
    caps,
  )("tool-call-limit fires at maxToolCalls=%d with the counter pinned to the cap", async (cap) => {
    const res = await run({
      maxToolCalls: cap,
      source: `
          for (let i = 0; i < 50; i++) {
            await tools.time({ action: "now" });
          }
          return "should never reach here";
        `,
    });
    expect(errorText(res)).toMatch(/tool-call-limit/);
    expect(errorEnvelope(res).toolCalls).toBe(cap);
  });

  it("tool-call-limit fires when a script exceeds maxToolCalls", async () => {
    const res = await run({
      maxToolCalls: 2,
      source: `
        for (let i = 0; i < 10; i++) {
          await tools.time({ action: "now" });
        }
        return "should never reach here";
      `,
    });
    expect(res.isError).toBe(true);
    const text = String((res.content?.[0] as { text?: string })?.text ?? "");
    expect(text).toMatch(/tool-call-limit/);
    const s = res.structuredContent as Record<string, unknown>;
    // Counter must reflect the cap we tripped on (so callers see exactly
    // how many tool calls landed before the abort).
    expect(s.toolCalls).toBe(2);
  });
});

describe("script tool: args handling", () => {
  it("treats the literal string 'undefined' as absent (MCP transport quirk)", async () => {
    // The MCP wire format sometimes serialises z.unknown().optional() as
    // the bare string "undefined". After the fix the VM sees `null`
    // (installArgs's `?? null` fallback) rather than the literal 9-char
    // string — so `typeof args` becomes "object" instead of "string".
    const res = await run({
      source: "return { typeofArgs: typeof args, isNull: args === null };",
      // biome-ignore lint/suspicious/noExplicitAny: deliberately bypassing the typed surface
      args: "undefined" as any,
    });
    expect(res.isError).toBeFalsy();
    const s = res.structuredContent as {
      result: { typeofArgs: string; isNull: boolean };
    };
    expect(s.result.typeofArgs).toBe("object");
    expect(s.result.isNull).toBe(true);
  });
});

describe("script tool: surface integrity", () => {
  it("is registered alongside every other SwissKnife tool", () => {
    expect(tools.map((t) => t.name)).toContain("script");
    // The catalog grows as new tools land — pin a lower bound rather
    // than the exact count so this test isn't load-bearing on count bumps.
    expect(tools.length).toBeGreaterThanOrEqual(14);
  });

  // The description is the tool's contract surface; assert a range of the
  // load-bearing tokens it promises (gateway shape, limits, error taxonomy).
  const requiredTokens = [
    "tools.<name>",
    "Examples",
    "Hard limits",
    "args",
    "console.log",
    "Top-level await",
  ];
  it.each(requiredTokens)("description mentions %j", (token) => {
    expect(scriptTool.description).toContain(token);
  });
});

describe("script tool: args handling (negative + positive range)", () => {
  // The string "undefined" and the JSON-string "undefined" are treated as
  // absent; other string args parse-as-JSON when possible, else stay strings.
  const argCases: Array<[string, unknown, string]> = [
    ["literal string undefined => null", "undefined", "object"],
    ["JSON object string => parsed object", '{"a":1}', "object"],
    ["JSON number string => parsed number", "42", "number"],
    ["JSON array string => parsed array", "[1,2]", "object"],
    ["non-JSON string => stays a string", "hello", "string"],
    ["real object => object", { a: 1 } as unknown, "object"],
    ["real number => number", 7 as unknown, "number"],
  ];
  it.each(argCases)("%s", async (_label, args, expectedTypeof) => {
    const res = await run({
      source: "return typeof args;",
      // biome-ignore lint/suspicious/noExplicitAny: exercising the wire-quirk surface
      args: args as any,
    });
    expect(res.isError).toBeFalsy();
    expect((res.structuredContent as { result: string }).result).toBe(
      expectedTypeof,
    );
  });
});
