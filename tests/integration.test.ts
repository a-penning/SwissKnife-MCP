import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createApp } from "../src/http.js";
import { tools as toolDefs } from "../src/tools/registry.js";

let server: Server;
let baseUrl: string;

beforeAll(async () => {
  server = createApp().listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const { port } = server.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve, reject) =>
    server.close((e) => (e ? reject(e) : resolve())),
  );
});

async function connect(): Promise<Client> {
  const client = new Client({ name: "integration-test", version: "0.0.0" });
  await client.connect(
    new StreamableHTTPClientTransport(new URL(`${baseUrl}/mcp`)),
  );
  return client;
}

async function call(
  client: Client,
  name: string,
  args: Record<string, unknown>,
): Promise<CallToolResult> {
  return (await client.callTool({ name, arguments: args })) as CallToolResult;
}

describe("integration: server surface", () => {
  it("serves /healthz", async () => {
    const res = await fetch(`${baseUrl}/healthz`);
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ status: "ok" });
  });

  it("lists every registered tool", async () => {
    const client = await connect();
    try {
      const { tools } = await client.listTools();
      expect(tools.map((t) => t.name).sort()).toEqual([
        "color",
        "convert-data",
        "crypto",
        "diff",
        "dns",
        "encode",
        "hash",
        "http",
        "id",
        "inspect",
        "json-query",
        "jwt",
        "net",
        "number",
        "regex",
        "script",
        "text",
        "time",
      ]);
      for (const tool of tools) {
        expect(tool.description, tool.name).toBeTruthy();
        expect(tool.inputSchema, tool.name).toBeTruthy();
      }
    } finally {
      await client.close();
    }
  });

  it("advertises each tool's params as JSON-Schema properties (schema-loss guard)", async () => {
    // Regression guard: wrapping a tool's input schema in a z.preprocess/
    // effects schema makes the SDK advertise `properties: {}` — every param
    // becomes invisible to clients even though `inputSchema` is still present
    // (so the truthiness check above passes). Assert the advertised properties
    // match each tool's declared shape keys exactly, through the real
    // tools/list path, so that failure mode can never ship silently again.
    const client = await connect();
    try {
      const { tools } = await client.listTools();
      const byName = new Map(tools.map((t) => [t.name, t]));
      for (const def of toolDefs) {
        const advertised = byName.get(def.name);
        const props = Object.keys(
          (advertised?.inputSchema?.properties as
            | Record<string, unknown>
            | undefined) ?? {},
        );
        const declared = Object.keys(def.inputSchema);
        expect(props.sort(), def.name).toEqual(declared.sort());
      }
    } finally {
      await client.close();
    }
  });

  it("rejects GET /mcp (stateless server)", async () => {
    const res = await fetch(`${baseUrl}/mcp`);
    expect(res.status).toBe(405);
  });
});

describe("integration: one happy path per tool", () => {
  it("exercises every tool end-to-end", async () => {
    const client = await connect();
    try {
      const encode = await call(client, "encode", {
        direction: "encode",
        format: "base64",
        input: "hello",
      });
      expect(encode.structuredContent).toMatchObject({ result: "aGVsbG8=" });

      const hash = await call(client, "hash", {
        algorithm: "sha256",
        input: "abc",
      });
      expect(hash.structuredContent).toMatchObject({
        digest:
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
      });

      const jwt = await call(client, "jwt", {
        action: "sign",
        key: "secret",
        payload: { sub: "it" },
      });
      const token = (jwt.structuredContent as { token: string }).token;
      const verify = await call(client, "jwt", {
        action: "verify",
        input: token,
        key: "secret",
      });
      expect(verify.structuredContent).toMatchObject({ valid: true });

      const id = await call(client, "id", {
        action: "generate",
        kind: "uuid-v4",
      });
      expect((id.structuredContent as { values: string[] }).values[0]).toMatch(
        /^[0-9a-f-]{36}$/,
      );

      const time = await call(client, "time", {
        action: "convert",
        input: "1700000000",
      });
      expect(time.structuredContent).toMatchObject({
        isoUtc: "2023-11-14T22:13:20.000Z",
      });

      const convert = await call(client, "convert-data", {
        from: "json",
        to: "yaml",
        input: '{"a":1}',
      });
      expect(
        (convert.structuredContent as { result: string }).result.trim(),
      ).toBe("a: 1");

      const text = await call(client, "text", {
        action: "case",
        input: "hello world",
        target: "pascal",
      });
      expect(text.structuredContent).toMatchObject({ result: "HelloWorld" });

      const regex = await call(client, "regex", {
        action: "match",
        pattern: "\\d+",
        input: "a1 b22",
      });
      expect(regex.structuredContent).toMatchObject({ count: 2 });

      const inspect = await call(client, "inspect", {
        kind: "url",
        value: "https://example.com/x?a=1",
      });
      expect(inspect.structuredContent).toMatchObject({
        hostname: "example.com",
      });

      const color = await call(client, "color", { input: "#ff0000" });
      expect(color.structuredContent).toMatchObject({
        rgb: "rgb(255, 0, 0)",
      });

      const diff = await call(client, "diff", { a: "x\n", b: "y\n" });
      expect(diff.structuredContent).toMatchObject({
        additions: 1,
        deletions: 1,
      });

      const jsonQuery = await call(client, "json-query", {
        query: "$.a[1]",
        input: '{"a":[1,2,3]}',
      });
      expect(jsonQuery.structuredContent).toMatchObject({
        values: [2],
        count: 1,
      });

      // The integration server doubles as the http tool's target: no
      // external network involved.
      const http = await call(client, "http", { url: `${baseUrl}/healthz` });
      expect(http.structuredContent).toMatchObject({
        status: 200,
        ok: true,
        json: { status: "ok" },
      });

      const number = await call(client, "number", {
        action: "roman",
        input: 1994,
      });
      expect(number.structuredContent).toMatchObject({ roman: "MCMXCIV" });

      // The script tool can call other tools end-to-end through MCP.
      const script = await call(client, "script", {
        source: `
          const h = await tools.hash({ algorithm: "sha256", input: args.s });
          return h.digest;
        `,
        args: { s: "abc" },
      });
      expect(script.structuredContent).toMatchObject({
        result:
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        toolCalls: 1,
      });
    } finally {
      await client.close();
    }
  });

  it("returns isError results for invalid input", async () => {
    const client = await connect();
    try {
      const res = await call(client, "encode", {
        direction: "decode",
        format: "base64",
        input: "!!!",
      });
      expect(res.isError).toBe(true);
    } finally {
      await client.close();
    }
  });

  it("rejects action-invalid field combinations at the schema boundary", async () => {
    // The `refine` hook rejects cross-field / action-specific mistakes before
    // the handler runs. Each pair below is a distinct rule across tools.
    const client = await connect();
    try {
      const cases: Array<[string, Record<string, unknown>, RegExp]> = [
        // inspect: array value only valid for url/certificate kinds.
        [
          "inspect",
          { kind: "tls", value: ["a.com:443", "b.com:443"] },
          /only supported for kind/i,
        ],
        // dns: host and ip are mutually exclusive.
        ["dns", { host: "example.com", ip: "1.1.1.1" }, /host OR ip/i],
        // jwt verify needs a key.
        ["jwt", { action: "verify", input: "a.b.c" }, /verify requires/i],
        // text replace needs find + replacement.
        ["text", { action: "replace", input: "x" }, /replace requires/i],
      ];
      for (const [name, args, pattern] of cases) {
        const res = await call(client, name, args);
        expect(res.isError, `${name} should reject`).toBe(true);
        expect(JSON.stringify(res.content), name).toMatch(pattern);
      }
    } finally {
      await client.close();
    }
  });

  it("unknown input keys fail loud at the MCP boundary (no silent strip)", async () => {
    // Without strict mode, Zod silently strips keys it doesn't know about
    // — meaning a typo or a renamed-away param disappears and the tool
    // either errors confusingly or (worse) returns wrong data. The server
    // boundary rejects unknown keys to fail loud instead.
    const client = await connect();
    try {
      const res = await call(client, "hash", {
        algorithm: "sha256",
        input: "abc",
        // Deliberately misspelled — should fail validation.
        outputEncodign: "hex",
      });
      expect(res.isError).toBe(true);
      const text = String((res.content?.[0] as { text?: string })?.text ?? "");
      expect(text.toLowerCase()).toMatch(/outputencodign|unrecognized|unknown/);
    } finally {
      await client.close();
    }
  });

  it("renamed params surface a migration hint, not a silent drop", async () => {
    // PV-4: http.bodyEncoding → requestBodyEncoding.
    // PV-5: jwt.token → input. number.value → input.
    // Each rename has a superRefine that points the caller at the new name.
    const client = await connect();
    try {
      const httpRes = await call(client, "http", {
        url: "http://example.invalid/",
        method: "POST",
        body: "aGVsbG8=",
        bodyEncoding: "base64",
      });
      expect(httpRes.isError).toBe(true);
      expect(JSON.stringify(httpRes.content)).toMatch(
        /bodyEncoding.*renamed.*requestBodyEncoding/,
      );

      const jwtRes = await call(client, "jwt", {
        action: "decode",
        token: "x.y.z",
      });
      expect(jwtRes.isError).toBe(true);
      expect(JSON.stringify(jwtRes.content)).toMatch(/token.*renamed.*input/);

      const numRes = await call(client, "number", {
        action: "roman",
        value: 7,
      });
      expect(numRes.isError).toBe(true);
      expect(JSON.stringify(numRes.content)).toMatch(/value.*renamed.*input/);
    } finally {
      await client.close();
    }
  });

  it("accepts JSON-stringified object params (clients that serialise nested args)", async () => {
    // Some MCP clients serialise a nested object argument to a JSON string at
    // the call boundary; the record-shaped params (jwt.payload/header,
    // http.headers) must accept that form, not reject it as a string.
    const client = await connect();
    try {
      // jwt.payload as a JSON STRING (no network needed for sign).
      const signed = await call(client, "jwt", {
        action: "sign",
        algorithm: "HS256",
        key: "secret",
        payload: '{"sub":"u1","role":"admin"}',
      });
      expect(signed.isError, JSON.stringify(signed.content)).toBeFalsy();
      const token = (signed.structuredContent as { token: string }).token;
      // Round-trip: decoding the signed token shows the coerced claims.
      const decoded = await call(client, "jwt", {
        action: "decode",
        input: token,
      });
      expect(decoded.structuredContent).toMatchObject({
        payload: { sub: "u1", role: "admin" },
      });
    } finally {
      await client.close();
    }
  });

  it("script: timeout error preserves logs/toolCalls/durationMs in structuredContent over MCP (CC-7 end-to-end)", async () => {
    // The CC-7 fix's whole point is that an MCP client gets the script's
    // console output back even after a timeout. This test rides the
    // protocol round-trip so we know the payload survives the wire, not
    // just the handler.
    const client = await connect();
    try {
      const res = await call(client, "script", {
        source: `
          console.log("before the hang");
          while (true) {}
        `,
        timeoutMs: 200,
      });
      expect(res.isError).toBe(true);
      // structuredContent must come through on the error path.
      const s = res.structuredContent as Record<string, unknown>;
      expect(s).toBeTruthy();
      expect(s.errorType).toBe("timeout");
      expect(Array.isArray(s.logs)).toBe(true);
      expect(
        (s.logs as string[]).some((l) => l.includes("before the hang")),
      ).toBe(true);
      expect(typeof s.toolCalls).toBe("number");
      expect(typeof s.durationMs).toBe("number");
    } finally {
      await client.close();
    }
  });

  it("handles concurrent clients without cross-talk", async () => {
    const [c1, c2] = await Promise.all([connect(), connect()]);
    try {
      const results = await Promise.all([
        call(c1, "encode", {
          direction: "encode",
          format: "base64",
          input: "one",
        }),
        call(c2, "encode", {
          direction: "encode",
          format: "base64",
          input: "two",
        }),
        call(c1, "hash", { algorithm: "md5", input: "abc" }),
        call(c2, "time", { action: "convert", input: "0" }),
      ]);
      expect(results[0]?.structuredContent).toMatchObject({ result: "b25l" });
      expect(results[1]?.structuredContent).toMatchObject({ result: "dHdv" });
      expect(results[2]?.structuredContent).toMatchObject({
        digest: "900150983cd24fb0d6963f7d28e17f72",
      });
      expect(results[3]?.structuredContent).toMatchObject({
        isoUtc: "1970-01-01T00:00:00.000Z",
      });
    } finally {
      await Promise.all([c1.close(), c2.close()]);
    }
  });
});
