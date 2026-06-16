import { Buffer } from "node:buffer";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { z } from "zod";
import { httpTool } from "../../src/tools/http.js";

let server: Server;
let baseUrl: string;

beforeAll(async () => {
  server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    switch (url.pathname) {
      case "/json": {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ greeting: "hello", n: 42 }));
        return;
      }
      case "/echo": {
        const chunks: Buffer[] = [];
        req.on("data", (c: Buffer) => chunks.push(c));
        req.on("end", () => {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(
            JSON.stringify({
              method: req.method,
              contentType: req.headers["content-type"] ?? null,
              xCustom: req.headers["x-custom"] ?? null,
              body: Buffer.concat(chunks).toString("utf8"),
            }),
          );
        });
        return;
      }
      case "/redirect": {
        res.writeHead(302, { location: "/json" });
        res.end();
        return;
      }
      case "/binary": {
        res.writeHead(200, { "content-type": "application/octet-stream" });
        res.end(Buffer.from([0xff, 0xfe, 0x00, 0x01]));
        return;
      }
      case "/big": {
        res.writeHead(200, { "content-type": "text/plain" });
        res.end("x".repeat(1000));
        return;
      }
      case "/slow": {
        // never responds; socket closed by afterAll teardown
        return;
      }
      case "/teapot": {
        res.writeHead(418, { "content-type": "text/plain" });
        res.end("short and stout");
        return;
      }
      case "/created": {
        res.writeHead(201, { "content-type": "text/plain" });
        res.end("made it");
        return;
      }
      case "/nocontent": {
        res.writeHead(204);
        res.end();
        return;
      }
      case "/badrequest": {
        res.writeHead(400, { "content-type": "text/plain" });
        res.end("bad");
        return;
      }
      case "/servererror": {
        res.writeHead(500, { "content-type": "text/plain" });
        res.end("boom");
        return;
      }
      case "/cookies": {
        res.writeHead(200, {
          "content-type": "text/plain",
          "set-cookie": ["a=1; Path=/", "b=2; HttpOnly"],
        });
        res.end("ok");
        return;
      }
      default: {
        res.writeHead(404);
        res.end("not found");
      }
    }
  });
  server.listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const { port } = server.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${port}`;
});

afterAll(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve, reject) =>
    server.close((e) => (e ? reject(e) : resolve())),
  );
});

type Args = Parameters<typeof httpTool.handler>[0];

async function run(args: Partial<Args>): Promise<CallToolResult> {
  return (await httpTool.handler({
    method: "GET",
    requestBodyEncoding: "utf8",
    timeoutMs: 10_000,
    redirect: "follow",
    maxResponseBytes: 256 * 1024,
    responseEncoding: "auto",
    ...args,
  } as Args)) as CallToolResult;
}

async function structured(
  args: Partial<Args>,
): Promise<Record<string, unknown>> {
  const res = await run(args);
  expect(res.isError, JSON.stringify(res.content)).toBeFalsy();
  return res.structuredContent as Record<string, unknown>;
}

describe("http: requests", () => {
  it("GET returns status, headers, body and parsed json", async () => {
    const out = await structured({ url: `${baseUrl}/json` });
    expect(out.status).toBe(200);
    expect(out.ok).toBe(true);
    expect(out.responseBodyEncoding).toBe("utf8");
    expect(out.json).toEqual({ greeting: "hello", n: 42 });
    expect((out.headers as Record<string, string>)["content-type"]).toContain(
      "application/json",
    );
    expect(out.durationMs).toBeTypeOf("number");
  });

  it("POST sends body and custom headers", async () => {
    const out = await structured({
      url: `${baseUrl}/echo`,
      method: "POST",
      body: "payload!",
      headers: { "x-custom": "yes", "content-type": "text/plain" },
    });
    expect(out.json).toMatchObject({
      method: "POST",
      contentType: "text/plain",
      xCustom: "yes",
      body: "payload!",
    });
  });

  // Every body-carrying method round-trips its body + method through /echo.
  const bodyMethods: Array<Args["method"]> = [
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "OPTIONS",
  ];
  it.each(
    bodyMethods,
  )("%s sends a text body to the echo route", async (method) => {
    const out = await structured({
      url: `${baseUrl}/echo`,
      method,
      body: "payload!",
    });
    expect(out.json).toMatchObject({ method, body: "payload!" });
  });

  // requestBodyEncoding range: utf8 sends verbatim; base64 is decoded first.
  const bodyEncodings: Array<["utf8" | "base64", string, string]> = [
    ["utf8", "hello", "hello"],
    ["base64", Buffer.from("hello").toString("base64"), "hello"],
    ["base64", Buffer.from("a/b+c=").toString("base64"), "a/b+c="],
  ];
  it.each(
    bodyEncodings,
  )("requestBodyEncoding=%s decodes the body before sending", async (requestBodyEncoding, body, expected) => {
    const out = await structured({
      url: `${baseUrl}/echo`,
      method: "POST",
      body,
      requestBodyEncoding,
    });
    expect((out.json as { body: string }).body).toBe(expected);
  });

  it("jsonBody serializes and sets content-type", async () => {
    const out = await structured({
      url: `${baseUrl}/echo`,
      method: "POST",
      jsonBody: { a: [1, 2] },
    });
    expect(out.json).toMatchObject({
      contentType: "application/json",
      body: '{"a":[1,2]}',
    });
  });

  // A range of status codes: every one is a successful *result* (never an
  // error), with `ok` true only for the 2xx band. Body comes back regardless.
  const statusCases: Array<[string, number, boolean]> = [
    ["/json", 200, true],
    ["/created", 201, true],
    ["/nocontent", 204, true],
    ["/badrequest", 400, false],
    ["/teapot", 418, false],
    ["/servererror", 500, false],
  ];
  it.each(
    statusCases,
  )("%s -> status %d (ok=%s), surfaced as a result not an error", async (path, status, ok) => {
    const out = await structured({ url: `${baseUrl}${path}` });
    expect(out.status).toBe(status);
    expect(out.ok).toBe(ok);
  });

  it("non-2xx is a result, not an error", async () => {
    const out = await structured({ url: `${baseUrl}/teapot` });
    expect(out.status).toBe(418);
    expect(out.ok).toBe(false);
    expect(out.body).toBe("short and stout");
  });

  it("follows redirects and reports the final URL", async () => {
    const out = await structured({ url: `${baseUrl}/redirect` });
    expect(out.status).toBe(200);
    expect(out.redirected).toBe(true);
    expect(out.finalUrl).toBe(`${baseUrl}/json`);
  });

  it("redirect: manual surfaces the 3xx", async () => {
    const out = await structured({
      url: `${baseUrl}/redirect`,
      redirect: "manual",
    });
    expect(out.status).toBe(302);
    expect((out.headers as Record<string, string>).location).toBe("/json");
  });

  it("redirect: 'error' fails on a 3xx", async () => {
    const res = await run({ url: `${baseUrl}/redirect`, redirect: "error" });
    expect(res.isError).toBe(true);
  });

  it("returns invalid UTF-8 bodies as base64", async () => {
    const out = await structured({ url: `${baseUrl}/binary` });
    expect(out.responseBodyEncoding).toBe("base64");
    expect(Buffer.from(out.body as string, "base64")).toEqual(
      Buffer.from([0xff, 0xfe, 0x00, 0x01]),
    );
  });

  it("truncates oversized responses instead of failing", async () => {
    const out = await structured({
      url: `${baseUrl}/big`,
      maxResponseBytes: 100,
    });
    expect(out.truncated).toBe(true);
    expect(out.bodyBytes).toBe(100);
    expect(out.body).toBe("x".repeat(100));
  });

  it("times out with a precise error", async () => {
    const res = await run({ url: `${baseUrl}/slow`, timeoutMs: 200 });
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res.content)).toContain("timed out after 200ms");
  });

  it("preserves multiple Set-Cookie headers separately", async () => {
    const out = await structured({ url: `${baseUrl}/cookies` });
    expect(out.setCookies).toEqual(["a=1; Path=/", "b=2; HttpOnly"]);
  });
});

describe("http: input contract", () => {
  // A range of unparseable URLs and unsupported protocols, each with the
  // message the tool promises. All fail before any socket is opened.
  const badUrls: Array<[string, RegExp]> = [
    ["not a url", /invalid URL/],
    ["://no-scheme", /invalid URL/],
    ["ftp://example.com/x", /unsupported URL protocol/],
    ["file:///etc/passwd", /unsupported URL protocol/],
    ["ws://example.com/x", /unsupported URL protocol/],
    ["data:text/plain,hi", /unsupported URL protocol/],
    ["mailto:a@b.com", /unsupported URL protocol/],
  ];
  it.each(badUrls)("rejects url %j", async (url, pattern) => {
    const res = await run({ url });
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res.content)).toMatch(pattern);
  });

  // GET and HEAD cannot carry a body, in either the `body` or `jsonBody` form.
  const bodyOnBodyless: Array<["GET" | "HEAD", Partial<Args>]> = [
    ["GET", { body: "nope" }],
    ["GET", { jsonBody: { a: 1 } }],
    ["HEAD", { body: "nope" }],
    ["HEAD", { jsonBody: [1, 2] }],
  ];
  it.each(bodyOnBodyless)("rejects %s with a body", async (method, extra) => {
    const res = await run({ url: `${baseUrl}/json`, method, ...extra });
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res.content)).toContain("cannot carry a body");
  });

  it("rejects body + jsonBody together", async () => {
    const res = await run({
      url: `${baseUrl}/echo`,
      method: "POST",
      body: "x",
      jsonBody: { y: 1 },
    });
    expect(res.isError).toBe(true);
  });

  it("connection refused is a precise error result", async () => {
    const res = await run({ url: "http://127.0.0.1:1/x", timeoutMs: 2000 });
    expect(res.isError).toBe(true);
  });

  it("invalid header name returns a clean error, not a thrown TypeError", async () => {
    const res = await run({
      url: `${baseUrl}/json`,
      headers: { "bad header name": "x" },
    });
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res.content)).toMatch(/invalid request headers/);
  });

  it("invalid base64 body is rejected up front, not sent as garbage", async () => {
    const res = await run({
      url: `${baseUrl}/echo`,
      method: "POST",
      body: "!!!not-valid-base64!!!",
      requestBodyEncoding: "base64",
    });
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res.content)).toMatch(/invalid body base64/);
  });

  it("jsonBody passed as a JSON-encoded string is parsed once, not double-encoded", async () => {
    // Simulates an MCP client serialising the value as a string because the
    // schema is z.unknown().
    const out = await structured({
      url: `${baseUrl}/echo`,
      method: "POST",
      jsonBody: '{"msg":"hi","n":[1,2,3]}' as unknown as Record<
        string,
        unknown
      >,
    });
    expect(out.json).toMatchObject({
      contentType: "application/json",
      body: '{"msg":"hi","n":[1,2,3]}',
    });
  });

  it("jsonBody passed as a non-JSON string is rejected with a useful error", async () => {
    const res = await run({
      url: `${baseUrl}/echo`,
      method: "POST",
      jsonBody: "not-json-just-text" as unknown as Record<string, unknown>,
    });
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res.content)).toMatch(
      /jsonBody was passed as a string/,
    );
  });
});

describe("http: text-field niceties", () => {
  it("base64 binary body shows a label in the text preview, not raw base64", async () => {
    const res = await run({ url: `${baseUrl}/binary` });
    const text = String((res.content?.[0] as { text?: string })?.text ?? "");
    expect(text).toMatch(/\[binary body — base64 in structuredContent/);
  });

  it("redirect:'error' surfaces the redirect as an error result", async () => {
    const res = await run({ url: `${baseUrl}/redirect`, redirect: "error" });
    expect(res.isError).toBe(true);
  });
});

describe("http: headers accept a JSON-stringified object", () => {
  // Some MCP clients serialise nested object args to a JSON string. The
  // coercion lives in the field schema (jsonObjectArg), so assert it at the
  // schema layer — the handler receives the already-parsed object.
  it("coerces a stringified headers object via the input schema", () => {
    const parsed = z
      .object(httpTool.inputSchema)
      .parse({ url: "https://example.com/", headers: '{"x-test":"hi"}' });
    expect(parsed.headers).toEqual({ "x-test": "hi" });
  });

  it("still accepts a real object and rejects a non-object string", () => {
    const obj = z
      .object(httpTool.inputSchema)
      .parse({ url: "https://example.com/", headers: { a: "b" } });
    expect(obj.headers).toEqual({ a: "b" });
    expect(() =>
      z
        .object(httpTool.inputSchema)
        .parse({ url: "https://example.com/", headers: "not json" }),
    ).toThrow();
  });
});
