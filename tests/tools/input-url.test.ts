import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { convertDataTool } from "../../src/tools/convert-data.js";
import { diffTool } from "../../src/tools/diff.js";
import { hashTool } from "../../src/tools/hash.js";
import { jsonQueryTool } from "../../src/tools/json-query.js";
import { regexTool } from "../../src/tools/regex.js";
import { textTool } from "../../src/tools/text.js";

// Serves fixed documents so the remote-input (inputUrl / aUrl / bUrl) path is
// exercised on its success path, not only its error contract.
const DOCS: Record<string, [string, string]> = {
  "/data.json": ["application/json", '{"items":[{"price":5},{"price":20}]}'],
  "/list.txt": ["text/plain", "banana\napple\ncherry\n"],
  "/abc.txt": ["text/plain", "abc"],
  "/left.txt": ["text/plain", "one\ntwo\n"],
  "/right.txt": ["text/plain", "one\nTWO\n"],
  "/users.csv": ["text/csv", "name,age\nada,36\nlin,7\n"],
};

let server: Server;
let baseUrl: string;

beforeAll(async () => {
  server = createServer((req, res) => {
    const path = (req.url ?? "/").split("?")[0] as string;
    const doc = DOCS[path];
    if (!doc) {
      res.writeHead(404);
      res.end("not found");
      return;
    }
    res.writeHead(200, { "content-type": doc[0] });
    res.end(doc[1]);
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

function structured(res: CallToolResult): Record<string, unknown> {
  expect(res.isError, JSON.stringify(res.content)).toBeFalsy();
  return res.structuredContent as Record<string, unknown>;
}

function errorText(res: CallToolResult): string {
  expect(res.isError, JSON.stringify(res.structuredContent)).toBe(true);
  return String((res.content?.[0] as { text?: string })?.text ?? "");
}

describe("remote inputs: success path", () => {
  it("json-query fetches and queries a JSON document", async () => {
    const res = (await jsonQueryTool.handler({
      query: "$.items[?(@.price < 10)].price",
      inputUrl: `${baseUrl}/data.json`,
      limit: 1000,
    } as Parameters<typeof jsonQueryTool.handler>[0])) as CallToolResult;
    expect(structured(res).values).toEqual([5]);
  });

  it("hash digests a fetched document (sha256 of 'abc')", async () => {
    const res = (await hashTool.handler({
      algorithm: "sha256",
      inputUrl: `${baseUrl}/abc.txt`,
      inputEncoding: "utf8",
      hmacKeyEncoding: "utf8",
      outputEncoding: "hex",
    } as Parameters<typeof hashTool.handler>[0])) as CallToolResult;
    expect(structured(res).digest).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  // The same fetched document, digested under a range of algorithms. Expected
  // digests are the canonical, independently-known hashes of the bytes "abc".
  const abcDigests: Array<[string, string]> = [
    ["md5", "900150983cd24fb0d6963f7d28e17f72"],
    ["sha1", "a9993e364706816aba3e25717850c26c9cd0d89d"],
    [
      "sha256",
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    ],
    [
      "sha512",
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" +
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    ],
  ];
  it.each(
    abcDigests,
  )("hash(%s) of the fetched 'abc' document matches the known digest", async (algorithm, expected) => {
    const res = (await hashTool.handler({
      algorithm,
      inputUrl: `${baseUrl}/abc.txt`,
      inputEncoding: "utf8",
      hmacKeyEncoding: "utf8",
      outputEncoding: "hex",
    } as Parameters<typeof hashTool.handler>[0])) as CallToolResult;
    expect(structured(res).digest).toBe(expected);
  });

  it("convert-data converts a fetched CSV to JSON", async () => {
    const res = (await convertDataTool.handler({
      from: "csv",
      to: "json",
      inputUrl: `${baseUrl}/users.csv`,
      indent: 2,
      csvDelimiter: ",",
      csvHeaders: true,
      csvDynamicTyping: true,
    } as Parameters<typeof convertDataTool.handler>[0])) as CallToolResult;
    expect(JSON.parse(structured(res).result as string)).toEqual([
      { name: "ada", age: 36 },
      { name: "lin", age: 7 },
    ]);
  });

  it("text sorts lines from a fetched document", async () => {
    const res = (await textTool.handler({
      action: "sort-lines",
      inputUrl: `${baseUrl}/list.txt`,
      separator: "-",
      order: "asc",
      numeric: false,
      unique: false,
    } as Parameters<typeof textTool.handler>[0])) as CallToolResult;
    // sort-lines preserves the trailing newline from the source document.
    expect(structured(res).result).toBe("apple\nbanana\ncherry\n");
  });

  it("regex matches against a fetched document", async () => {
    const res = (await regexTool.handler({
      action: "match",
      pattern: "an",
      flags: "g",
      inputUrl: `${baseUrl}/list.txt`,
    } as Parameters<typeof regexTool.handler>[0])) as CallToolResult;
    expect(structured(res).count).toBe(2); // "banana" -> 2
  });

  it("diff mixes a fetched side with an inline side", async () => {
    const res = (await diffTool.handler({
      aUrl: `${baseUrl}/left.txt`,
      bUrl: `${baseUrl}/right.txt`,
      mode: "lines",
      context: 3,
      aLabel: "a",
      bLabel: "b",
    } as Parameters<typeof diffTool.handler>[0])) as CallToolResult;
    const out = structured(res);
    expect(out.additions).toBe(1);
    expect(out.deletions).toBe(1);
  });
});

describe("remote inputs: exactly-one-of contract (fails before any fetch)", () => {
  const url = "http://127.0.0.1:1/x"; // never actually fetched on these paths

  // Each tool that takes the input/inputUrl pair must reject "both" and
  // "neither" with the exactly-one-of message — and must do so without ever
  // touching the network (the URL above is intentionally unroutable).
  it("hash rejects both input and inputUrl", async () => {
    const res = (await hashTool.handler({
      algorithm: "sha256",
      input: "abc",
      inputUrl: url,
      inputEncoding: "utf8",
      hmacKeyEncoding: "utf8",
      outputEncoding: "hex",
    } as Parameters<typeof hashTool.handler>[0])) as CallToolResult;
    expect(errorText(res)).toMatch(/exactly one of input/);
  });

  it("hash rejects neither input nor inputUrl", async () => {
    const res = (await hashTool.handler({
      algorithm: "sha256",
      inputEncoding: "utf8",
      hmacKeyEncoding: "utf8",
      outputEncoding: "hex",
    } as Parameters<typeof hashTool.handler>[0])) as CallToolResult;
    expect(errorText(res)).toMatch(/exactly one of input/);
  });

  it("regex rejects both input and inputUrl", async () => {
    const res = (await regexTool.handler({
      action: "match",
      pattern: "x",
      flags: "g",
      input: "abc",
      inputUrl: url,
    } as Parameters<typeof regexTool.handler>[0])) as CallToolResult;
    expect(errorText(res)).toMatch(/exactly one of input/);
  });

  it("text rejects neither input nor inputUrl", async () => {
    const res = (await textTool.handler({
      action: "sort-lines",
      separator: "-",
      order: "asc",
      numeric: false,
      unique: false,
    } as Parameters<typeof textTool.handler>[0])) as CallToolResult;
    expect(errorText(res)).toMatch(/exactly one of input/);
  });
});

describe("remote inputs: fetch error contract", () => {
  // Unsupported protocols and unparseable URLs are rejected by fetchBytes
  // before any socket is opened — fully offline.
  const badUrls: Array<[string, RegExp]> = [
    ["file:///etc/passwd", /unsupported URL protocol/],
    ["ftp://example.com/x", /unsupported URL protocol/],
    ["data:text/plain,hi", /unsupported URL protocol/],
    ["not-a-url", /invalid URL/],
    ["://missing-scheme", /invalid URL/],
  ];
  it.each(badUrls)("rejects inputUrl %j", async (badUrl, pattern) => {
    const res = (await hashTool.handler({
      algorithm: "sha256",
      inputUrl: badUrl,
      inputEncoding: "utf8",
      hmacKeyEncoding: "utf8",
      outputEncoding: "hex",
    } as Parameters<typeof hashTool.handler>[0])) as CallToolResult;
    expect(errorText(res)).toMatch(pattern);
  });

  // A reachable-but-404 path on the local server surfaces the HTTP-status
  // error from fetchBytes (no external network).
  it("surfaces a non-2xx response from the (local) server as an error", async () => {
    const res = (await hashTool.handler({
      algorithm: "sha256",
      inputUrl: `${baseUrl}/does-not-exist`,
      inputEncoding: "utf8",
      hmacKeyEncoding: "utf8",
      outputEncoding: "hex",
    } as Parameters<typeof hashTool.handler>[0])) as CallToolResult;
    expect(errorText(res)).toMatch(/HTTP 404/);
  });
});
