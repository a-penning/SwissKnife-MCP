import type { Server } from "node:http";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { guardedFetch } from "../../src/lib/ssrf.js";

const ENV = "SWISSKNIFE_BLOCK_PRIVATE_NETWORKS";
const original = process.env[ENV];

let server: Server;
let port: number;

beforeAll(async () => {
  server = http.createServer((_req, res) => {
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ ok: true }));
  });
  await new Promise<void>((resolve) =>
    server.listen(0, "127.0.0.1", () => {
      port = (server.address() as AddressInfo).port;
      resolve();
    }),
  );
});

afterAll(async () => {
  await new Promise<void>((resolve, reject) =>
    server.close((e) => (e ? reject(e) : resolve())),
  );
  if (original === undefined) delete process.env[ENV];
  else process.env[ENV] = original;
});

afterEach(() => {
  delete process.env[ENV];
});

describe("guardedFetch: SSRF guard off (passthrough)", () => {
  it("reaches a loopback server unchanged when the guard is off", async () => {
    delete process.env[ENV];
    const res = await guardedFetch(`http://localhost:${port}/`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });
});

describe("guardedFetch: SSRF guard on (pinned connector)", () => {
  // The connector resolves the hostname and refuses the connection when the
  // resolved address is private/loopback — the address screened is the one
  // dialled, so a rebinding flip cannot slip past.
  it.each(["localhost", "LOCALHOST", "localhost."])(
    "refuses a host (%j) that resolves to a loopback address",
    async (host) => {
      process.env[ENV] = "1";
      await expect(guardedFetch(`http://${host}:${port}/`)).rejects.toThrow();
    },
  );

  it("surfaces the SSRF reason in the error message", async () => {
    process.env[ENV] = "1";
    const error = await guardedFetch(`http://localhost:${port}/`).then(
      () => null,
      (e: unknown) => e as { message?: string; cause?: { message?: string } },
    );
    expect(error).not.toBeNull();
    // The eager assertUrlAllowed throws the reason directly (transport-
    // independent); fall back to the connector cause just in case.
    const text = `${error?.message ?? ""} ${error?.cause?.message ?? ""}`;
    expect(text).toMatch(/blocked request to private\/loopback/);
  });

  it("still serves the same URL once the guard is turned back off", async () => {
    delete process.env[ENV];
    const res = await guardedFetch(`http://localhost:${port}/`);
    expect(res.status).toBe(200);
  });
});
