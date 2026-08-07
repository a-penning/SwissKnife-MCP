import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { isBlockedIp, ssrfGuardEnabled } from "../../src/lib/ssrf.js";
import { dnsTool } from "../../src/tools/dns.js";
import { inspectTool } from "../../src/tools/inspect.js";
import { jwtTool } from "../../src/tools/jwt.js";

// Cross-tool regression suite for SSRF guard coverage. Every outbound
// primitive that used to bypass `SWISSKNIFE_BLOCK_PRIVATE_NETWORKS` is
// exercised here against an unmistakably-private target (loopback or
// cloud-metadata link-local) and must refuse before opening a socket.
//
// Loopback / link-local literals are short-circuited by `isBlockedIp`
// without any DNS or network I/O, so these tests stay hermetic.

const ENV = "SWISSKNIFE_BLOCK_PRIVATE_NETWORKS";

beforeEach(() => {
  process.env[ENV] = "1";
});
afterEach(() => {
  delete process.env[ENV];
});

function errorText(res: CallToolResult): string {
  return JSON.stringify(res.content);
}

describe("ssrf bypass coverage: jwt verify with JWKS URL", () => {
  // jose's createRemoteJWKSet would otherwise fetch the URL straight away
  // — our customFetch + pre-check refuses before the request leaves the
  // box. Any token will do; verification never gets that far.
  const ANY_TOKEN =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
    "eyJzdWIiOiJ4In0." +
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

  it.each([
    "http://127.0.0.1/jwks.json",
    "http://169.254.169.254/latest/meta-data/",
    "http://10.0.0.1/jwks.json",
  ])("refuses JWKS URL %s when the guard is on", async (jwksUrl) => {
    const res = (await jwtTool.handler({
      action: "verify",
      input: ANY_TOKEN,
      key: jwksUrl,
      algorithm: "HS256",
    } as Parameters<typeof jwtTool.handler>[0])) as CallToolResult;
    // The handler turns verify failures into structuredContent with
    // valid:false rather than isError:true — so we read failureReason.
    const out = res.structuredContent as Record<string, unknown> | undefined;
    if (out && out.valid === false) {
      expect(String(out.failureReason)).toMatch(
        /blocked request to private\/loopback/,
      );
    } else {
      expect(res.isError).toBe(true);
      expect(errorText(res)).toMatch(/blocked request to private\/loopback/);
    }
  });
});

describe("ssrf bypass coverage: inspect kind:tls", () => {
  it.each([
    "127.0.0.1:443",
    "169.254.169.254:443",
    "10.0.0.1:443",
    "[::1]:443",
  ])("refuses tls inspect of %s when the guard is on", async (target) => {
    const res = (await inspectTool.handler({
      kind: "tls",
      value: target,
      timeoutMs: 2000,
    } as Parameters<typeof inspectTool.handler>[0])) as CallToolResult;
    expect(res.isError).toBe(true);
    expect(errorText(res)).toMatch(
      /blocked TLS connection to private\/loopback/,
    );
  });
});

describe("ssrf bypass coverage: inspect kind:whois server override", () => {
  it.each(["127.0.0.1", "169.254.169.254", "10.0.0.1"])(
    "refuses whois lookup via private server %s when the guard is on",
    async (server) => {
      const res = (await inspectTool.handler({
        kind: "whois",
        value: "example.com",
        whoisServer: server,
        timeoutMs: 2000,
      } as Parameters<typeof inspectTool.handler>[0])) as CallToolResult;
      expect(res.isError).toBe(true);
      expect(errorText(res)).toMatch(/blocked whois server/);
    },
  );
});

describe("ssrf bypass coverage: dns resolver param", () => {
  it.each(["127.0.0.1", "169.254.169.254", "10.0.0.1", "::1"])(
    "refuses dns queries via private resolver %s when the guard is on",
    async (resolver) => {
      const res = (await dnsTool.handler({
        host: "example.com",
        type: "A",
        resolver,
        timeoutMs: 2000,
      } as Parameters<typeof dnsTool.handler>[0])) as CallToolResult;
      expect(res.isError).toBe(true);
      expect(errorText(res)).toMatch(/private\/loopback resolver/);
    },
  );
});

describe("ssrf bypass coverage: the refusal is gated on the env, not hard-coded", () => {
  beforeEach(() => {
    delete process.env[ENV];
  });
  // The guard-ON refusals above prove the checks fire. Here we confirm the
  // gate is the env, not a hard-coded block — asserted synchronously via the
  // two pure predicates the handlers consult, so no live lookup is needed:
  // with the guard off `ssrfGuardEnabled()` is false (so the resolver/host
  // checks are skipped) even though 127.0.0.1 is an address `isBlockedIp`
  // would reject when the guard is on.
  it("ssrfGuardEnabled() is false when the env is unset", () => {
    expect(ssrfGuardEnabled()).toBe(false);
  });
  it("the loopback resolver IP would still be blocked if the guard were on", () => {
    expect(isBlockedIp("127.0.0.1")).toBe(true);
  });
});
