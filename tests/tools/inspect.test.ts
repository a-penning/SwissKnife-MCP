import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import { inspectTool } from "../../src/tools/inspect.js";

// Live TLS / WHOIS / RDAP blocks are opt-in via SWISSKNIFE_LIVE_TESTS so the
// default unit run stays hermetic (TESTING-STRATEGY §7). url/certificate/batch
// blocks below are fixture-based and always run.
const liveDescribe = process.env.SWISSKNIFE_LIVE_TESTS
  ? describe
  : describe.skip;

type Args = Parameters<typeof inspectTool.handler>[0];

async function run(
  args: Partial<Args> & { kind: Args["kind"]; value: Args["value"] },
): Promise<CallToolResult> {
  return (await inspectTool.handler({
    timeoutMs: 5000,
    ...args,
  } as Args)) as CallToolResult;
}

async function structured(
  args: Partial<Args> & { kind: Args["kind"]; value: Args["value"] },
): Promise<Record<string, unknown>> {
  const res = await run(args);
  expect(res.isError, JSON.stringify(res.content)).toBeFalsy();
  return res.structuredContent as Record<string, unknown>;
}

describe("inspect: url", () => {
  it("decomposes a complex URL", async () => {
    const out = await structured({
      kind: "url",
      value:
        "https://user:pw@api.example.com:8443/v1/items%20list?tag=a&tag=b&q=hello%20world#frag",
    });
    expect(out.protocol).toBe("https");
    expect(out.hostname).toBe("api.example.com");
    expect(out.port).toBe("8443");
    expect(out.portIsDefault).toBe(false);
    expect(out.pathSegments).toEqual(["v1", "items list"]);
    expect(out.query).toEqual({ tag: ["a", "b"], q: "hello world" });
    expect(out.fragment).toBe("frag");
    expect(out.password).toBe("<redacted>");
  });
  // Default-port resolution + portIsDefault across the schemes that HAVE a
  // defined default. An explicit non-default port flips portIsDefault false.
  it.each<[string, string, boolean]>([
    ["https://example.com/x", "443", true],
    ["http://example.com/x", "80", true],
    ["ws://example.com/x", "80", true],
    ["wss://example.com/x", "443", true],
    ["ftp://example.com/x", "21", true],
    ["https://example.com:8443/x", "8443", false],
    ["http://example.com:8080/x", "8080", false],
    // explicit non-default port on a non-http scheme (ws default is 80)
    ["ws://example.com:8080/x", "8080", false],
    // an explicit port equal to the scheme default is normalised away by the
    // WHATWG URL parser (url.port becomes ""), so portIsDefault is true.
    ["https://example.com:443/x", "443", true],
  ])(
    "port resolution for %s → %s (default:%s)",
    async (value, port, isDefault) => {
      const out = await structured({ kind: "url", value });
      expect(out.port).toBe(port);
      expect(out.portIsDefault).toBe(isDefault);
    },
  );
  // Punycode <-> Unicode hostname decoding across a range of IDNs.
  it.each<[string, string]>([
    ["https://xn--mnchen-3ya.de/", "münchen.de"],
    ["https://xn--nxasmq6b.example/", "βόλοσ.example"],
    ["https://xn--80akhbyknj4f.example/", "испытание.example"],
  ])("decodes punycode hostname %s → %s", async (value, unicode) => {
    const out = await structured({ kind: "url", value });
    expect(out.hostnameUnicode).toBe(unicode);
  });
  // A range of inputs the URL parser must reject (no absolute form).
  it.each([
    "/just/a/path",
    "not a url at all",
    "http://", // no host
    "://missing-scheme.com",
    "",
    " ",
  ])("rejects unparseable URL %j", async (value) => {
    expect((await run({ kind: "url", value })).isError).toBe(true);
  });
  // pathSegments: percent-decoded when valid, kept raw when the escape is
  // malformed, empty when the path is "/".
  it.each<[string, string[]]>([
    ["https://example.com/%zz", ["%zz"]], // malformed escape kept raw
    ["https://example.com/a/b/c", ["a", "b", "c"]],
    ["https://example.com/items%20list", ["items list"]],
    ["https://example.com/", []],
    ["https://example.com/a//b", ["a", "b"]], // empty segments dropped
    ["https://example.com/%41%42", ["AB"]], // valid escapes decoded
  ])("pathSegments for %s → %j", async (value, segments) => {
    const out = await structured({ kind: "url", value });
    expect(out.pathSegments).toEqual(segments);
  });
  // Query parsing: single value → string, repeated key → array (order kept),
  // and dangerous prototype keys survive without corruption.
  it.each<[string, string]>([
    ["https://example.com/?q=hello", '{"q":"hello"}'],
    ["https://example.com/?tag=a&tag=b", '{"tag":["a","b"]}'],
    ["https://example.com/?tag=a&tag=b&tag=c", '{"tag":["a","b","c"]}'],
    ["https://example.com/?__proto__=a&__proto__=b", '{"__proto__":["a","b"]}'],
    ["https://example.com/?constructor=x", '{"constructor":"x"}'],
    ["https://example.com/?prototype=y", '{"prototype":"y"}'],
    ["https://example.com/?a=1&b=2", '{"a":"1","b":"2"}'],
  ])("query for %s → %s", async (value, json) => {
    const out = await structured({ kind: "url", value });
    expect(JSON.stringify(out.query)).toBe(json);
  });
});

describe("inspect: certificate", () => {
  const pem = readFileSync(
    join(__dirname, "../fixtures/test-cert.pem"),
    "utf8",
  );
  it("parses the test certificate", async () => {
    const out = await structured({ kind: "certificate", value: pem });
    expect(out.certificateCount).toBe(1);
    const cert = (out.certificates as Record<string, unknown>[])[0] as Record<
      string,
      unknown
    >;
    expect(String(cert.subject)).toContain("CN=test.swissknife.local");
    expect(cert.selfSigned).toBe(true);
    expect(cert.expired).toBe(false);
    expect(cert.keyType).toBe("rsa");
    expect((cert.keyDetails as Record<string, unknown>).modulusLength).toBe(
      2048,
    );
    expect(cert.subjectAltNames).toContain("DNS:test.swissknife.local");
    expect(String(cert.fingerprintSha256)).toMatch(
      /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/,
    );
    // SPKI fingerprint is added on the certificate inspect path now.
    expect(String(cert.spkiFingerprintSha256)).toMatch(
      /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/,
    );
  });
  // A range of inputs that are not a parseable X.509 certificate. Each is a
  // hard error (no silent acceptance). A bare CSR is the only PEM-armored
  // case and is rejected because the input contains no usable CERTIFICATE.
  it.each<[string, string]>([
    ["plain text", "not a cert"],
    ["empty", ""],
    ["base64 only, no armor", "dGhpcyBpcyBub3QgYSBjZXJ0"],
    [
      "a bare CSR (no cert in input)",
      "-----BEGIN CERTIFICATE REQUEST-----\nabc\n-----END CERTIFICATE REQUEST-----",
    ],
    [
      "garbage inside CERTIFICATE armor",
      "-----BEGIN CERTIFICATE-----\ndGhpcyBpcyBub3QgYSBjZXJ0\n-----END CERTIFICATE-----",
    ],
    [
      "private key only",
      "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
    ],
  ])("rejects %s", async (_label, value) => {
    expect((await run({ kind: "certificate", value })).isError).toBe(true);
  });
});

describe("inspect: certificate chain skips non-cert blocks instead of poisoning the whole input", () => {
  const pem = readFileSync(
    join(__dirname, "../fixtures/test-cert.pem"),
    "utf8",
  );
  it("includes a CSR-only input result as an error, but with skippedBlocks context", async () => {
    const csr =
      "-----BEGIN CERTIFICATE REQUEST-----\nMIHJMHEC\n-----END CERTIFICATE REQUEST-----";
    const res = await run({ kind: "certificate", value: `${pem}\n${csr}` });
    expect(res.isError).toBeFalsy();
    const out = res.structuredContent as Record<string, unknown>;
    expect(out.certificateCount).toBe(1);
    expect(out.skippedBlocks).toEqual([
      { index: 1, reason: "CERTIFICATE REQUEST (CSR) block" },
    ]);
  });
  it("names which PEM block failed when garbage is in CERTIFICATE armor", async () => {
    const bad =
      "-----BEGIN CERTIFICATE-----\ndGhpcyBpcyBub3QgYSBjZXJ0\n-----END CERTIFICATE-----";
    const res = await run({ kind: "certificate", value: bad });
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res.content)).toMatch(/block 1 of 1/);
  });
});

describe("inspect: batch for offline kinds", () => {
  it("batches kind='url' across an array of values", async () => {
    const out = await structured({
      kind: "url",
      value: [
        "https://example.com/a",
        "https://example.com/b",
        "not a url at all",
      ],
    });
    const results = out.results as Array<Record<string, unknown>>;
    expect(results).toHaveLength(2);
    expect(results[0]?.hostname).toBe("example.com");
    const failures = out.failures as Array<{ index: number; value: string }>;
    expect(failures).toHaveLength(1);
    expect(failures[0]?.index).toBe(2);
  });

  it("rejects batch input for kind='tls'", async () => {
    const res = await run({
      kind: "tls",
      // biome-ignore lint/suspicious/noExplicitAny: deliberately passing the wrong shape
      value: ["a.example.com", "b.example.com"] as any,
    });
    expect(res.isError).toBe(true);
    expect(JSON.stringify(res.content)).toMatch(/batch input.*tls/);
  });

  it("rejects batch input for kind='whois'", async () => {
    const res = await run({
      kind: "whois",
      // biome-ignore lint/suspicious/noExplicitAny: deliberately passing the wrong shape
      value: ["example.com", "iana.org"] as any,
    });
    expect(res.isError).toBe(true);
  });
});

describe("inspect: default timeout for network kinds", () => {
  it("schema default for timeoutMs is 10000 (bumped from 5000)", () => {
    // Build the input schema and parse a minimal object — the default
    // surfaces as the parsed value of timeoutMs when not provided.
    // (We don't want to actually exercise a 10s real connection in the
    // test runner; schema-level verification is enough.)
    const schema = z.object(inspectTool.inputSchema);
    const parsed = schema.parse({ kind: "url", value: "https://example.com" });
    expect(parsed.timeoutMs).toBe(10_000);
  });
});

liveDescribe("inspect: tls", () => {
  it("fetches and parses the cert chain from a live HTTPS endpoint", async () => {
    // cloudflare.com is extremely stable and serves a long-lived chain.
    const out = await structured({
      kind: "tls",
      value: "https://cloudflare.com",
      timeoutMs: 10_000,
    });
    expect(out.host).toBe("cloudflare.com");
    expect(out.port).toBe(443);
    expect(out.authorized).toBe(true);
    expect(typeof out.protocol).toBe("string");
    expect((out.protocol as string).startsWith("TLSv1")).toBe(true);
    expect(out.certificateCount).toBeGreaterThanOrEqual(1);
    const certs = out.certificates as Array<Record<string, unknown>>;
    const leaf = certs[0];
    expect(leaf).toBeTruthy();
    if (!leaf) return;
    expect(leaf.expired).toBe(false);
    // SPKI fingerprint is the same shape as the other fingerprints.
    expect(String(leaf.spkiFingerprintSha256)).toMatch(
      /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/,
    );
    // SANs include cloudflare.com (or a wildcard that covers it).
    const sans = leaf.subjectAltNames as string[];
    expect(
      sans.some(
        (s) =>
          s === "DNS:cloudflare.com" ||
          s === "DNS:*.cloudflare.com" ||
          s.endsWith("cloudflare.com"),
      ),
    ).toBe(true);
  }, 30_000);

  it("accepts host:port form without a scheme", async () => {
    const out = await structured({
      kind: "tls",
      value: "cloudflare.com:443",
      timeoutMs: 10_000,
    });
    expect(out.host).toBe("cloudflare.com");
    expect(out.port).toBe(443);
  }, 30_000);

  // A range of non-https schemes — all rejected OFFLINE (before any socket)
  // with a scheme error. No network involved.
  it.each(["ftp://example.com", "http://example.com", "ws://example.com"])(
    "rejects non-https scheme %s with a clear error (offline)",
    async (value) => {
      const res = await run({ kind: "tls", value });
      expect(res.isError).toBe(true);
      expect(JSON.stringify(res.content)).toContain("scheme");
    },
  );

  // Malformed host:port forms rejected OFFLINE on the port-range check —
  // no socket is opened. These do not introduce a network dependency.
  it.each(["example.com:99999", "example.com:0", "ftp://example.com:21"])(
    "rejects malformed/invalid target %s offline",
    async (value) => {
      const res = await run({ kind: "tls", value });
      expect(res.isError).toBe(true);
    },
  );

  it("times out cleanly when the host is unreachable", async () => {
    // TEST-NET-1 (192.0.2.x, RFC 5737) is reserved and unrouteable.
    const res = await run({
      kind: "tls",
      value: "192.0.2.1:443",
      timeoutMs: 300,
    });
    expect(res.isError).toBe(true);
    const text = String((res.content?.[0] as { text?: string })?.text ?? "");
    expect(text.toLowerCase()).toMatch(/timed out|timeout|connect/);
  });
});

liveDescribe("inspect: whois", () => {
  it("looks up a stable domain (example.com)", async () => {
    const out = await structured({
      kind: "whois",
      value: "example.com",
      timeoutMs: 15_000,
    });
    expect(out.kind).toBe("domain");
    expect(out.target).toBe("example.com");
    // example.com is IANA-managed and has a long-lived registration.
    expect(
      typeof out.registrar === "string" || out.registrar === undefined,
    ).toBe(true);
    if (out.expires) {
      expect(typeof out.daysRemaining).toBe("number");
      expect(out.daysRemaining as number).toBeGreaterThan(0);
    }
    expect(
      Array.isArray(out.nameservers) || out.nameservers === undefined,
    ).toBe(true);
  }, 30_000);

  it("looks up an IPv4 address (8.8.8.8)", async () => {
    const out = await structured({
      kind: "whois",
      value: "8.8.8.8",
      timeoutMs: 15_000,
    });
    expect(out.kind).toBe("ip");
    expect(out.target).toBe("8.8.8.8");
    // ARIN consistently reports Google here; tolerate either an org match or
    // the ASN being surfaced.
    const blob = JSON.stringify(out).toLowerCase();
    expect(blob).toMatch(/google|as15169|15169/);
  }, 30_000);

  it("looks up an ASN (AS15169)", async () => {
    const out = await structured({
      kind: "whois",
      value: "AS15169",
      timeoutMs: 15_000,
    });
    expect(out.kind).toBe("asn");
    expect(String(out.target)).toMatch(/^AS15169$/i);
    const blob = JSON.stringify(out).toLowerCase();
    expect(blob).toMatch(/google/);
  }, 30_000);

  // Octal/leading-zero IPv4 bypass attempts are rejected OFFLINE during
  // classification (before any socket) with a leading-zero hint.
  it.each(["010.0.0.1", "192.168.001.1", "0177.0.0.1"])(
    "rejects octal-bypass IPv4 %s before any network call",
    async (value) => {
      const res = await run({ kind: "whois", value });
      expect(res.isError).toBe(true);
      expect(JSON.stringify(res.content)).toMatch(/leading-zero/);
    },
  );

  // A range of targets that classify as none of domain/IP/ASN → OFFLINE
  // rejection (the classifier throws before contacting any whois server).
  it.each([
    "definitely not anything",
    "no spaces but no dots either",
    "!!!",
    "",
  ])("rejects un-classifiable whois target %j (offline)", async (value) => {
    expect((await run({ kind: "whois", value })).isError).toBe(true);
  });

  // whoisTarget override forces a classification that the value can't
  // satisfy → OFFLINE failure with a kind-specific message.
  it.each<[string, "domain" | "asn", RegExp]>([
    ["15169", "domain", /invalid domain/], // looks ASN; forced domain
    ["not-a-number", "asn", /invalid ASN/], // forced ASN, not numeric
  ])(
    "whoisTarget=%s override on %s fails offline",
    async (value, whoisTarget, re) => {
      const res = await run({ kind: "whois", value, whoisTarget });
      expect(res.isError).toBe(true);
      expect(JSON.stringify(res.content)).toMatch(re);
    },
  );
});
