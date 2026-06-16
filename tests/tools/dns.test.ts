import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";
import type { RecordType } from "../../src/lib/dns.js";
import { dnsTool } from "../../src/tools/dns.js";

// Blocks that hit real public DNS are opt-in via SWISSKNIFE_LIVE_TESTS so the
// default unit run (and CI) stays hermetic — per TESTING-STRATEGY §7, no live
// external network in the standard suite. They target extremely stable records:
// cloudflare.com (full record set), one.one.one.one (1.1.1.1), and the RFC 6761
// reserved .invalid TLD for guaranteed NXDOMAIN. The input/validation blocks
// below need no network and always run.
const liveDescribe = process.env.SWISSKNIFE_LIVE_TESTS
  ? describe
  : describe.skip;

type Args = Parameters<typeof dnsTool.handler>[0];

async function run(args: Partial<Args>): Promise<CallToolResult> {
  return (await dnsTool.handler({
    timeoutMs: 5000,
    ...args,
  } as Args)) as CallToolResult;
}

function structured(res: CallToolResult): Record<string, unknown> {
  expect(res.isError, JSON.stringify(res.content)).toBeFalsy();
  return res.structuredContent as Record<string, unknown>;
}

liveDescribe("dns: forward lookups", () => {
  it("resolves an A record", async () => {
    const res = structured(await run({ host: "one.one.one.one", type: "A" }));
    const addrs = res.addresses as string[];
    expect(addrs).toContain("1.1.1.1");
    expect(res.type).toBe("A");
  });

  it("resolves an AAAA record", async () => {
    const res = structured(
      await run({ host: "one.one.one.one", type: "AAAA" }),
    );
    const addrs = res.addresses as string[];
    expect(addrs.some((a) => a.startsWith("2606:4700:"))).toBe(true);
  });

  it("returns MX records sorted by priority", async () => {
    const res = structured(await run({ host: "cloudflare.com", type: "MX" }));
    const records = res.records as Array<{
      exchange: string;
      priority: number;
    }>;
    expect(records.length).toBeGreaterThan(0);
    const priorities = records.map((r) => r.priority);
    expect(priorities).toEqual([...priorities].sort((a, b) => a - b));
  });

  it("exposes TXT chunks and joined text", async () => {
    // example.com (RFC 2606) has a small, stable TXT set — fast.
    const res = structured(
      await run({ host: "example.com", type: "TXT", timeoutMs: 8000 }),
    );
    const records = res.records as Array<{ chunks: string[]; text: string }>;
    expect(records.length).toBeGreaterThan(0);
    for (const r of records) {
      expect(Array.isArray(r.chunks)).toBe(true);
      expect(r.text).toBe(r.chunks.join(""));
    }
  }, 15_000);

  it("returns SOA structure for a zone apex", async () => {
    const res = structured(await run({ host: "cloudflare.com", type: "SOA" }));
    expect(res.nsname).toBeTruthy();
    expect(res.hostmaster).toBeTruthy();
    expect(typeof res.serial).toBe("number");
    expect(typeof res.minttl).toBe("number");
    // Node's `resolveSoa` adds a stray `type: undefined` own property to its
    // result, which can spread over our deliberate `type: "SOA"`. Pin the
    // field so it can't drift back to undefined.
    expect(res.type).toBe("SOA");
    // And the SOA itself must be populated (a silent zero-filled "empty"
    // response would be the worst-case failure mode).
    expect(res.nsname).not.toBe("");
    expect(res.serial).not.toBe(0);
    expect(res).not.toHaveProperty("empty");
  });

  it("NXDOMAIN surfaces as a structured error, not an exception", async () => {
    // .invalid is reserved by RFC 6761 — any conformant resolver returns
    // NXDOMAIN / ENOTFOUND.
    const res = await run({
      host: "definitely-not-a-real-host.invalid",
      type: "A",
    });
    expect(res.isError).toBe(true);
    const text = String((res.content?.[0] as { text?: string })?.text ?? "");
    expect(text).toMatch(/ENOTFOUND|NXDOMAIN/);
  });

  it("respects timeoutMs when the resolver hangs", async () => {
    // TEST-NET-1 (192.0.2.0/24, RFC 5737) is unrouteable, so queries
    // never make it back; our wrapper's timeout is what must fire.
    const res = await run({
      host: "cloudflare.com",
      type: "A",
      resolver: "192.0.2.1",
      timeoutMs: 200,
    });
    expect(res.isError).toBe(true);
    const text = String((res.content?.[0] as { text?: string })?.text ?? "");
    expect(text.toLowerCase()).toMatch(
      /timed out|timeout|etimeout|esrvfail|econnrefused|equery/,
    );
  });
});

liveDescribe("dns: multi-type and default", () => {
  it("defaults to all common types when type is omitted", async () => {
    const res = structured(
      await run({ host: "cloudflare.com", timeoutMs: 6000 }),
    );
    // The default fan-out surfaces the resolved list, NOT a placeholder.
    expect(res.type).toEqual(["A", "AAAA", "MX", "TXT", "CNAME", "NS", "SOA"]);
    const records = res.records as Record<string, unknown>;
    expect(records.A).toBeTruthy();
    expect(records.SOA).toBeTruthy();
  }, 15_000);

  it("accepts an array of types and fans out across just those", async () => {
    const res = structured(
      await run({
        host: "cloudflare.com",
        type: ["A", "MX"] as RecordType[],
        timeoutMs: 6000,
      }),
    );
    const records = res.records as Record<string, unknown>;
    expect(records.A).toBeTruthy();
    expect(records.MX).toBeTruthy();
    expect(records.NS).toBeUndefined();
    // Surfaced as the resolved array so callers know what was actually queried.
    expect(res.type).toEqual(["A", "MX"]);
  }, 15_000);

  it("a single-string type keeps the flat shape (no behavioural change)", async () => {
    const res = structured(await run({ host: "one.one.one.one", type: "A" }));
    const addrs = res.addresses as string[];
    expect(addrs).toContain("1.1.1.1");
    // No `records` envelope in the single-type response.
    expect(res.records).toBeUndefined();
  });
});

liveDescribe("dns: ENODATA is a successful empty result, not an error", () => {
  it("returns empty records + empty:true when a host has no records of the asked type", async () => {
    // example.com (RFC 2606) is stable and has no SRV records — classic
    // ENODATA case. (We avoid MX here because IANA periodically populates
    // example.com's MX.)
    const res = await run({
      host: "example.com",
      type: "SRV",
      timeoutMs: 6000,
    });
    expect(res.isError).toBeFalsy();
    const s = res.structuredContent as Record<string, unknown>;
    expect(s.empty).toBe(true);
    expect(s.records).toEqual([]);
    expect(s.type).toBe("SRV");
  });

  it("a fan-out query with one ENODATA type sets empty:true on that type's record block", async () => {
    // example.com has no SRV, but has A/SOA — fan-out should surface the
    // empty SRV as a record with empty:true rather than in perTypeErrors.
    const res = structured(
      await run({
        host: "example.com",
        type: ["A", "SRV"] as RecordType[],
        timeoutMs: 6000,
      }),
    );
    const records = res.records as Record<string, Record<string, unknown>>;
    expect(records.A).toBeTruthy();
    expect((records.SRV as Record<string, unknown>).empty).toBe(true);
    expect(res.perTypeErrors).toBeUndefined();
  });
});

liveDescribe(
  "dns: CNAME at apex (no chain) returns empty rather than self-target",
  () => {
    it("collapses the all-self answer Node returns for a no-CNAME apex", async () => {
      // example.com has no CNAME at apex (RFC 1034 forbids it). Node's
      // resolveCname can return ['example.com'] back; we collapse that to
      // an empty result so callers don't mistake it for a real CNAME.
      const res = await run({
        host: "example.com",
        type: "CNAME",
        timeoutMs: 6000,
      });
      expect(res.isError).toBeFalsy();
      const s = res.structuredContent as Record<string, unknown>;
      // Either Node returned ENODATA (handled by the empty-result path) or
      // it returned the self-target (collapsed by the lib). Both paths must
      // end at empty:true.
      expect(s.empty).toBe(true);
      expect(s.targets).toEqual([]);
    });
  },
);

liveDescribe("dns: reverse lookups", () => {
  it("PTR for 1.1.1.1 returns one.one.one.one", async () => {
    const res = structured(await run({ ip: "1.1.1.1" }));
    const s = res as { hostnames: string[]; type: string };
    expect(s.type).toBe("PTR");
    expect(s.hostnames).toContain("one.one.one.one");
  });
});

describe("dns: input validation (fails before any network call)", () => {
  // "both host and ip" is mutually-exclusive and is rejected up front, before
  // any resolver is contacted — so a range of host/ip/type combos is safe to
  // assert offline.
  const both: Array<Partial<Args>> = [
    { host: "cloudflare.com", ip: "1.1.1.1" },
    { host: "example.com", ip: "8.8.8.8", type: "A" },
    { host: "one.one.one.one", ip: "2606:4700:4700::1111" },
    { host: "a.test", ip: "1.1.1.1", type: ["A", "MX"] as RecordType[] },
  ];
  it.each(both)("rejects both host and ip (%o)", async (args) => {
    const res = await run(args);
    expect(res.isError).toBe(true);
    const text = String((res.content?.[0] as { text?: string })?.text ?? "");
    expect(text).toMatch(/not both/);
  });

  // "neither host nor ip" is likewise rejected before any lookup.
  const neither: Array<Partial<Args>> = [
    {},
    { type: "A" },
    { type: ["A", "MX"] as RecordType[] },
    { resolver: "1.1.1.1", timeoutMs: 5000 },
  ];
  it.each(neither)("rejects neither host nor ip (%o)", async (args) => {
    const res = await run(args);
    expect(res.isError).toBe(true);
    const text = String((res.content?.[0] as { text?: string })?.text ?? "");
    expect(text).toMatch(/forward lookup.*reverse lookup|reverse lookup/);
  });
});

liveDescribe(
  "dns: array `type` keeps a consistent records-envelope shape",
  () => {
    it("a single-element array uses the records envelope (no flat shape)", async () => {
      const res = structured(
        await run({
          host: "one.one.one.one",
          type: ["A"] as RecordType[],
          timeoutMs: 6000,
        }),
      );
      // records.A must always be present when type is an array — callers
      // writing generic code shouldn't have to branch on array length.
      expect((res.records as Record<string, unknown>).A).toBeTruthy();
      expect(res.addresses).toBeUndefined();
    });

    it("every requested type appears in records, even on per-type failure", async () => {
      // example.com is IPv4-only most of the time — `AAAA` returns no
      // records. A per-type failure must still leave a key in `records`
      // rather than dropping the type silently.
      const res = structured(
        await run({
          host: "example.com",
          type: ["A", "AAAA"] as RecordType[],
          timeoutMs: 6000,
        }),
      );
      const records = res.records as Record<string, Record<string, unknown>>;
      expect(records.A).toBeTruthy();
      expect(records.AAAA).toBeTruthy();
      // The AAAA branch may be empty (no records) or full (host has AAAA).
      // Both shapes are valid — we just require the key exists.
    });
  },
);
