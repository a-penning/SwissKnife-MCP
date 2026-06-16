import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";
import { netTool } from "../../src/tools/net.js";

type Args = Parameters<typeof netTool.handler>[0];

function run(args: Partial<Args>): CallToolResult {
  return netTool.handler({
    action: "parse",
    ...args,
  } as Args) as CallToolResult;
}

function structured(res: CallToolResult): Record<string, unknown> {
  expect(res.isError, JSON.stringify(res.content)).toBeFalsy();
  return res.structuredContent as Record<string, unknown>;
}

// Independent helper: compute the unsigned big-endian integer value of a
// dotted-quad IPv4 string, reasoning straight from the octet weights rather
// than echoing tool output. (`<<` in JS is signed, so we use 2 ** n.)
function ipv4ToInt(addr: string): string {
  const [a, b, c, d] = addr.split(".").map(Number) as [
    number,
    number,
    number,
    number,
  ];
  return String(a * 2 ** 24 + b * 2 ** 16 + c * 2 ** 8 + d);
}

describe("net: parse", () => {
  // Positive IPv4 range. Expected forms derived by hand: v4 normalized ==
  // expanded == dotted input; bytes are the octets; ipv4Mapped is
  // ::ffff:<hex(hi16)>:<hex(lo16)> in ipaddr.js compressed form.
  it.each([
    ["192.168.1.5", [192, 168, 1, 5], "::ffff:c0a8:105"],
    ["0.0.0.0", [0, 0, 0, 0], "::ffff:0:0"],
    ["255.255.255.255", [255, 255, 255, 255], "::ffff:ffff:ffff"],
    ["1.2.3.4", [1, 2, 3, 4], "::ffff:102:304"],
    ["8.8.8.8", [8, 8, 8, 8], "::ffff:808:808"],
  ])("parses IPv4 %s", (ip, bytes, mapped) => {
    const s = structured(run({ action: "parse", value: ip }));
    expect(s.family).toBe(4);
    expect(s.normalized).toBe(ip);
    expect(s.expanded).toBe(ip);
    expect(s.bytes).toEqual(bytes);
    expect(s.integer).toBe(ipv4ToInt(ip));
    expect(s.ipv4Mapped).toBe(mapped);
  });

  // Positive IPv6 range. Expected normalized (compressed, lowercase) and
  // expanded (8 groups of unpadded hex per ipaddr.js toNormalizedString)
  // forms reasoned from RFC 5952 rules.
  it.each([
    ["2001:db8::1", "2001:db8::1", "2001:db8:0:0:0:0:0:1"],
    ["::1", "::1", "0:0:0:0:0:0:0:1"],
    ["::", "::", "0:0:0:0:0:0:0:0"],
    ["fe80::1", "fe80::1", "fe80:0:0:0:0:0:0:1"],
    [
      "2001:0db8:0000:0000:0000:0000:0000:0001",
      "2001:db8::1",
      "2001:db8:0:0:0:0:0:1",
    ],
  ])("parses IPv6 %s", (ip, normalized, expanded) => {
    const s = structured(run({ action: "parse", value: ip }));
    expect(s.family).toBe(6);
    expect(s.normalized).toBe(normalized);
    expect(s.expanded).toBe(expanded);
    // Big-endian byte array, always 16 bytes for v6.
    expect((s.bytes as number[]).length).toBe(16);
  });

  // IPv4-mapped IPv6 (::ffff:0:0/96) surfaces the embedded v4.
  it.each([
    ["::ffff:1.2.3.4", "1.2.3.4"],
    ["::ffff:192.168.0.1", "192.168.0.1"],
    ["::ffff:c0a8:105", "192.168.1.5"],
    ["::ffff:0.0.0.0", "0.0.0.0"],
  ])("parses IPv4-mapped %s → embedded %s", (ip, embedded) => {
    const s = structured(run({ action: "parse", value: ip }));
    expect(s.family).toBe(6);
    expect(s.embeddedIpv4).toBe(embedded);
  });

  // A range of distinct malformed inputs, each a different failure mode.
  it.each([
    ["not-an-ip"], // pure garbage
    ["010.0.0.1"], // leading-zero octet (octal-ambiguous) — must be rejected
    ["192.168.1.256"], // octet out of range
    ["192.168.1.1.1"], // too many octets
    ["1.2.3.04"], // leading zero on the last octet
    ["::ffff::1"], // double "::" in v6
    ["2001:db8:::1"], // triple colon
    ["gggg::1"], // non-hex group
    ["192.168.1.-1"], // negative octet
    [""], // empty
  ])("rejects malformed parse input %s", (ip) => {
    expect(run({ action: "parse", value: ip }).isError).toBe(true);
  });

  // The IPv4 guard rejects EVERY inet_aton-style ambiguous form — same
  // bucket as octal-leading-zero. Each of these has multiple "canonical"
  // interpretations across language stdlibs (so a guard whitelisting
  // 10.x can be tricked by a non-canonical encoding); we require strict
  // 4-decimal-octet shape and nothing else.
  it.each([
    "192.168.1", // 3-part → 192.168.0.1 in inet_aton
    "1.2.3", // 3-part → 1.2.0.3
    "1.2", // 2-part → 1.0.0.2
    "10", // single integer → 0.0.0.10
    "0x7f.0.0.1", // hex octet → 127.0.0.1
    "0xff.0xff.0xff.0xff", // all-hex octets
  ])("rejects ambiguous inet_aton-style IPv4 %s", (ip) => {
    expect(run({ action: "parse", value: ip }).isError).toBe(true);
  });
});

describe("net: classify", () => {
  // Positive + boundary cases across the documented IPv4 and IPv6 categories.
  // RFC mapping is derived from the V4_RANGE_INFO/V6_RANGE_INFO tables, which
  // in turn track the authoritative special-purpose registries.
  it.each([
    // --- IPv4 ---
    ["192.168.1.1", 4, "private", "RFC 1918"],
    ["192.168.0.0", 4, "private", "RFC 1918"], // 192.168/16 lower bound
    ["10.0.0.1", 4, "private", "RFC 1918"],
    ["10.255.255.255", 4, "private", "RFC 1918"], // 10/8 upper bound
    ["172.16.0.1", 4, "private", "RFC 1918"],
    ["172.31.255.255", 4, "private", "RFC 1918"], // 172.16/12 upper bound
    ["172.32.0.1", 4, "public", undefined], // just outside 172.16/12
    ["100.64.0.1", 4, "cgnat", "RFC 6598"],
    ["100.127.255.255", 4, "cgnat", "RFC 6598"], // 100.64/10 upper bound
    ["127.0.0.1", 4, "loopback", "RFC 5735"],
    ["127.255.255.255", 4, "loopback", "RFC 5735"],
    ["169.254.169.254", 4, "link-local", "RFC 3927"],
    ["169.254.0.0", 4, "link-local", "RFC 3927"],
    ["224.0.0.1", 4, "multicast", "RFC 5771"],
    ["239.255.255.255", 4, "multicast", "RFC 5771"], // top of 224/4
    ["255.255.255.255", 4, "broadcast", "RFC 919"],
    ["0.0.0.0", 4, "unspecified", "RFC 5735"],
    ["8.8.8.8", 4, "public", undefined],
    ["1.1.1.1", 4, "public", undefined],
    // --- IPv6 ---
    ["::1", 6, "loopback", "RFC 4291"],
    ["::", 6, "unspecified", "RFC 4291"],
    ["fe80::1", 6, "link-local", "RFC 4291"],
    ["fc00::1", 6, "unique-local", "RFC 4193"],
    ["fd00::1", 6, "unique-local", "RFC 4193"], // fc00::/7 includes fd00::/8
    ["ff02::1", 6, "multicast", "RFC 4291"],
    ["::ffff:1.2.3.4", 6, "ipv4-mapped", "RFC 4291"],
    ["2001:db8::1", 6, "reserved", undefined], // documentation block
    ["2606:4700:4700::1111", 6, "public", undefined], // global unicast
  ])("classifies %s as %s (%s)", (ip, family, category, rfc) => {
    const s = structured(run({ action: "classify", value: ip }));
    expect(s.family).toBe(family);
    expect(s.category).toBe(category);
    if (rfc !== undefined) expect(s.rfc).toBe(rfc);
  });

  // Negative range: classify shares parseAddress's strict validation, so the
  // same malformed-input families must error.
  it.each([
    ["nonsense"],
    ["010.0.0.1"], // octal-ambiguous leading zero
    ["256.1.1.1"], // octet out of range
    ["1.2.3.4.5"], // too many octets
    ["fffff::1"], // 5-hex group in v6
    [""],
  ])("rejects malformed classify input %s", (ip) => {
    expect(run({ action: "classify", value: ip }).isError).toBe(true);
  });

  // classify shares the same parse guard, so the same inet_aton-style
  // ambiguous forms must be rejected here too (see the parse block for
  // rationale).
  it.each([
    "1.2.3",
    "192.168.1",
    "1.2",
    "0x7f.0.0.1",
  ])("rejects ambiguous inet_aton-style IPv4 %s", (ip) => {
    expect(run({ action: "classify", value: ip }).isError).toBe(true);
  });
});

describe("net: cidr", () => {
  // IPv4 /<=30: broadcast present, usableHosts = 2^hostBits - 2, first/last
  // usable exclude network + broadcast. All expectations computed by hand
  // from the prefix length, not echoed from the tool.
  it.each([
    {
      cidr: "192.168.1.0/24",
      network: "192.168.1.0",
      broadcast: "192.168.1.255",
      firstUsable: "192.168.1.1",
      lastUsable: "192.168.1.254",
      mask: "255.255.255.0",
      hostCount: "256",
      usableHosts: "254",
    },
    {
      cidr: "10.0.0.0/8",
      network: "10.0.0.0",
      broadcast: "10.255.255.255",
      firstUsable: "10.0.0.1",
      lastUsable: "10.255.255.254",
      mask: "255.0.0.0",
      hostCount: String(2 ** 24),
      usableHosts: String(2 ** 24 - 2),
    },
    {
      cidr: "172.16.0.0/16",
      network: "172.16.0.0",
      broadcast: "172.16.255.255",
      firstUsable: "172.16.0.1",
      lastUsable: "172.16.255.254",
      mask: "255.255.0.0",
      hostCount: String(2 ** 16),
      usableHosts: String(2 ** 16 - 2),
    },
    {
      cidr: "192.168.1.0/30",
      network: "192.168.1.0",
      broadcast: "192.168.1.3",
      firstUsable: "192.168.1.1",
      lastUsable: "192.168.1.2",
      mask: "255.255.255.252",
      hostCount: "4",
      usableHosts: "2",
    },
    {
      cidr: "203.0.113.0/26",
      network: "203.0.113.0",
      broadcast: "203.0.113.63",
      firstUsable: "203.0.113.1",
      lastUsable: "203.0.113.62",
      mask: "255.255.255.192",
      hostCount: "64",
      usableHosts: "62",
    },
    {
      cidr: "0.0.0.0/0",
      network: "0.0.0.0",
      broadcast: "255.255.255.255",
      firstUsable: "0.0.0.1",
      lastUsable: "255.255.255.254",
      mask: "0.0.0.0",
      hostCount: String(2 ** 32),
      usableHosts: String(2 ** 32 - 2),
    },
  ])("describes IPv4 $cidr with broadcast + usable range", ({
    cidr,
    network,
    broadcast,
    firstUsable,
    lastUsable,
    mask,
    hostCount,
    usableHosts,
  }) => {
    const s = structured(run({ action: "cidr", value: cidr }));
    expect(s.family).toBe(4);
    expect(s.network).toBe(network);
    expect(s.broadcast).toBe(broadcast);
    // firstAddress / lastAddress are the inclusive range bounds.
    expect(s.firstAddress).toBe(network);
    expect(s.lastAddress).toBe(broadcast);
    // firstUsableHost / lastUsableHost exclude network + broadcast for
    // IPv4 /<=30 — what ipcalc and DHCP planners use.
    expect(s.firstUsableHost).toBe(firstUsable);
    expect(s.lastUsableHost).toBe(lastUsable);
    expect(s.usableHosts).toBe(usableHosts);
    expect(s.mask).toBe(mask);
    expect(s.hostCount).toBe(hostCount);
    expect(s.isHostBitsSet).toBe(false);
  });

  // Host-bits-set inputs normalise to the network address and flag the input,
  // never silently fixing up.
  it.each([
    ["192.168.1.42/24", "192.168.1.0"],
    ["10.1.2.3/8", "10.0.0.0"],
    ["203.0.113.200/26", "203.0.113.192"],
    ["2001:db8:1::abcd/32", "2001:db8::"],
  ])("normalises host bits in %s → %s", (cidr, network) => {
    const s = structured(run({ action: "cidr", value: cidr }));
    expect(s.network).toBe(network);
    expect(s.isHostBitsSet).toBe(true);
  });

  // /31 (RFC 3021) and /32 have no broadcast; every address is usable.
  it.each([
    ["10.0.0.0/31", "2"],
    ["10.0.0.1/32", "1"],
    ["192.168.0.0/31", "2"],
  ])("omits broadcast for small prefix %s (hostCount %s)", (cidr, hostCount) => {
    const s = structured(run({ action: "cidr", value: cidr }));
    expect(s.broadcast).toBeUndefined();
    expect(s.hostCount).toBe(hostCount);
    // /31, /32: usableHosts == hostCount (no exclusions).
    expect(s.usableHosts).toBe(hostCount);
  });

  // IPv6 prefixes: no broadcast, hostCount = 2^hostBits as a decimal string
  // (BigInt because the value overflows Number).
  it.each([
    ["2001:db8::/32", "2001:db8::", 1n << 96n],
    ["::/0", "::", 1n << 128n],
    ["2001:db8::/48", "2001:db8::", 1n << 80n],
    ["fe80::/64", "fe80::", 1n << 64n],
    ["2001:db8::/128", "2001:db8::", 1n],
    ["2001:db8::/127", "2001:db8::", 2n],
  ])("computes IPv6 %s with BigInt host counts", (cidr, network, hostCount) => {
    const s = structured(run({ action: "cidr", value: cidr }));
    expect(s.family).toBe(6);
    expect(s.network).toBe(network);
    expect(s.broadcast).toBeUndefined(); // no broadcast in IPv6
    expect(s.hostCount).toBe(hostCount.toString());
  });

  // Negative range: a spread of distinct malformed CIDR shapes.
  it.each([
    ["192.168.1.0/33"], // prefix > 32 for v4
    ["garbage/24"], // non-IP address part
    ["2001:db8::/129"], // prefix > 128 for v6
    ["192.168.1.0/-1"], // negative prefix
    ["192.168.1.0"], // missing prefix entirely
    ["010.0.0.0/24"], // octal-ambiguous octet in address part
    ["192.168.1.0/abc"], // non-numeric prefix
    ["256.0.0.0/8"], // octet out of range
  ])("rejects invalid CIDR %s", (cidr) => {
    expect(run({ action: "cidr", value: cidr }).isError).toBe(true);
  });
});

describe("net: contains", () => {
  // Membership tests across boundaries and both families. Truth reasoned from
  // the prefix: an IP is in-block iff its high `prefix` bits match the network.
  it.each([
    // in-block (including the network and broadcast addresses themselves)
    ["192.168.1.0/24", "192.168.1.50", true],
    ["192.168.1.0/24", "192.168.1.0", true], // network address
    ["192.168.1.0/24", "192.168.1.255", true], // broadcast address
    ["10.0.0.0/8", "10.255.255.255", true],
    ["0.0.0.0/0", "8.8.8.8", true], // default route covers everything v4
    ["192.168.1.0/32", "192.168.1.0", true], // exact host
    // out-of-block
    ["192.168.1.0/24", "192.168.2.50", false], // adjacent block
    ["192.168.1.0/24", "192.168.0.255", false], // one below the network
    ["192.168.1.0/24", "192.168.2.0", false], // one above broadcast
    ["192.168.1.0/32", "192.168.1.1", false], // off-by-one host
    // mismatched families never match (and never throw)
    ["192.168.1.0/24", "::1", false],
    ["2001:db8::/32", "192.168.1.1", false],
    // IPv6 membership
    ["2001:db8::/32", "2001:db8:1::1", true],
    ["2001:db8::/32", "2001:db9::1", false],
    ["::/0", "2001:db8::1", true], // default route covers everything v6
    ["fe80::/64", "fe80::abcd", true],
    ["fe80::/64", "fe81::1", false],
  ])("contains(%s, %s) === %s", (cidr, ip, expected) => {
    const s = structured(run({ action: "contains", cidr, ip }));
    expect(s.contains).toBe(expected);
  });

  // Negative range: malformed CIDR or IP must error rather than guess.
  it.each([
    ["192.168.1.0/33", "192.168.1.1"], // bad prefix
    ["garbage/24", "192.168.1.1"], // bad cidr address
    ["192.168.1.0/24", "not-an-ip"], // bad ip
    ["192.168.1.0/24", "010.0.0.1"], // octal-ambiguous ip
    ["010.0.0.0/24", "10.0.0.1"], // octal-ambiguous cidr
  ])("rejects malformed contains(%s, %s)", (cidr, ip) => {
    expect(run({ action: "contains", cidr, ip }).isError).toBe(true);
  });
});

describe("net: convert", () => {
  // IPv4 → IPv4-mapped IPv6. Mapped form computed independently:
  // ::ffff:<hi16-hex>:<lo16-hex> in ipaddr.js compression.
  it.each([
    ["192.168.1.5", "::ffff:c0a8:105"],
    ["0.0.0.0", "::ffff:0:0"],
    ["255.255.255.255", "::ffff:ffff:ffff"],
    ["1.2.3.4", "::ffff:102:304"],
  ])("converts IPv4 %s to mapped %s", (ip, mapped) => {
    const s = structured(run({ action: "convert", value: ip }));
    expect(s.family).toBe(4);
    expect(s.ipv4Mapped).toBe(mapped);
    expect(s.conversionAvailable).toBe(true);
  });

  // Mapped IPv6 → embedded IPv4 (the inverse direction).
  it.each([
    ["::ffff:1.2.3.4", "1.2.3.4"],
    ["::ffff:192.168.0.1", "192.168.0.1"],
    ["::ffff:c0a8:105", "192.168.1.5"],
    ["::ffff:0.0.0.0", "0.0.0.0"],
  ])("extracts embedded IPv4 from %s → %s", (ip, embedded) => {
    const s = structured(run({ action: "convert", value: ip }));
    expect(s.family).toBe(6);
    expect(s.embeddedIpv4).toBe(embedded);
    expect(s.conversionAvailable).toBe(true);
  });

  // Pure IPv6 has no cross-family form.
  it.each([
    ["2001:db8::1"],
    ["fe80::1"],
    ["::1"],
    ["fc00::1"],
  ])("returns no cross-family form for pure IPv6 %s", (ip) => {
    const s = structured(run({ action: "convert", value: ip }));
    expect(s.embeddedIpv4).toBeUndefined();
    expect(s.ipv4Mapped).toBeUndefined();
    expect(s.conversionAvailable).toBe(false);
  });

  // Negative range for convert.
  it.each([
    ["bogus"],
    ["010.0.0.1"],
    ["256.0.0.1"],
    [""],
  ])("rejects malformed convert input %s", (ip) => {
    expect(run({ action: "convert", value: ip }).isError).toBe(true);
  });
});

describe("net: validation", () => {
  // Each action errors when its required field(s) are missing — a range of
  // distinct missing-argument shapes.
  it.each([
    [{ action: "parse" as const }],
    [{ action: "classify" as const }],
    [{ action: "cidr" as const }],
    [{ action: "convert" as const }],
    [{ action: "contains" as const }], // both cidr and ip missing
    [{ action: "contains" as const, cidr: "192.168.1.0/24" }], // ip missing
    [{ action: "contains" as const, ip: "1.2.3.4" }], // cidr missing
  ])("rejects missing required fields for %o", (args) => {
    expect(run(args).isError).toBe(true);
  });
});
