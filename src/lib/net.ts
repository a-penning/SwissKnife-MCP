// IP / CIDR utilities. Built on ipaddr.js for parsing + range classification,
// with BigInt-based CIDR math layered on top because the library doesn't
// expose network/broadcast/host-count directly and rolling our own keeps
// behaviour explicit (especially for IPv6 prefixes whose host counts overflow
// Number).
//
// IPv4 vs IPv6 nuances we honour:
//  - IPv4 /31 (RFC 3021) and /32: no broadcast field; first==last==network
//  - IPv4 /<=30: broadcast = network | hostMask
//  - IPv6: no broadcast concept at all; firstHost==network, lastHost has
//    the all-ones host portion (still a valid unicast address modulo SLAAC
//    conventions, but reporting it as the upper bound is the standard view)
//  - hostBitsSet input (e.g. "192.168.1.5/24"): we normalise to the network
//    address and surface `isHostBitsSet: true` so callers know we
//    canonicalised — never silently fixed up.

import ipaddr from "ipaddr.js";

export type Family = 4 | 6;

// ipaddr.js accepts a wide set of inet_aton-style ambiguous IPv4 forms
// that we treat as security risks because none of them have a unique
// canonical interpretation across implementations:
//   - leading-zero octets (010.0.0.1 → 8.0.0.1 octal)
//   - hex octets        (0x7f.0.0.1 → 127.0.0.1)
//   - shorthand parts   (192.168.1 → 192.168.0.1, "10" → 0.0.0.10)
// All of these are classic SSRF-bypass shapes (different language stdlibs
// disagree on parsing them, so a guard that whitelists "10.x.x.x" can be
// tricked by a non-canonical encoding). Strict shape: four DECIMAL octets,
// each 0..255, no leading zeros (except the bare "0").
const STRICT_IPV4 = /^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/;

// Any input ipaddr.js considers a valid IPv4 — including the inet_aton
// shorthand forms — that isn't STRICT_IPV4 is rejected. We also reject
// bare integers ("10") and 1/2/3-part dotted forms ("1.2", "1.2.3") and
// hex-prefixed octets ("0x7f.0.0.1") even when ipaddr.js does not.
function assertStrictIpv4OrNotV4(s: string): void {
  if (STRICT_IPV4.test(s)) return; // canonical 4-decimal-octet form: OK

  // Reject hex-prefixed octets explicitly (some are valid v6 group chars
  // — but those occur in inputs with `:`, not `.`).
  if (/^0x[0-9a-fA-F]+(\.|$)/.test(s)) {
    throw new Error(
      `invalid IPv4 address: ${JSON.stringify(s)} — hex octets are rejected (ambiguous: 0x7f.0.0.1 parses as 127.0.0.1 in some libs but not others)`,
    );
  }

  // Bare integer (no dot) — inet_aton would read this as a single 32-bit
  // value. We require 4-octet dotted form, period.
  if (/^\d+$/.test(s)) {
    throw new Error(
      `invalid IPv4 address: ${JSON.stringify(s)} — bare integer rejected (use 4-octet dotted form like 0.0.0.${s})`,
    );
  }

  // Shorthand dotted forms (1.2, 1.2.3) — anything with a `.` that has
  // fewer than 4 octets but otherwise looks numeric.
  if (/^\d+(\.\d+){1,2}$/.test(s)) {
    throw new Error(
      `invalid IPv4 address: ${JSON.stringify(s)} — IPv4 must be exactly 4 dotted octets (inet_aton-style shorthand forms are rejected)`,
    );
  }

  // The original leading-zero / non-decimal-octet rejection, kept for the
  // 4-part case where the shape regex above doesn't catch them.
  if (/^\d+\.\d+\.\d+\.\d+$/.test(s)) {
    throw new Error(
      `invalid IPv4 address: ${JSON.stringify(s)} — leading-zero or out-of-range octets are rejected (ambiguous: some parsers read 010 as octal 8)`,
    );
  }
  // Otherwise: not v4-shaped → defer to v6 / general parse paths.
}

export interface ParsedAddress {
  input: string;
  family: Family;
  // Canonical string form (lowercase, no leading zeros, ::-compressed for v6)
  normalized: string;
  // Full uncompressed form. For v4: octets dotted. For v6: 8 groups of 4 hex.
  expanded: string;
  // Big-endian byte array as decimal numbers.
  bytes: number[];
  // Decimal value (string because IPv6 doesn't fit in Number).
  integer: string;
  // v4 only — the same address as ::ffff:a.b.c.d.
  ipv4Mapped?: string;
  // v6 only — present iff the address is in ::ffff:0:0/96; the embedded v4.
  embeddedIpv4?: string;
}

export function parseAddress(input: string): ParsedAddress {
  assertStrictIpv4OrNotV4(input);
  if (!ipaddr.isValid(input)) {
    throw new Error(`invalid IP address: ${JSON.stringify(input)}`);
  }
  const addr = ipaddr.parse(input);
  if (addr.kind() === "ipv4") {
    const v4 = addr as ipaddr.IPv4;
    return {
      input,
      family: 4,
      normalized: v4.toString(),
      expanded: v4.octets.join("."),
      bytes: [...v4.octets],
      integer: bytesToBigInt([...v4.octets]).toString(),
      ipv4Mapped: v4.toIPv4MappedAddress().toString(),
    };
  }
  const v6 = addr as ipaddr.IPv6;
  const out: ParsedAddress = {
    input,
    family: 6,
    normalized: v6.toString(),
    expanded: v6.toNormalizedString(),
    bytes: v6.toByteArray(),
    integer: bytesToBigInt(v6.toByteArray()).toString(),
  };
  if (v6.isIPv4MappedAddress()) {
    out.embeddedIpv4 = v6.toIPv4Address().toString();
  }
  return out;
}

// Map ipaddr.js range strings to a stable {category, rfc} pair so callers
// don't have to memorise the underlying library's naming.
const V4_RANGE_INFO: Record<string, { category: string; rfc?: string }> = {
  unicast: { category: "public" },
  unspecified: { category: "unspecified", rfc: "RFC 5735" },
  broadcast: { category: "broadcast", rfc: "RFC 919" },
  multicast: { category: "multicast", rfc: "RFC 5771" },
  linkLocal: { category: "link-local", rfc: "RFC 3927" },
  loopback: { category: "loopback", rfc: "RFC 5735" },
  carrierGradeNat: { category: "cgnat", rfc: "RFC 6598" },
  private: { category: "private", rfc: "RFC 1918" },
  reserved: { category: "reserved" },
};

const V6_RANGE_INFO: Record<string, { category: string; rfc?: string }> = {
  unicast: { category: "public" },
  unspecified: { category: "unspecified", rfc: "RFC 4291" },
  linkLocal: { category: "link-local", rfc: "RFC 4291" },
  multicast: { category: "multicast", rfc: "RFC 4291" },
  loopback: { category: "loopback", rfc: "RFC 4291" },
  uniqueLocal: { category: "unique-local", rfc: "RFC 4193" },
  ipv4Mapped: { category: "ipv4-mapped", rfc: "RFC 4291" },
  rfc6145: { category: "ipv4-ipv6-translation", rfc: "RFC 6145" },
  rfc6052: { category: "ipv4-embedded", rfc: "RFC 6052" },
  "6to4": { category: "6to4", rfc: "RFC 3056" },
  teredo: { category: "teredo", rfc: "RFC 4380" },
  benchmarking: { category: "benchmarking", rfc: "RFC 5180" },
  amt: { category: "amt", rfc: "RFC 7450" },
  as112v6: { category: "as112", rfc: "RFC 7535" },
  deprecated: { category: "deprecated" },
  orchidv2: { category: "orchid", rfc: "RFC 7343" },
  droneRemoteIdProtocolEntityTags: { category: "drone-rid", rfc: "RFC 9374" },
  reserved: { category: "reserved" },
};

export interface ClassifyResult {
  family: Family;
  category: string;
  rfc?: string;
  rangeKey: string; // raw ipaddr.js range name, for debugging
}

export function classifyAddress(input: string): ClassifyResult {
  assertStrictIpv4OrNotV4(input);
  if (!ipaddr.isValid(input)) {
    throw new Error(`invalid IP address: ${JSON.stringify(input)}`);
  }
  const addr = ipaddr.parse(input);
  const range = addr.range();
  if (addr.kind() === "ipv4") {
    const info = V4_RANGE_INFO[range] ?? { category: range };
    return { family: 4, rangeKey: range, ...info };
  }
  const info = V6_RANGE_INFO[range] ?? { category: range };
  return { family: 6, rangeKey: range, ...info };
}

export interface CidrResult {
  input: string;
  family: Family;
  prefixLength: number;
  network: string;
  // v4 only — broadcast = network | hostMask. Omitted for v6 and for v4
  // /31 / /32 (no broadcast in those small prefixes).
  broadcast?: string;
  // The first and last addresses INCLUDING network and broadcast. These
  // are what RFC 4632 calls the range; they are NOT the first/last
  // usable hosts.
  firstAddress: string;
  lastAddress: string;
  // The first and last *usable* host addresses (exclusive of network and
  // broadcast for IPv4 /<=30). Use these when building DHCP ranges,
  // firewall rules, or anything that needs assignable hosts.
  firstUsableHost?: string;
  lastUsableHost?: string;
  // Number of usable hosts. Undefined for IPv6 (no broadcast concept and
  // /128 has 1 host; /127 has 2; etc) — computed but reported as a
  // decimal string because IPv6 ranges overflow Number.
  usableHosts?: string;
  mask: string; // dotted (v4) or compressed (v6) form of the prefix mask
  // Decimal string — IPv6 host counts overflow Number for any prefix
  // shorter than /104 or so.
  hostCount: string;
  // True iff the input had host bits set (e.g. 192.168.1.5/24); we
  // normalise to the network address but flag the input form.
  isHostBitsSet: boolean;
}

export function describeCidr(input: string): CidrResult {
  const [addrPart] = input.split("/");
  if (addrPart) assertStrictIpv4OrNotV4(addrPart);
  if (!ipaddr.isValidCIDR(input)) {
    throw new Error(`invalid CIDR: ${JSON.stringify(input)}`);
  }
  const [addr, prefix] = ipaddr.parseCIDR(input);
  const family = (addr.kind() === "ipv4" ? 4 : 6) as Family;
  const totalBits = family === 4 ? 32 : 128;
  const hostBits = totalBits - prefix;

  const inputBigInt = bytesToBigInt(addr.toByteArray());
  const hostMask = (1n << BigInt(hostBits)) - 1n;
  const networkInt = inputBigInt & ~hostMask;
  const lastInt = networkInt | hostMask;
  const isHostBitsSet = inputBigInt !== networkInt;

  const network = bigIntToAddress(networkInt, family);
  const last = bigIntToAddress(lastInt, family);
  const mask = bigIntToAddress(
    ((1n << BigInt(prefix)) - 1n) << BigInt(hostBits),
    family,
  );

  const totalAddresses = 1n << BigInt(hostBits);
  // Usable hosts: for IPv4 /<=30, exclude network and broadcast. /31
  // (RFC 3021 point-to-point links) and /32 have no broadcast — both
  // addresses are usable. For IPv6, the same exclusion isn't standard
  // — but for /127 and /128 the math collapses similarly; we just
  // surface total counts on v6.
  let usableHosts: string | undefined;
  let firstUsableHost: string | undefined;
  let lastUsableHost: string | undefined;
  if (family === 4 && prefix <= 30) {
    usableHosts = (totalAddresses - 2n).toString();
    firstUsableHost = bigIntToAddress(networkInt + 1n, family);
    lastUsableHost = bigIntToAddress(lastInt - 1n, family);
  } else {
    // /31, /32, IPv6: every address in range is usable.
    usableHosts = totalAddresses.toString();
    firstUsableHost = network;
    lastUsableHost = last;
  }

  const out: CidrResult = {
    input,
    family,
    prefixLength: prefix,
    network,
    firstAddress: network,
    lastAddress: last,
    firstUsableHost,
    lastUsableHost,
    usableHosts,
    mask,
    hostCount: totalAddresses.toString(),
    isHostBitsSet,
  };
  if (family === 4 && prefix <= 30) {
    out.broadcast = last;
  }
  return out;
}

export function cidrContains(cidr: string, ip: string): boolean {
  assertStrictIpv4OrNotV4(ip);
  const [cidrAddrPart] = cidr.split("/");
  if (cidrAddrPart) assertStrictIpv4OrNotV4(cidrAddrPart);
  if (!ipaddr.isValidCIDR(cidr)) {
    throw new Error(`invalid CIDR: ${JSON.stringify(cidr)}`);
  }
  if (!ipaddr.isValid(ip)) {
    throw new Error(`invalid IP address: ${JSON.stringify(ip)}`);
  }
  const target = ipaddr.parse(ip);
  const parsedCidr = ipaddr.parseCIDR(cidr);
  // ipaddr.js only matches within the same family; cross-family returns
  // false rather than throwing.
  if (target.kind() !== parsedCidr[0].kind()) return false;
  // The library's signature is `addr.match([cidrAddr, prefix])`. Trust
  // its bit-level comparison rather than rolling our own.
  return target.match(parsedCidr);
}

function bytesToBigInt(bytes: number[]): bigint {
  let n = 0n;
  for (const b of bytes) {
    n = (n << 8n) | BigInt(b);
  }
  return n;
}

function bigIntToAddress(n: bigint, family: Family): string {
  const totalBits = family === 4 ? 32 : 128;
  const bytes: number[] = [];
  let v = n & ((1n << BigInt(totalBits)) - 1n); // mask to family width
  for (let i = 0; i < totalBits / 8; i++) {
    bytes.unshift(Number(v & 0xffn));
    v >>= 8n;
  }
  return family === 4
    ? ipaddr.fromByteArray(bytes).toString()
    : (ipaddr.fromByteArray(bytes) as ipaddr.IPv6).toString();
}
