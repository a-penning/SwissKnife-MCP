import { afterEach, describe, expect, it } from "vitest";
import {
  assertUrlAllowed,
  isBlockedIp,
  isBlockedIpv4,
  ssrfGuardEnabled,
} from "../../src/lib/ssrf.js";

const ENV = "SWISSKNIFE_BLOCK_PRIVATE_NETWORKS";

afterEach(() => {
  delete process.env[ENV];
});

describe("ssrf: isBlockedIpv4", () => {
  const blocked = [
    "0.0.0.0",
    "0.255.255.255", // 0.0.0.0/8 upper bound
    "127.0.0.1",
    "127.255.255.255", // loopback upper bound
    "10.0.0.0", // 10/8 lower bound
    "10.1.2.3",
    "10.255.255.255", // 10/8 upper bound
    "169.254.0.0", // link-local lower bound
    "169.254.169.254", // cloud metadata
    "169.254.255.255", // link-local upper bound
    "172.16.0.1", // 172.16/12 lower edge
    "172.20.10.5", // middle of 172.16/12
    "172.31.255.255", // 172.16/12 upper edge
    "192.168.0.0", // 192.168/16 lower bound
    "192.168.1.1",
    "192.168.255.255", // 192.168/16 upper bound
    "100.64.0.0", // CGNAT lower edge
    "100.64.0.1", // CGNAT
    "100.127.255.255", // CGNAT upper edge
  ];
  const allowed = [
    "8.8.8.8",
    "1.1.1.1",
    "172.15.255.255", // just below 172.16/12
    "172.15.0.1",
    "172.32.0.1", // just above 172.16/12
    "100.63.255.255", // just below CGNAT
    "100.63.0.1",
    "100.128.0.1", // just above CGNAT
    "93.184.216.34",
    "11.0.0.1", // adjacent to 10/8 but public
    "126.0.0.1", // adjacent to loopback but public
    "128.0.0.1", // adjacent to loopback but public
  ];
  // Inputs that are not IPv4 literals at all — the regex must reject them,
  // so the function returns false (not blocked, since it isn't even an IP).
  const notIpv4 = [
    "",
    "256.0.0.1", // octet out of range
    "1.2.3", // too few octets
    "1.2.3.4.5", // too many octets
    "1.2.3.x", // non-numeric octet
    "999.999.999.999",
    "::1", // v6, not v4
    "8.8.8.8 ", // trailing space breaks the anchored regex
  ];
  it.each(blocked)("blocks %s", (ip) => {
    expect(isBlockedIpv4(ip)).toBe(true);
  });
  it.each(allowed)("allows %s", (ip) => {
    expect(isBlockedIpv4(ip)).toBe(false);
  });
  it.each(notIpv4)("treats %j as not-a-v4-literal (returns false)", (ip) => {
    expect(isBlockedIpv4(ip)).toBe(false);
  });
});

describe("ssrf: isBlockedIp (v6 + mapped)", () => {
  const blocked = [
    "::1", // loopback
    "::", // unspecified
    "fe80::1", // link-local fe80::/10 lower
    "FE80::1", // case-insensitive
    "febf:ffff::1", // link-local fe80::/10 upper edge (0xfebf & 0xffc0 == 0xfe80)
    "fc00::1", // unique-local fc00::/7 lower
    "fd12:3456::1", // unique-local (fd00::/8 is within fc00::/7)
    "fdff:ffff::1", // unique-local upper edge
    "::ffff:127.0.0.1", // v4-mapped loopback
    "::ffff:10.0.0.1", // v4-mapped private
    "::ffff:169.254.169.254", // v4-mapped metadata
    "::ffff:192.168.1.1", // v4-mapped private
  ];
  const allowed = [
    "2606:4700:4700::1111", // Cloudflare public
    "2001:4860:4860::8888", // Google public
    "::ffff:8.8.8.8", // v4-mapped public
    "::ffff:1.1.1.1", // v4-mapped public
    "fe00::1", // just below fe80::/10 (0xfe00 & 0xffc0 == 0xfe00)
    "fec0::1", // just above fe80::/10 (site-local, not in guard's set)
    "2001:db8::1", // documentation range, not in the guard's blocklist
  ];
  // Garbage that isn't a parseable v6 first-group hex — must not throw and
  // must not be reported as blocked.
  const notBlocked = ["", "not-an-ip", "g::1"];
  it.each(blocked)("blocks %s", (ip) => {
    expect(isBlockedIp(ip)).toBe(true);
  });
  it.each(allowed)("allows %s", (ip) => {
    expect(isBlockedIp(ip)).toBe(false);
  });
  it.each(notBlocked)("does not block unparseable %j", (ip) => {
    expect(isBlockedIp(ip)).toBe(false);
  });
});

describe("ssrf: guard toggle env-var matrix", () => {
  const cases: Array<[string, boolean]> = [
    ["1", true],
    ["true", true],
    ["TRUE", true],
    ["yes", true], // any non-empty, non-"0", non-"false" value enables
    ["on", true],
    ["0", false],
    ["false", false],
    ["False", false],
    ["", false],
  ];
  it.each(cases)("env=%j -> enabled=%s", (val, expected) => {
    process.env[ENV] = val;
    expect(ssrfGuardEnabled()).toBe(expected);
  });
  it("is disabled when the env var is unset", () => {
    delete process.env[ENV];
    expect(ssrfGuardEnabled()).toBe(false);
  });
});

describe("ssrf: guard toggle + assertUrlAllowed", () => {
  it("is off by default", () => {
    expect(ssrfGuardEnabled()).toBe(false);
  });

  // When the guard is OFF, even blocked literals must be allowed through.
  const offAllowed = [
    "http://10.0.0.1/",
    "http://127.0.0.1/",
    "http://169.254.169.254/",
  ];
  it.each(offAllowed)("allows %s when the guard is off", async (url) => {
    await expect(assertUrlAllowed(new URL(url))).resolves.toBeUndefined();
  });

  // IPv4-literal hosts: node:dns lookup resolves the literal to itself without
  // a real network call, so these stay fully offline. (IPv6 literals are NOT
  // exercised here: URL.hostname keeps the surrounding brackets, so the value
  // handed to dns.lookup is "[::1]" — which never resolves and lands in the
  // "cannot resolve host" branch rather than the SSRF-block branch. The v6
  // blocklist itself is covered exhaustively by the isBlockedIp suite above.)
  const onBlocked = [
    "http://169.254.169.254/latest/meta-data/", // cloud metadata
    "http://127.0.0.1/",
    "http://10.0.0.1/",
    "http://192.168.0.1/",
    "http://172.16.0.1/",
    "http://100.64.0.1/", // CGNAT
  ];
  const onAllowed = [
    "http://1.1.1.1/",
    "http://8.8.8.8/",
    "https://93.184.216.34/",
  ];
  it.each(onBlocked)("blocks %s when the guard is on", async (url) => {
    process.env[ENV] = "1";
    await expect(assertUrlAllowed(new URL(url))).rejects.toThrow(
      /blocked request to private/,
    );
  });
  it.each(onAllowed)("permits %s when the guard is on", async (url) => {
    process.env[ENV] = "1";
    await expect(assertUrlAllowed(new URL(url))).resolves.toBeUndefined();
  });
});
