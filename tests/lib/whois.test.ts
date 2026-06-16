import { describe, expect, it } from "vitest";
import {
  classifyWhoisTarget,
  normalizeAsn,
  normalizeDomain,
  normalizeIp,
} from "../../src/lib/whois.js";

describe("classifyWhoisTarget", () => {
  // A range of inputs that should classify as a domain, with the expected
  // normalized (lowercased / punycoded) form derived from the input.
  const domains: Array<[string, string]> = [
    ["example.com", "example.com"],
    ["Example.COM", "example.com"],
    ["sub.domain.co.uk", "sub.domain.co.uk"],
    ["xn--mnchen-3ya.de", "xn--mnchen-3ya.de"], // already-punycode IDN
    ["a-b.example.org", "a-b.example.org"], // internal hyphen ok
    ["MixedCase.Example.NET", "mixedcase.example.net"],
  ];
  it.each(domains)("classifies %j as a domain", (input, normalized) => {
    expect(classifyWhoisTarget(input)).toEqual({ kind: "domain", normalized });
  });

  // A range of IP literals (v4 + v6) that classify as ip.
  const ips: Array<[string, RegExp]> = [
    ["8.8.8.8", /^8\.8\.8\.8$/],
    ["1.1.1.1", /^1\.1\.1\.1$/],
    ["192.0.2.1", /^192\.0\.2\.1$/],
    ["2606:4700:4700::1111", /^2606:4700:4700::1111$/i],
    ["::1", /^::1$/i],
  ];
  it.each(ips)("classifies %j as an ip", (input, normalizedRe) => {
    const out = classifyWhoisTarget(input);
    expect(out.kind).toBe("ip");
    expect(out.normalized).toMatch(normalizedRe);
  });

  // A range of ASN forms (with/without prefix, case-insensitive) -> bare digits.
  const asns: Array<[string, string]> = [
    ["AS15169", "15169"],
    ["as15169", "15169"],
    ["15169", "15169"],
    ["AS1", "1"],
    ["AS4294967295", "4294967295"], // max 32-bit ASN
  ];
  it.each(asns)("classifies %j as an asn", (input, normalized) => {
    expect(classifyWhoisTarget(input)).toEqual({ kind: "asn", normalized });
  });

  // A range of inputs that must throw — empty, octal-bypass IPs, malformed
  // ASN forms, and outright garbage. Each asserts the file's error pattern.
  const throwsWith: Array<[string, RegExp]> = [
    ["", /empty/],
    ["   ", /empty/], // whitespace-only trims to empty
    ["010.0.0.1", /leading-zero/], // octal-bypass IPv4
    ["AS-1", /not a domain, IP, or ASN/],
    ["AS", /not a domain, IP, or ASN/], // prefix without digits
    ["definitely not anything", /not a domain, IP, or ASN/],
    ["no-dot-here", /not a domain, IP, or ASN/], // single label, no TLD
    ["-leadinghyphen.com", /not a domain, IP, or ASN/],
  ];
  it.each(throwsWith)("rejects %j", (input, pattern) => {
    expect(() => classifyWhoisTarget(input)).toThrow(pattern);
  });

  it("rejects octal-bypass IPv4", () => {
    expect(() => classifyWhoisTarget("010.0.0.1")).toThrow(/leading-zero/);
  });
  it("rejects 'AS-1'", () => {
    expect(() => classifyWhoisTarget("AS-1")).toThrow(
      /not a domain, IP, or ASN/,
    );
  });
  it("accepts IDN punycode (xn-- prefix) labels", () => {
    // RFC 5891: every internationalised domain becomes xn--<encoded>.<tld>.
    // Rejecting the double-hyphen would silently break every IDN lookup.
    expect(classifyWhoisTarget("xn--mnchen-3ya.de")).toEqual({
      kind: "domain",
      normalized: "xn--mnchen-3ya.de",
    });
  });
  it("auto-punycodes Unicode IDN inputs to their xn-- form", () => {
    // Users type the human form ("münchen.de"); the registry only knows
    // the ASCII form (xn--mnchen-3ya.de). Translate transparently.
    expect(classifyWhoisTarget("münchen.de")).toEqual({
      kind: "domain",
      normalized: "xn--mnchen-3ya.de",
    });
  });
  it("rejects an empty string", () => {
    expect(() => classifyWhoisTarget("")).toThrow(/empty/);
  });
  it("rejects garbage", () => {
    expect(() => classifyWhoisTarget("definitely not anything")).toThrow();
  });
  it("respects an explicit override", () => {
    // 15169 alone is an ASN; force domain interpretation should still reject it
    expect(() => classifyWhoisTarget("15169", "domain")).toThrow(
      /invalid domain/,
    );
  });

  // Overrides force a specific interpretation; a range of (input, override)
  // pairs covering both forced-success and forced-failure.
  it("forces ip interpretation and rejects a non-IP", () => {
    expect(() => classifyWhoisTarget("example.com", "ip")).toThrow();
  });
  it("forces asn interpretation of a bare number", () => {
    expect(classifyWhoisTarget("15169", "asn")).toEqual({
      kind: "asn",
      normalized: "15169",
    });
  });
  it("forces asn but rejects a non-numeric value", () => {
    expect(() => classifyWhoisTarget("example.com", "asn")).toThrow(
      /invalid ASN/,
    );
  });
  it("forces domain interpretation of a value that auto-detects as a domain", () => {
    expect(classifyWhoisTarget("example.com", "domain")).toEqual({
      kind: "domain",
      normalized: "example.com",
    });
  });
});

describe("normalizeDomain", () => {
  it("flattens whoiser's per-server output and collapses redacted fields", () => {
    const fixture = {
      "whois.verisign-grs.com": {
        "Domain Name": "EXAMPLE.COM",
        Registrar: "Example Registrar, Inc.",
        "Registry Expiry Date": "2030-08-13T04:00:00Z",
        "Creation Date": "1995-08-14T04:00:00Z",
        "Updated Date": "2024-08-14T07:01:38Z",
        "Domain Status": [
          "clientTransferProhibited",
          "serverTransferProhibited",
        ],
        "Name Server": ["A.IANA-SERVERS.NET", "B.IANA-SERVERS.NET"],
        DNSSEC: "signedDelegation",
        "Registrant Organization": "REDACTED FOR PRIVACY",
        "Registrar Abuse Contact Email": "abuse@example.com",
      },
    };
    const out = normalizeDomain(
      "example.com",
      // biome-ignore lint/suspicious/noExplicitAny: hand-built fixture
      fixture as any,
    );
    expect(out.kind).toBe("domain");
    expect(out.registrar).toBe("Example Registrar, Inc.");
    expect(out.nameservers).toEqual([
      "a.iana-servers.net",
      "b.iana-servers.net",
    ]);
    expect(out.statusCodes).toEqual([
      "clientTransferProhibited",
      "serverTransferProhibited",
    ]);
    expect(out.expires).toBe("2030-08-13T04:00:00.000Z");
    expect(typeof out.daysRemaining).toBe("number");
    expect(out.registrant).toBe("redacted");
    expect(out.abuseContact).toBe("abuse@example.com");
    expect(out.whoisServer).toBe("whois.verisign-grs.com");
  });
  // A range of privacy-redaction phrasings the normaliser must collapse to the
  // literal "redacted", plus a real value that must pass through untouched.
  const registrantCases: Array<[string, string]> = [
    ["REDACTED FOR PRIVACY", "redacted"],
    ["Redacted for privacy", "redacted"],
    ["Privacy service provided by Withheld", "redacted"],
    ["Data Redacted", "redacted"],
    ["Not Disclosed", "redacted"],
    ["Private Whois", "redacted"],
    ["Withheld for privacy purposes", "redacted"],
    ["Contact the Registrar", "redacted"],
    ["Acme Corporation", "Acme Corporation"], // real org passes through
    ["Jane Doe", "Jane Doe"],
  ];
  it.each(registrantCases)("collapses registrant %j to %j", (raw, expected) => {
    const out = normalizeDomain("example.com", {
      "whois.example": {
        Registrar: "R",
        "Registrant Organization": raw,
        // biome-ignore lint/suspicious/noExplicitAny: hand-built fixture
      } as any,
    });
    expect(out.registrant).toBe(expected);
  });

  // ISO normalisation of expiry dates: parseable dates become ISO-8601;
  // daysRemaining is derived and must be a number; an unparseable date is
  // surfaced verbatim with no daysRemaining.
  const expiryCases: Array<[string, string | undefined, boolean]> = [
    ["2030-08-13T04:00:00Z", "2030-08-13T04:00:00.000Z", true],
    ["2025-01-01", "2025-01-01T00:00:00.000Z", true],
    ["not a date", "not a date", false],
  ];
  it.each(expiryCases)("normalises expiry %j", (raw, expectedIso, hasDays) => {
    const out = normalizeDomain("example.com", {
      "whois.example": {
        Registrar: "R",
        "Registry Expiry Date": raw,
        // biome-ignore lint/suspicious/noExplicitAny: hand-built fixture
      } as any,
    });
    expect(out.expires).toBe(expectedIso);
    expect(typeof out.daysRemaining === "number").toBe(hasDays);
  });

  it("throws on empty whoiser result", () => {
    expect(() =>
      // biome-ignore lint/suspicious/noExplicitAny: forcing empty fixture
      normalizeDomain("example.com", {} as any),
    ).toThrow(/no usable records/);
  });
  it("throws when every server returned only an error (no silent empty success)", () => {
    // Reproduces the live bug: whoiser returns { "<server>": { error: "..." } }
    // when DNS resolution to the registry's WHOIS server fails. The old
    // normaliser passed the empty-but-not-zero-keys guard and returned a
    // near-empty record. The new guard MUST throw.
    const errorOnly = {
      "whois.nic.google": {
        error: "getaddrinfo ENOTFOUND whois.nic.google",
      },
    };
    expect(() =>
      normalizeDomain(
        "example.com",
        // biome-ignore lint/suspicious/noExplicitAny: fixture
        errorOnly as any,
      ),
    ).toThrow(/no usable records.*ENOTFOUND/);
  });
  it("falls through to a usable entry when the first server errors", () => {
    // whoiser sometimes returns mixed results — an error from one server
    // plus a real response from another. firstResult() can pick the error
    // entry; the normaliser should still find and use the good one.
    const mixed = {
      "whois.iana.org": {
        error: "connection refused",
      },
      "whois.verisign-grs.com": {
        Registrar: "Real Registrar",
        "Name Server": ["NS1.EXAMPLE.NET"],
      },
    };
    const out = normalizeDomain(
      "example.com",
      // biome-ignore lint/suspicious/noExplicitAny: fixture
      mixed as any,
    );
    expect(out.registrar).toBe("Real Registrar");
    expect(out.nameservers).toEqual(["ns1.example.net"]);
  });
});

describe("normalizeIp", () => {
  it("maps RIPE-style fields", () => {
    const fixture = {
      inetnum: "8.8.8.0 - 8.8.8.255",
      netname: "GOOGLE",
      country: "US",
      OriginAS: "AS15169",
      contacts: {
        abuse: { "abuse-mailbox": "network-abuse@google.com" },
      },
      __raw: "",
      __comments: [],
    };
    const out = normalizeIp(
      "8.8.8.8",
      // biome-ignore lint/suspicious/noExplicitAny: fixture
      fixture as any,
    );
    expect(out.network).toBe("8.8.8.0 - 8.8.8.255");
    expect(out.organization).toBe("GOOGLE");
    expect(out.country).toBe("US");
    expect(out.asn).toBe("AS15169");
    expect(out.abuseContact).toBe("network-abuse@google.com");
  });
});

describe("normalizeAsn", () => {
  it("maps ASName / Country / RegDate", () => {
    const fixture = {
      ASName: "GOOGLE",
      Country: "US",
      RegDate: "2000-03-30",
      source: "ARIN",
      __raw: "",
      __comments: [],
    };
    const out = normalizeAsn(
      "AS15169",
      // biome-ignore lint/suspicious/noExplicitAny: fixture
      fixture as any,
    );
    expect(out.name).toBe("GOOGLE");
    expect(out.country).toBe("US");
    expect(out.registry).toBe("ARIN");
    expect(out.allocationDate).toBe("2000-03-30T00:00:00.000Z");
  });
});
