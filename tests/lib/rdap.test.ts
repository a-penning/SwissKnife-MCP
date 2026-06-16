import { describe, expect, it } from "vitest";
import {
  parseRdapAsn,
  parseRdapDomain,
  parseRdapIp,
} from "../../src/lib/rdap.js";

describe("parseRdapDomain", () => {
  it("extracts the standard RFC 9083 fields from a realistic gTLD response", () => {
    const fixture = {
      objectClassName: "domain",
      ldhName: "example.com",
      status: ["client transfer prohibited"],
      events: [
        { eventAction: "registration", eventDate: "2020-08-01T00:00:00Z" },
        { eventAction: "expiration", eventDate: "2026-08-01T00:00:00Z" },
        { eventAction: "last changed", eventDate: "2025-07-07T12:00:00Z" },
      ],
      nameservers: [
        { ldhName: "LOLA.NS.CLOUDFLARE.COM" },
        { ldhName: "MELNICOFF.NS.CLOUDFLARE.COM" },
      ],
      secureDNS: { delegationSigned: false, zoneSigned: true },
      entities: [
        {
          roles: ["registrar"],
          publicIds: [{ type: "IANA Registrar ID", identifier: "1068" }],
          vcardArray: [
            "vcard",
            [
              ["version", {}, "text", "4.0"],
              ["fn", {}, "text", "Namecheap Inc."],
            ],
          ],
          entities: [
            {
              roles: ["abuse"],
              vcardArray: [
                "vcard",
                [
                  ["version", {}, "text", "4.0"],
                  ["fn", {}, "text", "Namecheap Abuse"],
                  ["email", {}, "text", "abuse@namecheap.com"],
                ],
              ],
            },
          ],
        },
        {
          roles: ["registrant"],
          vcardArray: [
            "vcard",
            [
              ["version", {}, "text", "4.0"],
              ["fn", {}, "text", "REDACTED FOR PRIVACY"],
            ],
          ],
        },
      ],
    };
    const out = parseRdapDomain(fixture, "example.com");
    expect(out.kind).toBe("domain");
    expect(out.registrar).toBe("Namecheap Inc.");
    expect(out.nameservers).toEqual([
      "lola.ns.cloudflare.com",
      "melnicoff.ns.cloudflare.com",
    ]);
    expect(out.statusCodes).toEqual(["client transfer prohibited"]);
    expect(out.created).toBe("2020-08-01T00:00:00.000Z");
    expect(out.expires).toBe("2026-08-01T00:00:00.000Z");
    expect(typeof out.daysRemaining).toBe("number");
    expect(out.dnssec).toBe("zone-signed");
    expect(out.abuseContact).toBe("abuse@namecheap.com");
    // RDAP path doesn't apply the "redacted" string collapse — the registrant
    // value is passed through; callers see "REDACTED FOR PRIVACY" verbatim,
    // which is itself unambiguous. (Whoiser fallback path does the collapse.)
    expect(out.registrant).toBe("REDACTED FOR PRIVACY");
  });

  // secureDNS derivation: delegationSigned wins; else zoneSigned; else
  // unsigned; absent secureDNS leaves dnssec undefined.
  const dnssecCases: Array<[string, unknown, string | undefined]> = [
    ["delegationSigned only", { delegationSigned: true }, "delegation-signed"],
    [
      "delegationSigned beats zoneSigned",
      { delegationSigned: true, zoneSigned: true },
      "delegation-signed",
    ],
    [
      "zoneSigned only",
      { delegationSigned: false, zoneSigned: true },
      "zone-signed",
    ],
    ["zoneSigned true, delegation absent", { zoneSigned: true }, "zone-signed"],
    [
      "both false => unsigned",
      { delegationSigned: false, zoneSigned: false },
      "unsigned",
    ],
    ["empty secureDNS object => unsigned", {}, "unsigned"],
  ];
  it.each(dnssecCases)("dnssec from %s", (_label, secureDNS, expected) => {
    const out = parseRdapDomain({ secureDNS }, "example.com");
    expect(out.dnssec).toBe(expected);
  });

  it("dnssec is undefined when secureDNS is absent entirely", () => {
    const out = parseRdapDomain({ ldhName: "example.com" }, "example.com");
    expect(out.dnssec).toBeUndefined();
  });

  // A near-empty response must yield undefined (not null/empty) for every
  // optional field — assert the full range of them at once.
  it.each([
    "registrar",
    "nameservers",
    "statusCodes",
    "created",
    "updated",
    "expires",
    "daysRemaining",
    "abuseContact",
    "registrant",
    "whoisServer",
  ])("leaves %s undefined for a near-empty response", (field) => {
    const out = parseRdapDomain(
      { ldhName: "example.com" },
      "example.com",
    ) as unknown as Record<string, unknown>;
    expect(out[field]).toBeUndefined();
  });

  // statusCodes and nameservers: present-and-nonempty pass through; empty
  // arrays collapse to undefined (the "no data" contract).
  it("passes through a multi-entry status array", () => {
    const out = parseRdapDomain(
      { status: ["client transfer prohibited", "server hold"] },
      "example.com",
    );
    expect(out.statusCodes).toEqual([
      "client transfer prohibited",
      "server hold",
    ]);
  });
  it("collapses an empty status array to undefined", () => {
    const out = parseRdapDomain({ status: [] }, "example.com");
    expect(out.statusCodes).toBeUndefined();
  });
  it("lowercases nameservers and drops empty ldhName entries", () => {
    const out = parseRdapDomain(
      {
        nameservers: [
          { ldhName: "NS1.EXAMPLE.COM" },
          { ldhName: "" },
          { ldhName: "ns2.Example.com" },
        ],
      },
      "example.com",
    );
    expect(out.nameservers).toEqual(["ns1.example.com", "ns2.example.com"]);
  });
});

describe("parseRdapIp", () => {
  it("uses cidr0_cidrs when present", () => {
    const fixture = {
      objectClassName: "ip network",
      name: "GOOGLE-DNS",
      type: "DIRECT ALLOCATION",
      country: "US",
      cidr0_cidrs: [{ v4prefix: "8.8.8.0", length: 24 }],
      startAddress: "8.8.8.0",
      endAddress: "8.8.8.255",
    };
    const out = parseRdapIp(fixture, "8.8.8.8");
    expect(out.network).toBe("8.8.8.0/24");
    expect(out.country).toBe("US");
    expect(out.allocationType).toBe("DIRECT ALLOCATION");
  });

  it("falls back to startAddress / endAddress when no CIDR field exists", () => {
    const fixture = {
      name: "EXAMPLE",
      startAddress: "192.0.2.0",
      endAddress: "192.0.2.255",
    };
    const out = parseRdapIp(fixture, "192.0.2.1");
    expect(out.network).toBe("192.0.2.0 - 192.0.2.255");
  });

  // network field derivation across the full range of input shapes.
  const networkCases: Array<
    [string, Record<string, unknown>, string | undefined]
  > = [
    [
      "v4 CIDR prefix",
      { cidr0_cidrs: [{ v4prefix: "8.8.8.0", length: 24 }] },
      "8.8.8.0/24",
    ],
    [
      "v6 CIDR prefix",
      { cidr0_cidrs: [{ v6prefix: "2606:4700::", length: 32 }] },
      "2606:4700::/32",
    ],
    [
      "CIDR preferred over start/end range",
      {
        cidr0_cidrs: [{ v4prefix: "10.0.0.0", length: 8 }],
        startAddress: "10.0.0.0",
        endAddress: "10.255.255.255",
      },
      "10.0.0.0/8",
    ],
    [
      "start/end range fallback",
      { startAddress: "192.0.2.0", endAddress: "192.0.2.255" },
      "192.0.2.0 - 192.0.2.255",
    ],
    [
      "CIDR missing length falls through to range",
      {
        cidr0_cidrs: [{ v4prefix: "1.1.1.0" }],
        startAddress: "1.1.1.0",
        endAddress: "1.1.1.255",
      },
      "1.1.1.0 - 1.1.1.255",
    ],
    ["no addressing fields at all", { name: "X" }, undefined],
  ];
  it.each(
    networkCases,
  )("derives network from %s", (_label, fixture, expected) => {
    const out = parseRdapIp(fixture, "0.0.0.0");
    expect(out.network).toBe(expected);
  });

  // country / allocationType pass-through and absence.
  it("passes through country and allocationType when present", () => {
    const out = parseRdapIp(
      {
        country: "DE",
        type: "ALLOCATED PA",
        startAddress: "a",
        endAddress: "b",
      },
      "0.0.0.0",
    );
    expect(out.country).toBe("DE");
    expect(out.allocationType).toBe("ALLOCATED PA");
  });
  it("leaves country and allocationType undefined when absent", () => {
    const out = parseRdapIp({ startAddress: "a", endAddress: "b" }, "0.0.0.0");
    expect(out.country).toBeUndefined();
    expect(out.allocationType).toBeUndefined();
  });

  it("pulls organization from the registrant vcard if there's no top-level name", () => {
    const fixture = {
      entities: [
        {
          roles: ["registrant"],
          vcardArray: [
            "vcard",
            [
              ["version", {}, "text", "4.0"],
              ["fn", {}, "text", "Cloudflare, Inc."],
            ],
          ],
        },
      ],
      startAddress: "1.1.1.0",
      endAddress: "1.1.1.255",
    };
    const out = parseRdapIp(fixture, "1.1.1.1");
    expect(out.organization).toBe("Cloudflare, Inc.");
  });
});

describe("parseRdapAsn", () => {
  it("extracts name / country / allocationDate / registry", () => {
    const fixture = {
      objectClassName: "autnum",
      name: "GOOGLE",
      country: "US",
      port43: "whois.arin.net",
      events: [
        { eventAction: "registration", eventDate: "2000-03-30T00:00:00Z" },
      ],
    };
    const out = parseRdapAsn(fixture, "AS15169");
    expect(out.name).toBe("GOOGLE");
    expect(out.country).toBe("US");
    expect(out.allocationDate).toBe("2000-03-30T00:00:00.000Z");
    expect(out.registry).toBe("whois.arin.net");
    // The previous shape redundantly populated `whoisServer` from the
    // same field; that's gone now. `registry` is the canonical field.
    expect(
      (out as unknown as Record<string, unknown>).whoisServer,
    ).toBeUndefined();
  });
});
