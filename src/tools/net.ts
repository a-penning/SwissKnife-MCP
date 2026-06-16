import { z } from "zod";
import { toMessage } from "../lib/errors.js";
import {
  cidrContains,
  classifyAddress,
  describeCidr,
  parseAddress,
} from "../lib/net.js";
import { defineTool, err, ok, okJson } from "./types.js";

export const netTool = defineTool({
  name: "net",
  title: "IP & CIDR utilities",
  description:
    "Parse, classify, and compute on IP addresses and CIDR blocks. Use this when you have an IP and want to know what it is (public? private? loopback? CGNAT? multicast?), when you want every alternate representation of an address, when you need the first/last/usable host of a subnet, or when you need to test whether an address falls inside a CIDR.\n" +
    "\n" +
    "Actions:\n" +
    "  • 'parse' — normalise an address into every form (compressed and expanded, byte array, integer, v4-mapped v6 / embedded v4) plus its classification.\n" +
    "  • 'classify' — just the category (public / private / loopback / link-local / CGNAT / multicast / unique-local / …) and the defining RFC.\n" +
    "  • 'cidr' — describe a CIDR block: network, broadcast (IPv4 only), first/last address, first/last usable host, usable-host count, prefix length, mask, host count.\n" +
    "  • 'contains' — boolean test of whether a CIDR covers a given IP.\n" +
    "  • 'convert' — IPv4 ↔ IPv4-mapped IPv6 (::ffff:a.b.c.d).\n" +
    "\n" +
    "Examples:\n" +
    '  { "action": "parse", "value": "::ffff:192.168.1.1" }\n' +
    '  { "action": "classify", "value": "100.64.0.1" } → CGNAT (RFC 6598)\n' +
    '  { "action": "cidr", "value": "10.0.0.0/24" } → network, broadcast, usable host range, mask\n' +
    '  { "action": "contains", "cidr": "10.0.0.0/8", "ip": "10.1.2.3" } → true',
  inputSchema: {
    action: z.enum(["parse", "classify", "cidr", "contains", "convert"]),
    value: z
      .string()
      .optional()
      .describe(
        "parse/classify: IP address. cidr: CIDR notation (e.g. 192.168.1.0/24). convert: IP to convert.",
      ),
    ip: z.string().optional().describe("contains: the IP to test"),
    cidr: z.string().optional().describe("contains: the CIDR to test against"),
  },
  handler: (args) => {
    try {
      switch (args.action) {
        case "parse": {
          if (!args.value) return err("parse requires `value`");
          const parsed = parseAddress(args.value);
          // Include classification fields inline so callers don't have to
          // make a second `classify` call for the most common follow-up.
          const classified = classifyAddress(args.value);
          const result = {
            ...parsed,
            category: classified.category,
            ...(classified.rfc ? { rfc: classified.rfc } : {}),
            rangeKey: classified.rangeKey,
          };
          return ok(JSON.stringify(result, null, 2), { ...result });
        }
        case "classify": {
          if (!args.value) return err("classify requires `value`");
          const result = classifyAddress(args.value);
          // Echo the input back for parity with `parse` (callers writing
          // generic scripts shouldn't have to re-thread the input).
          return ok(`${result.category} (IPv${result.family})`, {
            input: args.value,
            ...result,
          });
        }
        case "cidr": {
          if (!args.value) return err("cidr requires `value`");
          const result = describeCidr(args.value);
          return ok(JSON.stringify(result, null, 2), { ...result });
        }
        case "contains": {
          if (!args.cidr || !args.ip) {
            return err("contains requires `cidr` and `ip`");
          }
          const contains = cidrContains(args.cidr, args.ip);
          return ok(contains ? "yes" : "no", {
            cidr: args.cidr,
            ip: args.ip,
            contains,
          });
        }
        case "convert": {
          if (!args.value) return err("convert requires `value`");
          // Mirror parse, then surface whichever cross-family form is
          // applicable. Anything richer (e.g. 6to4 extraction) lives in
          // parse already. `conversionAvailable` is always present so
          // callers can distinguish "no cross-family form exists for
          // this address" (pure IPv6 with no v4 embedding) from "something
          // went wrong".
          const parsed = parseAddress(args.value);
          const conversionAvailable =
            parsed.family === 4 || parsed.embeddedIpv4 !== undefined;
          const out: Record<string, unknown> = {
            input: parsed.input,
            family: parsed.family,
            normalized: parsed.normalized,
            conversionAvailable,
          };
          if (parsed.family === 4) {
            out.ipv4Mapped = parsed.ipv4Mapped;
          } else if (parsed.embeddedIpv4) {
            out.embeddedIpv4 = parsed.embeddedIpv4;
          }
          return okJson(out);
        }
      }
    } catch (e) {
      return err(toMessage(e));
    }
  },
});
