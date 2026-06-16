import { z } from "zod";
import {
  classifyDnsError,
  DEFAULT_FANOUT_TYPES,
  emptyResultForType,
  RECORD_TYPES,
  type RecordType,
  resolveOne,
  reverseLookup,
} from "../lib/dns.js";
import { isBlockedIp, ssrfGuardEnabled } from "../lib/ssrf.js";
import { defineTool, err, ok, singleOrArray } from "./types.js";

// Codes that mean "no records of that type exist" rather than "the lookup
// itself failed". Surfacing them as a clean empty result lets callers
// distinguish "ask was answered" from "ask blew up" without try/catch.
const EMPTY_RESULT_CODES = new Set(["ENODATA", "NODATA"]);

// In single-type mode, ENOTFOUND legitimately means NXDOMAIN (the host
// doesn't exist) and must surface as an error. In fan-out, the host
// presumably exists if any other type resolves — and Node's resolver
// returns ENOTFOUND for "type doesn't exist on this name" on some
// resolvers (CARES paths, system stub). So we widen the empty-set for
// fan-out only.
const FANOUT_EMPTY_CODES = new Set(["ENODATA", "NODATA", "ENOTFOUND"]);

// Render a single per-type result as a one-line human-readable string for
// the text field. structuredContent still carries the raw shape — this is
// purely about not making callers read JSON when they didn't have to.
function formatTypeForText(type: RecordType, value: unknown): string {
  if (
    value &&
    typeof value === "object" &&
    (value as { empty?: boolean }).empty
  ) {
    return "(no records)";
  }
  const v = value as Record<string, unknown>;
  switch (type) {
    case "A":
    case "AAAA":
      return (v.addresses as string[] | undefined)?.join(", ") ?? "";
    case "CNAME":
      return (v.targets as string[] | undefined)?.join(", ") ?? "";
    case "NS":
      return (v.servers as string[] | undefined)?.join(", ") ?? "";
    case "MX":
      return (
        (v.records as Array<{ priority: number; exchange: string }> | undefined)
          ?.map((r) => `${r.priority} ${r.exchange}`)
          .join(", ") ?? ""
      );
    case "TXT":
      return (
        (v.records as Array<{ text: string }> | undefined)
          ?.map((r) => JSON.stringify(r.text))
          .join(", ") ?? ""
      );
    case "SOA":
      return `${v.nsname ?? ""} ${v.hostmaster ?? ""} serial=${v.serial ?? "?"}`;
    case "SRV":
      return (
        (
          v.records as
            | Array<{
                name: string;
                port: number;
                priority: number;
                weight: number;
              }>
            | undefined
        )
          ?.map((r) => `${r.priority}/${r.weight} ${r.name}:${r.port}`)
          .join(", ") ?? ""
      );
    case "CAA":
      return JSON.stringify(v.records);
  }
}

export const dnsTool = defineTool({
  name: "dns",
  title: "DNS lookup",
  description:
    "Look up DNS records for a host (or PTR records for an IP). Use this when you want to know where a hostname points, who serves its mail, what TXT records it advertises (SPF/DKIM/DMARC/verification), what nameservers it uses, or what its SOA / SRV / CAA records say.\n" +
    "\n" +
    "**For 'what's the full DNS picture for this domain', call this tool ONCE with no `type`** — it fans out across A/AAAA/MX/TXT/CNAME/NS/SOA in parallel and returns a single envelope. Don't loop over the types yourself.\n" +
    "\n" +
    "Only pass `type` when you want a flat single-type response, or as an array to pick a custom subset (e.g. just SRV/CAA, which aren't in the default fan-out). Provide `ip` instead of `host` for a reverse (PTR) lookup.\n" +
    "\n" +
    "Optional `resolver` lets you query a specific DNS server (e.g. '1.1.1.1', '8.8.8.8') instead of the system resolver — handy for comparing what different resolvers see.\n" +
    "\n" +
    "An empty answer (no records of the requested type) is a successful empty result with `empty: true`, distinct from a real lookup failure (NXDOMAIN, SERVFAIL, REFUSED, timeout) which comes back as a structured error.\n" +
    "\n" +
    "Examples:\n" +
    '  { "host": "example.com" } → fan-out across A/AAAA/MX/TXT/CNAME/NS/SOA\n' +
    '  { "host": "example.com", "type": "MX" } → just the MX records\n' +
    '  { "host": "example.com", "type": ["SRV", "CAA"] } → custom subset\n' +
    '  { "ip": "1.1.1.1" } → PTR (reverse) lookup',
  inputSchema: {
    host: z.string().optional().describe("Hostname to look up (forward query)"),
    ip: z
      .string()
      .optional()
      .describe(
        "IP address for a reverse (PTR) lookup — mutually exclusive with host",
      ),
    type: singleOrArray(z.enum(RECORD_TYPES))
      .optional()
      .describe(
        "Record type. Omit for the default fan-out across A/AAAA/MX/TXT/CNAME/NS/SOA. SRV and CAA are not in the default set and must be requested explicitly. Pass an array to pick a subset. Pass a single string for a flat single-type response. Use `ip` instead of `host` for PTR (reverse) lookups.",
      ),
    resolver: z
      .string()
      .regex(
        /^(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9a-fA-F:]+)$/,
        "resolver must be an IPv4 or IPv6 address (e.g. 1.1.1.1, 2606:4700:4700::1111), not a hostname",
      )
      .optional()
      .describe(
        "Optional resolver IP (e.g. 1.1.1.1, 2606:4700:4700::1111). System resolver is used when omitted. Hostnames and host:port are rejected — Node's DNS resolver wants a plain IP.",
      ),
    timeoutMs: z.coerce.number().int().min(1).max(30_000).default(5_000),
  },
  refine: (args, ctx) => {
    if (args.host && args.ip) {
      ctx.addIssue({ code: "custom", message: "provide host OR ip, not both" });
    } else if (!args.host && !args.ip) {
      ctx.addIssue({
        code: "custom",
        message: "provide host (forward lookup) or ip (reverse lookup)",
      });
    }
  },
  handler: async (args) => {
    if (args.host && args.ip) {
      return err("provide host OR ip, not both");
    }
    if (!args.host && !args.ip) {
      return err("provide host (forward lookup) or ip (reverse lookup)");
    }
    // SSRF guard: the `resolver` parameter directs outbound DNS queries to
    // an arbitrary endpoint. When the guard is on, refuse private /
    // loopback addresses so the server can't be used to probe RFC1918
    // resolvers or land queries on cloud-metadata-adjacent IPs.
    if (args.resolver && ssrfGuardEnabled() && isBlockedIp(args.resolver)) {
      return err(
        `blocked dns query to private/loopback resolver ${args.resolver} — SSRF guard is on; unset SWISSKNIFE_BLOCK_PRIVATE_NETWORKS to allow`,
      );
    }

    if (args.ip) {
      try {
        const result = await reverseLookup(args.ip, {
          resolver: args.resolver,
          timeoutMs: args.timeoutMs,
        });
        return ok(
          result.hostnames.length
            ? result.hostnames.join("\n")
            : "(no PTR records)",
          { ip: args.ip, type: "PTR", ...result },
        );
      } catch (e) {
        const { code, message } = classifyDnsError(e);
        return err(`${code}: ${message}`);
      }
    }

    const host = args.host as string;

    // Resolve the requested type set. Omitted = fan-out across the common
    // types; array (any length, including 1) = "records envelope" shape so
    // callers writing generic code can rely on `r.records.<TYPE>` always
    // existing; single string = flat shape (no envelope).
    const arrayShape = args.type === undefined || Array.isArray(args.type);
    const requestedTypes: RecordType[] =
      args.type === undefined
        ? DEFAULT_FANOUT_TYPES
        : Array.isArray(args.type)
          ? args.type
          : [args.type];

    if (arrayShape) {
      const results: Record<string, unknown> = {};
      const perTypeErrors: Record<string, string> = {};
      await Promise.all(
        requestedTypes.map(async (t) => {
          try {
            results[t] = await resolveOne(host, {
              type: t,
              resolver: args.resolver,
              timeoutMs: args.timeoutMs,
            });
          } catch (e) {
            const { code, message } = classifyDnsError(e);
            if (FANOUT_EMPTY_CODES.has(code)) {
              // ENODATA/NODATA/ENOTFOUND-for-one-type-in-a-fan-out all mean
              // "no records of this type" — surface as empty so callers can
              // distinguish "no records" from "the lookup itself failed".
              // In fan-out context ENOTFOUND for one type doesn't imply
              // the host doesn't exist (another type may resolve fine).
              results[t] = { ...emptyResultForType(t), empty: true };
            } else {
              // Transport/protocol failure (SERVFAIL, timeout, REFUSED, …).
              // Surface in BOTH records (so the key is always present) AND
              // perTypeErrors (for the structured error detail).
              results[t] = {
                ...emptyResultForType(t),
                empty: true,
                error: `${code}: ${message}`,
              };
              perTypeErrors[t] = `${code}: ${message}`;
            }
          }
        }),
      );
      const summary = requestedTypes
        .map((t) => `${t}: ${formatTypeForText(t, results[t])}`)
        .join("\n");
      const structured: Record<string, unknown> = {
        host,
        // Always surface the resolved list so callers can see what was
        // actually fanned out, including when type was omitted.
        type: requestedTypes,
        records: results,
      };
      if (Object.keys(perTypeErrors).length > 0) {
        structured.perTypeErrors = perTypeErrors;
      }
      return ok(summary || "(no records found)", structured);
    }

    const onlyType = requestedTypes[0] as RecordType;
    try {
      const result = await resolveOne(host, {
        type: onlyType,
        resolver: args.resolver,
        timeoutMs: args.timeoutMs,
      });
      // Node's `dns.promises.resolveSoa()` adds a stray `type: undefined`
      // own property to its result, so a naive `...result` AFTER our
      // `type: onlyType` would silently wipe the type back to undefined.
      // Spread first, then explicitly set `type` so our value wins.
      return ok(JSON.stringify(result, null, 2), {
        host,
        ...(result as Record<string, unknown>),
        type: onlyType,
      });
    } catch (e) {
      const { code, message } = classifyDnsError(e);
      // An empty answer is a successful empty result, not an error — see
      // the description. Real failures (NXDOMAIN, SERVFAIL, timeout, …)
      // still surface via err().
      if (EMPTY_RESULT_CODES.has(code)) {
        const empty = emptyResultForType(onlyType);
        return ok(`(no ${onlyType} records)`, {
          host,
          type: onlyType,
          ...empty,
          empty: true,
        });
      }
      return err(`${code}: ${message}`);
    }
  },
});
