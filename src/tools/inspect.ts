import { X509Certificate } from "node:crypto";
import { lookup } from "node:dns/promises";
import { domainToUnicode } from "node:url";
import { z } from "zod";
import { batchProcess } from "../lib/batch.js";
import {
  fetchTlsChain,
  parseTlsTarget,
  spkiFingerprintSha256,
} from "../lib/cert.js";
import { daysFromNow, daysSince } from "../lib/datetime.js";
import { toMessage } from "../lib/errors.js";
import { isBlockedIp, ssrfGuardEnabled } from "../lib/ssrf.js";
import {
  classifyWhoisTarget,
  lookupWhois,
  type WhoisTargetKind,
} from "../lib/whois.js";
import { defineTool, err, ok, okJson, singleOrBatch } from "./types.js";

const DEFAULT_PORTS: Record<string, string> = {
  "http:": "80",
  "https:": "443",
  "ftp:": "21",
  "ws:": "80",
  "wss:": "443",
};

function inspectUrl(value: string): Record<string, unknown> {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`not a parseable absolute URL: ${JSON.stringify(value)}`);
  }
  // Object.create(null) so keys like "__proto__" and "constructor" can't
  // collide with Object.prototype members and end up dropped or corrupted.
  const query = Object.create(null) as Record<string, string | string[]>;
  for (const [k, v] of url.searchParams) {
    if (!Object.hasOwn(query, k)) {
      query[k] = v;
    } else {
      const existing = query[k];
      if (Array.isArray(existing)) existing.push(v);
      else query[k] = [existing as string, v];
    }
  }
  const unicodeHost = domainToUnicode(url.hostname);
  const pathSegments: string[] = [];
  for (const seg of url.pathname.split("/").filter(Boolean)) {
    try {
      pathSegments.push(decodeURIComponent(seg));
    } catch {
      // %-escape malformed; keep the raw segment so the rest of the URL
      // structure is still inspectable.
      pathSegments.push(seg);
    }
  }
  return {
    href: url.href,
    protocol: url.protocol.replace(/:$/, ""),
    username: url.username || undefined,
    password: url.password ? "<redacted>" : undefined,
    hostname: url.hostname,
    ...(unicodeHost !== url.hostname ? { hostnameUnicode: unicodeHost } : {}),
    port: url.port || DEFAULT_PORTS[url.protocol] || undefined,
    portIsDefault: url.port === "" && url.protocol in DEFAULT_PORTS,
    path: url.pathname,
    pathSegments,
    query: { ...query },
    fragment: url.hash ? url.hash.slice(1) : undefined,
    origin: url.origin !== "null" ? url.origin : undefined,
  };
}

function inspectCertificates(value: string): Record<string, unknown> {
  const blocks = value.match(
    /-----BEGIN ([A-Z0-9 ]+)-----[\s\S]*?-----END \1-----/g,
  );
  if (!blocks || blocks.length === 0) {
    throw new Error(
      "no PEM blocks found (expected -----BEGIN CERTIFICATE----- ...)",
    );
  }
  const certificates: Record<string, unknown>[] = [];
  const skipped: { index: number; reason: string }[] = [];
  for (let i = 0; i < blocks.length; i++) {
    const block = blocks[i] as string;
    if (block.includes("CERTIFICATE REQUEST")) {
      skipped.push({ index: i, reason: "CERTIFICATE REQUEST (CSR) block" });
      continue;
    }
    if (!block.startsWith("-----BEGIN CERTIFICATE-----")) {
      skipped.push({ index: i, reason: "non-certificate PEM block" });
      continue;
    }
    let cert: X509Certificate;
    try {
      cert = new X509Certificate(block);
    } catch (e) {
      throw new Error(
        `failed to parse PEM block ${i + 1} of ${blocks.length} (CERTIFICATE): ${toMessage(e)}`,
      );
    }
    const validFrom = new Date(cert.validFrom);
    const validTo = new Date(cert.validTo);
    const daysRemaining = daysFromNow(validTo.toISOString()) ?? 0;
    const ageInDays = daysSince(validFrom.toISOString()) ?? 0;
    const keyDetails = cert.publicKey.asymmetricKeyDetails ?? {};
    certificates.push({
      subject: cert.subject,
      issuer: cert.issuer,
      selfSigned: cert.subject === cert.issuer,
      serialNumber: cert.serialNumber,
      validFrom: validFrom.toISOString(),
      validTo: validTo.toISOString(),
      expired: daysRemaining < 0,
      daysRemaining,
      ageInDays,
      subjectAltNames: cert.subjectAltName?.split(", ") ?? [],
      isCA: cert.ca,
      keyType: cert.publicKey.asymmetricKeyType,
      keyDetails: {
        ...("modulusLength" in keyDetails
          ? { modulusLength: keyDetails.modulusLength }
          : {}),
        ...("namedCurve" in keyDetails
          ? { namedCurve: keyDetails.namedCurve }
          : {}),
      },
      fingerprintSha1: cert.fingerprint,
      fingerprintSha256: cert.fingerprint256,
      spkiFingerprintSha256: spkiFingerprintSha256(cert),
    });
  }
  if (certificates.length === 0) {
    throw new Error("PEM input contained no CERTIFICATE blocks");
  }
  return {
    certificateCount: certificates.length,
    certificates,
    ...(skipped.length ? { skippedBlocks: skipped } : {}),
  };
}

async function inspectWhois(
  value: string,
  whoisTarget: WhoisTargetKind | undefined,
  whoisServer: string | undefined,
  followRaw: number | undefined,
  timeoutMs: number,
): Promise<Record<string, unknown>> {
  const follow =
    followRaw === 0 || followRaw === 1 || followRaw === 2
      ? followRaw
      : undefined;
  const classified = classifyWhoisTarget(value, whoisTarget);
  // The user-supplied server bypasses whoiser's own (vetted) registry
  // bootstrap, so it gets the same SSRF guard the http/inputUrl path
  // honours — and we resolve to a pinned IP ourselves so whoiser's
  // internal DNS lookup can't open a rebinding window between our
  // check and its dial.
  let serverForWhoiser = whoisServer;
  if (whoisServer && ssrfGuardEnabled()) {
    const bareHost = whoisServer.replace(/^[a-z]+:\/\//i, "").split("/")[0];
    if (!bareHost) {
      throw new Error(
        `invalid whoisServer: ${JSON.stringify(whoisServer)} — could not extract a host`,
      );
    }
    serverForWhoiser = await resolveAndPinHost(bareHost, "whois server");
  }
  const result = await lookupWhois(classified, {
    timeoutMs,
    ...(serverForWhoiser ? { server: serverForWhoiser } : {}),
    ...(follow ? { follow } : {}),
  });
  return { ...result };
}

/** Resolve a host to an IP and refuse blocked addresses. Used for paths
 *  where the downstream library does its own DNS and we want to pin the
 *  address it dials. */
async function resolveAndPinHost(host: string, label: string): Promise<string> {
  const isIpLiteral = /^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes(":");
  if (isIpLiteral) {
    if (isBlockedIp(host)) {
      throw new Error(
        `blocked ${label} ${host} — SSRF guard is on; unset SWISSKNIFE_BLOCK_PRIVATE_NETWORKS to allow`,
      );
    }
    return host;
  }
  let resolved: Array<{ address: string }>;
  try {
    resolved = await lookup(host, { all: true });
  } catch (e) {
    throw new Error(
      `cannot resolve ${label} ${JSON.stringify(host)}: ${toMessage(e)}`,
    );
  }
  const blocked = resolved.find((r) => isBlockedIp(r.address));
  if (blocked) {
    throw new Error(
      `blocked ${label} ${blocked.address} (host ${JSON.stringify(host)}) — SSRF guard is on`,
    );
  }
  return (resolved[0] as { address: string }).address;
}

async function inspectTls(
  value: string,
  servername: string | undefined,
  timeoutMs: number,
): Promise<Record<string, unknown>> {
  const target = parseTlsTarget(value);
  const chain = await fetchTlsChain(target.host, target.port, {
    servername: servername ?? target.servername,
    timeoutMs,
  });
  const parsedChain = inspectCertificates(chain.certificatesPem.join("\n"));
  return {
    host: target.host,
    port: target.port,
    protocol: chain.protocol,
    cipher: chain.cipher,
    authorized: chain.authorized,
    ...(chain.authorizationError
      ? { authorizationError: chain.authorizationError }
      : {}),
    ...parsedChain,
  };
}

export const inspectTool = defineTool({
  name: "inspect",
  title: "URL, certificate, TLS & WHOIS inspector",
  description:
    "Pull a structured artefact apart so you can see what's inside.\n" +
    "\n" +
    "Pick a `kind`:\n" +
    "  • 'url' — split a URL into scheme, host (punycode-decoded), port, path segments, query parameters, and fragment.\n" +
    "  • 'certificate' — parse one or more PEM X.509 certificates: subject, issuer, SANs, validity, fingerprints, SPKI pin.\n" +
    "  • 'tls' — open a live TLS connection to a host and return the served chain plus the negotiated protocol/cipher.\n" +
    "  • 'whois' — look up a domain, IP, or ASN via RDAP (with a WHOIS port-43 fallback); returns registrar, expiry, abuse contact, nameservers, etc.\n" +
    "\n" +
    "Use 'url' to extract parts you'd otherwise pull with brittle regex; 'certificate' to check expiry, key strength, or SAN coverage on a chain you already have; 'tls' to see what a live host is actually serving; 'whois' to check who owns a domain/IP or when it expires.\n" +
    "\n" +
    "Pass an array to `value` for kind 'url' or 'certificate' to inspect many at once.\n" +
    "\n" +
    "Examples:\n" +
    '  { "kind": "url", "value": "https://example.com/a/b?x=1#frag" } → scheme/host/path/query/fragment\n' +
    '  { "kind": "tls", "value": "example.com:443" } → chain + negotiated protocol/cipher\n' +
    '  { "kind": "whois", "value": "example.com" } → registrar / expiry / nameservers\n' +
    '  { "kind": "certificate", "value": "-----BEGIN CERTIFICATE-----\\n…" } → parsed fields',
  inputSchema: {
    kind: z.enum(["url", "certificate", "tls", "whois"]),
    value: singleOrBatch.describe(
      "URL, PEM text, host[:port] / https URL (kind 'tls'), or domain / IP / ASN (kind 'whois'). Arrays are only valid for kind 'url' and 'certificate'.",
    ),
    servername: z
      .string()
      .optional()
      .describe(
        "kind='tls' only: SNI override (defaults to the host). Ignored for other kinds.",
      ),
    whoisTarget: z
      .enum(["domain", "ip", "asn"])
      .optional()
      .describe(
        "kind='whois' only: override auto-detection of the target type.",
      ),
    whoisServer: z
      .string()
      .optional()
      .describe(
        "kind='whois' only: override the WHOIS/RDAP server (subject to the SSRF guard when enabled).",
      ),
    whoisFollow: z.coerce
      .number()
      .int()
      .min(0)
      .max(2)
      .optional()
      .describe(
        "kind='whois' only: how many WHOIS referral hops to follow (0, 1, or 2).",
      ),
    timeoutMs: z.coerce
      .number()
      .int()
      .min(1)
      .max(30_000)
      .default(10_000)
      .describe("kind='tls' / 'whois' only: network timeout in milliseconds."),
  },
  refine: (args, ctx) => {
    if (
      Array.isArray(args.value) &&
      args.kind !== "url" &&
      args.kind !== "certificate"
    ) {
      ctx.addIssue({
        code: "custom",
        message: `batch input (value as array) is only supported for kind 'url' or 'certificate', not '${args.kind}'`,
        path: ["value"],
      });
    }
    if (args.servername !== undefined && args.kind !== "tls") {
      ctx.addIssue({
        code: "custom",
        message: "`servername` only applies to kind 'tls'",
        path: ["servername"],
      });
    }
    for (const field of [
      "whoisTarget",
      "whoisServer",
      "whoisFollow",
    ] as const) {
      if (args[field] !== undefined && args.kind !== "whois") {
        ctx.addIssue({
          code: "custom",
          message: `\`${field}\` only applies to kind 'whois'`,
          path: [field],
        });
      }
    }
  },
  handler: async (args) => {
    try {
      if (Array.isArray(args.value)) {
        if (args.kind !== "url" && args.kind !== "certificate") {
          return err(
            `batch input (value as array) is only supported for kind 'url' or 'certificate', not '${args.kind}'`,
          );
        }
        const fn = args.kind === "url" ? inspectUrl : inspectCertificates;
        const { results, failures } = batchProcess(args.value, (v) => ({
          value: v,
          ...fn(v),
        }));
        return ok(JSON.stringify({ results, failures }, null, 2), {
          results,
          failures,
        });
      }

      const value = args.value;
      if (args.kind === "tls") {
        const structured = await inspectTls(
          value,
          args.servername,
          args.timeoutMs,
        );
        return okJson(structured);
      }
      if (args.kind === "whois") {
        const structured = await inspectWhois(
          value,
          args.whoisTarget,
          args.whoisServer,
          args.whoisFollow,
          args.timeoutMs,
        );
        return okJson(structured);
      }
      const structured =
        args.kind === "url" ? inspectUrl(value) : inspectCertificates(value);
      return ok(JSON.stringify(structured, null, 2), structured);
    } catch (e) {
      return err(toMessage(e));
    }
  },
});
