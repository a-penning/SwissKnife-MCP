import { toMessage } from "./errors.js";
// WHOIS / RDAP lookup wrapper around `whoiser`. We don't maintain the
// TLD-server map ourselves — `whoiser` keeps that updated. Our job is the
// thin contract layer:
//   1. Classify the target as domain / ipv4 / ipv6 / asn (auto-detect or
//      caller-overridden).
//   2. Dispatch to the right `whoiser` entry point.
//   3. Flatten its multi-server / nested response into a single small
//      object with stable field names.
//   4. Collapse privacy-redacted values to the literal string "redacted"
//      so callers can distinguish "registry hid this" from "not provided".

import { domainToASCII } from "node:url";
import { firstResult, whoisAsn, whoisDomain, whoisIp } from "whoiser";
import { daysFromNow } from "./datetime.js";
import { parseAddress } from "./net.js";
import { lookupAsnRdap, lookupDomainRdap, lookupIpRdap } from "./rdap.js";

// whoiser does not re-export its types from the main entrypoint, so we
// declare the minimal shapes we touch. Both shapes are intentionally
// permissive — registries return wildly different field sets and we want
// the normalisers to keep working against them.
interface DomainWhoisData {
  [key: string]: string | string[];
}
type DomainWhois = Record<string, DomainWhoisData>;
interface WhoisDataGroup {
  [key: string]: string | undefined;
}
interface WhoisData {
  [key: string]: unknown;
  contacts?: Record<string, WhoisDataGroup>;
}

export type WhoisTargetKind = "domain" | "ip" | "asn";

export interface ClassifiedTarget {
  kind: WhoisTargetKind;
  normalized: string; // domain (lowercased), IP (canonical), ASN (bare digits)
}

// IPv6 ipaddr.js can swallow a lot of shapes; we keep IPv4 strict (rejects
// 010.0.0.1 etc) by going through parseAddress.
function looksLikeIp(value: string): boolean {
  return value.includes(":") || /^\d+\.\d+\.\d+\.\d+$/.test(value);
}

// "AS15169" or "15169" — explicit "AS-1" or "as0" is rejected. Bounded so
// callers can't sneak a 2^53 number through.
const ASN_RE = /^(?:[Aa][Ss])?(\d{1,10})$/;
// RFC 1035 + RFC 5891: labels are 1-63 chars, may not start or end with a
// hyphen. We intentionally DO allow internal "--" sequences — IDN
// punycode labels start with "xn--" (RFC 5891 §4.2.3), and rejecting
// them would silently break every internationalised domain lookup.
const DOMAIN_LABEL = /^(?=[A-Za-z0-9-]{1,63}$)(?!-)[A-Za-z0-9-]+(?<!-)$/;

function looksLikeAsn(value: string): boolean {
  return ASN_RE.test(value);
}

function isLikelyDomain(value: string): boolean {
  if (!value.includes(".")) return false;
  const labels = value.split(".");
  if (labels.length < 2) return false;
  return labels.every((l) => DOMAIN_LABEL.test(l));
}

export function classifyWhoisTarget(
  value: string,
  override?: WhoisTargetKind,
): ClassifiedTarget {
  const trimmed = value.trim();
  if (!trimmed) {
    throw new Error("whois target is empty");
  }
  if (override === "ip" || (!override && looksLikeIp(trimmed))) {
    const parsed = parseAddress(trimmed); // throws on octal-bypass etc.
    return { kind: "ip", normalized: parsed.normalized };
  }
  if (override === "asn" || (!override && looksLikeAsn(trimmed))) {
    const m = ASN_RE.exec(trimmed);
    if (!m) {
      throw new Error(`invalid ASN: ${JSON.stringify(value)}`);
    }
    return { kind: "asn", normalized: m[1] as string };
  }
  // Try punycode-encoding before deciding it's not a domain — users will
  // type Unicode IDN forms ("münchen.de") and the right thing to do is
  // resolve them to ASCII (xn--mnchen-3ya.de) for the actual lookup.
  // domainToASCII returns "" for inputs that aren't valid domains at all.
  const ascii = trimmed.includes(".")
    ? domainToASCII(trimmed.toLowerCase())
    : "";
  const candidate = ascii && ascii.length > 0 ? ascii : trimmed.toLowerCase();
  if (override === "domain" || (!override && isLikelyDomain(candidate))) {
    if (!isLikelyDomain(candidate)) {
      throw new Error(`invalid domain: ${JSON.stringify(value)}`);
    }
    return { kind: "domain", normalized: candidate };
  }
  throw new Error(
    `whois target ${JSON.stringify(value)} is not a domain, IP, or ASN — pass whoisTarget to override auto-detection`,
  );
}

const REDACTED_PATTERNS = [
  /^redacted\b/i,
  /redacted for privacy/i,
  /^privacy[\s-]*(service|protected|redaction|guardian)?/i,
  /^data redacted/i,
  /^not disclosed/i,
  /^private whois/i,
  /^withheld\b/i,
  /^see whois/i,
  /^contact the registrar/i,
];

function maybeRedacted(value: string): string {
  return REDACTED_PATTERNS.some((re) => re.test(value)) ? "redacted" : value;
}

function pickFirstString(
  source: Record<string, unknown>,
  ...keys: string[]
): string | undefined {
  for (const k of keys) {
    const v = source[k];
    if (Array.isArray(v) && typeof v[0] === "string" && v[0].length > 0) {
      return maybeRedacted(v[0]);
    }
    if (typeof v === "string" && v.length > 0) {
      return maybeRedacted(v);
    }
  }
  return undefined;
}

function pickStringArray(
  source: Record<string, unknown>,
  ...keys: string[]
): string[] | undefined {
  for (const k of keys) {
    const v = source[k];
    if (Array.isArray(v) && v.length > 0) {
      const out = v
        .filter((x): x is string => typeof x === "string" && x.length > 0)
        .map(maybeRedacted);
      if (out.length > 0) return out;
    } else if (typeof v === "string" && v.length > 0) {
      return [maybeRedacted(v)];
    }
  }
  return undefined;
}

function pickIsoDate(
  source: Record<string, unknown>,
  ...keys: string[]
): string | undefined {
  const raw = pickFirstString(source, ...keys);
  if (!raw || raw === "redacted") return raw;
  const d = new Date(raw);
  if (Number.isNaN(d.getTime())) return raw; // surface as-is so caller can see it
  return d.toISOString();
}

export interface NormalizedDomainWhois {
  target: string;
  kind: "domain";
  registrar?: string;
  nameservers?: string[];
  statusCodes?: string[];
  created?: string;
  updated?: string;
  expires?: string;
  daysRemaining?: number;
  dnssec?: string;
  abuseContact?: string;
  registrant?: string;
  whoisServer?: string;
}

export interface NormalizedIpWhois {
  target: string;
  kind: "ip";
  network?: string;
  organization?: string;
  country?: string;
  asn?: string;
  abuseContact?: string;
  allocationType?: string;
  whoisServer?: string;
}

export interface NormalizedAsnWhois {
  target: string;
  kind: "asn";
  // `name` is the ASN handle (e.g. "GOOGLE"). `organization` is the
  // human-readable owner ("Google LLC") when the registry surfaces both.
  name?: string;
  organization?: string;
  country?: string;
  registry?: string;
  allocationDate?: string;
}

export type NormalizedWhois =
  | NormalizedDomainWhois
  | NormalizedIpWhois
  | NormalizedAsnWhois;

export function normalizeDomain(
  target: string,
  result: DomainWhois,
): NormalizedDomainWhois {
  const serverNames = Object.keys(result);
  // Every server whoiser tried that returned an error. If we have NO
  // successful entries (every entry is an error-only object), surface the
  // collected errors — otherwise the tool would silently return an
  // almost-empty record as if the lookup succeeded.
  const entryHasUsableData = (e: Record<string, unknown>): boolean => {
    const keys = Object.keys(e);
    if (keys.length === 0) return false;
    if (keys.length === 1 && keys[0] === "error") return false;
    return true;
  };
  const usable = serverNames.filter((s) =>
    entryHasUsableData(result[s] as unknown as Record<string, unknown>),
  );
  if (usable.length === 0) {
    const errs = serverNames
      .map((s) => {
        const e = (result[s] as unknown as Record<string, unknown>).error;
        return e ? `${s}: ${String(e)}` : `${s}: (empty response)`;
      })
      .join("; ");
    throw new Error(
      `WHOIS returned no usable records for ${JSON.stringify(target)} — ${errs || "no servers contacted"}`,
    );
  }
  const best = firstResult(result) as DomainWhoisData & Record<string, unknown>;
  if (!best || !entryHasUsableData(best)) {
    // firstResult picked an error-only entry even though usable ones exist;
    // fall back to the first usable entry directly.
    const fallback = result[usable[0] as string] as DomainWhoisData &
      Record<string, unknown>;
    return normalizeDomain(target, { [usable[0] as string]: fallback });
  }
  const whoisServer = serverNames.find((s) => result[s] === best) ?? undefined;
  const expires = pickIsoDate(
    best,
    "Registry Expiry Date",
    "Registrar Registration Expiration Date",
    "Expiry Date",
    "Expiration Date",
    "Expires On",
    "paid-till",
  );
  return stripUndef({
    target,
    kind: "domain" as const,
    registrar: pickFirstString(best, "Registrar", "Sponsoring Registrar"),
    nameservers: pickStringArray(best, "Name Server", "nserver")?.map((n) =>
      n.toLowerCase(),
    ),
    statusCodes: pickStringArray(best, "Domain Status", "status"),
    created: pickIsoDate(
      best,
      "Creation Date",
      "Created On",
      "Registered On",
      "created",
    ),
    updated: pickIsoDate(
      best,
      "Updated Date",
      "Last Updated On",
      "changed",
      "last-update",
    ),
    expires,
    daysRemaining: daysFromNow(expires),
    dnssec: pickFirstString(best, "DNSSEC", "dnssec"),
    abuseContact: pickFirstString(
      best,
      "Registrar Abuse Contact Email",
      "Registrar Abuse Contact",
      "Abuse Contact Email",
    ),
    registrant: pickFirstString(
      best,
      "Registrant Organization",
      "Registrant Name",
      "registrant",
    ),
    whoisServer,
  });
}

function flattenWhoisData(data: WhoisData): Record<string, unknown> {
  // whoiser's IP/ASN responses are shaped { fieldName: string|string[],
  // contacts: { roleName: { ... } }, __raw, __comments }. Flatten the
  // contacts groups into top-level keyed-by-role so the picker can find
  // e.g. "abuse-c email" without us hardcoding every shape.
  const flat: Record<string, unknown> = { ...data };
  if (data.contacts) {
    for (const [role, fields] of Object.entries(data.contacts)) {
      if (fields && typeof fields === "object") {
        for (const [k, v] of Object.entries(fields)) {
          flat[`${role} ${k}`] = v;
        }
      }
    }
  }
  return flat;
}

export function normalizeIp(
  target: string,
  result: WhoisData,
): NormalizedIpWhois {
  const flat = flattenWhoisData(result);
  return stripUndef({
    target,
    kind: "ip" as const,
    network: pickFirstString(
      flat,
      "inetnum",
      "inet6num",
      "CIDR",
      "NetRange",
      "route",
    ),
    organization: pickFirstString(
      flat,
      "OrgName",
      "Organization",
      "org-name",
      "owner",
      "netname",
      "descr",
    ),
    country: pickFirstString(flat, "Country", "country"),
    asn: pickFirstString(flat, "OriginAS", "origin", "aut-num"),
    abuseContact: pickFirstString(
      flat,
      "abuse email",
      "abuse e-mail",
      "abuse abuse-mailbox",
      "abuse-mailbox",
      "OrgAbuseEmail",
      "abuse-c email",
      "abuse-c e-mail",
    ),
    allocationType: pickFirstString(flat, "NetType", "status"),
    whoisServer: pickFirstString(flat, "source"),
  });
}

export function normalizeAsn(
  target: string,
  result: WhoisData,
): NormalizedAsnWhois {
  const flat = flattenWhoisData(result);
  return stripUndef({
    target,
    kind: "asn" as const,
    name: pickFirstString(flat, "ASName", "as-name", "owner"),
    organization: pickFirstString(flat, "OrgName", "Organization", "org-name"),
    country: pickFirstString(flat, "Country", "country"),
    registry: pickFirstString(flat, "source"),
    allocationDate: pickIsoDate(flat, "RegDate", "created"),
    // `whoisServer` is intentionally NOT populated from `source`. The
    // `source` field is the registry NAME (e.g. "ARIN"), not a server
    // hostname; the prior code surfaced "ARIN" under whoisServer and
    // misled anyone trying to follow up with a direct port-43 query.
  });
}

function stripUndef<T extends Record<string, unknown>>(obj: T): T {
  for (const k of Object.keys(obj)) {
    if (obj[k] === undefined) delete obj[k];
  }
  return obj;
}

export interface WhoisLookupOptions {
  timeoutMs?: number;
  server?: string;
  // whoiser only accepts 1 or 2 for follow; we accept 0 at the tool
  // schema level (callers shouldn't have to remember the literal pair)
  // and treat 0 as "use default referral behaviour" — that's what
  // whoiser does when follow is unset.
  follow?: 0 | 1 | 2;
}

// Errors that come back from RDAP and should NOT trigger a WHOIS fallback —
// they're real "the registry says this target doesn't exist" answers, not
// transport failures.
const RDAP_AUTHORITATIVE_ERRORS = [/RDAP 404/];

function isRdapAuthoritative(err: unknown): boolean {
  const msg = toMessage(err);
  return RDAP_AUTHORITATIVE_ERRORS.some((re) => re.test(msg));
}

export async function lookupWhois(
  target: ClassifiedTarget,
  opts: WhoisLookupOptions = {},
): Promise<NormalizedWhois> {
  const timeout = opts.timeoutMs ?? 10_000;
  // RDAP-first dispatch. Only the explicit `server` override or an
  // authoritative 404 short-circuits the fallback — anything else (no
  // bootstrap entry, transport error, malformed JSON) drops to whoiser so
  // the small number of legacy-only TLDs keep working.
  if (target.kind === "domain") {
    if (!opts.server) {
      try {
        return await lookupDomainRdap(target.normalized, timeout);
      } catch (e) {
        if (isRdapAuthoritative(e)) throw e;
      }
    }
    const raw = await whoisDomain(target.normalized, {
      timeout,
      ...(opts.server ? { host: opts.server } : {}),
      ...(opts.follow ? { follow: opts.follow } : {}),
    });
    return normalizeDomain(target.normalized, raw);
  }
  if (target.kind === "ip") {
    if (!opts.server) {
      try {
        return await lookupIpRdap(target.normalized, timeout);
      } catch (e) {
        if (isRdapAuthoritative(e)) throw e;
      }
    }
    const raw = await whoisIp(target.normalized, {
      timeout,
      ...(opts.server ? { host: opts.server } : {}),
    });
    return normalizeIp(target.normalized, raw);
  }
  const asnNum = Number(target.normalized);
  if (!Number.isFinite(asnNum)) {
    throw new Error(`invalid ASN value: ${target.normalized}`);
  }
  if (!opts.server) {
    try {
      return await lookupAsnRdap(asnNum, timeout);
    } catch (e) {
      if (isRdapAuthoritative(e)) throw e;
    }
  }
  const raw = await whoisAsn(asnNum, {
    timeout,
    ...(opts.server ? { host: opts.server } : {}),
  });
  return normalizeAsn(`AS${target.normalized}`, raw);
}
