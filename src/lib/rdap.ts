// RDAP (Registration Data Access Protocol) — RFC 7480/9082/9083.
//
// Why this exists: `whoiser` (our other WHOIS backend) is port-43 only,
// and a growing number of TLDs (.dev, .app, .page, most post-2014 gTLDs,
// every RIR for IP/ASN data) publish only RDAP. IANA hosts canonical
// bootstrap files mapping TLDs / IPv4 / IPv6 / ASN ranges to RDAP base
// URLs; we fetch them on first use, cache for the process lifetime, and
// use them to pick the right server for each lookup.
//
// We parse the RFC 9083 JSON ourselves rather than pulling another dep —
// the shape is small, well-specified, and the same across every RIR/
// registry. Coverage of unusual fields (e.g. roid, lang) is intentionally
// omitted; we extract the canonical subset our normaliser surfaces.

import { daysFromNow } from "./datetime.js";
import { cidrContains } from "./net.js";
import { assertUrlAllowed, guardedFetch, ssrfGuardEnabled } from "./ssrf.js";
import type {
  NormalizedAsnWhois,
  NormalizedDomainWhois,
  NormalizedIpWhois,
} from "./whois.js";

const BOOTSTRAP_URLS = {
  dns: "https://data.iana.org/rdap/dns.json",
  ipv4: "https://data.iana.org/rdap/ipv4.json",
  ipv6: "https://data.iana.org/rdap/ipv6.json",
  asn: "https://data.iana.org/rdap/asn.json",
} as const;

type BootstrapKind = keyof typeof BOOTSTRAP_URLS;

interface BootstrapFile {
  services: Array<[string[], string[]]>;
}

// IANA updates the bootstrap registries infrequently; cache for a few hours so
// a single poisoned-but-well-formed response can't stick for the whole process
// lifetime, while normal lookups still avoid re-fetching on every call.
const CACHE_TTL_MS = 6 * 60 * 60 * 1000;
const cache = new Map<
  BootstrapKind,
  { fetchedAt: number; value: Promise<BootstrapFile> }
>();

async function loadBootstrap(
  kind: BootstrapKind,
  timeoutMs: number,
): Promise<BootstrapFile> {
  const existing = cache.get(kind);
  if (existing && Date.now() - existing.fetchedAt < CACHE_TTL_MS) {
    return existing.value;
  }
  const p = (async () => {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), timeoutMs);
    try {
      // Hardcoded data.iana.org URLs, but still honour the guard so a
      // hostile DNS resolver / hosts file can't redirect bootstrap to an
      // internal address.
      const bootstrapUrl = new URL(BOOTSTRAP_URLS[kind]);
      await assertUrlAllowed(bootstrapUrl);
      const res = await guardedFetch(bootstrapUrl, {
        signal: ctl.signal,
        redirect: ssrfGuardEnabled() ? "manual" : "follow",
      });
      if (ssrfGuardEnabled() && res.status >= 300 && res.status < 400) {
        throw new Error(
          `IANA RDAP bootstrap (${kind}) responded with redirect ${res.status}; refusing to follow while SSRF guard is on`,
        );
      }
      if (!res.ok) {
        throw new Error(
          `IANA RDAP bootstrap fetch (${kind}) failed: HTTP ${res.status}`,
        );
      }
      const j = (await res.json()) as BootstrapFile;
      if (!j || !Array.isArray(j.services)) {
        throw new Error(`IANA RDAP bootstrap (${kind}) is malformed`);
      }
      // Shape sanity check: the DNS registry must cover the ubiquitous `com`
      // TLD. A well-formed-but-truncated/poisoned response that drops it would
      // otherwise be cached and silently fail every subsequent lookup.
      if (kind === "dns") {
        const hasCom = j.services.some(([tags]) =>
          tags.some((tag) => tag.toLowerCase() === "com"),
        );
        if (!hasCom) {
          throw new Error(
            "IANA RDAP bootstrap (dns) is missing the 'com' TLD — refusing a suspect response",
          );
        }
      }
      return j;
    } finally {
      clearTimeout(t);
    }
  })();
  // Drop failed lookups so the next call retries.
  p.catch(() => cache.delete(kind));
  cache.set(kind, { fetchedAt: Date.now(), value: p });
  return p;
}

function tldOf(domain: string): string {
  const i = domain.lastIndexOf(".");
  return i === -1 ? domain : domain.slice(i + 1).toLowerCase();
}

async function findDomainRdapBase(
  domain: string,
  timeoutMs: number,
): Promise<string | null> {
  const tld = tldOf(domain);
  const boot = await loadBootstrap("dns", timeoutMs);
  for (const [tags, urls] of boot.services) {
    if (tags.some((t) => t.toLowerCase() === tld)) {
      const url = urls.find((u) => u.startsWith("https://")) ?? urls[0];
      return url ? ensureTrailingSlash(url) : null;
    }
  }
  return null;
}

async function findIpRdapBase(
  ip: string,
  timeoutMs: number,
): Promise<string | null> {
  const kind: BootstrapKind = ip.includes(":") ? "ipv6" : "ipv4";
  const boot = await loadBootstrap(kind, timeoutMs);
  let bestPrefix = -1;
  let bestUrl: string | null = null;
  for (const [cidrs, urls] of boot.services) {
    for (const cidr of cidrs) {
      const prefix = Number(cidr.split("/")[1] ?? "0");
      if (prefix <= bestPrefix) continue;
      let contained = false;
      try {
        contained = cidrContains(cidr, ip);
      } catch {
        continue;
      }
      if (contained) {
        bestPrefix = prefix;
        bestUrl = urls.find((u) => u.startsWith("https://")) ?? urls[0] ?? null;
      }
    }
  }
  return bestUrl ? ensureTrailingSlash(bestUrl) : null;
}

async function findAsnRdapBase(
  asn: number,
  timeoutMs: number,
): Promise<string | null> {
  const boot = await loadBootstrap("asn", timeoutMs);
  for (const [ranges, urls] of boot.services) {
    for (const range of ranges) {
      const [loStr, hiStr] = range.includes("-")
        ? range.split("-", 2)
        : [range, range];
      const lo = Number(loStr);
      const hi = Number(hiStr);
      if (!Number.isFinite(lo) || !Number.isFinite(hi)) continue;
      if (asn >= lo && asn <= hi) {
        const url = urls.find((u) => u.startsWith("https://")) ?? urls[0];
        return url ? ensureTrailingSlash(url) : null;
      }
    }
  }
  return null;
}

function ensureTrailingSlash(url: string): string {
  return url.endsWith("/") ? url : `${url}/`;
}

interface RdapResponse {
  [k: string]: unknown;
}

async function rdapFetch(
  url: string,
  timeoutMs: number,
): Promise<RdapResponse> {
  // The base URL is registry-supplied via IANA bootstrap and registries
  // legitimately redirect (e.g. `domain/foo` → canonical case). Follow up
  // to RDAP_REDIRECT_HOPS hops, re-validating each one against the SSRF
  // guard so the chain can't tunnel into private space.
  let currentUrl = url;
  for (let hop = 0; hop <= RDAP_REDIRECT_HOPS; hop++) {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), timeoutMs);
    let res: Response;
    try {
      await assertUrlAllowed(new URL(currentUrl));
      res = await guardedFetch(currentUrl, {
        signal: ctl.signal,
        headers: { Accept: "application/rdap+json" },
        redirect: "manual",
      });
    } finally {
      clearTimeout(t);
    }
    if (res.status >= 300 && res.status < 400) {
      const location = res.headers.get("location");
      if (!location) {
        throw new Error(
          `RDAP redirect ${res.status} at ${currentUrl} has no Location header`,
        );
      }
      if (hop === RDAP_REDIRECT_HOPS) {
        throw new Error(
          `RDAP redirect chain exceeded ${RDAP_REDIRECT_HOPS} hops starting at ${url}`,
        );
      }
      const next = new URL(location, currentUrl);
      // RFC 7480 §5.1 mandates HTTPS for RDAP; refuse a downgrade so a
      // redirect can't drop us onto plaintext (or a non-web scheme).
      if (next.protocol !== "https:") {
        throw new Error(
          `RDAP redirect to non-https URL ${JSON.stringify(next.toString())} refused`,
        );
      }
      currentUrl = next.toString();
      continue;
    }
    if (res.status === 404) {
      throw new Error(`RDAP 404 — target not found at ${currentUrl}`);
    }
    if (!res.ok) {
      throw new Error(`RDAP HTTP ${res.status} at ${currentUrl}`);
    }
    const text = await res.text();
    try {
      return JSON.parse(text) as RdapResponse;
    } catch {
      throw new Error(`RDAP response from ${currentUrl} was not valid JSON`);
    }
  }
  // The for-loop always returns or throws inside; this is unreachable.
  throw new Error(`RDAP fetch fell through redirect loop at ${url}`);
}

const RDAP_REDIRECT_HOPS = 3;

// --- RDAP JSON parsing -----------------------------------------------------

// vcardArray is shaped: ["vcard", [[propName, params, type, value], ...]].
// Extract a single property's string value by name.
function vcardProp(vcardArray: unknown, propName: string): string | undefined {
  if (!Array.isArray(vcardArray) || vcardArray.length < 2) return undefined;
  const props = vcardArray[1];
  if (!Array.isArray(props)) return undefined;
  for (const p of props) {
    if (
      Array.isArray(p) &&
      typeof p[0] === "string" &&
      p[0].toLowerCase() === propName.toLowerCase() &&
      typeof p[3] === "string" &&
      p[3].length > 0
    ) {
      return p[3];
    }
  }
  return undefined;
}

interface RdapEntity {
  roles?: string[];
  vcardArray?: unknown;
  publicIds?: Array<{ type?: string; identifier?: string }>;
  entities?: RdapEntity[];
}

// Walk top-level + nested entities looking for a role match. RDAP allows
// "abuse" to be nested under "registrar", so we recurse one level.
function findEntitiesByRole(
  entities: RdapEntity[] | undefined,
  role: string,
): RdapEntity[] {
  if (!entities) return [];
  const out: RdapEntity[] = [];
  for (const e of entities) {
    if (e.roles?.some((r) => r.toLowerCase() === role.toLowerCase())) {
      out.push(e);
    }
    if (e.entities) {
      out.push(...findEntitiesByRole(e.entities, role));
    }
  }
  return out;
}

interface RdapEvent {
  eventAction?: string;
  eventDate?: string;
}

function findEvent(
  events: RdapEvent[] | undefined,
  action: string,
): string | undefined {
  if (!events) return undefined;
  for (const e of events) {
    if (e.eventAction?.toLowerCase() === action.toLowerCase()) {
      return e.eventDate;
    }
  }
  return undefined;
}

function toIso(dateStr: string | undefined): string | undefined {
  if (!dateStr) return undefined;
  const d = new Date(dateStr);
  return Number.isNaN(d.getTime()) ? dateStr : d.toISOString();
}

function stripUndef<T extends Record<string, unknown>>(obj: T): T {
  for (const k of Object.keys(obj)) {
    if (obj[k] === undefined) delete obj[k];
  }
  return obj;
}

export function parseRdapDomain(
  json: RdapResponse,
  target: string,
): NormalizedDomainWhois {
  const entities = json.entities as RdapEntity[] | undefined;
  const events = json.events as RdapEvent[] | undefined;
  const nameservers = (json.nameservers as Array<{ ldhName?: string }>) ?? [];
  const status = (json.status as string[]) ?? [];
  const secureDNS = json.secureDNS as
    | { delegationSigned?: boolean; zoneSigned?: boolean }
    | undefined;

  const [registrar] = findEntitiesByRole(entities, "registrar");
  const [abuseEntity] = findEntitiesByRole(entities, "abuse");
  const [registrant] = findEntitiesByRole(entities, "registrant");

  const expires = toIso(findEvent(events, "expiration"));

  return stripUndef({
    target,
    kind: "domain" as const,
    registrar: registrar ? vcardProp(registrar.vcardArray, "fn") : undefined,
    nameservers:
      nameservers.length > 0
        ? nameservers
            .map((n) => (n.ldhName ?? "").toLowerCase())
            .filter((s) => s.length > 0)
        : undefined,
    statusCodes: status.length > 0 ? status : undefined,
    created: toIso(findEvent(events, "registration")),
    updated: toIso(findEvent(events, "last changed")),
    expires,
    daysRemaining: daysFromNow(expires),
    dnssec: secureDNS
      ? secureDNS.delegationSigned
        ? "delegation-signed"
        : secureDNS.zoneSigned
          ? "zone-signed"
          : "unsigned"
      : undefined,
    abuseContact: abuseEntity
      ? vcardProp(abuseEntity.vcardArray, "email")
      : registrar
        ? vcardProp(registrar.vcardArray, "email")
        : undefined,
    registrant: registrant
      ? (vcardProp(registrant.vcardArray, "fn") ??
        vcardProp(registrant.vcardArray, "org"))
      : undefined,
    whoisServer: typeof json.port43 === "string" ? json.port43 : undefined,
  });
}

export function parseRdapIp(
  json: RdapResponse,
  target: string,
): NormalizedIpWhois {
  const entities = json.entities as RdapEntity[] | undefined;
  const [registrant] = findEntitiesByRole(entities, "registrant");
  const [abuseEntity] = findEntitiesByRole(entities, "abuse");

  // Prefer the CIDR form (RFC 9082 §5.5 / RFC 7483) when present, else
  // fall through to startAddress/endAddress range.
  const cidrs = json.cidr0_cidrs as
    | Array<{ v4prefix?: string; v6prefix?: string; length?: number }>
    | undefined;
  let network: string | undefined;
  if (cidrs && cidrs.length > 0) {
    const c = cidrs[0] as {
      v4prefix?: string;
      v6prefix?: string;
      length?: number;
    };
    const prefix = c.v4prefix ?? c.v6prefix;
    if (prefix && typeof c.length === "number") {
      network = `${prefix}/${c.length}`;
    }
  }
  if (!network && json.startAddress && json.endAddress) {
    network = `${json.startAddress} - ${json.endAddress}`;
  }

  return stripUndef({
    target,
    kind: "ip" as const,
    network,
    organization: registrant
      ? (vcardProp(registrant.vcardArray, "fn") ??
        vcardProp(registrant.vcardArray, "org"))
      : typeof json.name === "string"
        ? json.name
        : undefined,
    country: typeof json.country === "string" ? json.country : undefined,
    asn: undefined, // RDAP IP responses don't carry origin ASN
    abuseContact: abuseEntity
      ? vcardProp(abuseEntity.vcardArray, "email")
      : undefined,
    allocationType: typeof json.type === "string" ? json.type : undefined,
    whoisServer: typeof json.port43 === "string" ? json.port43 : undefined,
  });
}

export function parseRdapAsn(
  json: RdapResponse,
  target: string,
): NormalizedAsnWhois {
  const entities = json.entities as RdapEntity[] | undefined;
  const events = json.events as RdapEvent[] | undefined;
  const [registrant] = findEntitiesByRole(entities, "registrant");

  return stripUndef({
    target,
    kind: "asn" as const,
    name: typeof json.name === "string" ? json.name : undefined,
    organization: registrant
      ? (vcardProp(registrant.vcardArray, "fn") ??
        vcardProp(registrant.vcardArray, "org"))
      : undefined,
    country: typeof json.country === "string" ? json.country : undefined,
    registry: typeof json.port43 === "string" ? json.port43 : undefined,
    allocationDate: toIso(findEvent(events, "registration")),
  });
}

// --- Top-level dispatchers --------------------------------------------------

export async function lookupDomainRdap(
  domain: string,
  timeoutMs: number,
): Promise<NormalizedDomainWhois> {
  const base = await findDomainRdapBase(domain, timeoutMs);
  if (!base) {
    throw new Error(
      `no RDAP server registered with IANA for TLD .${tldOf(domain)}`,
    );
  }
  const json = await rdapFetch(`${base}domain/${domain}`, timeoutMs);
  return parseRdapDomain(json, domain);
}

export async function lookupIpRdap(
  ip: string,
  timeoutMs: number,
): Promise<NormalizedIpWhois> {
  const base = await findIpRdapBase(ip, timeoutMs);
  if (!base) {
    throw new Error(`no RDAP server registered with IANA for IP ${ip}`);
  }
  const json = await rdapFetch(`${base}ip/${ip}`, timeoutMs);
  return parseRdapIp(json, ip);
}

export async function lookupAsnRdap(
  asn: number,
  timeoutMs: number,
): Promise<NormalizedAsnWhois> {
  const base = await findAsnRdapBase(asn, timeoutMs);
  if (!base) {
    throw new Error(`no RDAP server registered with IANA for AS${asn}`);
  }
  const json = await rdapFetch(`${base}autnum/${asn}`, timeoutMs);
  return parseRdapAsn(json, `AS${asn}`);
}
