import { type CaaRecord, promises as dnsPromises, Resolver } from "node:dns";
import { toMessage } from "./errors.js";

// Record types this server understands. We deliberately don't expose every
// rrtype Node knows about — these are the ones with stable structured
// shapes that callers actually use day-to-day.
export const RECORD_TYPES = [
  "A",
  "AAAA",
  "MX",
  "TXT",
  "CNAME",
  "NS",
  "SOA",
  "SRV",
  "CAA",
] as const;

export type RecordType = (typeof RECORD_TYPES)[number];

// Types fanned out when the caller doesn't pass a `type`. SRV and CAA are
// excluded because they're not interesting for most "show me everything
// about this host" queries and would just bloat the response with empties.
export const DEFAULT_FANOUT_TYPES: RecordType[] = [
  "A",
  "AAAA",
  "MX",
  "TXT",
  "CNAME",
  "NS",
  "SOA",
];

export interface ResolveOptions {
  type: RecordType;
  resolver?: string;
  timeoutMs: number;
}

// Public resolvers used to fall back on when the system stub can't answer
// a forward or reverse query (containerised environments and CGNAT'd
// networks often have stub resolvers that quietly drop or return NODATA
// for queries that upstream resolvers handle fine — e.g. SOA at apex,
// PTR for a public IP).
const PUBLIC_FALLBACK_RESOLVERS = ["1.1.1.1", "8.8.8.8"];

// Wraps Node's promise resolver with a manual timeout (the native API has
// no per-call timeout — only system-level retries). On timeout we cancel
// outstanding queries via Resolver.cancel() so we don't leak sockets.
//
// When no explicit `resolver` is supplied and the system stub answers
// ENODATA, retry against a public resolver. Some local stubs return
// NODATA for records (notably SOA at apex) that the upstream authoritative
// servers will happily return — silently treating that as "no records"
// would be a silent-wrong-answer.
export async function resolveOne(
  host: string,
  opts: ResolveOptions,
): Promise<unknown> {
  if (opts.resolver) {
    return resolveWithCustom(host, opts);
  }
  try {
    return await withTimeout(
      resolveByType(dnsPromises, host, opts.type),
      opts.timeoutMs,
      `dns ${opts.type} lookup for ${host}`,
    );
  } catch (e) {
    const code =
      e instanceof Error && "code" in e
        ? String((e as { code: unknown }).code)
        : "";
    if (code !== "ENODATA" && code !== "NODATA") throw e;
    for (const server of PUBLIC_FALLBACK_RESOLVERS) {
      try {
        const promised = wrapResolver(makeResolverRaw(server));
        return await withTimeout(
          resolveByType(promised, host, opts.type),
          opts.timeoutMs,
          `dns ${opts.type} lookup for ${host} via ${server}`,
        );
      } catch {
        // Try the next fallback. We only swallow ENODATA from the
        // fallback chain; the original error is re-thrown below if
        // every fallback also fails.
      }
    }
    throw e;
  }
}

function makeResolverRaw(server: string): Resolver {
  const r = new Resolver();
  r.setServers([server]);
  return r;
}

async function resolveWithCustom(
  host: string,
  opts: ResolveOptions,
): Promise<unknown> {
  const resolver = new Resolver();
  resolver.setServers([opts.resolver as string]);
  // The resolver exposes the same family of resolveX methods as the global,
  // but only via callbacks. Wrap them in a tiny promise adapter.
  const promised = wrapResolver(resolver);
  try {
    return await withTimeout(
      resolveByType(promised, host, opts.type),
      opts.timeoutMs,
      `dns ${opts.type} lookup for ${host} via ${opts.resolver}`,
      () => resolver.cancel(),
    );
  } finally {
    // No explicit close on Resolver; cancel() is the cleanup hook for
    // any in-flight queries we're abandoning.
  }
}

interface ResolverLike {
  resolve4(host: string): Promise<string[]>;
  resolve6(host: string): Promise<string[]>;
  resolveMx(
    host: string,
  ): Promise<Array<{ exchange: string; priority: number }>>;
  resolveTxt(host: string): Promise<string[][]>;
  resolveCname(host: string): Promise<string[]>;
  resolveNs(host: string): Promise<string[]>;
  resolveSoa(host: string): Promise<{
    nsname: string;
    hostmaster: string;
    serial: number;
    refresh: number;
    retry: number;
    expire: number;
    minttl: number;
  }>;
  resolveSrv(
    host: string,
  ): Promise<
    Array<{ name: string; port: number; priority: number; weight: number }>
  >;
  resolveCaa(host: string): Promise<CaaRecord[]>;
  reverse(ip: string): Promise<string[]>;
}

function wrapResolver(resolver: Resolver): ResolverLike {
  const promisify =
    <T>(
      method: (host: string, cb: (err: Error | null, res: T) => void) => void,
    ) =>
    (host: string): Promise<T> =>
      new Promise((resolve, reject) => {
        method.call(resolver, host, (err, res) =>
          err ? reject(err) : resolve(res),
        );
      });
  return {
    resolve4: promisify(resolver.resolve4),
    resolve6: promisify(resolver.resolve6),
    resolveMx: promisify(resolver.resolveMx),
    resolveTxt: promisify(resolver.resolveTxt),
    resolveCname: promisify(resolver.resolveCname),
    resolveNs: promisify(resolver.resolveNs),
    resolveSoa: promisify(resolver.resolveSoa),
    resolveSrv: promisify(resolver.resolveSrv),
    resolveCaa: promisify(resolver.resolveCaa),
    reverse: promisify(resolver.reverse),
  };
}

async function resolveByType(
  r: ResolverLike,
  host: string,
  type: RecordType,
): Promise<unknown> {
  switch (type) {
    case "A":
      return { addresses: await r.resolve4(host) };
    case "AAAA":
      return { addresses: await r.resolve6(host) };
    case "MX": {
      const records = await r.resolveMx(host);
      records.sort((a, b) => a.priority - b.priority);
      return { records };
    }
    case "TXT":
      // Each entry is a chunk array; the joined string is the common form
      // callers want. Surface both — joined for convenience, chunks for
      // anything that genuinely needs the wire format (e.g. DKIM keys
      // longer than 255 bytes that arrive split).
      return {
        records: (await r.resolveTxt(host)).map((chunks) => ({
          chunks,
          text: chunks.join(""),
        })),
      };
    case "CNAME": {
      // Node's resolveCname can return the queried name back when there is
      // no CNAME at apex (RFC 1034 forbids CNAME coexisting with other RR
      // types at the zone apex, so an apex lookup with no CNAME is just
      // empty). Treat the all-self answer as an empty result; don't filter
      // individual self-matches inside a real chain, since those would be
      // legitimate data.
      const targets = await r.resolveCname(host);
      const lowerHost = host.toLowerCase().replace(/\.$/, "");
      const everyTargetIsHost =
        targets.length > 0 &&
        targets.every((t) => t.toLowerCase().replace(/\.$/, "") === lowerHost);
      return everyTargetIsHost ? { targets: [], empty: true } : { targets };
    }
    case "NS":
      return { servers: await r.resolveNs(host) };
    case "SOA":
      return await r.resolveSoa(host);
    case "SRV": {
      const records = await r.resolveSrv(host);
      records.sort((a, b) => a.priority - b.priority || b.weight - a.weight);
      return { records };
    }
    case "CAA":
      return { records: await r.resolveCaa(host) };
  }
}

// Shape of the "no records of this type" result, matching the non-empty
// per-type shape's primary array field. The single-type and fan-out paths
// both surface this when ENODATA / NODATA comes back, so callers see a
// consistent empty result rather than a thrown error.
export function emptyResultForType(type: RecordType): Record<string, unknown> {
  switch (type) {
    case "A":
    case "AAAA":
      return { addresses: [] };
    case "CNAME":
      return { targets: [] };
    case "NS":
      return { servers: [] };
    case "MX":
    case "TXT":
    case "SRV":
    case "CAA":
      return { records: [] };
    case "SOA":
      // A live SOA result is a flat object — we mirror that here with
      // zero-valued fields so callers see the same shape whether the
      // zone has an SOA or not. (The previous `{ records: [] }` was
      // inconsistent with the non-empty shape.)
      return {
        nsname: "",
        hostmaster: "",
        serial: 0,
        refresh: 0,
        retry: 0,
        expire: 0,
        minttl: 0,
      };
  }
}

function makeResolver(server: string): ResolverLike {
  return wrapResolver(makeResolverRaw(server));
}

export async function reverseLookup(
  ip: string,
  opts: { resolver?: string; timeoutMs: number },
): Promise<{ hostnames: string[] }> {
  const tryReverse = async (r: ResolverLike): Promise<string[]> =>
    withTimeout(r.reverse(ip), opts.timeoutMs, `dns reverse lookup for ${ip}`);

  if (opts.resolver) {
    // Explicit resolver: caller asked for that one specifically, don't
    // silently swap to a public fallback if it fails.
    return { hostnames: await tryReverse(makeResolver(opts.resolver)) };
  }

  // No explicit resolver — try the system stub, then a public fallback
  // if it returns ENOTFOUND. The fallback only kicks in for "stub can't
  // answer this name" failures, not for transport / timeout errors,
  // which propagate as before.
  try {
    return { hostnames: await tryReverse(dnsPromises) };
  } catch (e) {
    const code =
      e instanceof Error && "code" in e
        ? String((e as { code: unknown }).code)
        : "";
    if (code !== "ENOTFOUND") throw e;
    for (const server of PUBLIC_FALLBACK_RESOLVERS) {
      try {
        return { hostnames: await tryReverse(makeResolver(server)) };
      } catch {
        // try the next fallback
      }
    }
    throw e; // re-throw the original ENOTFOUND if every fallback also failed
  }
}

function withTimeout<T>(
  work: Promise<T>,
  ms: number,
  label: string,
  onTimeout?: () => void,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      if (onTimeout) {
        try {
          onTimeout();
        } catch {
          // best-effort cancel; the rejection below is what the caller sees
        }
      }
      reject(new Error(`${label} timed out after ${ms}ms`));
    }, ms);
    work.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (err) => {
        clearTimeout(timer);
        reject(err);
      },
    );
  });
}

// Map Node's DNS error codes to a stable string the tool surface can return
// without leaking the underlying library's quirks. Anything we don't
// recognise comes back as the original code so callers can still act on it.
export function classifyDnsError(e: unknown): {
  code: string;
  message: string;
} {
  if (e instanceof Error && "code" in e) {
    const code = String((e as { code: unknown }).code);
    return { code, message: e.message };
  }
  return {
    code: "EUNKNOWN",
    message: toMessage(e),
  };
}
