import { lookup as dnsLookup } from "node:dns";
import { lookup } from "node:dns/promises";
import { Agent } from "undici";
import { toMessage } from "./errors.js";

/**
 * Optional SSRF guard for outbound requests (the `http` tool and every
 * `inputUrl` fetcher). Off by default so the documented "probe your localhost
 * health route" use case keeps working; operators hosting the server on a
 * public box set SWISSKNIFE_BLOCK_PRIVATE_NETWORKS to refuse requests that
 * resolve to loopback / private / link-local addresses (e.g. the cloud
 * metadata endpoint 169.254.169.254).
 */
export function ssrfGuardEnabled(): boolean {
  const v = process.env.SWISSKNIFE_BLOCK_PRIVATE_NETWORKS;
  return (
    v !== undefined && v !== "" && v !== "0" && v.toLowerCase() !== "false"
  );
}

export function isBlockedIpv4(ip: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return false;
  const octets = m.slice(1).map(Number) as [number, number, number, number];
  if (octets.some((n) => n > 255)) return false;
  const [a, b] = octets;
  if (a === 0) return true; // 0.0.0.0/8 "this host"
  if (a === 127) return true; // loopback
  if (a === 10) return true; // private
  if (a === 169 && b === 254) return true; // link-local (incl. metadata)
  if (a === 172 && b >= 16 && b <= 31) return true; // private
  if (a === 192 && b === 168) return true; // private
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64/10
  return false;
}

export function isBlockedIp(ip: string): boolean {
  const addr = ip.toLowerCase();
  if (isBlockedIpv4(addr)) return true;
  const mapped = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(addr);
  if (mapped) return isBlockedIpv4(mapped[1] as string);
  if (addr === "::1" || addr === "::") return true; // loopback / unspecified
  const first = Number.parseInt(addr.split(":")[0] || "", 16);
  if (Number.isNaN(first)) return false;
  if ((first & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
  if ((first & 0xfe00) === 0xfc00) return true; // fc00::/7 unique-local
  return false;
}

/**
 * Throws when the guard is on and the host resolves to a blocked address.
 *
 * This is the eager, friendly-error pre-check used by the fetch sites. The
 * authoritative gate that actually closes the DNS-rebinding window is
 * {@link guardedFetch}, whose connector screens the exact address it dials —
 * see the note there. Use this for a clear up-front error; rely on
 * `guardedFetch` for the connect-time guarantee.
 */
async function assertHostAllowed(host: string): Promise<void> {
  if (!ssrfGuardEnabled()) return;
  // IPv6 literals arrive bracketed (`[::1]`) from URL.hostname; strip so
  // both blocklist and dns.lookup see the bare address.
  const bare =
    host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
  // Short-circuit IP literals — `dns.lookup` resolves them to themselves,
  // but a caller passing an IP directly (e.g. dns resolver param) wants
  // a synchronous check without paying for that round-trip.
  if (isBlockedIp(bare)) {
    throw new Error(
      `blocked request to private/loopback address ${bare} — SSRF guard is on; unset SWISSKNIFE_BLOCK_PRIVATE_NETWORKS to allow`,
    );
  }
  let resolved: Array<{ address: string }>;
  try {
    resolved = await lookup(bare, { all: true });
  } catch (e) {
    throw new Error(
      `cannot resolve host ${JSON.stringify(host)}: ${toMessage(e)}`,
    );
  }
  for (const { address } of resolved) {
    if (isBlockedIp(address)) {
      throw new Error(
        `blocked request to private/loopback address ${address} (host ${JSON.stringify(host)}) — SSRF guard is on; unset SWISSKNIFE_BLOCK_PRIVATE_NETWORKS to allow`,
      );
    }
  }
}

/** URL-shaped variant of {@link assertHostAllowed}. */
export async function assertUrlAllowed(url: URL): Promise<void> {
  await assertHostAllowed(url.hostname);
}

/**
 * DNS resolver that doubles as the SSRF gate: it resolves the host and refuses
 * the whole connection if *any* returned address is blocked, otherwise hands
 * the resolved addresses straight to the connector. Because the addresses
 * screened here are the exact ones undici dials, there is no resolve-then-
 * connect gap — this closes the DNS-rebinding TOCTOU that a separate
 * `assertUrlAllowed` + `fetch` pair leaves open.
 */
function guardedLookup(
  hostname: string,
  _options: unknown,
  callback: (
    err: Error | null,
    addresses: Array<{ address: string; family: number }>,
  ) => void,
): void {
  dnsLookup(hostname, { all: true }, (err, resolved) => {
    if (err) {
      callback(err, []);
      return;
    }
    const blocked = resolved.find((r) => isBlockedIp(r.address));
    if (blocked) {
      callback(
        new Error(
          `blocked request to private/loopback address ${blocked.address} (host ${JSON.stringify(hostname)}) — SSRF guard is on; unset SWISSKNIFE_BLOCK_PRIVATE_NETWORKS to allow`,
        ),
        [],
      );
      return;
    }
    callback(
      null,
      resolved.map((r) => ({ address: r.address, family: r.family })),
    );
  });
}

let guardedAgent: Agent | undefined;
function getGuardedAgent(): Agent {
  if (!guardedAgent) {
    guardedAgent = new Agent({ connect: { lookup: guardedLookup } });
  }
  return guardedAgent;
}

/**
 * `fetch` wrapper that pins DNS resolution under the SSRF guard. With the guard
 * off it is plain `fetch` (the documented "probe localhost" path is untouched).
 * With it on, requests go through an undici dispatcher whose connector screens
 * and dials the resolved IP in one step — so a record that flips to a private
 * address between check and connect can't slip through. TLS SNI and certificate
 * validation still use the URL hostname, not the pinned IP.
 */
export function guardedFetch(
  url: string | URL,
  init?: RequestInit,
): Promise<Response> {
  if (!ssrfGuardEnabled()) return fetch(url, init);
  return fetch(url, {
    ...init,
    dispatcher: getGuardedAgent(),
  } as RequestInit);
}
