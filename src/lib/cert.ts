import { createHash, type X509Certificate } from "node:crypto";
import { lookup } from "node:dns/promises";
import { connect, type DetailedPeerCertificate } from "node:tls";
import { toMessage } from "./errors.js";
import { isBlockedIp, ssrfGuardEnabled } from "./ssrf.js";

// Compute the SHA-256 fingerprint of the SubjectPublicKeyInfo DER bytes
// (aka "SPKI pin", the form used in HTTP Public Key Pinning and the way
// most TLS-pinning libraries refer to a cert by its key). Returns the
// canonical colon-separated uppercase hex digest to match the existing
// SHA-1/SHA-256 cert fingerprints surfaced by inspect.
export function spkiFingerprintSha256(cert: X509Certificate): string {
  const spkiDer = cert.publicKey.export({ type: "spki", format: "der" });
  const digest = createHash("sha256").update(spkiDer).digest("hex");
  return formatColonHex(digest);
}

function formatColonHex(hex: string): string {
  const upper = hex.toUpperCase();
  const parts: string[] = [];
  for (let i = 0; i < upper.length; i += 2) parts.push(upper.slice(i, i + 2));
  return parts.join(":");
}

export interface FetchedChain {
  protocol: string | null; // e.g. "TLSv1.3" — null if the handshake didn't negotiate
  cipher: { name: string; version: string } | null;
  authorized: boolean;
  authorizationError?: string;
  // Each chain entry as a PEM string, leaf first.
  certificatesPem: string[];
}

export interface FetchTlsOptions {
  servername?: string;
  timeoutMs: number;
}

// Open a TLS connection long enough to see the peer's cert chain, then
// close. `rejectUnauthorized: false` because we are INSPECTING — a stale
// or self-signed chain is data, not an error. authorized + the error
// reason are surfaced separately so callers can act on validation state.
//
// SSRF: when the guard is on, resolve the host ourselves and dial the
// pinned IP. tls.connect would otherwise do its own lookup, opening a
// DNS-rebinding window between a separate check and the actual connect.
export async function fetchTlsChain(
  host: string,
  port: number,
  opts: FetchTlsOptions,
): Promise<FetchedChain> {
  // IPv6 literals reach us either bare (`::1`) or bracketed (`[::1]` from
  // a parsed URL). Strip the brackets so the blocklist regex matches and
  // tls.connect receives a form it can resolve.
  const bareHost =
    host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
  const isIpLiteral =
    /^\d+\.\d+\.\d+\.\d+$/.test(bareHost) || bareHost.includes(":");

  let dialHost = bareHost;
  if (ssrfGuardEnabled()) {
    if (isIpLiteral) {
      if (isBlockedIp(bareHost)) {
        throw new Error(
          `blocked TLS connection to private/loopback address ${bareHost} — SSRF guard is on; unset SWISSKNIFE_BLOCK_PRIVATE_NETWORKS to allow`,
        );
      }
    } else {
      let resolved: Array<{ address: string }>;
      try {
        resolved = await lookup(bareHost, { all: true });
      } catch (e) {
        throw new Error(
          `cannot resolve host ${JSON.stringify(bareHost)}: ${toMessage(e)}`,
        );
      }
      const blocked = resolved.find((r) => isBlockedIp(r.address));
      if (blocked) {
        throw new Error(
          `blocked TLS connection to private/loopback address ${blocked.address} (host ${JSON.stringify(bareHost)}) — SSRF guard is on; unset SWISSKNIFE_BLOCK_PRIVATE_NETWORKS to allow`,
        );
      }
      // Dial the resolved IP directly; SNI / servername still carry the
      // original host so the handshake completes against the right cert.
      dialHost = (resolved[0] as { address: string }).address;
    }
  }

  return new Promise((resolve, reject) => {
    let settled = false;
    const settle = (fn: () => void) => {
      if (settled) return;
      settled = true;
      fn();
    };

    // RFC 6066 forbids SNI on an IP literal; passing one trips a Node
    // deprecation warning and is ignored anyway. Only set SNI when the
    // host is a name.
    const servername = opts.servername ?? (isIpLiteral ? undefined : bareHost);
    const socket = connect({
      host: dialHost,
      port,
      ...(servername ? { servername } : {}),
      rejectUnauthorized: false,
      // ALPN: ask for anything reasonable so servers that require it still
      // hand us their cert. The list is a superset of typical browser ALPN.
      ALPNProtocols: ["h2", "http/1.1"],
    });

    const onTimeout = () => {
      settle(() =>
        reject(
          new Error(
            `TLS handshake to ${host}:${port} timed out after ${opts.timeoutMs}ms`,
          ),
        ),
      );
      socket.destroy();
    };
    socket.setTimeout(opts.timeoutMs, onTimeout);

    socket.once("error", (e) => {
      settle(() =>
        reject(
          new Error(
            `TLS connection to ${host}:${port} failed: ${toMessage(e)}`,
          ),
        ),
      );
    });

    socket.once("secureConnect", () => {
      try {
        // detailed=true walks the issuerCertificate chain. The Node typings
        // say `PeerCertificate | {}` (empty object when not authorized in
        // some legacy paths); guard accordingly.
        const peer = socket.getPeerCertificate(true);
        if (!peer || Object.keys(peer).length === 0) {
          settle(() =>
            reject(new Error(`no peer certificate from ${host}:${port}`)),
          );
          socket.end();
          return;
        }
        const chain = walkChain(peer);
        const cipher = socket.getCipher();
        settle(() =>
          resolve({
            protocol: socket.getProtocol(),
            cipher: cipher
              ? { name: cipher.name, version: cipher.version }
              : null,
            authorized: socket.authorized,
            ...(socket.authorizationError
              ? { authorizationError: String(socket.authorizationError) }
              : {}),
            certificatesPem: chain.map(certBufferToPem),
          }),
        );
      } catch (e) {
        settle(() => reject(e instanceof Error ? e : new Error(String(e))));
      } finally {
        socket.end();
      }
    });
  });
}

// Walk getPeerCertificate(true)'s issuerCertificate chain, deduping on
// raw DER so a self-signed root (whose issuerCertificate is itself)
// doesn't make us loop.
// A real chain is a handful of certs; cap the walk so a pathological peer
// can't make us emit an unbounded number of PEM blocks.
const MAX_CHAIN_CERTS = 10;

function walkChain(leaf: DetailedPeerCertificate): Buffer[] {
  const out: Buffer[] = [];
  const seen = new Set<string>();
  let current: DetailedPeerCertificate | undefined = leaf;
  while (current?.raw && out.length < MAX_CHAIN_CERTS) {
    const key = current.raw.toString("base64");
    if (seen.has(key)) break;
    seen.add(key);
    out.push(current.raw);
    const next: DetailedPeerCertificate | undefined = current.issuerCertificate;
    if (!next || next === current) break;
    current = next;
  }
  return out;
}

function certBufferToPem(buf: Buffer): string {
  const base64 = buf.toString("base64");
  const lines: string[] = [];
  for (let i = 0; i < base64.length; i += 64) {
    lines.push(base64.slice(i, i + 64));
  }
  return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----`;
}

// Parse a URL or host:port string into the connect target. Defaults to
// 443 when no port is provided, mirroring how every other tool treats
// HTTPS-flavoured inputs.
export function parseTlsTarget(value: string): {
  host: string;
  port: number;
  servername?: string;
} {
  let host = value;
  let port = 443;
  let servername: string | undefined;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) {
    let url: URL;
    try {
      url = new URL(value);
    } catch {
      throw new Error(`not a parseable URL: ${JSON.stringify(value)}`);
    }
    if (url.protocol !== "https:" && url.protocol !== "tls:") {
      throw new Error(
        `unsupported scheme ${JSON.stringify(url.protocol)} — tls inspection requires https:// or tls://`,
      );
    }
    host = url.hostname;
    port = url.port ? Number(url.port) : 443;
    servername = url.hostname;
  } else {
    const m = /^(.+?):(\d+)$/.exec(value);
    if (m) {
      host = m[1] as string;
      port = Number(m[2] as string);
    }
  }
  if (!host) {
    throw new Error(`could not extract a host from ${JSON.stringify(value)}`);
  }
  if (!Number.isFinite(port) || port < 1 || port > 65535) {
    throw new Error(`invalid port ${port} for ${JSON.stringify(value)}`);
  }
  return { host, port, servername };
}
