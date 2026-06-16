import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import express, {
  type NextFunction,
  type Request,
  type Response,
} from "express";
import { escapeHtml } from "./lib/encode.js";
import { toMessage } from "./lib/errors.js";
import { buildServer, VERSION } from "./server.js";
import { tools } from "./tools/registry.js";

const LOG_LEVEL = process.env.LOG_LEVEL ?? "info";

/** Requests per minute per client IP on POST /mcp. Override with SWISSKNIFE_RATE_LIMIT; 0 disables. */
const DEFAULT_RATE_LIMIT_PER_MINUTE = 300;

function rateLimitPerMinute(): number {
  const raw = process.env.SWISSKNIFE_RATE_LIMIT;
  if (raw === undefined || raw === "") return DEFAULT_RATE_LIMIT_PER_MINUTE;
  const n = Number(raw);
  return Number.isInteger(n) && n >= 0 ? n : DEFAULT_RATE_LIMIT_PER_MINUTE;
}

export interface AppConfig {
  /** Bind address, used to seed the default Host allow-list. */
  host?: string;
  /**
   * Hostnames accepted in the `Host` header. Overrides `SWISSKNIFE_ALLOWED_HOSTS`
   * when provided. Matching is port-agnostic — only the hostname is compared.
   */
  allowedHosts?: string[];
  /**
   * Origins accepted in the `Origin` header. Overrides `SWISSKNIFE_ALLOWED_ORIGINS`
   * when provided. Requests with no `Origin` header (non-browser clients) pass.
   */
  allowedOrigins?: string[];
  /**
   * Per-IP requests/minute on POST /mcp. Overrides `SWISSKNIFE_RATE_LIMIT` when
   * provided; 0 disables. Defaults to {@link DEFAULT_RATE_LIMIT_PER_MINUTE}.
   */
  rateLimitPerMinute?: number;
}

const LOOPBACK_HOSTS = ["localhost", "127.0.0.1", "::1"];
const WILDCARD_HOSTS = new Set(["", "0.0.0.0", "::", "*"]);

function splitList(value: string | undefined): string[] {
  return (value ?? "")
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
}

/** Lowercased hostname from a `host:port` authority, with the port and IPv6 brackets stripped. */
function hostnameOf(authority: string): string {
  const value = authority.trim().toLowerCase();
  if (value.startsWith("[")) {
    const end = value.indexOf("]");
    return end === -1 ? value.slice(1) : value.slice(1, end);
  }
  const colon = value.indexOf(":");
  return colon === -1 ? value : value.slice(0, colon);
}

function buildAllowedHosts(config: AppConfig): Set<string> {
  const names = new Set(LOOPBACK_HOSTS);
  const bound = (config.host ?? "").trim().toLowerCase();
  if (!WILDCARD_HOSTS.has(bound)) names.add(hostnameOf(bound));
  const extra =
    config.allowedHosts ?? splitList(process.env.SWISSKNIFE_ALLOWED_HOSTS);
  for (const entry of extra) names.add(hostnameOf(entry));
  return names;
}

function buildAllowedOrigins(config: AppConfig): Set<string> {
  const extra =
    config.allowedOrigins ?? splitList(process.env.SWISSKNIFE_ALLOWED_ORIGINS);
  return new Set(extra.map((origin) => origin.toLowerCase()));
}

function forbid(res: Response, message: string): void {
  res.status(403).json({
    jsonrpc: "2.0",
    error: { code: -32000, message },
    id: null,
  });
}

/**
 * DNS-rebinding and browser-CSRF guard. A foreign page can resolve its own
 * hostname to a loopback/LAN address and POST to this server; the SDK transport
 * accepts any `Host`, so without this check the server is an open SSRF proxy
 * for anything that can reach the port. We reject unexpected `Host` hostnames
 * and, when present, disallowed `Origin` values. Requests with no `Origin`
 * (non-browser MCP clients) are allowed.
 */
/**
 * Fixed-window per-IP rate limiter for the one expensive endpoint. `script` and
 * `regex` can each tie up real CPU/memory, so an unthrottled client is a cheap
 * DoS. Health/index routes are deliberately left unlimited. For shared hosting,
 * prefer a rate limit at the reverse proxy too — and note `req.ip` is the proxy
 * unless Express `trust proxy` is configured.
 */
function rateLimiter(perMinute: number) {
  const WINDOW_MS = 60_000;
  const hits = new Map<string, { count: number; reset: number }>();
  let lastSweep = 0;
  return (req: Request, res: Response, next: NextFunction): void => {
    if (perMinute <= 0) {
      next();
      return;
    }
    const now = Date.now();
    if (now - lastSweep >= WINDOW_MS) {
      for (const [key, entry] of hits) {
        if (entry.reset <= now) hits.delete(key);
      }
      lastSweep = now;
    }
    const key = req.ip ?? "unknown";
    let entry = hits.get(key);
    if (!entry || entry.reset <= now) {
      entry = { count: 0, reset: now + WINDOW_MS };
      hits.set(key, entry);
    }
    entry.count++;
    if (entry.count > perMinute) {
      res.setHeader(
        "Retry-After",
        String(Math.ceil((entry.reset - now) / 1000)),
      );
      res.status(429).json({
        jsonrpc: "2.0",
        error: { code: -32000, message: "Too many requests" },
        id: null,
      });
      return;
    }
    next();
  };
}

function originGuard(allowedHosts: Set<string>, allowedOrigins: Set<string>) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const host = req.headers.host;
    if (host === undefined || !allowedHosts.has(hostnameOf(host))) {
      forbid(res, "Host header not allowed");
      return;
    }
    const origin = req.headers.origin;
    if (origin !== undefined && !allowedOrigins.has(origin.toLowerCase())) {
      forbid(res, "Origin not allowed");
      return;
    }
    next();
  };
}

/** Logs method + tool name + duration only — argument values may contain secrets. */
function logRequest(body: unknown, status: number, startedAt: number): void {
  if (LOG_LEVEL === "silent") return;
  const elapsed = Date.now() - startedAt;
  const requests = (Array.isArray(body) ? body : [body]).filter(
    (m): m is { method?: string; params?: { name?: string } } =>
      typeof m === "object" && m !== null && "method" in m,
  );
  for (const message of requests) {
    const tool =
      message.method === "tools/call" ? ` ${message.params?.name}` : "";
    console.error(`[mcp] ${message.method}${tool} -> ${status} (${elapsed}ms)`);
  }
}

function indexPage(): string {
  const rows = tools
    .map(
      (t) =>
        `<tr><td><code>${escapeHtml(t.name)}</code></td><td>${escapeHtml(t.title)}</td><td>${escapeHtml(t.description.split(". ")[0] ?? "")}.</td></tr>`,
    )
    .join("\n");
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>SwissKnife MCP</title>
<style>body{font:15px/1.5 -apple-system,sans-serif;max-width:880px;margin:2rem auto;padding:0 1rem;color:#222}
table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:.4rem .6rem;text-align:left}
code{background:#f4f4f4;padding:.1em .3em;border-radius:3px}</style></head>
<body><h1>🔧 SwissKnife MCP v${escapeHtml(VERSION)}</h1>
<p>Deterministic developer utilities over MCP. Endpoint: <code>POST /mcp</code> (Streamable HTTP, stateless). Health: <code>GET /healthz</code>.</p>
<table><tr><th>Tool</th><th>Title</th><th>Summary</th></tr>${rows}</table>
<p>Connect: <code>claude mcp add --transport http swissknife http://localhost:12345/mcp</code></p>
</body></html>`;
}

export function createApp(config: AppConfig = {}): express.Express {
  const app = express();
  app.use(express.json({ limit: "1mb" }));

  const allowedHosts = buildAllowedHosts(config);
  const allowedOrigins = buildAllowedOrigins(config);
  const limiter = rateLimiter(
    config.rateLimitPerMinute ?? rateLimitPerMinute(),
  );

  app.get("/healthz", (_req: Request, res: Response) => {
    res.json({ status: "ok", version: VERSION });
  });

  app.get("/", (_req: Request, res: Response) => {
    res
      .type("html")
      .set("X-Content-Type-Options", "nosniff")
      .set("X-Frame-Options", "DENY")
      .set("Referrer-Policy", "no-referrer")
      // The page is fully static bar one inline <style>; lock everything else down.
      .set(
        "Content-Security-Policy",
        "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'",
      )
      .send(indexPage());
  });

  // Stateless: fresh server+transport per request so concurrent clients
  // cannot collide on request IDs, and any replica can serve any request.
  app.post(
    "/mcp",
    limiter,
    originGuard(allowedHosts, allowedOrigins),
    async (req: Request, res: Response) => {
      const startedAt = Date.now();
      const server = buildServer();
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
      });
      res.on("close", () => {
        logRequest(req.body, res.statusCode, startedAt);
        void transport.close();
        void server.close();
      });
      try {
        await server.connect(transport);
        // We hand the SDK the already-parsed body (express.json, 1 MB cap).
        // That's fine for the stateless request/response tools here; a future
        // streaming protocol change would need to stop pre-buffering instead.
        await transport.handleRequest(req, res, req.body);
      } catch (error) {
        // Gate on LOG_LEVEL like the access log, and emit only the message —
        // never the full Error (stack/cause may echo request internals).
        if (LOG_LEVEL !== "silent") {
          const reason = toMessage(error);
          console.error(`[mcp] request failed: ${reason}`);
        }
        if (!res.headersSent) {
          res.status(500).json({
            jsonrpc: "2.0",
            error: { code: -32603, message: "Internal server error" },
            id: null,
          });
        }
      }
    },
  );

  const methodNotAllowed = (_req: Request, res: Response) => {
    res.status(405).json({
      jsonrpc: "2.0",
      error: { code: -32000, message: "Method not allowed: stateless server" },
      id: null,
    });
  };
  app.get("/mcp", methodNotAllowed);
  app.delete("/mcp", methodNotAllowed);

  return app;
}
