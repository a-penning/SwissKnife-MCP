import type { IncomingHttpHeaders, Server } from "node:http";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type AppConfig, createApp } from "../src/http.js";

interface Reply {
  status: number;
  headers: IncomingHttpHeaders;
}

function request(
  port: number,
  opts: {
    host?: string;
    origin?: string;
    method?: string;
    path?: string;
  },
): Promise<Reply> {
  const { host, origin, method = "POST", path = "/mcp" } = opts;
  const headers: Record<string, string> = {
    "content-type": "application/json",
  };
  if (host !== undefined) headers.Host = host;
  if (origin !== undefined) headers.Origin = origin;
  return new Promise<Reply>((resolve, reject) => {
    const req = http.request(
      { host: "127.0.0.1", port, path, method, headers },
      (res) => {
        res.resume();
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, headers: res.headers }),
        );
      },
    );
    req.on("error", reject);
    if (method === "POST") {
      req.end(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }));
    } else {
      req.end();
    }
  });
}

function boot(
  config: AppConfig = {},
): Promise<{ server: Server; port: number }> {
  return new Promise((resolve) => {
    const server = createApp(config).listen(0, "127.0.0.1", () => {
      resolve({ server, port: (server.address() as AddressInfo).port });
    });
  });
}

function close(server: Server): Promise<void> {
  return new Promise((resolve, reject) =>
    server.close((e) => (e ? reject(e) : resolve())),
  );
}

describe("http: DNS-rebinding / origin guard (default loopback allow-list)", () => {
  let server: Server;
  let port: number;
  beforeAll(async () => {
    ({ server, port } = await boot());
  });
  afterAll(() => close(server));

  // Loopback hostnames are always allowed, regardless of port (the rebinding
  // threat is the foreign *hostname*, not the port the client used).
  it.each(["localhost", "127.0.0.1", "127.0.0.1:9999", "[::1]"])(
    "allows POST /mcp with Host %j and no Origin",
    async (host) => {
      const { status } = await request(port, { host });
      expect(status).not.toBe(403);
    },
  );

  // A page served from any other hostname that resolves to loopback/LAN must be
  // rejected — this is the rebinding/CSRF defense.
  it.each(["evil.com", "attacker.test", "169.254.169.254", "example.com"])(
    "rejects POST /mcp with foreign Host %j",
    async (host) => {
      const { status } = await request(port, { host });
      expect(status).toBe(403);
    },
  );

  it("rejects an allowed Host when an Origin is present and not allow-listed", async () => {
    const { status } = await request(port, {
      host: "127.0.0.1",
      origin: "https://evil.com",
    });
    expect(status).toBe(403);
  });

  it("allows an allowed Host with no Origin header (non-browser client)", async () => {
    const { status } = await request(port, { host: "localhost" });
    expect(status).not.toBe(403);
  });

  it.each(["/", "/healthz"])(
    "does not guard GET %j (foreign Host still served)",
    async (path) => {
      const { status } = await request(port, {
        host: "evil.com",
        method: "GET",
        path,
      });
      expect(status).toBe(200);
    },
  );
});

describe("http: origin guard with explicit allow-lists", () => {
  let server: Server;
  let port: number;
  beforeAll(async () => {
    ({ server, port } = await boot({
      host: "0.0.0.0",
      allowedHosts: ["swissknife.example.com:8443"],
      allowedOrigins: ["https://app.example.com"],
    }));
  });
  afterAll(() => close(server));

  it("admits the configured Host (port ignored)", async () => {
    const { status } = await request(port, { host: "swissknife.example.com" });
    expect(status).not.toBe(403);
  });

  it("still admits loopback alongside the configured Host", async () => {
    const { status } = await request(port, { host: "127.0.0.1" });
    expect(status).not.toBe(403);
  });

  it("rejects a Host outside the allow-list", async () => {
    const { status } = await request(port, { host: "other.example.com" });
    expect(status).toBe(403);
  });

  it("admits the configured Origin", async () => {
    const { status } = await request(port, {
      host: "swissknife.example.com",
      origin: "https://app.example.com",
    });
    expect(status).not.toBe(403);
  });

  it("rejects an Origin outside the allow-list", async () => {
    const { status } = await request(port, {
      host: "swissknife.example.com",
      origin: "https://evil.example.com",
    });
    expect(status).toBe(403);
  });
});

describe("http: rate limiting on POST /mcp", () => {
  let server: Server;
  let port: number;
  beforeAll(async () => {
    ({ server, port } = await boot({ rateLimitPerMinute: 2 }));
  });
  afterAll(() => close(server));

  it("429s once the per-window limit is exceeded", async () => {
    const a = await request(port, { host: "127.0.0.1" });
    const b = await request(port, { host: "127.0.0.1" });
    const c = await request(port, { host: "127.0.0.1" });
    expect(a.status).not.toBe(429);
    expect(b.status).not.toBe(429);
    expect(c.status).toBe(429);
  });

  it("does not rate-limit GET /healthz", async () => {
    for (let i = 0; i < 5; i++) {
      const { status } = await request(port, {
        host: "127.0.0.1",
        method: "GET",
        path: "/healthz",
      });
      expect(status).toBe(200);
    }
  });
});

describe("http: rate limiting disabled (limit 0)", () => {
  let server: Server;
  let port: number;
  beforeAll(async () => {
    ({ server, port } = await boot({ rateLimitPerMinute: 0 }));
  });
  afterAll(() => close(server));

  it("never 429s", async () => {
    for (let i = 0; i < 6; i++) {
      const { status } = await request(port, { host: "127.0.0.1" });
      expect(status).not.toBe(429);
    }
  });
});

describe("http: security headers on GET /", () => {
  let server: Server;
  let port: number;
  beforeAll(async () => {
    ({ server, port } = await boot());
  });
  afterAll(() => close(server));

  it("sets hardening headers on the index page", async () => {
    const { status, headers } = await request(port, {
      host: "127.0.0.1",
      method: "GET",
      path: "/",
    });
    expect(status).toBe(200);
    expect(headers["x-content-type-options"]).toBe("nosniff");
    expect(headers["x-frame-options"]).toBe("DENY");
    expect(headers["referrer-policy"]).toBe("no-referrer");
    expect(String(headers["content-security-policy"])).toMatch(
      /default-src 'none'/,
    );
  });
});
