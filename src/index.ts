import { createApp } from "./http.js";

function cliArg(name: string): string | undefined {
  const index = process.argv.indexOf(`--${name}`);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

// Default port 12345 matches the mapping in docker-compose.yml and the example
// .mcp.json in README/DEPLOYMENT. `npm run dev` overrides this with PORT=6789 so
// the watch-mode dev server doesn't clash with a running container.
const port = Number(cliArg("port") ?? process.env.PORT ?? 12345);
const host = cliArg("host") ?? process.env.HOST ?? "127.0.0.1";

if (!Number.isInteger(port) || port < 0 || port > 65535) {
  console.error(`invalid port: ${cliArg("port") ?? process.env.PORT}`);
  process.exit(1);
}

const app = createApp({ host });
const httpServer = app.listen(port, host, () => {
  console.error(`swissknife-mcp listening on http://${host}:${port}/mcp`);
});

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    httpServer.close(() => process.exit(0));
    // force-exit if connections refuse to drain
    setTimeout(() => process.exit(0), 3000).unref();
  });
}
