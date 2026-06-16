import { readFileSync } from "node:fs";
import { defineConfig } from "tsup";

// Single source of truth for the version is package.json. tsup inlines it
// at build time so the running server's /healthz, MCP server-info, and any
// other VERSION reference can't drift from the package.
const { version } = JSON.parse(
  readFileSync(new URL("./package.json", import.meta.url), "utf8"),
) as { version: string };

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  clean: true,
  banner: { js: "#!/usr/bin/env node" },
  define: {
    __SWISSKNIFE_VERSION__: JSON.stringify(version),
  },
});
