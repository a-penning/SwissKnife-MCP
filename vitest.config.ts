import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts"],
    env: { LOG_LEVEL: "silent" },
    // Generates tests/fixtures/test-cert.pem on first run via openssl,
    // so the .pem (with its embedded public key) is never committed.
    globalSetup: ["./tests/fixtures/generate-cert.ts"],
  },
});
