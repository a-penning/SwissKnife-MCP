// vitest globalSetup: generate the self-signed test certificate the
// inspect-cert tests need. Generating it at test-time (instead of
// committing the .pem) keeps key material — even the throwaway test
// kind — out of the public repo history.
//
// Idempotent: skips regeneration if the fixture already exists, so
// re-runs are fast.

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const CERT_PATH = join(here, "test-cert.pem");

export default function setup(): void {
  if (existsSync(CERT_PATH)) return;
  mkdirSync(dirname(CERT_PATH), { recursive: true });
  try {
    execFileSync(
      "openssl",
      [
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        "/dev/null",
        "-out",
        CERT_PATH,
        "-days",
        "3650",
        "-subj",
        "/C=GB/O=SwissKnife Test/CN=test.swissknife.local",
        "-addext",
        "subjectAltName=DNS:test.swissknife.local",
      ],
      { stdio: "pipe" },
    );
  } catch (e) {
    throw new Error(
      `failed to generate ${CERT_PATH} via openssl — install openssl (or pre-populate the file). underlying: ${e instanceof Error ? e.message : String(e)}`,
    );
  }
}
