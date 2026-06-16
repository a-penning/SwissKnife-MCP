# Security Policy

## Supported versions

SwissKnife MCP is early-alpha (`0.x`). Only the latest `main` / most recent
release receives security fixes.

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Report privately via GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability):
open the repository's **Security → Report a vulnerability** form. We'll
acknowledge receipt and work with you on a fix and disclosure timeline.

## Scope notes

The server is **unauthenticated by design** and ships outbound primitives
(`http`, `dns`, `inspect`). Running it exposed to untrusted networks without a
proxy is a deployment mistake, not a vulnerability — see
[`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md). The optional
`SWISSKNIFE_BLOCK_PRIVATE_NETWORKS` SSRF guard, the `Host`/`Origin` allow-list,
and the per-IP rate limit are the relevant hardening controls.
