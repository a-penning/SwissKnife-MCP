# SwissKnife MCP

A self-hostable HTTP MCP server of deterministic developer utilities. This file
is the entry point — the detail lives in the docs below. Read the relevant one
before working in that area.

## Docs

- [`docs/AGENT-INSTRUCTIONS.md`](docs/AGENT-INSTRUCTIONS.md) — operating manual for LLM agents (include in your `CLAUDE.md` / `AGENTS.md`)
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — transport, server core, how tools are wired
- [`docs/TOOLS.md`](docs/TOOLS.md) — conventions for authoring tools (the rulebook, not a catalogue — for the live list, read `src/tools/*.ts` or call `tools/list`)
- [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) — local setup, scripts, adding a tool
- [`docs/TESTING-STRATEGY.md`](docs/TESTING-STRATEGY.md) — **read before writing or editing tests**
- [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) — Docker, npx, hosting, client config

## Conventions

- ⚠️ **Never increment the version without prior confirmation from the user.**
  The `version` in `package.json` (and any version references in docs) is a
  deliberate, user-owned decision — do not bump it as a side effect of any other
  change. Ask first, every time.
- **Verify before committing.** Run `npm run verify` (lint → typecheck → build →
  test). Don't use `--no-verify`, skip hooks, or force-push — fix the underlying
  issue instead.
- **Every code change ships with a test**, following `docs/TESTING-STRATEGY.md`:
  ranges over single values, positive *and* negative cases, expected values
  derived independently (never pasted from tool output).
- **Errors are values.** Handlers return errors via the `err()`/`ok()` helpers —
  never throw, never silently coerce or guess on malformed input. The promise is
  "results are never guessed"; honour it.
- **Parameter naming.** `input` / `inputUrl` for data the tool *transforms*;
  `value` / `host` / `url` for a *target* it looks up. We're early-alpha — rename
  to fit the convention rather than carrying compatibility aliases.
- **Keep docs in sync.** A capability that's documented but unimplemented (or
  vice versa) is a bug. Update the tool's `description` and any matching prose
  under `docs/` in the same change.
