# Contributing

Thanks for your interest in SwissKnife MCP. The detailed guides live under
[`docs/`](docs/) — this file is the short version GitHub surfaces.

## Setup & workflow

- Local setup, scripts, and how to add a tool: [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md)
- How to write tests (read before adding any): [`docs/TESTING-STRATEGY.md`](docs/TESTING-STRATEGY.md)
- Authoring conventions for tools: [`docs/TOOLS.md`](docs/TOOLS.md)
- Architecture overview: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)

## Before opening a PR

- **Run `npm run verify`** (lint → typecheck → build → test) and make sure it passes.
- **Ship a test with every code change**, following the testing strategy:
  ranges over single values, positive *and* negative cases, expected values
  derived independently.
- **Don't bump the version.** `package.json`'s `version` is owned by the
  maintainer; leave it alone.
- Use [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `docs:`, `chore:`…).
- New runtime dependencies need a reason — the budget in
  [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) is deliberate.

By contributing you agree your work is licensed under the project's
[MIT License](LICENSE).
