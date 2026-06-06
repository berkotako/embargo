# Development

Local setup and workflow. Keep this accurate — Claude Code relies on the commands here.

## Prerequisites

- Rust (stable, edition 2021+) — engine, sandbox
- Node.js LTS + npm — gateway, console, admission
- Docker + Docker Compose — full local stack
- Postgres 15+ and Redis 7+ (provided by compose, or run your own)

## First-time setup

```bash
cp .env.example .env        # fill in the vars below
docker compose up -d postgres redis
cd engine && cargo build
cd ../gateway && npm ci
cd ../console && npm ci
```

## Environment variables

| Var | Used by | Purpose |
|---|---|---|
| `EMBARGO_UPSTREAM` | gateway | upstream registry (default `https://registry.npmjs.org`) |
| `EMBARGO_ENGINE_RPC` | gateway, admission | address of the engine RPC service |
| `DATABASE_URL` | engine, console | Postgres connection string |
| `REDIS_URL` | engine | verdict cache |
| `OSV_API` / `GH_ADVISORY_TOKEN` | engine | external advisory feeds |

Never commit `.env`. Never commit registry creds or attestation keys.

## Running the stack

```bash
docker compose up           # gateway + engine + postgres + redis + console
# gateway on :4873 (Verdaccio default), console on :3000, engine RPC internal
```

Point a client at the local gateway to test end to end:

```bash
echo "registry=http://localhost:4873/" > /tmp/proj/.npmrc
cd /tmp/proj && npm install <some-package>   # resolves through Embargo
```

## Per-component commands

```bash
# Engine
cd engine
cargo test
cargo clippy -- -D warnings
cargo fmt --check

# Gateway
cd gateway
npm run build
npm test
npm run lint

# Console
cd console
npm run dev      # local dev server
npm run build
npm test
```

## Testing philosophy

- Every signal has a benign + malicious fixture pair (see `docs/SIGNALS.md`).
- Engine scoring functions are pure (no I/O) and unit-tested in isolation.
- Gateway has an integration test that asserts a HELD version is stripped from the packument and a
  pinned-but-held version yields a clear Embargo error (not `ETARGET`).
- Never weaken a gate or fixture to make a test pass. A test failing on a correctly-held version
  means the test is wrong.

## Before opening a PR

1. Tests pass for every component you touched.
2. `cargo clippy -- -D warnings` and `cargo fmt --check` clean (Rust).
3. Lint + Prettier clean (TS).
4. Conventional Commit messages, scoped by layer (`feat(gateway): ...`).
5. New signals include fixtures and tests.
6. Docs updated if behavior or commands changed — especially `CLAUDE.md` and this file.

## Security note

This is defensive tooling. Do not add anything that helps evade the gate, exfiltrate data, or
weaken a verdict. Report suspected vulnerabilities per `SECURITY.md` (do not open public issues for
them).
