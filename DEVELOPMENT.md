# Development

Local setup, run instructions, and the operational contract for every
component. Keep this accurate.

## Prerequisites

- **Rust** stable (edition 2021+) — `engine`, `sandbox`
- **protoc** (Protocol Buffers compiler) — the engine/sandbox build gRPC stubs
- **Node.js 20+** + npm — `gateway`, `console`, `admission`
- **Postgres 16** and **Redis 7** — engine state + verdict cache
- **openssl** — generating dev mTLS certs
- A Linux kernel with **unprivileged user namespaces** + **seccomp user-notify**
  for the `sandbox` (L3) — its containment tests are otherwise skipped

```bash
sudo apt-get install -y protobuf-compiler postgresql redis-server
```

## Repository layout

```
/policy      Policy schema (JSON Schema) + YAML DSL + examples
/engine      Rust workspace: embargo-core (pure logic) + embargo-engine (I/O)
/gateway     L1 Verdaccio plugin (TS) — packument rewriting
/admission   L2 CI gate (TS) — lockfile-diff check + GitHub Action
/sandbox     L3 containment (Rust) — namespaced, egress-controlled install runner
/console     Admin UI (React + Vite + TS)
/docs        Design docs; ARCHITECTURE.md is authoritative
```

## Quick start with Docker Compose

The fastest way to a running stack — Postgres + Redis + engine + console:

```bash
docker compose up --build
# console      → http://localhost:4000   (dev auth: pick a role at sign-in)
# admin API    → http://localhost:8080/api
# engine gRPC  → localhost:50051 (mTLS)  ·  metrics/health → :9090
```

What compose wires up:
- **certgen** generates dev mTLS material into a shared volume (idempotent).
- **engine** runs in `dev` auth mode and **self-seeds** `policy/examples/default.yaml`
  on first boot (via `EMBARGO__BOOTSTRAP_POLICY_PATH`), so resolve has a policy to
  enforce immediately. Health-gated startup, depends on db + redis + certgen.
- **console** is built with `VITE_AUTH_MODE=dev` and proxies `/api` → engine.
- **gateway** is Verdaccio + the Embargo filter, talking to the engine over the
  mTLS chain `certgen` issued. Point a client at it: `registry=http://localhost:4873/`.

The console signs you in with a role picker (`viewer` / `responder` / `admin`)
and the engine enforces RBAC on every call. For production, switch both to
`oidc` (engine `EMBARGO__AUTH__MODE=oidc` + JWKS; console `VITE_AUTH_MODE=oidc`
+ `VITE_OIDC_*`).

`certgen` runs `scripts/gen-dev-certs.sh` to mint a CA that signs the engine's
server cert and the gateway/admission/sandbox client certs — the same script you
can run locally (`scripts/gen-dev-certs.sh certs`) for non-Docker runs.

The rest of this doc covers running each component directly (no Docker).

## Engine

A Cargo workspace. `embargo-core` is pure (no I/O, fully unit-tested);
`embargo-engine` is the I/O shell (gRPC + Postgres + Redis + the JSON admin
facade for the console).

### Build & test

```bash
cd engine
export PROTOC=$(which protoc)

# Pure core — no services needed:
cargo test -p embargo-core

# Full build/clippy. sqlx verifies queries at compile time, so either point at a
# live, migrated DB…
export DATABASE_URL=postgres://postgres:postgres@localhost/embargo
cargo build && cargo clippy --all-targets -- -D warnings

# …or build offline against the committed query cache (engine/.sqlx):
SQLX_OFFLINE=true cargo build

# DB-backed integration tests (resolve, extractor, provenance, advisory, the
# HTTP facade, RBAC) are #[ignore]'d; run them against a live stack:
export EMBARGO_REDIS_URL=redis://localhost:6379
cargo test -p embargo-engine -- --include-ignored
```

After changing any SQL, regenerate the offline cache (`cargo install sqlx-cli`):
`cargo sqlx prepare --workspace`.

### Run

```bash
createdb embargo                       # migrations run automatically at startup

mkdir -p certs && cd certs             # dev mTLS for the gRPC listener
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout engine.key -out engine.crt -subj "/CN=localhost"
cp engine.crt ca.crt && cd ..

SQLX_OFFLINE=true \
EMBARGO__DATABASE__URL=postgres://postgres:postgres@localhost/embargo \
EMBARGO__REDIS__URL=redis://localhost:6379 \
EMBARGO__TLS__CERT_PEM=certs/engine.crt \
EMBARGO__TLS__KEY_PEM=certs/engine.key \
EMBARGO__TLS__CA_PEM=certs/ca.crt \
EMBARGO__OBSERVABILITY__LOG_FORMAT=pretty \
EMBARGO__AUTH__MODE=dev \
  ./target/debug/embargo-engine
```

The engine listens on three ports: **gRPC** (`50051`, mTLS — gateway / admission
/ sandbox), **admin HTTP/JSON** (`8080` — console), and **metrics/health**
(`9090` — `/metrics`, `/health/live`, `/health/ready`).

### Configuration

All config is `EMBARGO__`-prefixed env (double underscore nests), or a
`config/engine.{toml,yaml}` file.

| Key | Default | Purpose |
|---|---|---|
| `database.url` | — | Postgres connection string |
| `redis.url` | — | verdict cache |
| `grpc.addr` | `[::]:50051` | mTLS gRPC listener |
| `admin_http_addr` | `[::]:8080` | JSON admin facade (console) |
| `metrics_addr` | `[::]:9090` | Prometheus + health |
| `tls.{cert,key,ca}_pem` | — | gRPC mTLS material |
| `upstream_registry` | `https://registry.npmjs.org` | extractor source |
| `osv_endpoint` | `https://api.osv.dev` | advisory feed |
| `auth.mode` | `disabled` | `oidc` \| `dev` \| `disabled` |
| `auth.jwks_url` / `auth.jwks_inline` | — | OIDC verification keys |
| `auth.issuer` / `auth.audience` | — | OIDC token validation |
| `auth.roles_claim` / `auth.email_claim` | `roles` / `email` | claim mapping |
| `auth.admin_roles` / `auth.responder_roles` | `embargo-admin` / `embargo-responder` | role mapping |

> On a host without IPv6, set the `*_addr` values to `0.0.0.0:PORT`.

## Admin facade & auth

The console talks to the engine's JSON admin facade (`:8080/api/*`). Every
endpoint authenticates and enforces RBAC server-side (`viewer` / `responder` /
`admin`); the audit log records the real principal.

| Method | Path | Min role |
|---|---|---|
| GET | `/api/whoami` | any (establishes session) |
| GET | `/api/verdicts?verdict=hold\|deny` | viewer |
| GET | `/api/policies`, `/api/policies/dryrun` | viewer |
| GET | `/api/approvals` | viewer |
| POST | `/api/approvals` | responder |
| POST | `/api/approvals/{id}/revoke` | responder |
| GET | `/api/audit` | viewer |
| GET | `/api/dashboard` | viewer |
| GET | `/api/watchlist` | viewer |
| POST / PATCH / DELETE | `/api/watchlist[/{id}]` | admin |
| GET | `/api/known-malicious`, `/api/known-malicious/status` | viewer |
| POST | `/api/known-malicious`, `/api/known-malicious/remove`, `/api/known-malicious/sync` | admin |

**Auth modes** (`auth.mode`):
- `oidc` — verify an RS256 bearer JWT against the IdP JWKS; map a roles claim.
- `dev` — trust `X-Embargo-Role` / `X-Embargo-Email` headers (local only).
- `disabled` — open, treated as admin (logged loudly; never for production).

## Console

```bash
cd console
npm ci
npm run dev          # http://localhost:4000 ; proxies /api → :8080
npm run typecheck && npm run lint && npm run build
```

Env (Vite):

| Var | Purpose |
|---|---|
| `VITE_API_BASE` | API base (default `/api`, proxied in dev) |
| `VITE_AUTH_MODE` | `oidc` \| `dev` \| `disabled` (match the engine) |
| `VITE_OIDC_AUTHORITY` / `VITE_OIDC_CLIENT_ID` / `VITE_OIDC_SCOPE` | OIDC login |

On load the console handles any OIDC redirect, calls `/api/whoami`, and renders
the app with the server-enforced role (or the login screen).

## Gateway (L1)

```bash
cd gateway && npm ci
npm run typecheck && npm run lint && npm test
```

A Verdaccio plugin: intercepts the packument and strips HOLD/DENY versions via
`engine.ResolvePackument`. Point a client at it with one `.npmrc` line:
`registry=http://localhost:4873/`.

## Admission (L2)

```bash
cd admission && npm ci
npm run typecheck && npm run lint && npm test && npm run build
```

CLI: `embargo-admit --lockfile package-lock.json --base origin/main --engine
host:50051`. Also a GitHub Action (`admission/action.yml`). Supports
`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`.

## Sandbox (L3)

```bash
cd sandbox && export PROTOC=$(which protoc)
cargo test                       # pure unit tests
cargo test -- --include-ignored  # + real containment (needs userns)
```

Run an install under egress control:

```bash
./target/debug/embargo-sandbox run --allow 10.0.0.5 --detect-chain \
  --package left-pad --version 1.0.0 --engine host:50051 -- npm ci
```

## CI

`.github/workflows/ci.yml` runs every component: engine (fmt / clippy / test
offline + a Postgres+Redis integration job), gateway, admission, console,
sandbox (with the real containment test on a userns-capable runner), and policy
schema validation.

## Conventions

- **Rust:** `cargo fmt` + `cargo clippy -- -D warnings` clean; errors via
  `thiserror`/`anyhow`; no `unwrap()` in non-test code; `unsafe` only in
  `sandbox`, each block justified.
- **TypeScript:** strict mode; ESLint + Prettier clean; no `any` without a
  reason comment.
- **Commits:** Conventional Commits scoped by layer (`feat(engine): …`).
- **Signals:** every signal ships a benign + malicious fixture pair
  (`engine/fixtures/`); never weaken a gate to pass a test.

## Security

Defensive tooling only. Do not add anything that helps evade the gate,
exfiltrate data, or weaken a verdict. Report vulnerabilities per `SECURITY.md`.
