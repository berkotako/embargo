# Embargo — Project Build Plan (master)

Top-level plan for building Embargo as a **real, production-grade** defensive dependency firewall —
not a prototype or MVP. The repo is currently **docs only, no code**; this sequences the full build
and defines the contracts and production posture every component must meet.

Read `CLAUDE.md` and `docs/ARCHITECTURE.md` first (authoritative). This plan turns them into a build
order. Per-component detail lives in `docs/plans/`.

## Build philosophy (read this)

- **Production from day one, not "smallest thing that works."** Every component ships with HA,
  security, observability, tests, and docs as acceptance criteria — not follow-ups. A milestone is
  "done" only when it could run in production for a real org.
- **No throwaway slices.** Milestones are sequenced by dependency and each is independently
  deployable and operable, but each is built to the full quality bar (see "Definition of Done").
- The four **production pillars** below are cross-cutting and present from the **first** milestone,
  not bolted on later.

## Scope (locked with the user)

- **Single-org, self-hosted, production-HA.** Kubernetes + Helm is the primary deployment target;
  Docker Compose is for local dev. HA engine/gateway, Postgres + Redis with failover. **Not**
  multi-tenant (single-org isolation; multi-tenancy is explicitly out of scope for this build).
- **Pillars designed in from the start:** (1) **SSO + real RBAC**, (2) **full observability**,
  (3) **compliance reporting**, (4) **self supply-chain security** (Embargo dogfoods itself).

## Where we are

Only documentation exists. None of the six components are started:

```
/engine     Rust — Policy & Signal Engine (the core)          — NOT STARTED
/gateway    L1 — Verdaccio plugin (Node/TS)                   — NOT STARTED
/admission  L2 — CI gate (GitHub Action / CLI, TS)            — NOT STARTED
/sandbox    L3 — install runner + eBPF (Rust)                 — NOT STARTED
/console    Web admin UI (React + TS)                         — PLANNED (docs/CONSOLE_PLAN.md)
/policy     Policy schema + example policies (DSL)            — NOT STARTED
```

## Non-negotiable principles (from CLAUDE.md — every plan inherits these)

1. **The engine is the product; the proxy is plumbing.** All policy/signal logic in `/engine`.
2. **Default to HOLD, never auto-DENY on weak signals.** FP rate is the primary product metric.
3. **Score chains, not single facts.** Signals emit weighted findings; policy decides verdicts.
4. **Never weaken a gate to make a test pass.**
5. **Defensive only.** Nothing that helps evade the gate or exfiltrate data.

The verdict model (ALLOW / HOLD / DENY) and the rule that a version flagged during a cooldown HOLD
escalates to a **permanent** DENY are load-bearing in every layer.

## Component dependency graph

```
            ┌─────────────┐
            │   /policy    │  schema + example policies (DSL)
            └──────┬───────┘
                   ▼
   AuthZ/RBAC ┌─────────────┐      RPC + admin API (the seam, authenticated + RBAC'd)
   ───────────│   /engine    │◄──────────────────────────────┐
   OTel/metrics│ (the brain) │                                │
   ───────────└──┬───────┬───┘                                │
                 │       │  events/containment                │
        ┌────────▼─┐ ┌───▼───────┐ ┌──────────┐ ┌────────────┴─┐
        │ /gateway │ │/admission │ │ /sandbox │ │   /console   │
        │   (L1)   │ │   (L2)    │ │   (L3)   │ │ SSO + RBAC UI│
        └──────────┘ └───────────┘ └──────────┘ └──────────────┘
```

`/policy` is the foundation. `/engine` is the brain. The other four are authenticated clients of the
engine. AuthN/AuthZ, observability, and audit cross every edge.

## The central contract: engine RPC + admin API + data model

Lock this first; everything is written against it. Production requirements baked in:

- **Transport:** gRPC via `tonic`, **mutual TLS** between components, on `EMBARGO_ENGINE_RPC`. Every
  call carries an authenticated identity (service identity for gateway/sandbox/admission; user
  identity via OIDC for console) and is **authorized by RBAC** before execution.
- **Hot path:** `Resolve(pkg, version, requester)` and `ResolvePackument(pkg, versions[])` —
  cache-first (Redis), no uncached network in the resolve path, p99 latency under SLO.
- **Event ingest:** `ReportEvent(containment_event | install_signal)` from the sandbox.
- **Admin API (console):** queue, dashboard aggregates, policies CRUD, approvals (request/grant/
  expire, time-boxed), inspector, audit/export — all RBAC-gated, all audited.
- **Data model (Postgres):** `policies`, `verdicts`, `signals`, `approvals`, `audit`
  (immutable, hash-chained), plus `users`/`roles`/`sessions` for RBAC and access logs for compliance.
  Redis caches verdicts keyed by `package@version` (TTL = `expires_at`). All schema via versioned,
  reversible migrations.

## Production pillars (cross-cutting — apply to every component)

### 1. Security — AuthN / AuthZ
- **OIDC SSO** for human users (console). Pluggable provider (Okta/Entra/Auth0/Keycloak).
- **RBAC** enforced server-side in the engine admin API (not just hidden UI): roles `viewer`,
  `approver`, `admin` to start, modeled as role→permission so it extends. Every privileged action
  checks permission and writes an audit row. The console's role switcher becomes a real
  session/role, with a dev-only demo toggle behind a flag.
- **Service-to-service:** mTLS + scoped service identities for gateway/sandbox/admission → engine.
- **Secrets:** never in-repo; Vault or K8s Secrets/External-Secrets. Documented in `DEVELOPMENT.md`.

### 2. Observability
- **Tracing:** OpenTelemetry across gateway → engine → store, with the resolve path instrumented.
- **Metrics:** Prometheus — resolve latency (p50/p95/p99), cache hit ratio, verdict counts by type,
  **false-positive rate** (dismissed HOLDs), gate availability, feed freshness, queue depth.
- **Logging:** structured (JSON), correlation IDs, no secrets/PII.
- **Dashboards + alerting** on SLOs (below). Alerts page on SLO burn, feed staleness, gate errors.

### 3. Compliance reporting
- **Tamper-evident audit:** hash-chained rows (engine), with optional external anchoring; verified
  in the console. Append-only; no in-place edits.
- **Retention policies** + **signed exports** (CSV/JSON) for evidence. Access logs for every admin
  read/write. SOC2-style evidence surface in the console audit screen.

### 4. Self supply-chain security (dogfood)
- **SLSA provenance** for our own builds; **signed releases** (Sigstore/cosign); **SBOMs** (Syft)
  per artifact; **reproducible builds** where feasible; pinned, hash-locked dependencies.
- **Embargo gates its own dependencies** via the admission gate in our CI once it exists.

## Deployment & HA (single-org, production)

- **Kubernetes + Helm** primary; Docker Compose for local dev only.
- **Engine:** stateless, horizontally scalable behind a service; readiness/liveness probes; graceful
  shutdown; rolling deploys. **Gateway:** multi-replica behind an LB. **Sandbox:** isolated node
  pool / sandboxed runner.
- **Postgres:** primary + replica with automated failover (e.g. CloudNativePG/Patroni), PITR
  backups, tested restore. **Redis:** Sentinel or cluster; cache is rebuildable so failure degrades,
  not breaks.
- **DR:** documented RTO/RPO, backup/restore runbooks, periodic restore drills.

## SLOs (initial targets — tune on real traffic)

- Resolve hot-path p99 ≤ 50 ms (cache hit); packument rewrite adds ≤ small bounded overhead.
- Gateway availability ≥ 99.9%. A HELD-but-pinned version always yields a clear error, never `ETARGET`.
- Advisory feed freshness ≤ 15 min. False-positive rate tracked and trended (primary product metric).

## Testing strategy (all components)

- **Unit:** pure engine scoring functions; exhaustive. **Fixtures:** every signal ships a benign +
  malicious pair (`docs/SIGNALS.md`). **Integration:** gateway packument strip + pinned-held error;
  store/feeds. **E2E:** client `npm install` through the stack resolves correctly. **Load:** resolve
  path under target QPS meets SLO. **Chaos:** kill engine/PG/Redis replicas, assert graceful
  degradation. **Security:** fuzz detectors; red-team evasion suite (crafted packages that try to
  slip a known signal — must fail to evade); authz tests (every role × every privileged action).

## CI/CD & release engineering

- CI runs: `cargo fmt --check` + `clippy -D warnings` + tests (Rust); ESLint/Prettier + build +
  tests (TS); container builds; SBOM + provenance + signing on release; vulnerability scan.
- Trunk-based with protected `main`; Conventional Commits; automated versioning + changelog; signed,
  immutable release artifacts; Helm chart published per release.

## Definition of Done (per component)

Code + tests (unit/integration as applicable) green · clippy/lint clean · RBAC-enforced where it
exposes actions · traced + metered + structured-logged · audit rows for privileged actions ·
Helm-deployable with probes/limits · docs updated (`CLAUDE.md`, `DEVELOPMENT.md`, this plan's status).

## Build milestones (sequenced by dependency; each is production-grade & deployable)

> Pillars (SSO/RBAC, observability, compliance audit, self-supply-chain) and HA are present starting
> at **M1** — they are not a later milestone.

### M1 — Foundation, contracts, and a production firewall doing policy+cooldown
- Repo scaffolding (Cargo workspace; TS workspaces), CI/CD, Helm chart skeleton, Compose for dev,
  secrets + mTLS plumbing, OTel/metrics/logging baseline, OIDC SSO + RBAC scaffold.
- **`/policy`** schema + JSON Schema + examples. → `docs/plans/policy.md`
- **`/engine` core:** migrations, policy resolution (most-specific-wins + globs), cooldown,
  provenance gate, store + Redis cache, gRPC `Resolve`/`ResolvePackument`, RBAC'd admin API,
  hash-chained audit. → `docs/plans/engine.md`
- **`/gateway`:** packument rewriting, pinned-but-held clear error, hot-path cache. → `docs/plans/gateway.md`
- **`/console`:** SSO login, RBAC-gated queue + approvals on the real admin API; shell + remaining
  screens follow in M2. → `docs/CONSOLE_PLAN.md`

### M2 — Signal engine + full console (the differentiator)
- **`/engine`:** pure signal detectors + composite chains (`docs/SIGNALS.md`), tarball/manifest
  diffing, external feeds (OSV/GitHub Advisory), verdict escalation (HOLD→DENY, advisory = auto-DENY),
  npm OIDC **provenance verification** — each with benign+malicious fixtures and evasion tests.
- **`/console`:** all six screens, dry-run, dashboards; compliance audit/export surface.

### M3 — Pipeline admission + install containment
- **`/admission` (L2):** lockfile-diff CI gate (GitHub Action + CLI), diff-aware, exception workflow
  against the shared approvals store. → `docs/plans/admission.md`
- **`/sandbox` (L3):** namespaced/seccomp `npm ci` runner with egress allowlist; phone-home
  postinstall blocked + reported to the engine as a high-weight signal. → `docs/plans/sandbox.md`

### M4 — Runtime depth, scale, and compliance maturity
- **`/sandbox`:** eBPF (`aya`) runtime chain detection (secret read → serialize → egress).
- Autoscaling + perf hardening to SLO under load; DR drills; advanced compliance reporting
  (retention, signed evidence, external audit anchoring).

## Cross-cutting conventions (CLAUDE.md / DEVELOPMENT.md / CONTRIBUTING.md)

- **Rust:** edition 2021+, `cargo fmt` + `clippy -D warnings` clean, `thiserror`/`anyhow`, **no
  `unwrap()` in non-test code**, **no `unsafe` outside `/sandbox`** (justified per block there).
- **TypeScript:** strict, no unexplained `any`, ESLint + Prettier clean.
- **Commits:** Conventional Commits scoped by layer (`feat(engine):` …).
- **Tests:** signal fixtures (benign+malicious); gateway resolution integration tests; pure engine
  unit tests. Never weaken a gate to pass.
- **Docs:** keep `CLAUDE.md` "Build / test / run" and `DEVELOPMENT.md` accurate as commands become
  real. **Secrets:** `.env`/Vault, never committed.

## Plan index

| Component | Plan | First milestone | Status |
|---|---|---|---|
| Policy schema / DSL | `docs/plans/policy.md` | M1 | planned |
| Engine (Rust core) | `docs/plans/engine.md` | M1 → M2 | planned |
| Gateway (L1) | `docs/plans/gateway.md` | M1 | planned |
| Console (React+TS) | `docs/CONSOLE_PLAN.md` | M1 → M2 | planned |
| Admission (L2) | `docs/plans/admission.md` | M3 | planned |
| Sandbox (L3) | `docs/plans/sandbox.md` | M3 → M4 | planned |

> Living documents. As components are built, fold real commands into `CLAUDE.md`/`DEVELOPMENT.md`
> and update the status column.
