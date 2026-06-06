# Embargo — Project Build Plan (master)

This is the top-level plan for building Embargo from its current state (**docs only, no code**) to a
working defensive dependency firewall. It sequences the components, defines the contracts between
them, and points to the per-component sub-plans.

Read `CLAUDE.md` and `docs/ARCHITECTURE.md` first — they are authoritative. This plan turns them
into a build order. Each sub-plan under `docs/plans/` expands one component.

## Where we are

The repository contains only documentation (`CLAUDE.md`, `README.md`, `docs/ARCHITECTURE.md`,
`docs/SIGNALS.md`, `docs/DEVELOPMENT.md`, `CONTRIBUTING.md`, `SECURITY.md`) and the committed
console design reference (`docs/design/console-prototype/`). None of the six components in the repo
layout exist yet:

```
/engine     Rust — Policy & Signal Engine (the core)          — NOT STARTED
/gateway    L1 — Verdaccio plugin (Node/TS)                   — NOT STARTED
/admission  L2 — CI gate (GitHub Action / CLI, TS)            — NOT STARTED
/sandbox    L3 — install runner + eBPF (Rust)                 — NOT STARTED
/console    Web admin UI (React + TS)                         — PLANNED (docs/CONSOLE_PLAN.md)
/policy     Policy schema + example policies (DSL)            — NOT STARTED
```

## The non-negotiable principles (every sub-plan inherits these)

From `CLAUDE.md`:
1. **The engine is the product; the proxy is plumbing.** All policy/signal logic lives in `/engine`.
   The gateway/admission/sandbox are thin enforcement points that ask the engine for verdicts.
2. **Default to HOLD, never auto-DENY on weak signals.** FP rate is the primary product metric.
3. **Score chains, not single facts.** Signals compose; they emit weighted findings, not verdicts.
4. **Never weaken a gate to make a test pass.** A correctly-held version failing a test = wrong test.
5. **Defensive only.** Nothing that helps evade the gate or exfiltrate data.

The **verdict model** (ALLOW / HOLD / DENY) and the rule that a version flagged during a cooldown
HOLD escalates to a *permanent* DENY are load-bearing and appear in every layer.

## Component dependency graph

```
            ┌─────────────┐
            │   /policy    │  schema + example policies (DSL)
            │  (canonical) │  consumed by engine, admission, console
            └──────┬───────┘
                   │ defines rules + JSON Schema
                   ▼
            ┌─────────────┐      RPC contract (the seam)
            │   /engine    │◄───────────────────────────┐
            │  (the brain) │                             │
            └──┬───────┬───┘                             │
   verdicts/   │       │  events/containment             │
   RPC + store │       │                                 │
        ┌──────▼──┐ ┌──▼────────┐ ┌──────────┐ ┌─────────┴────┐
        │/gateway │ │/admission │ │ /sandbox │ │   /console   │
        │  (L1)   │ │   (L2)    │ │   (L3)   │ │ reads store+ │
        │         │ │           │ │          │ │  engine API  │
        └─────────┘ └───────────┘ └──────────┘ └──────────────┘
```

`/policy` is the foundation (everyone needs the rule schema). `/engine` is the brain. The other four
are clients of the engine (over RPC) and/or the shared state store.

## The central contract: the engine RPC + data model

Everything hinges on the engine's interface. Lock this early; the other components are written
against it. Recommended (confirm at implementation):

- **Transport:** gRPC via `tonic` (typed, streaming-capable, good Rust+TS codegen) over a local
  socket / internal address (`EMBARGO_ENGINE_RPC`). A JSON-over-HTTP fallback is acceptable for the
  MVP if gRPC tooling slows things down — keep the message shapes identical either way.
- **Core call (hot path):** `Resolve(package, version, requester) -> { verdict, reason, signals[],
  score, expires_at }`. Must be cache-first (Redis); no uncached network in this path.
- **Bulk call:** `ResolvePackument(package, versions[]) -> map<version, Verdict>` so the gateway can
  filter a whole packument in one round-trip.
- **Event ingest:** `ReportEvent(containment_event | install_signal)` from the sandbox (L3).
- **Admin/read API (for console):** queue, dashboard aggregates, policies (CRUD), approvals
  (request/grant/expire), inspector, audit — these can be a separate read/write API surface backed
  by the same store.

**Data model** (Postgres; from `ARCHITECTURE.md` §Data model — implement as migrations in `/engine`):
`policies`, `verdicts` (package,version → verdict, reason, signals[], computed_at, expires_at),
`signals`, `approvals` (time-boxed, status), `audit` (immutable, hash-chained, exportable). Redis
holds the verdict cache keyed by (package, version).

## Recommended build order (mapped to the ARCHITECTURE roadmap phases)

### Phase 0 — MVP (beats native cooldown on day one)
Goal: a client points `.npmrc` at the gateway and held versions disappear from resolution, with a
minimal console to approve/deny.
1. **`/policy`** — schema + JSON Schema + 1–2 example policies (most-specific-wins, cooldown,
   fast-track). Small but unblocks everyone. → `docs/plans/policy.md`
2. **`/engine` (core slice)** — workspace scaffold, Postgres migrations + Redis cache, policy
   resolution (most-specific-wins + glob), cooldown verdicts, the RPC server (`Resolve` /
   `ResolvePackument`), audit writes. No signals yet. → `docs/plans/engine.md`
3. **`/gateway`** — Verdaccio + plugin: intercept packument, call engine, strip HOLD/DENY from
   `versions`/`time`, cache, and the pinned-but-held → clear-error path. → `docs/plans/gateway.md`
4. **`/console` (MVP slice)** — queue + approve/deny wired to the engine read/write API (the rest of
   the screens follow in Phase 1). → `docs/CONSOLE_PLAN.md`
5. **Infra** — `docker-compose.yml` (gateway + engine + postgres + redis + console), `.env.example`
   with the vars from `DEVELOPMENT.md`, and CI (cargo fmt/clippy/test, TS lint/build/test).

### Phase 1 — Differentiator: signal gating
6. **`/engine` (signals)** — pure signal detectors + composite chains from `docs/SIGNALS.md`
   (start: `new_lifecycle_script`, `binding_gyp_introduced`, `provenance_missing`, `advisory_match`),
   tarball/manifest diffing, external feeds (OSV / GH Advisory), verdict escalation (HOLD→DENY,
   advisory = auto-DENY), each with a benign+malicious fixture pair.
7. **`/console` (full)** — remaining five screens + role gating + dry-run, per `docs/CONSOLE_PLAN.md`.
8. **`/engine`** — provenance enforcement (npm OIDC attestation verification).

### Phase 2 — Enforcement + containment
9. **`/admission` (L2)** — lockfile-diff CI gate (GitHub Action + CLI), diff-aware, exception
   workflow against the shared approvals store. → `docs/plans/admission.md`
10. **`/sandbox` (L3)** — namespaced/seccomp `npm ci` runner with egress allowlist; phone-home
    postinstall blocked and reported to the engine as a high-weight signal. → `docs/plans/sandbox.md`

### Phase 3 — Depth
11. **`/sandbox`** — eBPF (`aya`) runtime chain detection (secret read → serialize → egress).
12. **`/console`** — RBAC + OIDC SSO; **infra** — Helm chart.

## Cross-cutting conventions (from CLAUDE.md / DEVELOPMENT.md / CONTRIBUTING.md)

- **Rust:** edition 2021+, `cargo fmt` + `cargo clippy -- -D warnings` clean, errors via
  `thiserror`/`anyhow`, **no `unwrap()` in non-test code**, **no `unsafe` outside `/sandbox`** (and
  justified per-block there).
- **TypeScript:** strict mode, no unexplained `any`, ESLint + Prettier clean.
- **Commits:** Conventional Commits scoped by layer (`feat(engine):`, `feat(gateway):`, …).
- **Tests:** every signal ships a benign + malicious fixture pair; gateway resolution changes need an
  integration test; engine scoring functions are pure and unit-tested. Never weaken a gate to pass.
- **Docs:** update `CLAUDE.md` "Build / test / run" and `docs/DEVELOPMENT.md` whenever a component's
  commands become real. Keep both accurate — Claude Code relies on them.
- **Secrets:** `.env` (gitignored); never commit tokens, registry creds, or attestation keys.

## Plan index

| Component | Plan | Phase | Status |
|---|---|---|---|
| Policy schema / DSL | `docs/plans/policy.md` | 0 | planned |
| Engine (Rust core) | `docs/plans/engine.md` | 0 → 1 | planned |
| Gateway (L1) | `docs/plans/gateway.md` | 0 | planned |
| Console (React+TS) | `docs/CONSOLE_PLAN.md` | 0 → 1 | planned |
| Admission (L2) | `docs/plans/admission.md` | 2 | planned |
| Sandbox (L3) | `docs/plans/sandbox.md` | 2 → 3 | planned |

> These are living documents. As a component is built, fold the real commands into `CLAUDE.md` /
> `DEVELOPMENT.md` and update the status column here.
