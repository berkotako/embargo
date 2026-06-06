# CLAUDE.md

Guidance for Claude Code when working in the Embargo repository.

## What Embargo is

Embargo is a **self-hosted, policy-enforcing npm registry gateway**. It sits in front of
`registry.npmjs.org` and *refuses to serve* dependency versions until they pass age, provenance,
and behavioral-signal checks. It is a **firewall that blocks**, not a scanner that warns after the
fact.

The one-line mental model: a client points `registry=` at Embargo; Embargo intercepts the
**packument** (`GET /{package}` metadata) and filters the `versions`/`time` maps so the client's
resolver never sees disallowed versions.

Scope of this repo (layers 1–3 + console):
- **L1 Ingress Gateway** — packument rewriting, cooldown, provenance enforcement, signal gating.
- **L2 Admission Control** — policy-as-code CI gate that fails builds violating policy.
- **L3 Containment** — sandboxed installs + (later) eBPF egress monitoring.
- **Console** — web admin for policy authoring, quarantine review, approvals, audit.

Read `docs/ARCHITECTURE.md` for the full design before making structural changes.

## Core principles (do not violate)

1. **The engine is the product; the proxy is plumbing.** Value lives in the Policy & Signal
   Engine. Do not reinvent the registry — the L1 gateway is built on Verdaccio (a proven MIT
   registry proxy), not from scratch. Engine logic must never leak into the proxy layer.
2. **Default to HOLD, never auto-DENY on weak signals.** False-positive rate is the primary
   product metric. New/uncertain signals quarantine for human review; they do not silently block.
   When in doubt, HOLD and surface the reason.
3. **Score chains, not single facts.** "Reads env vars" is benign alone. "new dep + reads env +
   new egress host" is a verdict. Signal logic composes; it does not match single APIs.
4. **Never weaken a gate to make a test pass.** If a test fails because a version is correctly
   held, the test is wrong, not the gate.
5. **This is defensive security tooling.** All code here detects/blocks malicious packages. Never
   add functionality that would help *evade* the gate or exfiltrate data.

## Repo layout

```
/engine        Rust — Policy & Signal Engine (the core). Scoring, tarball diffing, signal extraction.
/gateway       L1 — Verdaccio plugin (Node/TS) that calls the engine over local RPC.
/admission     L2 — CI gate: GitHub Action / CLI that evaluates lockfile diffs against policy.
/sandbox       L3 — namespaced/seccomp install runner; eBPF egress monitor (aya, later phase).
/console       Web admin UI (React + TS).
/policy        Policy schema + example policies (the per-scope DSL).
/docs          Design docs. ARCHITECTURE.md is authoritative.
```

## Verdict model (used everywhere)

Every package version resolves to exactly one verdict:
- **ALLOW** (green) — served normally.
- **HOLD** (amber) — stripped from the packument; re-evaluated when cooldown expires.
- **DENY** (red) — stripped permanently; surfaced in console.

A version flagged by a signal *during* its cooldown HOLD escalates to DENY — it is NOT silently
allowed when the timer expires. This is the whole point; do not regress it.

## Conventions

- **Rust (engine, sandbox):** edition 2021+. `cargo fmt` + `cargo clippy -- -D warnings` clean
  before commit. Errors via `thiserror`/`anyhow`; no `unwrap()` in non-test code. Keep `unsafe`
  out of the engine entirely; confine it to the sandbox crate with a comment justifying each block.
- **TypeScript (gateway, console, admission):** strict mode on. No `any` without a `// reason`
  comment. ESLint + Prettier clean before commit.
- **Commits:** Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`). Reference
  the layer in scope, e.g. `feat(gateway): strip held versions from packument`.
- **Tests:** every signal needs a fixture pair (a benign version + a malicious version that
  triggers it). Engine logic is not "done" without both. See `docs/SIGNALS.md`.
- **Secrets:** never commit tokens, registry creds, or attestation keys. Use `.env` (gitignored)
  and document required vars in `docs/DEVELOPMENT.md`.

## Build / test / run

> Fill these in as the toolchain solidifies; keep this section accurate — Claude Code relies on it.

```bash
# Engine (Rust)
cd engine && cargo build && cargo test && cargo clippy -- -D warnings

# Gateway (Verdaccio plugin)
cd gateway && npm ci && npm run build && npm test

# Console
cd console && npm ci && npm run dev   # local dev server

# Full local stack
docker compose up   # gateway + engine + postgres + redis + console
```

## When implementing a signal

1. Read `docs/SIGNALS.md` for the catalog and the scoring contract.
2. Add the detection in `/engine`, returning a weighted signal, never a hard verdict.
3. Add a benign + malicious fixture pair under `engine/fixtures/`.
4. The verdict (HOLD/DENY threshold) is policy-driven — do not hardcode block decisions in the
   signal itself.

## What NOT to do

- Do not bypass the packument-rewriting mechanism by patching clients or fighting the resolver.
- Do not hardcode `registry.npmjs.org` outside the gateway's uplink config — the upstream is
  configurable.
- Do not break existing lockfiles. A pinned-but-held version must produce a clear Embargo error
  with the approval link, never a cryptic resolver failure.
- Do not add network calls in the hot path (packument rewrite) that aren't cached — latency on
  resolve is user-facing.
