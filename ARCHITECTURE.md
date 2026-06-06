# Architecture

Authoritative design reference for Embargo. `CLAUDE.md` points here for structural decisions.

## Thesis

Time-based cooldown is now native in npm (`min-release-age`), pnpm, Yarn, and Bun, and is moving
to on-by-default. So "a proxy that adds a cooldown" is not a product. Embargo's defensible wedge is
what the package managers structurally won't do:

- **Per-registry / per-scope / per-package policy** (native cooldown is global; npm has no
  exclusion list).
- **Fast-track exceptions** for emergency CVE fixes.
- **Signal-based gating** — use the cooldown window to *evaluate* the version, not just delay it.
- **Pipeline admission control + install containment** — defense in depth past resolution time.

Embargo is **open + self-hosted + enforced as a gate that refuses to serve the version** — versus
closed SaaS scanners that warn after the fact.

## Component overview

```
Client (npm/pnpm/yarn/bun, .npmrc → registry=embargo)
        │  GET /{package}
        ▼
┌──────────────────────────────────────────────┐
│ L1 Ingress Gateway (Verdaccio plugin)         │
│   intercepts packument, applies verdicts      │
└───────────────┬──────────────────────────────┘
                │ RPC
                ▼
┌──────────────────────────────────────────────┐
│ Policy & Signal Engine (Rust) — the core      │
│   cooldown · provenance · signal scoring       │
└───┬───────────────┬───────────────┬───────────┘
    │               │               │
    ▼               ▼               ▼
 State store   External feeds   L2 / L3 enforcement
 (PG + Redis)  (OSV, advisory,  (admission gate,
               provenance)       sandbox runner)
                                      ▲
                                      │
                                Web Admin Console
                                (reads store + engine API)
```

The engine is the shared brain. L1/L2/L3 are enforcement points that ask it for verdicts and feed
it events. The console reads/writes the store and the engine API.

## L1 — Ingress Gateway

### Packument rewriting (the core mechanism)

All four package managers fetch the packument (`GET /{package}`: the `versions` map and `time`
map) before resolving. Embargo intercepts that response and filters the maps so the resolver never
sees disallowed versions. Per version, the engine returns ALLOW / HOLD / DENY:

- **ALLOW** — stays in the map.
- **HOLD** — stripped; reason recorded; auto re-evaluated when cooldown expires.
- **DENY** — stripped permanently; reason recorded; surfaced in console.

Why this works: it shapes the menu the resolver orders from rather than fighting the resolver, and
it's protocol-level so it's uniform across npm/pnpm/yarn/bun with one `.npmrc` line.

**Lockfile edge case:** a version already pinned in a lockfile but now HELD must produce a clear
Embargo error (reason + approval link), not a cryptic `ETARGET`. Degrade gracefully; never break
existing lockfiles.

**Hot-path rule:** packument rewrite is user-facing latency. Verdicts are cached in Redis;
no uncached network calls in this path.

### Cooldown (per-scope)

Most-specific-wins policy resolution. Example: `@mycompany/*` → 0d, `**` → 7d, with per-package
overrides and a fast-track allow list.

### Provenance enforcement

Per-policy, require a valid build-provenance attestation (npm OIDC trusted publishing) for
designated critical packages; DENY versions whose provenance is absent or unverifiable. Catches
review-bypass / out-of-pipeline publishes (e.g. orphan-commit attacks).

### Signal gating

During the HOLD window the engine scores age-independent signals (see `SIGNALS.md`) and can
escalate HOLD→DENY. A version flagged mid-cooldown is denied permanently rather than installed
when the timer expires. OSV / GitHub Advisory matches convert to DENY automatically.

## L2 — Admission Control

A pre-merge / pre-build check (GitHub Action / CLI) that fails the build when a **lockfile diff**
introduces a version violating policy (in-cooldown, unattested where required, advisory-flagged,
new install script vs. prior version).

- **Policy-as-code:** one central, version-controlled policy that repos inherit.
- **Exception workflow:** overrides only via logged, time-boxed approvals.
- **Diff-aware:** evaluate only what changed in the lockfile, so CI stays fast.

The attacks land in CI/CD, not laptops — so this is half the value, not polish.

## L3 — Containment

- **Sandboxed install:** run `npm ci` in a namespaced, egress-controlled environment (seccomp +
  network allowlist, or microVM). Install can only reach the gateway + allowed hosts; a phoning-
  home postinstall is blocked and recorded as a signal.
- **eBPF runtime monitoring (later phase):** watch node processes for the chain that signals
  compromise — secret/env read → serialize → egress to non-allowlisted host. A single syscall has
  no intent; the chain does.
- Containment events feed back as high-weight signals (sandbox egress attempt → auto-DENY).

## Data model (sketch)

- `policies` — scope pattern, cooldown, require_provenance, fast_track list, precedence.
- `verdicts` — (package, version) → verdict, reason, signals[], computed_at, expires_at.
- `signals` — per (package, version): type, weight, evidence, detected_at.
- `approvals` — verdict_id, requester, approver, justification, expires_at, status.
- `audit` — actor, action, target, before/after, timestamp (immutable, exportable).

## Tech stack

- **Engine / sandbox:** Rust. eBPF via `aya`.
- **Gateway:** Verdaccio + middleware plugin (Node/TS), engine over local RPC.
- **State:** Postgres (policy/verdicts/audit) + Redis (verdict cache).
- **Console:** React + TS.
- **Distribution:** Docker Compose (MVP) → Helm (later).

## Roadmap (phases)

- **Phase 0 — MVP:** packument rewriting + per-scope cooldown + fast-track list + minimal console
  (queue + approve/deny). Beats native cooldown on day one.
- **Phase 1 — Differentiator:** signal gating (start: new lifecycle script, binding.gyp,
  provenance, advisory match), HOLD→DENY escalation, full console, provenance enforcement.
- **Phase 2 — Enforcement + containment:** L2 admission gate, L3 sandboxed install.
- **Phase 3 — Depth:** eBPF chain detection, RBAC + OIDC SSO, Helm.

## Threat model (what L1–L3 cover)

| Threat | Defense |
|---|---|
| Token hijack → poisoned legit package (Axios, debug/chalk) | L1 cooldown + provenance + republish-anomaly signal |
| Self-propagating worm (Shai-Hulud/Miasma) | L1 signals + provenance; L3 egress catches steal-and-exfil |
| Review-bypass via orphan commits (Red Hat) | L1 provenance/attestation enforcement |
| Install exec surviving lifecycle-script disabling (PackageGate, binding.gyp) | L3 sandboxed install |
| Import-time backdoor (Telnyx) | L3 runtime eBPF chain detection |

**Non-goals:** not an SCA/CVE scanner (pair with Grype/Trivy), not a runtime EDR. It is a
resolution-time gate + install-time container.
