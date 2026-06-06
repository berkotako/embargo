# Plan — `/admission` (L2 Admission Control, GitHub Action / CLI, TS)

Defense-in-depth past resolution time. The attacks land in CI/CD, not laptops — so this is half the
value, not polish.

## Purpose

A pre-merge / pre-build check that **fails the build** when a **lockfile diff** introduces a version
that violates policy (in-cooldown, unattested where required, advisory-flagged, or a new install
script vs. the prior version). Policy-as-code: one central, version-controlled policy that repos
inherit.

## Tech & conventions

- TypeScript (strict, ESLint + Prettier). Packaged as a **composite/Node GitHub Action** + a
  standalone **CLI** (same core, two entry points).
- Evaluates against the same `/policy` ruleset and asks the **engine** for verdicts
  (`EMBARGO_ENGINE_RPC`) — it does not re-implement scoring.

## How it works

```
1. Detect lockfile(s): package-lock.json | pnpm-lock.yaml | yarn.lock | bun.lockb
2. Diff vs. base ref → the set of ADDED/CHANGED (package, version) entries only (diff-aware: fast).
3. For each changed entry: engine.Resolve(pkg, version) → verdict.
4. If any HOLD/DENY without a valid, unexpired exception:
     - fail the check (non-zero exit)
     - print a clear report: package@version, verdict, reason, signals, approval link
   else pass.
```

Diff-aware evaluation keeps CI fast — only what changed is checked.

## Exception workflow

Overrides only via **logged, time-boxed approvals** — the same `approvals` store the console writes
to and the engine owns. The admission gate reads exceptions; an active, unexpired exception for an
exact `package@version` lets the build pass (and is recorded). No ad-hoc bypass env var.

## Module sketch

```
/admission
  package.json  tsconfig.json  action.yml   # GitHub Action metadata
  src/
    cli.ts                 # `embargo-admit` standalone entry
    action.ts              # GitHub Action entry (reads inputs, sets outputs/annotations)
    lockfiles/             # parsers: npm / pnpm / yarn / bun → normalized {pkg, version}
    diff.ts                # base-vs-head changed-deps set
    evaluate.ts            # engine.Resolve per changed dep; apply exceptions
    report.ts              # human + GH-annotation output (reasons + approval links)
  test/
    diff.test.ts
    evaluate.test.ts       # held dep fails; exception lets it pass; advisory always fails
```

## Testing

- Lockfile diff correctness across all four package managers.
- A changed dep that the engine HOLDs/DENYs fails the gate; a matching active exception passes it.
- Advisory-flagged version fails regardless. Never weaken the gate to pass a test.

## Phasing

- **Phase 2:** GitHub Action + CLI, npm + pnpm lockfiles first, then yarn + bun.
- Later: PR comment summarizing verdicts; org-level shared policy distribution; per-repo overlays.

## Out of scope

- Scoring/policy logic (engine + `/policy`). Acting as an SCA/CVE scanner (pair with Grype/Trivy).
