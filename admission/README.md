# Embargo L2 — Admission Gate

A pre-merge / pre-build check that **fails the build when a lockfile diff
introduces a version held or denied by Embargo policy**. The attacks land in
CI/CD, not laptops — so this gate is half the value, not polish.

It does not re-implement scoring: it parses the lockfile diff and asks the
**engine** (`engine.Resolve`) for a verdict per changed dependency.

## How it works

```
1. Detect the lockfile format (package-lock.json | pnpm-lock.yaml | yarn.lock | bun.lock).
2. Parse the head lockfile and the base (via `git show <base>:<lockfile>`).
3. Diff → the set of ADDED/CHANGED (package, version) entries only (fast).
4. engine.Resolve(pkg, version) for each changed entry.
5. If any verdict is HOLD or DENY → fail (non-zero exit) with a clear report
   (reason + approval link). Otherwise pass.
```

Diff-aware evaluation keeps CI fast — only what changed is checked.

## Exceptions

Overrides are time-boxed, audited approvals owned by the engine. Because
`engine.Resolve` already applies the approval workflow, a dependency with an
active, unexpired exception resolves to ALLOW and passes the gate — there is no
ad-hoc bypass env var.

## Use as a GitHub Action

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0 # needed so the base ref is available to diff
- uses: berkotako/embargo/admission@main
  with:
    lockfile: package-lock.json
    base-ref: origin/main
    engine-addr: embargo-engine.internal:50051
    console-url: https://embargo.example.com
    tls-cert: ${{ runner.temp }}/client.crt
    tls-key: ${{ runner.temp }}/client.key
    tls-ca: ${{ runner.temp }}/ca.crt
```

## Use as a CLI

```bash
embargo-admit \
  --lockfile package-lock.json \
  --base origin/main \
  --engine embargo-engine.internal:50051 \
  --console https://embargo.example.com \
  --report embargo-report.json
# exit 0 = all ALLOW, 1 = blocked, 2 = usage/IO error
```

mTLS is configured via `EMBARGO_TLS_CERT` / `EMBARGO_TLS_KEY` / `EMBARGO_TLS_CA`.

## Supported lockfiles

| File | Status |
|---|---|
| `package-lock.json` (npm v1/v2/v3) | ✅ |
| `pnpm-lock.yaml` (v6 and v9 key formats) | ✅ |
| `yarn.lock` (classic v1 and berry v2+) | ✅ |
| `bun.lock` (text) | ✅ |
| `bun.lockb` (binary) | ⚠️ convert first: `bun bun.lockb` or commit `bun.lock` |

## Self-dogfood

Once deployed, Embargo runs this gate in its own CI against its own lockfiles.
