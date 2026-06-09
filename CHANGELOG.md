# Changelog

All notable changes to Embargo are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **Typosquatting signal** (`typosquat`) — flags a package name that is a
  near-miss of a popular one (Damerau-Levenshtein edit distance, separator
  variants, Unicode homoglyphs) against a bundled popular-name corpus, plus a
  `lookalike_dropper` composite chain (typosquat + install-time script).
- **Watchlist + continuous tracking** — a persistent Postgres watchlist of
  packages/scopes and a background worker that re-evaluates each enabled target
  on a configurable interval (or off). Admin API under `/api/watchlist`.
- **Known-malicious feed** (opt-in) — sync a curated malware dataset (default
  Datadog's npm manifest, Apache-2.0 — see `NOTICE`) into the engine; a match is
  an immediate DENY, un-bypassable by fast-track. New console **Known Packages**
  screen and `/api/known-malicious` API (view/search, manual block, sync).

### Fixed

- Policy dry-run now computes `would_release` / `affected_pkgs` for real instead
  of returning placeholders.
- DB-backed engine integration tests run single-threaded in CI to remove
  shared-state flakiness.

## [0.1.0] — 2026-06-08

First public, deployable release. The full L1–L3 firewall, the policy & signal
engine, the admin console, and the CI gate are built, tested, and packaged as
published container images.

### Added

- **Policy & Signal Engine (core)** — most-specific-wins per-scope policy,
  cooldown, provenance enforcement, and behavioral signal scoring with
  HOLD→DENY escalation that is permanent when a version is flagged mid-cooldown.
  Behavioral signals: new lifecycle script, `binding.gyp`, new capability dep,
  republish anomaly, maintainer change, tarball/repo mismatch, obfuscation, plus
  composite chains; OSV advisory matches auto-DENY. Each signal ships a
  benign + malicious fixture pair.
- **L1 Ingress Gateway** — Verdaccio storage-filter that strips HOLD/DENY
  versions from the packument over mTLS gRPC to the engine; fail-open (dev) or
  fail-closed (prod).
- **L2 Admission gate** — CLI + GitHub Action that fails CI on a lockfile diff
  introducing a held/denied version (npm, pnpm, Yarn, Bun).
- **L3 Sandbox** — namespaced, egress-allowlisted install runner with seccomp
  capture and runtime secret→egress chain detection.
- **Admin Console** — quarantine review, policy, approvals, audit, dashboard;
  OIDC/dev/disabled auth with server-side RBAC over an authenticated admin API.
- **Engine internals** — Postgres state, Redis verdict cache, hash-chained audit
  log, mTLS gRPC, JSON admin facade, Prometheus metrics + health, OpenTelemetry.
- **Packaging & deployment** — `docker compose` dev stack and `compose.prod.yml`
  pulling pinned GHCR images; `make up` one-command bootstrap and `make onboard`
  client onboarding; a tag-triggered release workflow that publishes
  `embargo-engine`, `embargo-gateway`, and `embargo-console` images to GHCR.
- **Docs** — README, ARCHITECTURE, SIGNALS, DEVELOPMENT, DEPLOYMENT, FAQ, and
  STATUS, with illustrations.

### Known follow-ups (tracked, non-blocking)

- Sigstore signature verification (Fulcio identity + Rekor inclusion) beyond the
  current structural provenance check.
- A periodic advisory-sync job re-scanning already-served versions.
- An `aya` eBPF data source for the runtime chain detector (lower overhead than
  seccomp).
- A Helm chart for Kubernetes deployments.

[0.1.0]: https://github.com/berkotako/embargo/releases/tag/v0.1.0
