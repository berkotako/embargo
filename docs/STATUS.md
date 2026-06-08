# Project status

A snapshot of what is built and verified. The authoritative design is
[`ARCHITECTURE.md`](../ARCHITECTURE.md); run instructions are in
[`DEVELOPMENT.md`](../DEVELOPMENT.md).

## What works today

A client pointing `registry=` at the gateway gets a firewalled view of npm: the
engine resolves **cooldown + per-scope policy + provenance + behavioral signals
+ advisories**, holds new/uncertain versions, and permanently denies a version
flagged mid-cooldown. The same policy is enforced in CI (admission) and the
install is contained at runtime (sandbox). The console drives review and
approvals over an authenticated, RBAC'd API.

## Components & tests

| Component | State | Tests (verified) |
|---|---|---|
| `engine` / embargo-core | pure policy + signal logic | 47 unit + 3 fixture integration |
| `engine` / embargo-engine | gRPC, Postgres, Redis, extractor, provenance, advisory, admin facade, auth/RBAC | 35 (unit + DB-backed integration) |
| `gateway` (L1) | packument rewriting | 6 |
| `admission` (L2) | lockfile-diff CI gate, 4 formats | 20 |
| `sandbox` (L3) | namespaced egress containment + runtime chain detection | 21 unit + 2 real-kernel integration |
| `console` | admin UI, OIDC login, live engine wiring | typecheck + lint + build |

Everything builds clean under `clippy -D warnings` (Rust) / strict TypeScript,
and is wired into CI (`.github/workflows/ci.yml`).

## End-to-end checks performed

- Engine boots and serves all admin endpoints; a `POST`→`GET` approval
  round-trips through Postgres.
- OIDC: no token → `401`, a valid admin JWT → `200`, and the audit log records
  the real principal.
- L3: a probe attempting a non-allowlisted connection is blocked + captured;
  loopback is allowed; a secret-read→egress sequence is flagged as a chain.

## Tracked follow-ups (not blocking the core)

- **Provenance:** Sigstore signature verification (Fulcio cert identity + Rekor
  inclusion) beyond today's structural check.
- **Advisories:** a periodic sync job that re-scans already-served versions
  against refreshed OSV data.
- **eBPF:** an `aya` ring-buffer data source for the runtime chain detector
  (lower overhead than the seccomp source; needs kernel BTF + `CAP_BPF`).
- **Packaging:** a verified `docker compose up` / Helm chart with cert-gen +
  seed, and the gateway/console production images.
