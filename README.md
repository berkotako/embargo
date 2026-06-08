# Embargo

**A self-hosted dependency firewall for npm.** Embargo sits in front of the npm registry and
*refuses to serve* package versions until they pass age, provenance, and behavioral-risk checks.
It's a firewall that blocks — not a scanner that warns after the fact.

> Status: all layers (L1–L3), the policy & signal engine, the admin console, and the CI gate are
> built and tested. See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the design and
> [`DEVELOPMENT.md`](DEVELOPMENT.md) to run it locally.

## Why

The npm ecosystem has been hit by a wave of supply-chain attacks — token-hijacked releases of
hugely popular packages (Axios, debug/chalk), self-propagating worms (Shai-Hulud/Miasma),
review-bypass via orphan commits, and install/import-time backdoors. Native package-manager
cooldowns (`min-release-age` and friends) help against the smash-and-grab window but are global,
have no exception mechanism, and can't act on *why* a version is suspicious.

Embargo adds what the package managers structurally won't:

- **Per-scope policy** — hold public packages, pass your own `@org/*` instantly.
- **Fast-track exceptions** — bypass the hold for emergency CVE fixes.
- **Signal gating** — use the cooldown window to actually evaluate the version (new install
  scripts, missing provenance, republish anomalies, advisory matches) and block the bad ones.
- **Pipeline admission control** — fail CI builds that introduce policy-violating versions.
- **Install containment** — run installs sandboxed with controlled egress.

Open, self-hosted, and enforced as a gate.

## How it works

Point your client at Embargo with one line:

```
# .npmrc
registry=https://embargo.your-org.internal/
```

Embargo intercepts the package metadata npm fetches before resolving and filters out versions that
violate policy — so your resolver simply never picks a held or denied version. Works with npm,
pnpm, Yarn, and Bun.

Every version gets one of three verdicts:

- 🟢 **ALLOW** — served normally
- 🟡 **HOLD** — withheld during cooldown / pending review
- 🔴 **DENY** — blocked (flagged by a signal or advisory)

## Components

| Component | Layer | What it does |
|---|---|---|
| [`engine`](engine/) | core | Policy & signal engine (Rust): resolution, cooldown, provenance, behavioral signals, OSV advisories, mTLS gRPC + a JSON admin API |
| [`gateway`](gateway/) | L1 | Verdaccio plugin — rewrites the packument, stripping HOLD/DENY versions |
| [`admission`](admission/) | L2 | CI gate (CLI + GitHub Action) — fails builds whose lockfile diff introduces a held/denied version |
| [`sandbox`](sandbox/) | L3 | Namespaced, egress-controlled install runner; blocks + captures phone-home and the runtime secret→egress chain |
| [`console`](console/) | UI | Web admin — quarantine review, policy, approvals, audit, dashboard (OIDC + server-side RBAC) |
| [`policy`](policy/) | — | Versioned policy schema (JSON Schema) + YAML DSL + examples |

How the layers compose: a client points `registry=` at the **gateway**, which asks the **engine**
for verdicts and strips disallowed versions from the metadata. The engine resolves cooldown +
per-scope policy + provenance + behavioral signals + advisories, escalating HOLD→DENY permanently
when a version is flagged mid-cooldown. The **admission** gate enforces the same policy in CI, the
**sandbox** contains the install itself, and the **console** drives review and approvals.

## Quick start

```bash
# services
createdb embargo && redis-server &

# engine (dev auth, dev mTLS certs) — see DEVELOPMENT.md for the full command
cd engine && cargo build && ./target/debug/embargo-engine   # :8080 admin, :50051 gRPC

# console
cd console && npm ci && npm run dev                          # http://localhost:4000
```

See [`DEVELOPMENT.md`](DEVELOPMENT.md) for the full per-component setup, config, and run commands.

## Documentation

- [Status](docs/STATUS.md) — what's built and verified, with test counts
- [Architecture](ARCHITECTURE.md) — authoritative design
- [Signals](SIGNALS.md) — the detection catalog and scoring contract
- [Development](DEVELOPMENT.md) — local setup, run commands, config, the admin API
- [Project plan](docs/PROJECT_PLAN.md) and [per-component plans](docs/plans/)
- [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

## License

TBD (open-core intended: gateway/engine/signals/console/CI-gate open; multi-tenancy, SSO/RBAC, and
compliance reporting as the enterprise tier).

## Not a

SCA/CVE scanner (pair it with Grype/Trivy) or a runtime EDR. Embargo is a resolution-time gate plus
install-time containment.
