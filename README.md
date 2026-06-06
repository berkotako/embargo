# Embargo

**A self-hosted dependency firewall for npm.** Embargo sits in front of the npm registry and
*refuses to serve* package versions until they pass age, provenance, and behavioral-risk checks.
It's a firewall that blocks — not a scanner that warns after the fact.

> Status: early development. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the design and
> [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) to run it locally.

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

| | |
|---|---|
| **Gateway** | L1 ingress — packument rewriting, cooldown, provenance, signal gating |
| **Engine** | the policy & signal core (Rust) |
| **Admission** | L2 — CI gate that fails policy-violating builds |
| **Sandbox** | L3 — egress-controlled install runner |
| **Console** | web admin — policy, quarantine review, approvals, audit |

## Quick start

```bash
cp .env.example .env
docker compose up
# gateway on :4873, console on :3000
```

See [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) for the full setup.

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — authoritative design
- [Signals](docs/SIGNALS.md) — the detection catalog and scoring contract
- [Development](docs/DEVELOPMENT.md) — local setup and workflow
- [Contributing](CONTRIBUTING.md)
- [Security](SECURITY.md)

## License

TBD (open-core intended: gateway/engine/signals/console/CI-gate open; multi-tenancy, SSO/RBAC, and
compliance reporting as the enterprise tier).

## Not a

SCA/CVE scanner (pair it with Grype/Trivy) or a runtime EDR. Embargo is a resolution-time gate plus
install-time containment.
