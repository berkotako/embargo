# Embargo Policy DSL

Specification for the per-scope policy ruleset consumed by the engine, admission gate, and console.

## Quick start

```yaml
version: 1
rules:
  - scope: "@mycompany/*"
    cooldown_hours: 0
    require_provenance: true
    on_hard_signal: deny
    fast_track:
      - "@mycompany/design-tokens"
    enabled: true
  - scope: "**"
    cooldown_hours: 72
    require_provenance: false
    on_hard_signal: deny
    enabled: true
```

## Schema

The canonical contract is `policy.schema.json` (JSON Schema draft 2020-12). Every consumer
(Rust engine, TypeScript console/admission) validates against it. The YAML authoring format is
validated against this schema before the engine accepts it.

**Versioning:** the `version` field is the schema version. When the schema changes in a
breaking way, the version increments and a migration path is documented in this file.

## Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `scope` | string | yes | Glob or comma-separated list of globs over package names |
| `cooldown_hours` | integer ≥ 0 | yes | Hours a new version must age before being served; 0 = immediate |
| `require_provenance` | boolean | yes | Deny versions without verified SLSA/npm build-provenance attestation |
| `on_hard_signal` | `"deny"` \| `"hold"` | yes | Action when advisory/typosquat/republish-anomaly fires |
| `fast_track` | string[] | no | Exact package names exempt from this rule's cooldown and provenance |
| `enabled` | boolean | yes | Disabled rules are skipped during resolution |

## Glob syntax

- `@scope/name` — exact scoped package.
- `@scope/*` — all packages under a scope (one path segment; does not cross `/`).
- `name` — exact bare package name.
- `**` — matches any package name (catch-all; lowest specificity).
- Comma-separated list (`"express,axios,react"`) — rule matches if **any** glob in the list matches.

## Resolution semantics (most-specific-wins)

When a package name matches multiple rules, exactly one rule wins: the one with the highest
**specificity score**. Disabled rules (`enabled: false`) are excluded before scoring.

### Specificity scoring

| Pattern type | Score | Examples |
|---|---|---|
| Exact name | 4 | `@mycompany/auth`, `express` |
| Scoped with full name | 3 | `@types/node` |
| Scoped wildcard | 2 | `@mycompany/*`, `@types/*` |
| Single bare glob | 1 | `lodash,express` (multi-glob rules score on the best-matching glob) |
| Double wildcard | 0 | `**` |

If two rules produce the same specificity score (e.g. two `@scope/*` rules matching the same
package), the rule appearing **earlier** in the `rules` array wins. Document this ordering
explicitly in your policy file.

### Fast-track

Within the winning rule, a package listed in `fast_track` bypasses that rule's `cooldown_hours`
and `require_provenance` check. Fast-track entries are **exact package names only** — globs are
not allowed in `fast_track`.

### Example resolution

Policy:
```
rule A: scope="@mycompany/*"  cooldown=0  require_provenance=true
rule B: scope="**"            cooldown=72 require_provenance=false
```

Package `@mycompany/auth` → rule A wins (score 2 > score 0). Cooldown = 0 hours, provenance required.
Package `lodash` → only rule B matches. Cooldown = 72 hours, provenance not required.
Package `@mycompany/design-tokens` (in rule A's fast_track) → rule A wins, fast_track bypasses cooldown + provenance.

## Authoring and applying policies

Policy changes are submitted through the engine's RBAC'd admin API and are audited in the
tamper-evident audit log. Policies are **not** applied by editing files directly on the server;
the file format is the human-readable source of truth that is version-controlled in your repo and
submitted via the engine API.

```bash
# Apply a policy via the CLI (requires an admin-scoped API token):
embargo policy apply policy/examples/default.yaml
```

## Examples

- `examples/default.yaml` — balanced default for most organizations.
- `examples/strict.yaml` — high-security environments (fintech, healthcare, critical infra).

## Schema migrations

| Version | Changes |
|---|---|
| 1 | Initial version. All M1 fields. |
