# Plan — `/policy` (schema + DSL + example policies)

Foundational and small. It defines the rule format that the **engine** evaluates, the **admission**
gate enforces, and the **console** policy editor authors. Build this first so the others have a
canonical contract.

## Purpose

A version-controlled, per-scope policy DSL. One central policy that repos inherit. Resolves
**most-specific-wins**. Encodes cooldown, provenance requirement, fast-track allow-list, and the
on-hard-signal action.

## Scope (Phase 0)

- A canonical **schema** for a policy rule + ruleset.
- A **JSON Schema** (`policy.schema.json`) so every consumer (Rust engine, TS console/admission) can
  validate the same way, regardless of language.
- 1–2 **example policies** that mirror the console design's demo rules.
- A short **spec doc** for resolution semantics (specificity + matching).

## Format

- **Authoring format:** YAML (human-friendly, comments, diffs cleanly). Validate against the JSON
  Schema. (TOML acceptable if preferred — keep the schema the source of truth either way.)
- Location: `/policy/` with `policy.schema.json`, `examples/*.yaml`, and `README.md` (the spec).

## Rule shape (fields, derived from ARCHITECTURE data model + console design)

```yaml
# /policy/examples/default.yaml
version: 1
rules:
  - scope: "@mycompany/*"        # glob over package names
    cooldown_hours: 0            # hold new versions until this age; 0 = allow immediately
    require_provenance: true     # deny versions without a verified SLSA attestation
    on_hard_signal: deny         # advisory/typosquat → deny | hold
    fast_track:                  # packages exempt from cooldown + provenance under this rule
      - "@mycompany/design-tokens"
      - "@mycompany/feature-flags"
    enabled: true
  - scope: "@types/*"
    cooldown_hours: 6
    require_provenance: false
    on_hard_signal: deny
    enabled: true
  - scope: "express, axios, chalk, react, **/lodash"   # comma list of globs
    cooldown_hours: 24
    require_provenance: true
    on_hard_signal: deny
    enabled: true
  - scope: "**"                  # default — broadest, lowest specificity
    cooldown_hours: 72
    require_provenance: false
    on_hard_signal: deny
    enabled: true
```

## Resolution semantics (spec the engine implements)

- **Glob matching:** `@scope/*` matches one path segment; `**` matches everything; a comma-separated
  `scope` is a set of globs (rule matches if any glob matches).
- **Specificity score** (most-specific-wins): rank candidates so the most specific matching rule
  decides. Heuristic (document precisely): exact name > `@scope/name` > `@scope/*` > single bare glob
  > `**`. The console renders this as a 1–4 specificity indicator and an explicit resolution order —
  keep the scoring consistent with that UI.
- **Exactly one rule wins** per (package). `fast_track` within the winning rule bypasses cooldown +
  provenance for the listed packages. Disabled rules are skipped.

## Consumers (keep in sync)

- **Engine** (`docs/plans/engine.md`): the `policy` module deserializes this and implements
  resolution. The schema is the contract.
- **Console** (`docs/CONSOLE_PLAN.md`): the Policy Editor's fields (scope, cooldown hours,
  on-advisory action, require-provenance, enabled, fast-track) map 1:1 to this shape — its mock
  `POLICIES`/`DRYRUN` are a preview of the real thing.
- **Admission** (`docs/plans/admission.md`): loads the same policy to evaluate lockfile diffs.

## Out of scope (now)

- Policy inheritance/overrides across multiple files (single ruleset first).
- Per-repo policy layering (Phase 2, admission concern).
- A bespoke parser — start with YAML + JSON Schema, not a hand-rolled DSL grammar.
