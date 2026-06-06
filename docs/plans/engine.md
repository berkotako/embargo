# Plan — `/engine` (Policy & Signal Engine, Rust)

**The core. The engine is the product.** Everything else asks it for verdicts. This is the largest
and most important component. Read `docs/SIGNALS.md` (scoring contract) and `docs/ARCHITECTURE.md`
(data model, verdict escalation) before building.

## Purpose

Given a `(package, version)` and context, produce exactly one verdict — **ALLOW / HOLD / DENY** —
with reason, contributing signals, and a score. Owns: policy resolution, cooldown, provenance
checks, signal scoring, verdict escalation, the state store, and external advisory feeds. Serves
verdicts to the gateway/admission over RPC and powers the console's read/write API.

## Tech & conventions

- Rust, edition 2021+. `cargo fmt` + `cargo clippy -- -D warnings` clean. Errors via
  `thiserror`/`anyhow`. **No `unwrap()` in non-test code. No `unsafe` anywhere in this crate.**
- Async runtime: `tokio`. RPC: `tonic` (gRPC) — see master plan contract. Postgres: `sqlx`
  (compile-checked queries, migrations). Redis: `redis`/`deadpool-redis`. Globs: `globset`.
- **Hot-path rule:** packument-resolve verdicts are cached in Redis; no uncached network calls in
  the resolve path. Static scans are bounded (timeout + size cap); a package that can't be scanned
  in budget is **HELD pending review**, never allowed by default.

## Crate / module layout

Cargo workspace so the pure scoring core is isolated from I/O and independently testable:

```
/engine
  Cargo.toml                  # workspace
  crates/
    embargo-core/             # PURE: types, policy resolution, signal detectors, escalation.
      src/                    # NO I/O here — input = artifact+metadata+prev, output = findings.
        types.rs              # Verdict, Severity, Provenance, Signal, Finding, PolicyRule, ...
        policy.rs             # most-specific-wins resolution + glob matching (per /policy spec)
        cooldown.rs           # age vs cooldown → base verdict
        provenance.rs         # attestation presence/level → finding (verification I/O lives outside)
        signals/              # one module per detector; each pure fn(prev,new,meta)->Vec<Signal>
          mod.rs              # catalog + dispatch
          lifecycle_script.rs # new pre/post/install script vs prior (manifest diff)
          binding_gyp.rs      # binding.gyp introduced (tarball inspection)
          capability_dep.rs   # new dep touching net/fs/child_process
          republish.rs        # tarball changed for already-published version
          maintainer.rs       # new publisher/token/geo
          tarball_mismatch.rs # artifact != source repo
          obfuscation.rs      # high-entropy/packed payload markers
        chains.rs             # composite chains (stealer / out-of-pipeline / native-exec smuggling)
        escalate.rs           # base verdict + Σ weights vs thresholds → final verdict
      fixtures/<signal>/{benign,malicious}/   # required per signal (SIGNALS.md)
    embargo-engine/           # I/O shell around the core
      src/
        main.rs
        rpc.rs                # tonic server: Resolve / ResolvePackument / ReportEvent
        admin_api.rs          # console read/write surface (queue/dash/policies/approvals/audit)
        store/                # Postgres (sqlx) — repositories for the data model
          migrations/         # policies, verdicts, signals, approvals, audit
        cache.rs              # Redis verdict cache (key: package@version)
        feeds/                # OSV + GitHub Advisory clients (cached, off the hot path)
        provenance_verify.rs  # npm OIDC attestation verification (network, cached)
        fetch.rs              # tarball/manifest fetch + parse (cached; never on hot path)
```

## Core types (embargo-core)

```rust
enum Verdict { Allow, Hold, Deny }
enum Severity { High, Med, Low }
enum Provenance { Ok, Missing, Partial }
struct Signal { id: SignalId, weight: u32, evidence: String, severity: Severity }
struct Finding { verdict: Verdict, reason: String, score: u32, signals: Vec<Signal>,
                 expires_at: Option<DateTime> }
struct PolicyRule { scope: Vec<Glob>, cooldown_hours: u32, require_provenance: bool,
                    on_hard_signal: Verdict, fast_track: Vec<String>, enabled: bool }
```

## The resolve algorithm (the heart)

```
resolve(pkg, version, ctx):
  1. cache lookup (Redis); if fresh and not expired → return.
  2. base = policy.resolve(pkg) → cooldown.eval(version_age) + provenance gate
       - fast_track hit → ALLOW (skip cooldown + provenance)
       - younger than cooldown → HOLD (expires_at = published + cooldown)
       - require_provenance && missing → HOLD (or DENY per rule) 
  3. signals = run pure detectors over (prev_version_artifact, this_artifact, metadata)
       + advisory feed match (OSV/GHSA)
       + composite chains
  4. final = escalate(base, signals):
       - signals only escalate TOWARD deny, never relax toward allow
       - advisory match → automatic DENY
       - a HELD version crossing the DENY threshold during cooldown → PERMANENT DENY
         (must NOT become allowed when the timer later expires — load-bearing)
  5. persist verdict + signals (Postgres), write audit row, cache (Redis), return.
```

`escalate`, `policy.resolve`, and every detector are **pure** and unit-tested in `embargo-core`.
I/O (fetch, feeds, store, cache, provenance verification) lives in `embargo-engine` and feeds inputs
into the pure core.

## Verdict escalation rules (from SIGNALS.md — do not regress)

- A signal returns a **weighted finding, never a verdict**. Thresholds (policy) decide HOLD/DENY.
- **Score chains, not single facts** — prefer emitting a composite finding when constituents
  co-occur (e.g. stealer chain = new capability dep + secret read + new lifecycle script).
- **Bias to HOLD** for new/low-confidence signals. FP rate is the product metric.
- Advisory (OSV/GHSA) match = automatic DENY. Mid-cooldown DENY-threshold crossing = permanent DENY.

## RPC + admin API surface

- `Resolve(pkg, version, requester) -> Finding` (hot path, cache-first).
- `ResolvePackument(pkg, versions[]) -> map<version, Verdict>` (gateway filters whole packument in
  one call).
- `ReportEvent(event)` — sandbox containment / install signals; high-weight, can auto-DENY.
- Admin/read API for the console: queue, dashboard aggregates, policies CRUD, approvals
  (request/grant/expire, time-boxed), inspector timeline, audit (immutable, hash-chained, CSV-able).

## State store (Postgres) + cache (Redis)

Implement `ARCHITECTURE.md` data model as sqlx migrations: `policies`, `verdicts`, `signals`,
`approvals`, `audit`. Audit rows are immutable and **hash-chained** (each row hashes the previous —
the console surfaces and verifies this). Redis caches verdicts keyed by `package@version` with TTL
tied to `expires_at`.

## Testing

- Every signal: a benign fixture (must NOT fire) + a malicious fixture (must fire with expected
  weight), under `crates/embargo-core/fixtures/<signal>/`. Not "done" without both.
- Composite chains tested as chains, not just constituents.
- `escalate` tested for: signals never relax to ALLOW; advisory → DENY; mid-cooldown DENY is
  permanent.
- Pure core has no I/O in tests; store/feeds tested separately (integration, behind a feature/flag).

## Phasing

- **Phase 0:** types, policy resolution, cooldown, RPC (`Resolve`/`ResolvePackument`), store + cache,
  audit. No signals. (Unblocks gateway + console MVP.)
- **Phase 1:** signal detectors + chains + feeds (OSV/GHSA) + escalation + provenance verification.
- **Phase 2:** ingest `ReportEvent` from sandbox as high-weight signals.

## Out of scope (now)

- eBPF / runtime detection (that's `/sandbox`, Phase 3 — it only *feeds* the engine events).
- Multi-tenancy. ML scoring (weights are tuned heuristics on real traffic).
