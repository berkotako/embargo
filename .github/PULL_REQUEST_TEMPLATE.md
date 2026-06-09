<!-- Thanks for contributing to Embargo. Keep PRs focused on one layer/concern. -->

## What & why

<!-- What does this change do, and why? Link the issue it addresses. -->

Closes #

## Layer / scope

<!-- Tick the area(s) this touches. -->

- [ ] `engine` — Policy & Signal Engine (Rust)
- [ ] `gateway` — L1 Verdaccio plugin (TS)
- [ ] `admission` — L2 CI gate (TS)
- [ ] `sandbox` — L3 containment (Rust)
- [ ] `console` — web admin UI (TS)
- [ ] `policy` / `docs` / CI

## Checklist

- [ ] Conventional Commit title, scoped by layer (e.g. `fix(engine): …`).
- [ ] Rust: `cargo fmt` + `cargo clippy -- -D warnings` clean; no `unwrap()` in
      non-test code; any `unsafe` is confined to `sandbox` with a justification.
- [ ] TS: strict mode; ESLint clean; no unexplained `any`.
- [ ] Tests added/updated and passing (new signals ship a benign + malicious
      fixture pair; resolution changes have an integration test).
- [ ] Docs updated in the same PR if behavior/architecture changed
      (`CLAUDE.md`, `docs/ARCHITECTURE.md`, `docs/SIGNALS.md`).

## Gate-safety attestation

- [ ] This change does **not** weaken a verdict, help evade the gate, or exfiltrate
      data. If it changes verdict behavior, I explained why it is correct above.

<!-- Security vulnerabilities: do NOT open a public PR/issue — see SECURITY.md. -->
