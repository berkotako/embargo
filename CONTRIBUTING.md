# Contributing to Embargo

Thanks for helping build a dependency firewall. A few things keep this project coherent.

## Ground rules

- **Embargo is defensive security tooling.** Contributions detect and block malicious packages.
  We do not accept anything that helps evade the gate, exfiltrate data, or weaken a verdict.
- **The engine is the product; the proxy is plumbing.** Detection/policy logic belongs in
  `/engine`. The gateway stays a thin enforcement point on top of Verdaccio.
- **Default to HOLD, never auto-DENY on weak signals.** False-positive rate is our primary metric.

## Workflow

1. Open an issue describing the change before large PRs.
2. Branch from `main`; keep PRs focused on one layer/concern.
3. Use Conventional Commits, scoped by layer: `feat(gateway):`, `fix(engine):`, `docs:`.
4. Ensure all checks pass (see `docs/DEVELOPMENT.md` → "Before opening a PR").

## Code standards

- **Rust:** `cargo fmt`, `cargo clippy -- -D warnings`, no `unwrap()` in non-test code, `unsafe`
  confined to the sandbox crate with a justifying comment.
- **TypeScript:** strict mode, no unexplained `any`, ESLint + Prettier clean.
- **Tests:** new signals require a benign + malicious fixture pair. Gateway changes affecting
  resolution require an integration test. Never weaken a gate to pass a test.

## Adding a signal

Follow the checklist in `docs/SIGNALS.md`. A signal returns a weighted finding, never a verdict;
the HOLD/DENY decision is policy-driven.

## Reporting security issues

Do not open public issues for vulnerabilities. See `SECURITY.md`.

## Docs

If your change alters behavior, commands, or architecture, update the relevant doc in the same PR —
especially `CLAUDE.md`, `docs/ARCHITECTURE.md`, and `docs/DEVELOPMENT.md`.
