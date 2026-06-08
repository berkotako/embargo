# Embargo L3 — Containment

The last line of defense: run installs in a box so a malicious package can't
phone home. A blocked outbound connection is **captured and reported** to the
engine as a high-weight `sandbox_egress_attempt` signal, which can escalate a
verdict to DENY.

## What it does

```
embargo-sandbox run \
  --allow 10.0.0.5 \            # registry/gateway IP (loopback is always allowed)
  --package left-pad --version 1.0.0 \
  --engine embargo-engine:50051 \
  --pipeline build/deploy --repo acme/app \
  -- npm ci
```

1. Forks a child that enters a **user namespace** (granting `CAP_SYS_ADMIN` so an
   unprivileged caller may install a user-notify filter) plus **pid + mount**
   namespaces for isolation.
2. Installs a **seccomp** filter that returns `SECCOMP_RET_USER_NOTIF` for every
   `connect()`; the listener fd is handed back to the parent over `SCM_RIGHTS`.
3. Execs the install command. The parent **supervises** each `connect()`: it
   reads the destination from the child's memory, and
   - **allows** loopback + allowlisted IPs (the syscall continues), or
   - **blocks** everything else with `EPERM` and captures `{pid, host:port}`.
4. Each blocked attempt is emitted via `engine.ReportEvent` in the shape the
   console's containment feed expects: `{ pkg, host, pipeline, repo, attempts,
   time, note }`.

A phoning-home `postinstall` is therefore blocked and recorded, while the
install still completes against the allowlisted registry.

## Runtime compromise-chain detection (M4)

With `--detect-chain`, the supervisor also observes `openat()` and correlates
per process: a **secret read → non-allowlisted egress** within a time window is
the stealer chain. "A single syscall has no intent; the chain does." A detected
chain is reported as an `ebpf_chain` event (engine signal
`EbpfCompromiseChain`, weight 100 — the highest-confidence containment finding).

```bash
embargo-sandbox run --allow 10.0.0.5 --detect-chain \
  --package left-pad --version 1.0.0 --engine embargo-engine:50051 \
  -- npm ci
```

The correlation engine (`chain.rs`) is pure and source-agnostic. Today the data
source is the seccomp supervisor (observing every `openat()`, so this mode is
heavier than plain egress control). In production the same engine is fed by an
**eBPF** ring buffer for lower-overhead, harder-to-forge visibility — that path
requires kernel BTF + `CAP_BPF`/`CAP_PERFMON` and is the M4+ data source; the
correlation logic is unchanged.

## Architecture

| Module | Responsibility | `unsafe`? |
|---|---|---|
| `allowlist.rs` | parse a raw sockaddr, decide allow/block | no — pure, unit-tested |
| `chain.rs` | correlate runtime events → compromise-chain detection | no — pure, unit-tested |
| `seccomp.rs` | build the BPF filter, install the listener, run the user-notify loop (connect + openat) | yes — confined raw syscalls/ioctls, each justified |
| `runner.rs` | fork, enter namespaces, pass the fd, exec, reap | yes — fork/exec |
| `report.rs` | `engine.ReportEvent` gRPC client (egress + chain) | no |

This is the only crate permitted `unsafe` (per `CLAUDE.md`); every `unsafe`
block carries a justifying comment.

## Requirements

- Linux ≥ 5.0 with **unprivileged user namespaces** enabled and **seccomp
  user-notification** (`CONFIG_SECCOMP` + notify). Egress control is enforced by
  seccomp, so allowlisted hosts remain reachable while everything else is denied
  at `connect()` — no NAT/veth plumbing required.
- Deploy on an isolated Kubernetes node pool with a strict security context.

## Testing

```bash
cargo test                       # pure unit tests (allowlist, BPF shape, ioctl numbers, report)
cargo test -- --include-ignored  # + real end-to-end containment (needs userns)
```

The `containment` integration test runs the built binary with a `probe` payload
that attempts an external connection and a loopback connection, then asserts the
external one was blocked + captured and loopback was allowed.

## Roadmap

- **M3:** namespaced install runner + seccomp egress allowlist + capture + `ReportEvent`. ✅
- **M4:** runtime compromise-chain detection (secret read → non-allowlisted egress),
  correlation engine + seccomp data source. ✅ eBPF/`aya` data source (lower
  overhead, requires BTF + `CAP_BPF`) is the production follow-up — same engine.
