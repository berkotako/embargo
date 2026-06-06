# Plan — `/sandbox` (L3 Containment, Rust)

The last line of defense: run installs in a box so a malicious package can't phone home, and
(later) watch running processes for the chain that signals compromise. Containment events feed back
to the **engine** as high-weight signals.

## Purpose

1. **Sandboxed install (Phase 2):** run `npm ci` in a namespaced, egress-controlled environment.
   The install can only reach the gateway + an allowlist of hosts; a phoning-home `postinstall` is
   **blocked and recorded** as a signal (`sandbox_egress_attempt` → high weight, can auto-DENY).
2. **eBPF runtime monitoring (Phase 3):** watch node processes for the compromise chain —
   secret/env read → serialize → egress to a non-allowlisted host. A single syscall has no intent;
   the chain does.

## Tech & conventions

- Rust. This is the **only** crate permitted `unsafe`, and **every `unsafe` block carries a comment
  justifying it** (per CLAUDE.md). `cargo fmt` + `cargo clippy -- -D warnings` clean. No `unwrap()`
  in non-test code.
- Isolation primitives: Linux namespaces + seccomp + a network allowlist (or a microVM). eBPF via
  `aya` for the runtime phase.

## How it works

```
Phase 2 — sandboxed install:
  1. spin a namespaced env (user/net/mount ns) with seccomp profile
  2. network egress allowlist = { gateway, explicitly allowed hosts }
  3. run `npm ci`
  4. any egress attempt to a non-allowlisted host → block + capture
       (pkg, target host:port, pipeline/repo, attempts, timestamp)
  5. emit engine.ReportEvent(containment_event)  → high-weight signal
     (the console Dashboard "Recent containment events" feed renders exactly this shape)

Phase 3 — eBPF chain detection:
  attach probes; correlate secret/env read → serialize → egress(non-allowlisted)
  → emit high-weight chain signal; single syscalls alone do not fire.
```

## Engine integration (the contract)

Containment + chain events are reported via the engine's `ReportEvent` RPC and become **high-weight
signals** that can escalate a verdict to DENY. The shape must match what the console expects in its
containment feed: `{ pkg, host, pipeline, repo, attempts, time, note? }`.

## Module sketch

```
/sandbox
  Cargo.toml
  src/
    main.rs
    runner.rs        # namespaced/seccomp `npm ci` runner
    egress.rs        # allowlist enforcement + capture (unsafe confined here, justified)
    report.rs        # engine.ReportEvent client
    ebpf/            # Phase 3: aya programs + loader for chain detection
  tests/
    egress_block.rs  # phone-home postinstall is blocked + reported
```

## Testing

- A fixture package with a phone-home `postinstall` is **blocked**, install still completes/fails
  cleanly, and a containment event is emitted with the right fields.
- An allowlisted host is reachable; a non-allowlisted host is not.
- (Phase 3) chain fixture fires the chain signal; benign secret-read-only does not.

## Phasing

- **Phase 2:** install runner + egress allowlist + `ReportEvent`.
- **Phase 3:** eBPF chain detection.

## Out of scope

- Being a runtime EDR. Scoring (engine owns weights/thresholds; sandbox only reports evidence).
- Anything that would help evade the gate (forbidden).
