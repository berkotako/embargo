# Security Policy

Embargo is security tooling, so its own security posture matters.

## Reporting a vulnerability

**Do not open a public issue for security vulnerabilities.**

Report privately to the maintainers (add your contact: security@your-domain or a private
advisory). Include:

- a description of the issue and its impact,
- steps to reproduce or a proof of concept,
- affected component(s) and version/commit.

We aim to acknowledge reports promptly and will coordinate a fix and disclosure timeline with you.

## Scope of particular concern

Because Embargo gates dependency resolution, the highest-impact issues are:

- **Gate bypass** — any way to get a HELD or DENIED version served to a client.
- **Verdict tampering** — manipulating cached verdicts, policy, or the audit log.
- **Sandbox escape** — escaping the L3 install container or its egress controls.
- **Signal evasion** — crafting a malicious package that reliably evades a documented signal.
- **Privilege issues in the console** — bypassing RBAC, forging approvals.

## Supported versions

During early development, only `main` is supported. A version support policy will be added once we
tag releases.
