# Plan — `/gateway` (L1 Ingress Gateway, Verdaccio plugin, Node/TS)

The enforcement point clients actually talk to. **Plumbing, not product** — it holds no policy or
signal logic; it asks the engine and shapes the packument. Built on Verdaccio (proven MIT registry
proxy), never from scratch.

## Purpose

Sit in front of the upstream registry. Intercept the **packument** (`GET /{package}`: the `versions`
and `time` maps) and filter out versions the engine says are HOLD/DENY, so the client's resolver
never sees a disallowed version. One `.npmrc` line on the client (`registry=`) covers npm, pnpm,
Yarn, and Bun because this is protocol-level.

## Tech & conventions

- Verdaccio + a middleware/plugin (Node/TS, strict mode, no unexplained `any`, ESLint + Prettier).
- Talks to the engine over RPC (`EMBARGO_ENGINE_RPC`); upstream is configurable
  (`EMBARGO_UPSTREAM`, default `https://registry.npmjs.org`). **Never hardcode npmjs.org outside the
  uplink config.**
- **Hot-path rule:** packument rewrite is user-facing latency. Verdicts come from the engine's
  Redis-backed cache; **no uncached network calls** in this path. Prefer one
  `ResolvePackument(pkg, versions[])` round-trip per packument.

## How it works

```
client GET /{package}  ──►  gateway plugin
                              1. fetch upstream packument (Verdaccio uplink)
                              2. engine.ResolvePackument(pkg, Object.keys(versions))
                              3. for each version verdict:
                                   ALLOW → keep
                                   HOLD/DENY → delete from `versions` AND `time`,
                                               record reason
                              4. return filtered packument
```

The resolver then simply can't pick a held/denied version — we shape the menu, we don't fight the
resolver.

## Critical edge case — pinned-but-held lockfile

A version already pinned in a client's lockfile but now **HELD** must produce a **clear Embargo
error** (reason + approval link), **not** a cryptic `ETARGET`/resolver failure. Degrade gracefully;
never break existing lockfiles. This is an explicit gateway responsibility and needs an integration
test.

## Configuration

| Var | Purpose |
|---|---|
| `EMBARGO_UPSTREAM` | upstream registry (default `https://registry.npmjs.org`) |
| `EMBARGO_ENGINE_RPC` | engine RPC address |

## Module sketch

```
/gateway
  package.json  tsconfig.json  .eslintrc  .prettierrc
  verdaccio/config.yaml         # uplink = EMBARGO_UPSTREAM; load the plugin
  src/
    plugin.ts                   # Verdaccio plugin entry (middleware hook)
    packument.ts                # filter versions/time maps by verdict
    engine-client.ts            # RPC client (ResolvePackument / Resolve)
    held-error.ts               # build the clear Embargo error for pinned-but-held
    cache.ts                    # (thin) read-through of engine verdict cache if needed
  test/
    packument.strip.test.ts     # HELD/DENY versions removed from versions + time
    pinned-held.error.test.ts   # pinned-but-held → clear Embargo error, not ETARGET
```

## Testing (from DEVELOPMENT.md)

- Integration test: a HELD version is **stripped from the packument** (both `versions` and `time`).
- Integration test: a **pinned-but-held** version yields a clear Embargo error, not `ETARGET`.
- Never weaken a gate or fixture to make a test pass — a correctly-held version failing a test means
  the test is wrong.

## Production requirements (M1)

- **HA:** multi-replica behind a load balancer; readiness/liveness probes; graceful shutdown;
  rolling deploys; Helm-deployable with resource limits.
- **Security:** mTLS + scoped service identity to the engine; no privileged admin surface here.
- **Observability:** OpenTelemetry spans for the resolve path (gateway → engine); Prometheus metrics
  (rewrite latency, versions stripped, cache hit ratio, upstream errors); structured logs with
  correlation IDs.
- **SLO:** packument rewrite adds only a small bounded overhead; gateway availability ≥ 99.9%; a
  pinned-but-held version always returns a clear Embargo error, never `ETARGET`.

## Milestones

- **M1:** packument rewrite + engine resolve + cache + pinned-but-held error path + HA + mTLS +
  observability — a production firewall enforcing policy/cooldown.
- **Later:** richer reasons/links, per-requester telemetry feeding the engine.

## Non-goals

- Policy/signal logic (engine only). Patching clients or fighting the resolver (forbidden — we work
  via packument rewriting). Adding uncached network calls to the rewrite path.
