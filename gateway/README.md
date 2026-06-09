# Embargo L1 — Gateway

The ingress firewall. A **Verdaccio storage-filter plugin** that intercepts each
packument and strips the versions the engine says are HOLD or DENY, so a client's
resolver never sees a disallowed version. Protocol-level — one `.npmrc` line and
it works across npm, pnpm, Yarn, and Bun.

```
client (registry=…/gateway) ──GET /{pkg}──▶ Verdaccio ──uplink──▶ npm
                                              │
                                       filter_metadata(packument)
                                              │ engine.ResolvePackument (mTLS)
                                              ▼
                                  strip HOLD/DENY from versions+time+dist-tags
```

## How it plugs in

Verdaccio calls a storage filter's `filter_metadata(packument)` after fetching
metadata from the uplink, before resolving. `EmbargoStorageFilter.filter_metadata`
asks the engine for verdicts (`ResolvePackument`) and rewrites the packument:

- ALLOW versions stay.
- HOLD/DENY versions are removed from `versions` and `time`; `dist-tags`
  pointing at a stripped version are dropped; an `_embargo` block with approval
  links is attached.

A pinned-but-held version yields a clear Embargo error with an approval link
(via `buildHeldError`), never a cryptic `ETARGET`.

### Fail mode

If the engine is unreachable the filter **fails closed** by default: it serves
no versions, so the gate stays shut at the cost of breaking installs. Set
`fail-closed: false` (dev only) to instead serve the unfiltered packument for
availability, logging loudly. Engine RPCs carry a deadline (`timeout-ms`,
default 5000) so a hung engine triggers the fail mode instead of stalling
installs forever.

## Configuration (`verdaccio.config.yaml`)

```yaml
filters:
  embargo:
    engine-addr: engine:50051       # the engine's gRPC listener
    console-url: http://localhost:4000
    tls-cert: /certs/gateway.crt     # client mTLS to the engine
    tls-key:  /certs/gateway.key
    tls-ca:   /certs/ca.crt
    fail-closed: false
```

Verdaccio resolves the filter name `embargo` to the plugin directory
`verdaccio-embargo` under its `plugins` path.

## Build & run

```bash
# unit tests (rewrite + filter logic) — no engine needed
npm ci && npm run typecheck && npm run lint && npm test

# container: build from the repo root so the engine proto is bundled
docker build -f gateway/Dockerfile -t embargo-gateway .
docker run -p 4873:4873 -v $PWD/certs:/certs:ro embargo-gateway
```

Point a client at it:

```
# .npmrc
registry=http://localhost:4873/
```

## End-to-end test

`test/e2e.test.ts` drives the rewrite against a **live engine over mTLS**
(skipped unless `EMBARGO_E2E` is set):

```bash
scripts/gen-dev-certs.sh /tmp/certs            # CA + engine + gateway certs
# …start the engine with those certs + a seeded policy (see DEVELOPMENT.md)…
EMBARGO_E2E=1 EMBARGO_ENGINE_ADDR=localhost:50051 EMBARGO_CERTS=/tmp/certs \
  npm test -- e2e
```

It asserts a fresh (HELD) version is stripped while an aged one is served, and
that a cert-less client is rejected (mTLS enforced).

## Notes

- The gRPC proto is bundled into the image at
  `/verdaccio/plugins/verdaccio-embargo/proto` and located via `EMBARGO_PROTO_DIR`.
- mTLS to the engine needs a client cert/key signed by the engine's CA. In
  `docker compose` the `certgen` service issues the whole chain (CA + engine
  server cert + `gateway` client cert) into a shared volume; the gateway service
  mounts it and is wired up out of the box.
