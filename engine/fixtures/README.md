# Signal fixtures

Per `docs/SIGNALS.md`, every signal ships a **fixture pair**: a benign version that
must NOT trigger it and a malicious version that must.

## Layout

```
fixtures/<scenario>/
  benign/              # current version that should produce NO finding
  benign_prior/        # (optional) the prior version, for diff-based signals
  malicious/           # current version that SHOULD produce the finding/chain
  malicious_prior/     # (optional) the prior version
```

Each variant directory is a real npm-package-shaped tree (`package.json` plus any
referenced source files). An optional `embargo-fixture.json` sidecar supplies
metadata that isn't in `package.json` — the provenance attestation repo, the
publisher identity, the republish burst count — i.e. data the engine's I/O layer
would normally fetch from the registry/attestation service.

## Loader + assertions

The loader and the benign-vs-malicious assertions live in
`crates/embargo-core/tests/fixtures.rs`. The test reads each fixture directory into
a `VersionArtifact`, runs `extract_signals`, and asserts the expected outcome. It
runs against the pure core (no database), so `cargo test -p embargo-core` exercises
the full extraction pipeline end-to-end.

## Coverage

| Scenario | Asserts |
|---|---|
| `stealer_chain` | malicious → `new_lifecycle_script` + `capability_dep` + `stealer_chain`; benign → none |
| `binding_gyp` | malicious → `binding.gyp` introduced; benign (native addon that always shipped one) → none |
| `tarball_mismatch` | malicious → `tarball_repo_mismatch` + `out_of_pipeline_chain`; benign → none |

Per-detector benign/malicious pairs for every signal are additionally covered by
the unit tests inside each `signals/<name>.rs` module.
