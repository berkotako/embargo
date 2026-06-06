# Signals

The signal catalog and scoring contract for the Policy & Signal Engine. Read this before
implementing or modifying any detection in `/engine`.

## Scoring contract (the rules signals must obey)

1. **A signal returns a weighted finding, never a verdict.** Signals contribute weight + evidence.
   The HOLD/DENY decision is made by policy thresholds, not by the signal. Do not hardcode block
   decisions inside a signal.
2. **Score chains, not single facts.** Compose related signals. A single sensitive API has no
   intent; a chain (new dep + secret read + new egress host) does. Prefer emitting a composite
   finding when the constituent signals co-occur.
3. **Age-independent.** Signals evaluate the *content/metadata* of a version, not how old it is —
   cooldown handles age. Signals run during the HOLD window to decide HOLD→DENY escalation.
4. **Every signal ships with a fixture pair.** A benign version that must NOT trigger it, and a
   malicious version that must. Located in `engine/fixtures/<signal>/`. Not "done" without both.
5. **Bias to HOLD.** A new or low-confidence signal raises weight toward HOLD (human review), not
   DENY. False positives that a human can dismiss beat false negatives nobody sees — but a flood of
   false HOLDs erodes trust, so tune weights against real traffic. FP rate is the product metric.

## Verdict escalation

```
base verdict = cooldown / provenance policy result (ALLOW | HOLD | DENY)
final verdict = escalate(base, sum(signal weights) vs policy thresholds)

- signals can only escalate toward DENY, never relax toward ALLOW
- a HELD version that crosses the DENY threshold during cooldown is denied PERMANENTLY
  (not allowed when the timer expires)
- an external advisory match (OSV / GitHub Advisory) is an automatic DENY
```

## Catalog

Weights are starting points — tune on real traffic. `H` = high, `M` = medium, `L` = low.

| Signal | Detects | Source | Weight |
|---|---|---|---|
| `new_lifecycle_script` | pre/post/install script added vs. prior version | manifest diff | H |
| `binding_gyp_introduced` | install-time native exec vector | tarball inspection | H |
| `new_capability_dep` | new dep touching network / fs / `child_process` | dep-tree diff + static scan | M |
| `provenance_missing` | review-bypass / out-of-pipeline publish | npm attestations | H |
| `republish_anomaly` | sudden token-driven mass republish (worm) | publish metadata / maintainer history | H |
| `maintainer_change` | new publisher / geo / token | registry metadata | M |
| `tarball_repo_mismatch` | published artifact ≠ source repo | provenance + repo diff | H |
| `advisory_match` | OSV / GitHub Advisory hit during cooldown | external feeds | DENY |
| `sandbox_egress_attempt` | install tried to reach non-allowlisted host | L3 containment | H |
| `obfuscation_markers` | high-entropy/packed payload; known stealer patterns | static scan | M |

## Composite chains (emit when constituents co-occur)

- **Stealer chain:** `new_capability_dep` (network) + env/secret read in install script +
  `new_lifecycle_script` → strong DENY candidate. Mirrors the Shai-Hulud / Miasma stealer pattern.
- **Out-of-pipeline poison:** `provenance_missing` + `tarball_repo_mismatch` → DENY candidate.
  Mirrors orphan-commit review-bypass.
- **Native exec smuggling:** `binding_gyp_introduced` + `obfuscation_markers` → DENY candidate.

## Implementation notes

- Tarball diffing and manifest/dep-tree diffing live in the engine; they take (prev_version,
  new_version) and emit findings. Cache parsed tarballs — re-fetching on every packument is a
  hot-path violation.
- Static scans must be bounded (timeout + size cap). A package that can't be scanned in budget is
  HELD pending review, not allowed by default.
- Keep detection logic pure/testable: input = version artifact + metadata + prior version; output
  = `Vec<Signal>`. No I/O inside the scoring functions; fetch in a separate layer.

## Adding a new signal (checklist)

1. Define the signal type + default weight here.
2. Implement a pure detector in `/engine` returning `Vec<Signal>`.
3. Add `engine/fixtures/<signal>/benign/` and `engine/fixtures/<signal>/malicious/`.
4. Add a test asserting benign → no finding, malicious → finding with expected weight.
5. If it composes into a known chain, wire the composite and test the chain too.
