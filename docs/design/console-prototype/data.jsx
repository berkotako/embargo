/* global window */
// EMBARGO demo dataset. All fictional. Assigned to window.EMBARGO.

(function () {
  // ---- Signal catalog: the behavioral / provenance risk signals ----
  const SIGNALS = {
    "new-postinstall":   { label: "new postinstall script",      sev: "high", desc: "package.json gained a postinstall hook not present in the prior version" },
    "provenance-missing":{ label: "provenance missing",          sev: "high", desc: "no signed build attestation (SLSA) published for this version" },
    "advisory-match":    { label: "advisory match",              sev: "high", desc: "version range matches a known GHSA / CVE advisory" },
    "binding-gyp":       { label: "binding.gyp introduced",      sev: "high", desc: "native build descriptor added — version can compile arbitrary code at install" },
    "typosquat":         { label: "typosquat similarity",        sev: "high", desc: "package name within edit-distance 1 of a high-traffic package" },
    "republish-anomaly": { label: "republish anomaly",           sev: "med",  desc: "tarball changed for an already-published version (content drift)" },
    "new-network":       { label: "new network host",            sev: "med",  desc: "install/runtime references a network host not seen in prior versions" },
    "maintainer-change": { label: "maintainer change",           sev: "med",  desc: "publish token belongs to an account added in the last 30 days" },
    "minified-source":   { label: "minified source added",       sev: "med",  desc: "obfuscated / minified file shipped outside dist/ build output" },
    "entropy-spike":     { label: "high-entropy string",         sev: "med",  desc: "long base64/hex blob added to source (possible packed payload)" },
    "young-release":     { label: "release age below cooldown",  sev: "low",  desc: "version is younger than the policy cooldown window" },
    "deprecated-dep":    { label: "deprecated transitive dep",   sev: "low",  desc: "pulls a transitive dependency flagged deprecated upstream" },
  };

  function ago(s) { return s; }

  // ---- Quarantine queue ----
  const QUEUE = [
    {
      id: "q-001", scope: "@mycompany", name: "auth-sdk", version: "4.2.0",
      verdict: "HOLD", score: 62,
      reason: "Provenance missing on internal scope + young release",
      signals: [
        { id: "provenance-missing", w: 30 },
        { id: "young-release", w: 12 },
        { id: "maintainer-change", w: 20 },
      ],
      cooldownRemaining: 5520, cooldownTotal: 86400,
      provenance: "missing", firstSeen: "2h 14m ago", firstSeenAbs: "2026-06-07 09:47Z",
      registry: "npmjs.org", publisher: "ci-bot@mycompany", unpacked: "1.8 MB", files: 214,
      prevVersion: "4.1.7",
      requesters: [
        { repo: "mycompany/payments-api", pipeline: "ci/build #4821", count: 6 },
        { repo: "mycompany/web-dashboard", pipeline: "ci/build #2210", count: 2 },
      ],
      diff: [
        { t: "add", path: "scripts/postinstall.js", size: "+1.2 KB", flag: "INSTALL SCRIPT" },
        { t: "add", path: "src/telemetry/collector.ts", size: "+4.4 KB" },
        { t: "mod", path: "package.json", size: "~", note: "added \"postinstall\"" },
        { t: "del", path: "src/legacy/v3-shim.ts", size: "-2.1 KB" },
      ],
      advisory: null,
    },
    {
      id: "q-002", scope: null, name: "chalk", version: "5.4.1",
      verdict: "DENY", score: 91,
      reason: "Advisory match (GHSA) + republish anomaly on pinned version",
      signals: [
        { id: "advisory-match", w: 40 },
        { id: "republish-anomaly", w: 28 },
        { id: "entropy-spike", w: 18 },
      ],
      cooldownRemaining: null, cooldownTotal: null,
      provenance: "ok", firstSeen: "47m ago", firstSeenAbs: "2026-06-07 11:14Z",
      registry: "npmjs.org", publisher: "sindresorhus", unpacked: "44 KB", files: 18,
      prevVersion: "5.4.0",
      requesters: [
        { repo: "mycompany/web-dashboard", pipeline: "ci/build #2213", count: 11 },
      ],
      diff: [
        { t: "mod", path: "source/index.js", size: "~", flag: "REPUBLISHED", note: "content changed, version unchanged" },
        { t: "add", path: "source/vendor.min.js", size: "+38 KB", flag: "MINIFIED" },
      ],
      advisory: { id: "GHSA-7p4x-9c2q-vm83", title: "Prototype pollution via crafted style string", severity: "High", range: ">=5.4.0 <5.4.2" },
    },
    {
      id: "q-003", scope: null, name: "left-pad", version: "1.4.0",
      verdict: "HOLD", score: 48,
      reason: "Maintainer change + release age below cooldown",
      signals: [
        { id: "maintainer-change", w: 20 },
        { id: "young-release", w: 12 },
        { id: "new-network", w: 16 },
      ],
      cooldownRemaining: 61200, cooldownTotal: 86400,
      provenance: "partial", firstSeen: "4h 02m ago", firstSeenAbs: "2026-06-07 07:59Z",
      registry: "npmjs.org", publisher: "azer-new", unpacked: "6 KB", files: 7,
      prevVersion: "1.3.0",
      requesters: [{ repo: "mycompany/utils-lib", pipeline: "ci/build #882", count: 3 }],
      diff: [
        { t: "add", path: "index.js", size: "~", note: "rewritten" },
        { t: "add", path: "lib/fetch-config.js", size: "+0.9 KB", flag: "NETWORK" },
      ],
      advisory: null,
    },
    {
      id: "q-004", scope: null, name: "node-ipc", version: "11.1.1",
      verdict: "DENY", score: 96,
      reason: "binding.gyp introduced + new network host + high-entropy payload",
      signals: [
        { id: "binding-gyp", w: 34 },
        { id: "new-network", w: 22 },
        { id: "entropy-spike", w: 24 },
        { id: "new-postinstall", w: 16 },
      ],
      cooldownRemaining: null, cooldownTotal: null,
      provenance: "missing", firstSeen: "1h 36m ago", firstSeenAbs: "2026-06-07 10:25Z",
      registry: "npmjs.org", publisher: "RIAEvangelist", unpacked: "212 KB", files: 64,
      prevVersion: "11.1.0",
      requesters: [{ repo: "mycompany/infra-agent", pipeline: "ci/build #1190", count: 1 }],
      diff: [
        { t: "add", path: "binding.gyp", size: "+0.4 KB", flag: "NATIVE BUILD" },
        { t: "add", path: "dao/ssh.js", size: "+3.7 KB", flag: "NETWORK" },
        { t: "add", path: "scripts/postinstall.js", size: "+2.0 KB", flag: "INSTALL SCRIPT" },
        { t: "mod", path: "package.json", size: "~", note: "added gyp + postinstall" },
      ],
      advisory: { id: "GHSA-97m3-w2cp-4xx6", title: "Embedded geolocation-gated payload", severity: "Critical", range: ">=11.0.0 <=11.1.1" },
    },
    {
      id: "q-005", scope: "@types", name: "node", version: "22.4.1",
      verdict: "HOLD", score: 22,
      reason: "Release age below cooldown",
      signals: [{ id: "young-release", w: 12 }, { id: "deprecated-dep", w: 8 }],
      cooldownRemaining: 14400, cooldownTotal: 86400,
      provenance: "ok", firstSeen: "23h 41m ago", firstSeenAbs: "2026-06-06 12:20Z",
      registry: "npmjs.org", publisher: "types-bot", unpacked: "2.1 MB", files: 312,
      prevVersion: "22.4.0",
      requesters: [
        { repo: "mycompany/payments-api", pipeline: "ci/build #4820", count: 14 },
        { repo: "mycompany/infra-agent", pipeline: "ci/build #1188", count: 9 },
      ],
      diff: [{ t: "mod", path: "index.d.ts", size: "~", note: "type updates only" }],
      advisory: null,
    },
    {
      id: "q-006", scope: null, name: "colors", version: "1.4.44",
      verdict: "DENY", score: 88,
      reason: "Republish anomaly + infinite-loop payload pattern",
      signals: [{ id: "republish-anomaly", w: 28 }, { id: "entropy-spike", w: 20 }, { id: "advisory-match", w: 40 }],
      cooldownRemaining: null, cooldownTotal: null,
      provenance: "missing", firstSeen: "6h 18m ago", firstSeenAbs: "2026-06-07 05:43Z",
      registry: "npmjs.org", publisher: "marak", unpacked: "39 KB", files: 22,
      prevVersion: "1.4.0",
      requesters: [{ repo: "mycompany/cli-tools", pipeline: "ci/build #560", count: 4 }],
      diff: [
        { t: "add", path: "lib/index.js", size: "~", flag: "REPUBLISHED" },
        { t: "add", path: "lib/custom/american.js", size: "+11 KB", flag: "OBFUSCATED" },
      ],
      advisory: { id: "GHSA-5q4x-3q4f-9j2c", title: "Intentional denial-of-service via infinite loop", severity: "High", range: ">=1.4.1" },
    },
    {
      id: "q-007", scope: "@mycompany", name: "design-tokens", version: "2.0.0",
      verdict: "HOLD", score: 18,
      reason: "Major version bump within cooldown window",
      signals: [{ id: "young-release", w: 12 }],
      cooldownRemaining: 70200, cooldownTotal: 86400,
      provenance: "ok", firstSeen: "5h 50m ago", firstSeenAbs: "2026-06-07 06:11Z",
      registry: "npmjs.org", publisher: "ci-bot@mycompany", unpacked: "120 KB", files: 41,
      prevVersion: "1.9.3",
      requesters: [{ repo: "mycompany/web-dashboard", pipeline: "ci/build #2209", count: 5 }],
      diff: [{ t: "add", path: "tokens/v2.json", size: "+8 KB" }, { t: "del", path: "tokens/v1.json", size: "-6 KB" }],
      advisory: null,
    },
    {
      id: "q-008", scope: null, name: "axios", version: "1.7.3",
      verdict: "HOLD", score: 34,
      reason: "Provenance missing + young release",
      signals: [{ id: "provenance-missing", w: 30 }, { id: "young-release", w: 12 }],
      cooldownRemaining: 28800, cooldownTotal: 86400,
      provenance: "missing", firstSeen: "19h 08m ago", firstSeenAbs: "2026-06-06 16:53Z",
      registry: "npmjs.org", publisher: "jasonsaayman", unpacked: "1.6 MB", files: 156,
      prevVersion: "1.7.2",
      requesters: [
        { repo: "mycompany/payments-api", pipeline: "ci/build #4818", count: 22 },
        { repo: "mycompany/web-dashboard", pipeline: "ci/build #2206", count: 13 },
      ],
      diff: [{ t: "mod", path: "dist/axios.js", size: "~", note: "build output" }],
      advisory: null,
    },
    {
      id: "q-009", scope: null, name: "event-stream", version: "3.3.6",
      verdict: "DENY", score: 94,
      reason: "Typosquat-installed transitive (flatmap-stream) + entropy spike",
      signals: [{ id: "typosquat", w: 36 }, { id: "entropy-spike", w: 24 }, { id: "new-postinstall", w: 16 }, { id: "maintainer-change", w: 20 }],
      cooldownRemaining: null, cooldownTotal: null,
      provenance: "missing", firstSeen: "3h 22m ago", firstSeenAbs: "2026-06-07 08:39Z",
      registry: "npmjs.org", publisher: "right9ctrl", unpacked: "28 KB", files: 14,
      prevVersion: "3.3.4",
      requesters: [{ repo: "mycompany/wallet-service", pipeline: "ci/build #77", count: 1 }],
      diff: [
        { t: "mod", path: "package.json", size: "~", flag: "DEP ADDED", note: "added flatmap-stream@0.1.1" },
        { t: "add", path: "node_modules/flatmap-stream/index.min.js", size: "+9 KB", flag: "OBFUSCATED" },
      ],
      advisory: { id: "GHSA-mh6f-8j2x-4483", title: "Malicious transitive dependency (flatmap-stream)", severity: "Critical", range: "=3.3.6" },
    },
    {
      id: "q-010", scope: "@mycompany", name: "telemetry-agent", version: "0.9.1",
      verdict: "HOLD", score: 40,
      reason: "New network host + minified source outside dist",
      signals: [{ id: "new-network", w: 22 }, { id: "minified-source", w: 16 }],
      cooldownRemaining: 43200, cooldownTotal: 86400,
      provenance: "partial", firstSeen: "11h 30m ago", firstSeenAbs: "2026-06-07 00:31Z",
      registry: "npmjs.org", publisher: "ci-bot@mycompany", unpacked: "340 KB", files: 58,
      prevVersion: "0.9.0",
      requesters: [{ repo: "mycompany/infra-agent", pipeline: "ci/build #1187", count: 2 }],
      diff: [{ t: "add", path: "src/ingest.min.js", size: "+22 KB", flag: "MINIFIED" }, { t: "add", path: "src/hosts.json", size: "+0.3 KB", flag: "NETWORK" }],
      advisory: null,
    },
    {
      id: "q-011", scope: null, name: "ua-parser-js", version: "1.0.38",
      verdict: "HOLD", score: 30,
      reason: "Maintainer change + provenance missing",
      signals: [{ id: "maintainer-change", w: 20 }, { id: "provenance-missing", w: 30 }],
      cooldownRemaining: 7200, cooldownTotal: 86400,
      provenance: "missing", firstSeen: "22h 05m ago", firstSeenAbs: "2026-06-06 13:56Z",
      registry: "npmjs.org", publisher: "faisalman", unpacked: "96 KB", files: 33,
      prevVersion: "1.0.37",
      requesters: [{ repo: "mycompany/web-dashboard", pipeline: "ci/build #2201", count: 8 }],
      diff: [{ t: "mod", path: "src/ua-parser.js", size: "~" }],
      advisory: null,
    },
    {
      id: "q-012", scope: null, name: "rc", version: "1.2.9",
      verdict: "DENY", score: 84,
      reason: "Typosquat similarity to widely-used 'rc' + install script",
      signals: [{ id: "typosquat", w: 36 }, { id: "new-postinstall", w: 16 }, { id: "provenance-missing", w: 30 }],
      cooldownRemaining: null, cooldownTotal: null,
      provenance: "missing", firstSeen: "8h 44m ago", firstSeenAbs: "2026-06-07 03:17Z",
      registry: "npmjs.org", publisher: "dominictarr-x", unpacked: "12 KB", files: 9,
      prevVersion: "1.2.8",
      requesters: [{ repo: "mycompany/cli-tools", pipeline: "ci/build #558", count: 2 }],
      diff: [{ t: "add", path: "scripts/postinstall.js", size: "+0.8 KB", flag: "INSTALL SCRIPT" }],
      advisory: null,
    },
    {
      id: "q-013", scope: "@mycompany", name: "feature-flags", version: "3.4.0",
      verdict: "HOLD", score: 16,
      reason: "Release age below cooldown",
      signals: [{ id: "young-release", w: 12 }],
      cooldownRemaining: 3000, cooldownTotal: 86400,
      provenance: "ok", firstSeen: "23h 12m ago", firstSeenAbs: "2026-06-06 12:49Z",
      registry: "npmjs.org", publisher: "ci-bot@mycompany", unpacked: "88 KB", files: 26,
      prevVersion: "3.3.9",
      requesters: [{ repo: "mycompany/web-dashboard", pipeline: "ci/build #2198", count: 7 }],
      diff: [{ t: "mod", path: "src/client.ts", size: "~" }],
      advisory: null,
    },
    {
      id: "q-014", scope: null, name: "is-promise", version: "4.0.0",
      verdict: "HOLD", score: 26,
      reason: "Republish anomaly (low confidence)",
      signals: [{ id: "republish-anomaly", w: 28 }],
      cooldownRemaining: 36000, cooldownTotal: 86400,
      provenance: "ok", firstSeen: "16h 49m ago", firstSeenAbs: "2026-06-06 19:12Z",
      registry: "npmjs.org", publisher: "forbeslindesay", unpacked: "4 KB", files: 5,
      prevVersion: "3.0.0",
      requesters: [{ repo: "mycompany/utils-lib", pipeline: "ci/build #879", count: 4 }],
      diff: [{ t: "mod", path: "index.js", size: "~" }],
      advisory: null,
    },
  ];

  // ---- Dashboard ----
  const hours = Array.from({ length: 24 }, (_, i) => i);
  function series(base, amp, seed) {
    return hours.map((h) => Math.max(0, Math.round(base + amp * Math.sin((h + seed) / 3.1) + ((h * 7 + seed * 13) % 9) - 4)));
  }
  const DASHBOARD = {
    stats: {
      held:    { value: 38, delta: +12, spark: series(6, 4, 1) },
      denied:  { value: 9,  delta: +3,  spark: series(2, 2, 5) },
      allowed: { value: 1284, delta: -4, spark: series(48, 20, 2) },
    },
    pendingApprovals: 7,
    trend: {
      allowed: series(46, 18, 2),
      held:    series(7, 4, 1),
      denied:  series(2, 2, 5),
    },
    topHeld: [
      { name: "axios", count: 9 },
      { name: "@types/node", count: 7 },
      { name: "@mycompany/auth-sdk", count: 6 },
      { name: "ua-parser-js", count: 5 },
      { name: "@mycompany/design-tokens", count: 4 },
    ],
    containment: [
      { pkg: "node-ipc@11.1.1", host: "45.137.21.9:22", pipeline: "ci/build #1190", repo: "infra-agent", time: "10:31Z", attempts: 3 },
      { pkg: "event-stream@3.3.6", host: "copay-checkout.herokuapp[.]com", pipeline: "ci/build #77", repo: "wallet-service", time: "08:42Z", attempts: 1 },
      { pkg: "colors@1.4.44", host: "—", pipeline: "ci/build #560", repo: "cli-tools", time: "05:46Z", attempts: 1, note: "infinite loop — process killed" },
      { pkg: "rc@1.2.9", host: "146.59.156.12:443", pipeline: "ci/build #558", repo: "cli-tools", time: "03:19Z", attempts: 2 },
    ],
  };

  // ---- Policies (most-specific-wins ordering) ----
  const POLICIES = [
    {
      id: "p-1", scope: "@mycompany/*", specificity: 4, enabled: true,
      cooldownHours: 0, requireProvenance: true, fastTrack: ["@mycompany/design-tokens", "@mycompany/feature-flags"],
      action: "Allow internal scope, no cooldown, provenance required",
      author: "h.okafor", edited: "2026-05-29",
    },
    {
      id: "p-2", scope: "@types/*", specificity: 3, enabled: true,
      cooldownHours: 6, requireProvenance: false, fastTrack: [],
      action: "Type defs — short 6h cooldown, provenance optional",
      author: "d.reyes", edited: "2026-05-12",
    },
    {
      id: "p-3", scope: "express, axios, chalk, react, **/lodash", specificity: 2, enabled: true,
      cooldownHours: 24, requireProvenance: true, fastTrack: [],
      action: "Critical-path public packages — 24h cooldown + provenance",
      author: "h.okafor", edited: "2026-06-01",
    },
    {
      id: "p-4", scope: "**", specificity: 1, enabled: true,
      cooldownHours: 72, requireProvenance: false, fastTrack: [],
      action: "Default — hold everything 72h, deny on advisory/typosquat",
      author: "system", edited: "2026-04-02",
    },
  ];
  const DRYRUN = {
    window: "last 7 days",
    evaluated: 4218,
    before: { allowed: 3980, held: 214, denied: 24 },
    after:  { allowed: 3902, held: 286, denied: 30 },
    changes: [
      { pkg: "axios@1.7.3", was: "ALLOW", now: "HOLD", why: "require provenance now matches" },
      { pkg: "lodash@4.17.21", was: "ALLOW", now: "HOLD", why: "24h cooldown extended to critical-path" },
      { pkg: "@mycompany/auth-sdk@4.2.0", was: "HOLD", now: "DENY", why: "missing provenance on internal scope" },
      { pkg: "rc@1.2.9", was: "HOLD", now: "DENY", why: "typosquat rule promoted to deny" },
    ],
  };

  // ---- Approvals & exceptions ----
  const APPROVALS = [
    { id: "a-1", pkg: "axios@1.7.3", type: "fast-track", by: "m.tanaka", role: "approver", justification: "Hotfix for payment timeout incident INC-4471; provenance pending upstream.", approver: "h.okafor", granted: "2026-06-07 09:12Z", expiry: "2026-06-08 09:12Z", status: "active" },
    { id: "a-2", pkg: "@mycompany/auth-sdk@4.1.7", type: "exception", by: "d.reyes", role: "approver", justification: "Internal SDK, provenance signing not yet wired in CI.", approver: "h.okafor", granted: "2026-06-05 14:02Z", expiry: "2026-06-19 14:02Z", status: "active" },
    { id: "a-3", pkg: "left-pad@1.4.0", type: "override", by: "k.nguyen", role: "viewer", justification: "Requesting early release — build blocked.", approver: null, granted: null, expiry: null, status: "pending" },
    { id: "a-4", pkg: "@types/node@22.4.1", type: "override", by: "s.alvi", role: "approver", justification: "CI green, low risk type-only change.", approver: "m.tanaka", granted: "2026-06-06 18:40Z", expiry: "2026-06-07 18:40Z", status: "active" },
    { id: "a-5", pkg: "chalk@5.3.0", type: "exception", by: "h.okafor", role: "admin", justification: "Pre-advisory baseline pin for legacy dashboard.", approver: "h.okafor", granted: "2026-05-20 11:00Z", expiry: "2026-06-03 11:00Z", status: "expired" },
    { id: "a-6", pkg: "ua-parser-js@1.0.37", type: "fast-track", by: "d.reyes", role: "approver", justification: "Rollback target during maintainer-change investigation.", approver: "h.okafor", granted: "2026-05-31 08:25Z", expiry: "2026-06-02 08:25Z", status: "expired" },
    { id: "a-7", pkg: "@mycompany/telemetry-agent@0.9.1", type: "override", by: "k.nguyen", role: "viewer", justification: "Need staging build to validate new ingest host.", approver: null, granted: null, expiry: null, status: "pending" },
  ];

  // ---- Inspector: per-package version timeline ----
  const INSPECTOR = {
    "@mycompany/auth-sdk": {
      scope: "@mycompany", name: "auth-sdk", latest: "4.2.0", weekly: "internal",
      maintainers: ["ci-bot@mycompany", "h.okafor"], repo: "github.com/mycompany/auth-sdk",
      versions: [
        { version: "4.2.0", verdict: "HOLD", date: "2026-06-07", provenance: "missing", signals: ["provenance-missing", "young-release", "maintainer-change"], pulledBy: "ci-bot", pipeline: "payments-api #4821" },
        { version: "4.1.7", verdict: "ALLOW", date: "2026-05-22", provenance: "ok", signals: [], pulledBy: "ci-bot", pipeline: "payments-api #4720", exception: true },
        { version: "4.1.6", verdict: "ALLOW", date: "2026-05-09", provenance: "ok", signals: [], pulledBy: "ci-bot", pipeline: "web-dashboard #2100" },
        { version: "4.1.5", verdict: "HOLD", date: "2026-04-28", provenance: "partial", signals: ["young-release"], pulledBy: "ci-bot", pipeline: "payments-api #4600" },
        { version: "4.1.0", verdict: "ALLOW", date: "2026-03-14", provenance: "ok", signals: [], pulledBy: "ci-bot", pipeline: "web-dashboard #1990" },
      ],
    },
    "axios": {
      scope: null, name: "axios", latest: "1.7.3", weekly: "58.2M",
      maintainers: ["jasonsaayman"], repo: "github.com/axios/axios",
      versions: [
        { version: "1.7.3", verdict: "HOLD", date: "2026-06-06", provenance: "missing", signals: ["provenance-missing", "young-release"], pulledBy: "ci-bot", pipeline: "payments-api #4818" },
        { version: "1.7.2", verdict: "ALLOW", date: "2026-05-19", provenance: "ok", signals: [], pulledBy: "ci-bot", pipeline: "payments-api #4701" },
        { version: "1.7.1", verdict: "ALLOW", date: "2026-05-02", provenance: "ok", signals: [], pulledBy: "ci-bot", pipeline: "web-dashboard #2055" },
        { version: "1.7.0", verdict: "ALLOW", date: "2026-04-20", provenance: "ok", signals: ["young-release"], pulledBy: "ci-bot", pipeline: "web-dashboard #2010" },
      ],
    },
  };

  // ---- Audit log (immutable, hash-chained) ----
  const AUDIT = [
    { ts: "2026-06-07 11:18:42Z", actor: "h.okafor", role: "admin", action: "VERDICT_DENY", target: "chalk@5.4.1", detail: "Advisory GHSA-7p4x-9c2q-vm83 confirmed", hash: "a91f3c2e" },
    { ts: "2026-06-07 11:02:08Z", actor: "system", role: "engine", action: "POLICY_EVAL", target: "chalk@5.4.1", detail: "republish-anomaly fired (w28)", hash: "7d40b1aa" },
    { ts: "2026-06-07 10:33:51Z", actor: "system", role: "engine", action: "CONTAINMENT", target: "node-ipc@11.1.1", detail: "blocked egress 45.137.21.9:22", hash: "0c5e8f19" },
    { ts: "2026-06-07 10:26:14Z", actor: "system", role: "engine", action: "VERDICT_DENY", target: "node-ipc@11.1.1", detail: "binding.gyp + entropy-spike (score 96)", hash: "f2a7d004" },
    { ts: "2026-06-07 09:12:03Z", actor: "h.okafor", role: "admin", action: "OVERRIDE_FASTTRACK", target: "axios@1.7.3", detail: "INC-4471 hotfix, expiry 24h", hash: "3be19c7d" },
    { ts: "2026-06-07 09:11:40Z", actor: "m.tanaka", role: "approver", action: "OVERRIDE_REQUEST", target: "axios@1.7.3", detail: "justification submitted", hash: "88c0a45f" },
    { ts: "2026-06-07 08:40:22Z", actor: "system", role: "engine", action: "VERDICT_DENY", target: "event-stream@3.3.6", detail: "typosquat transitive flatmap-stream", hash: "b1772ee9" },
    { ts: "2026-06-06 18:40:55Z", actor: "m.tanaka", role: "approver", action: "EXCEPTION_GRANT", target: "@types/node@22.4.1", detail: "type-only, expiry 24h", hash: "5a3f0b88" },
    { ts: "2026-06-06 16:55:10Z", actor: "system", role: "engine", action: "VERDICT_HOLD", target: "axios@1.7.3", detail: "provenance-missing + young-release", hash: "c70e2d31" },
    { ts: "2026-06-01 14:22:09Z", actor: "h.okafor", role: "admin", action: "POLICY_UPDATE", target: "rule: critical-path", detail: "added require-provenance=true", hash: "e0918a4c" },
    { ts: "2026-05-31 08:25:33Z", actor: "h.okafor", role: "admin", action: "OVERRIDE_FASTTRACK", target: "ua-parser-js@1.0.37", detail: "rollback during investigation", hash: "2f6b119d" },
    { ts: "2026-05-29 10:04:18Z", actor: "h.okafor", role: "admin", action: "POLICY_UPDATE", target: "rule: @mycompany/*", detail: "cooldown 24h → 0h, provenance required", hash: "9c4e7a02" },
    { ts: "2026-05-22 13:47:51Z", actor: "d.reyes", role: "approver", action: "VERDICT_ALLOW", target: "@mycompany/auth-sdk@4.1.7", detail: "exception granted (14d)", hash: "44d1f6b3" },
    { ts: "2026-05-20 11:00:02Z", actor: "h.okafor", role: "admin", action: "EXCEPTION_GRANT", target: "chalk@5.3.0", detail: "legacy pin, expiry 14d", hash: "1ab90c55" },
  ];

  const USERS = {
    "h.okafor":  { name: "Hana Okafor",   role: "admin",    color: "#4d8dff" },
    "m.tanaka":  { name: "Mira Tanaka",   role: "approver", color: "#46c46a" },
    "d.reyes":   { name: "Diego Reyes",   role: "approver", color: "#e7b53d" },
    "k.nguyen":  { name: "Kai Nguyen",    role: "viewer",   color: "#a06ad4" },
    "s.alvi":    { name: "Sana Alvi",     role: "approver", color: "#3fb6c4" },
    "system":    { name: "Embargo Engine", role: "engine", color: "#5b6478" },
  };

  window.EMBARGO = { SIGNALS, QUEUE, DASHBOARD, POLICIES, DRYRUN, APPROVALS, INSPECTOR, AUDIT, USERS };
})();
