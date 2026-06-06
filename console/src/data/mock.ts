// ---------------------------------------------------------------------------
// Mock data — mirrors the design prototype's data.jsx exactly.
// Replaced by api.ts calls once the engine HTTP facade is live.
// ---------------------------------------------------------------------------
import type {
  Approval,
  AuditEntry,
  ContainmentEvent,
  DashboardStats,
  PolicyRule,
  VersionVerdict,
} from '../types/index.ts';

export const MOCK_HELD: VersionVerdict[] = [
  {
    package: 'lodash',
    version: '4.17.22',
    verdict: 'HOLD',
    reasons: ['cooldown: 48h remaining'],
    signals: [
      { id: 's1', type: 'new_lifecycle_script', severity: 'high', weight: 72, evidence: { script: 'postinstall' }, detectedAt: '2026-06-01T12:00:00Z' },
      { id: 's2', type: 'tarball_mismatch', severity: 'medium', weight: 38, evidence: {}, detectedAt: '2026-06-01T12:00:00Z' },
    ],
    provenance: { status: 'absent' },
    computedAt: '2026-06-01T12:00:00Z',
    expiresAt: '2026-06-03T12:00:00Z',
  },
  {
    package: 'axios',
    version: '1.7.3',
    verdict: 'HOLD',
    reasons: ['cooldown: 12h remaining'],
    signals: [],
    provenance: { status: 'verified', workflow: 'release.yml', repo: 'axios/axios' },
    computedAt: '2026-06-05T00:00:00Z',
    expiresAt: '2026-06-06T00:00:00Z',
  },
  {
    package: 'express',
    version: '4.19.3',
    verdict: 'HOLD',
    reasons: ['cooldown: 60h remaining'],
    signals: [
      { id: 's3', type: 'binding_gyp', severity: 'medium', weight: 50, evidence: {}, detectedAt: '2026-06-04T08:00:00Z' },
    ],
    provenance: { status: 'absent' },
    computedAt: '2026-06-04T00:00:00Z',
    expiresAt: '2026-06-07T00:00:00Z',
  },
];

export const MOCK_DENIED: VersionVerdict[] = [
  {
    package: '@colors/colors',
    version: '1.6.0',
    verdict: 'DENY',
    reasons: ['advisory: GHSA-0000-xkcd-0001 (malicious publish)'],
    signals: [
      { id: 's4', type: 'advisory_match', severity: 'critical', weight: 100, evidence: { advisory_id: 'GHSA-0000-xkcd-0001' }, detectedAt: '2026-05-15T00:00:00Z' },
    ],
    provenance: { status: 'absent' },
    computedAt: '2026-05-15T00:00:00Z',
    expiresAt: null,
  },
];

export const MOCK_POLICIES: PolicyRule[] = [
  {
    id: 'p1',
    scope: '@mycompany/*',
    cooldownHours: 0,
    requireProvenance: true,
    onHardSignal: 'deny',
    fastTrack: ['@mycompany/design-tokens', '@mycompany/feature-flags'],
    enabled: true,
    specificity: 2,
  },
  {
    id: 'p2',
    scope: '@types/*',
    cooldownHours: 6,
    requireProvenance: false,
    onHardSignal: 'deny',
    fastTrack: [],
    enabled: true,
    specificity: 2,
  },
  {
    id: 'p3',
    scope: 'express,axios,chalk,react,lodash',
    cooldownHours: 24,
    requireProvenance: true,
    onHardSignal: 'deny',
    fastTrack: [],
    enabled: true,
    specificity: 1,
  },
  {
    id: 'p4',
    scope: '**',
    cooldownHours: 72,
    requireProvenance: false,
    onHardSignal: 'deny',
    fastTrack: [],
    enabled: true,
    specificity: 0,
  },
];

export const MOCK_APPROVALS: Approval[] = [
  {
    id: 'a1',
    package: 'webpack',
    version: '5.92.0',
    requesterId: 'u1',
    approverId: null,
    justification: 'Security patch for CVE-2024-43788. Build pipeline unblocked.',
    expiresAt: '2026-06-13T12:00:00Z',
    status: 'pending',
    createdAt: '2026-06-06T10:00:00Z',
  },
  {
    id: 'a2',
    package: 'next',
    version: '14.2.4',
    requesterId: 'u2',
    approverId: 'u3',
    justification: 'Emergency fix for XSS in App Router. Approved by security team.',
    expiresAt: '2026-06-20T00:00:00Z',
    status: 'active',
    createdAt: '2026-06-03T09:00:00Z',
  },
];

export const MOCK_AUDIT: AuditEntry[] = [
  {
    id: 'au1',
    actor: { type: 'user', id: 'u3', email: 'alice@example.com', role: 'admin', name: 'Alice' },
    action: 'approval_granted',
    target: { type: 'package_version', package: 'next', version: '14.2.4' },
    before: null,
    after: { ttl_hours: 168, justification: 'Emergency XSS fix' },
    timestamp: '2026-06-03T09:05:00Z',
    prevHash: 'abc123',
    contentHash: 'def456',
  },
  {
    id: 'au2',
    actor: { type: 'user', id: 'u3', email: 'alice@example.com', role: 'admin', name: 'Alice' },
    action: 'policy_updated',
    target: { type: 'policy', scope: 'express,axios,chalk,react,lodash' },
    before: { cooldown_hours: 48 },
    after: { cooldown_hours: 24 },
    timestamp: '2026-06-02T14:30:00Z',
    prevHash: 'xyz789',
    contentHash: 'ghi012',
  },
];

export const MOCK_STATS: DashboardStats = {
  held: 14,
  denied: 3,
  allowed: 10482,
  advisoryMatches: 2,
  heldTrend: [2, 5, 3, 8, 6, 14, 14],
  topSignals: [
    { type: 'new_lifecycle_script', count: 8, share: 0.57 },
    { type: 'binding_gyp', count: 3, share: 0.21 },
    { type: 'tarball_mismatch', count: 3, share: 0.21 },
  ],
  recentEvents: [
    {
      id: 'ce1',
      pkg: '@stripe/stripe-js',
      host: 'telemetry.evil.com:443',
      pipeline: 'build/deploy',
      repo: 'acme-corp/frontend',
      attempts: 1,
      time: '2026-06-05T22:14:00Z',
      note: 'postinstall attempted outbound connection',
    },
  ],
};

export const MOCK_DRYRUN = {
  total: 847,
  nowBlocked: 12,
  wouldRelease: 3,
  affectedPkgs: ['lodash', 'express', '@types/node'],
};
