// ---------------------------------------------------------------------------
// Core domain types — mirrors the engine's gRPC proto + policy schema.
// ---------------------------------------------------------------------------

export type Verdict = 'ALLOW' | 'HOLD' | 'DENY';

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export type OnHardSignal = 'deny' | 'hold';

export interface PolicyRule {
  id: string;
  scope: string;
  cooldownHours: number;
  requireProvenance: boolean;
  onHardSignal: OnHardSignal;
  fastTrack: string[];
  enabled: boolean;
  /** 0–4 specificity score (4 = most specific). */
  specificity: number;
}

export interface Signal {
  id: string;
  type: string;
  severity: Severity;
  /** Raw weight 0–100. Policy thresholds decide the verdict. */
  weight: number;
  evidence: Record<string, unknown>;
  detectedAt: string; // ISO 8601
}

export interface Provenance {
  status: 'verified' | 'invalid' | 'absent';
  workflow?: string;
  repo?: string;
  reason?: string;
}

export interface VersionVerdict {
  package: string;
  version: string;
  verdict: Verdict;
  reasons: string[];
  signals: Signal[];
  provenance: Provenance | null;
  computedAt: string;
  expiresAt: string | null;
}

export interface Approval {
  id: string;
  package: string;
  version: string;
  requesterId: string;
  approverId: string | null;
  justification: string;
  expiresAt: string | null;
  status: 'pending' | 'active' | 'expired' | 'revoked';
  createdAt: string;
}

export type AuditAction =
  | 'verdict_computed'
  | 'verdict_overridden'
  | 'policy_updated'
  | 'policy_created'
  | 'policy_deleted'
  | 'approval_granted'
  | 'approval_revoked'
  | 'approval_expired'
  | 'signal_reported'
  | 'containment_event';

export interface AuditActor {
  type: 'user' | 'service' | 'system';
  id?: string;
  email?: string;
  role?: string;
  name?: string;
}

export interface AuditEntry {
  id: string;
  actor: AuditActor;
  action: AuditAction;
  target: {
    type: 'package_version' | 'policy' | 'approval';
    package?: string;
    version?: string;
    scope?: string;
    id?: string;
  };
  before: Record<string, unknown> | null;
  after: Record<string, unknown> | null;
  timestamp: string;
  prevHash: string | null;
  contentHash: string;
}

export interface ContainmentEvent {
  id: string;
  pkg: string;
  host: string;
  pipeline: string;
  repo: string;
  attempts: number;
  time: string;
  note?: string;
}

export interface DashboardStats {
  held: number;
  denied: number;
  allowed: number;
  advisoryMatches: number;
  heldTrend: number[];
  topSignals: Array<{ type: string; count: number; share: number }>;
  recentEvents: ContainmentEvent[];
}

/** RBAC roles understood by the console. */
export type UserRole = 'viewer' | 'responder' | 'admin';

export interface CurrentUser {
  id: string;
  email: string;
  name: string;
  role: UserRole;
  avatarInitials: string;
}
