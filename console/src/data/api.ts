// ---------------------------------------------------------------------------
// API stub — the seam between mock data (now) and the live engine (M2).
//
// Every function returns a Promise wrapping mock data with a simulated network
// delay. To wire the real engine, replace each function body with a fetch()
// call to the engine's HTTP admin facade (or gRPC-web gateway).
//
// IMPORTANT: Do not add engine logic here. The engine owns all verdict
// computation. This file only translates HTTP responses to domain types.
// ---------------------------------------------------------------------------

import type {
  Approval,
  AuditEntry,
  DashboardStats,
  PolicyRule,
  VersionVerdict,
} from '../types/index.ts';
import {
  MOCK_APPROVALS,
  MOCK_AUDIT,
  MOCK_DENIED,
  MOCK_DRYRUN,
  MOCK_HELD,
  MOCK_POLICIES,
  MOCK_STATS,
} from './mock.ts';

const LATENCY = 180; // ms — simulates realistic network round-trip

function delay<T>(value: T): Promise<T> {
  return new Promise((resolve) => setTimeout(() => resolve(value), LATENCY));
}

// ---------------------------------------------------------------------------
// Quarantine
// ---------------------------------------------------------------------------

export async function getHeldVersions(): Promise<VersionVerdict[]> {
  return delay([...MOCK_HELD]);
}

export async function getDeniedVersions(): Promise<VersionVerdict[]> {
  return delay([...MOCK_DENIED]);
}

export async function getVersionVerdict(
  pkg: string,
  version: string,
): Promise<VersionVerdict | null> {
  const all = [...MOCK_HELD, ...MOCK_DENIED];
  return delay(all.find((v) => v.package === pkg && v.version === version) ?? null);
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

export async function getPolicies(): Promise<PolicyRule[]> {
  return delay([...MOCK_POLICIES]);
}

export async function upsertPolicy(rule: PolicyRule): Promise<PolicyRule> {
  return delay(rule);
}

export async function deletePolicy(id: string): Promise<void> {
  void id;
  return delay(undefined);
}

export async function getDryRun(): Promise<typeof MOCK_DRYRUN> {
  return delay({ ...MOCK_DRYRUN });
}

// ---------------------------------------------------------------------------
// Approvals
// ---------------------------------------------------------------------------

export async function getApprovals(): Promise<Approval[]> {
  return delay([...MOCK_APPROVALS]);
}

export async function createApproval(
  pkg: string,
  version: string,
  justification: string,
  ttlHours: number,
): Promise<Approval> {
  const approval: Approval = {
    id: crypto.randomUUID(),
    package: pkg,
    version,
    requesterId: 'current-user',
    approverId: null,
    justification,
    expiresAt: new Date(Date.now() + ttlHours * 3600_000).toISOString(),
    status: 'pending',
    createdAt: new Date().toISOString(),
  };
  return delay(approval);
}

export async function revokeApproval(id: string, _reason: string): Promise<void> {
  void id;
  return delay(undefined);
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

export async function getAuditLog(limit = 50): Promise<AuditEntry[]> {
  void limit;
  return delay([...MOCK_AUDIT]);
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

export async function getDashboardStats(): Promise<DashboardStats> {
  return delay({ ...MOCK_STATS });
}
