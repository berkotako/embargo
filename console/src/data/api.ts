// ---------------------------------------------------------------------------
// Live engine API. Talks to the engine's JSON admin facade (see
// engine/src/http.rs). In dev, Vite proxies /api → the engine (vite.config.ts);
// in production nginx proxies /api → the engine. Responses are already shaped
// (camelCase) to match the domain types, so mapping is the identity.
//
// IMPORTANT: the engine owns all verdict computation. This file only performs
// HTTP and returns typed results.
// ---------------------------------------------------------------------------

import type {
  Approval,
  AuditEntry,
  CurrentUser,
  DashboardStats,
  PolicyRule,
  UserRole,
  VersionVerdict,
} from '../types/index.ts';
import { authHeaders } from '../lib/auth.ts';

const BASE = (import.meta.env.VITE_API_BASE as string | undefined) ?? '/api';

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { accept: 'application/json', ...authHeaders() },
  });
  if (!res.ok) throw new ApiError(res.status, `GET ${path} failed`);
  return (await res.json()) as T;
}

async function send<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { 'content-type': 'application/json', accept: 'application/json', ...authHeaders() },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  if (!res.ok) throw new ApiError(res.status, `${method} ${path} failed`);
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  return (text ? JSON.parse(text) : undefined) as T;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

// ---------------------------------------------------------------------------
// Quarantine
// ---------------------------------------------------------------------------

export async function getHeldVersions(): Promise<VersionVerdict[]> {
  return get<VersionVerdict[]>('/verdicts?verdict=hold');
}

export async function getDeniedVersions(): Promise<VersionVerdict[]> {
  return get<VersionVerdict[]>('/verdicts?verdict=deny');
}

export async function getVersionVerdict(
  pkg: string,
  version: string,
): Promise<VersionVerdict | null> {
  const all = [...(await getHeldVersions()), ...(await getDeniedVersions())];
  return all.find((v) => v.package === pkg && v.version === version) ?? null;
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

export async function getPolicies(): Promise<PolicyRule[]> {
  return get<PolicyRule[]>('/policies');
}

export interface DryRun {
  total: number;
  nowBlocked: number;
  wouldRelease: number;
  affectedPkgs: string[];
}

export async function getDryRun(): Promise<DryRun> {
  return get<DryRun>('/policies/dryrun');
}

// ---------------------------------------------------------------------------
// Approvals
// ---------------------------------------------------------------------------

export async function getApprovals(): Promise<Approval[]> {
  return get<Approval[]>('/approvals');
}

export async function createApproval(
  pkg: string,
  version: string,
  justification: string,
  ttlHours: number,
): Promise<Approval> {
  return send<Approval>('POST', '/approvals', {
    package: pkg,
    version,
    justification,
    ttlHours,
  });
}

export async function revokeApproval(id: string, reason: string): Promise<void> {
  await send<void>('POST', `/approvals/${encodeURIComponent(id)}/revoke`, { reason });
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

export async function getAuditLog(limit = 50): Promise<AuditEntry[]> {
  return get<AuditEntry[]>(`/audit?limit=${limit}`);
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

export async function getDashboardStats(): Promise<DashboardStats> {
  return get<DashboardStats>('/dashboard');
}

// ---------------------------------------------------------------------------
// Known-malicious feed
// ---------------------------------------------------------------------------

export interface KnownMaliciousEntry {
  package: string;
  version: string;
  source: string;
  syncedAt: string;
}

export interface KnownMaliciousSource {
  source: string;
  count: number;
  lastSyncedAt: string;
}

export interface KnownMaliciousStatus {
  feedEnabled: boolean;
  feedSource: string;
  feedIntervalSecs: number;
  total: number;
  sources: KnownMaliciousSource[];
}

export async function getKnownMalicious(search?: string): Promise<KnownMaliciousEntry[]> {
  const q = search && search.trim() ? `?search=${encodeURIComponent(search.trim())}` : '';
  return get<KnownMaliciousEntry[]>(`/known-malicious${q}`);
}

export async function getKnownMaliciousStatus(): Promise<KnownMaliciousStatus> {
  return get<KnownMaliciousStatus>('/known-malicious/status');
}

/** Add a manual block. Omit `version` (or pass '*') to block all versions. */
export async function addKnownMalicious(pkg: string, version?: string): Promise<void> {
  await send<void>('POST', '/known-malicious', { package: pkg, version });
}

export async function removeKnownMalicious(
  pkg: string,
  version: string,
  source?: string,
): Promise<void> {
  await send<void>('POST', '/known-malicious/remove', { package: pkg, version, source });
}

/** Trigger an immediate feed re-sync (admin). Returns rows written. */
export async function syncKnownMalicious(): Promise<{ written: number }> {
  return send<{ written: number }>('POST', '/known-malicious/sync');
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

interface WhoAmI {
  email: string;
  role: UserRole;
  authMode: string;
}

/** Establish the session: the engine returns the server-enforced role. */
export async function whoami(): Promise<CurrentUser> {
  const w = await get<WhoAmI>('/whoami');
  const name = w.email.split('@')[0] || w.email || 'user';
  return {
    id: w.email,
    email: w.email,
    name,
    role: w.role,
    avatarInitials: (name[0] ?? 'U').toUpperCase(),
  };
}
