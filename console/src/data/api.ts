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

/**
 * Open a *pending* exception request (separation of duties). It does not grant
 * until a different admin approves it via {@link approveApproval}.
 */
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

/** Approve a pending request (admin-only; the engine rejects self-approval). */
export async function approveApproval(id: string): Promise<Approval> {
  return send<Approval>('POST', `/approvals/${encodeURIComponent(id)}/approve`);
}

/** Reject a pending request (admin-only). */
export async function rejectApproval(id: string, reason: string): Promise<void> {
  await send<void>('POST', `/approvals/${encodeURIComponent(id)}/reject`, { reason });
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
  ecosystem: string;
  syncedAt: string;
}

export interface KnownMaliciousSource {
  source: string;
  ecosystem: string;
  count: number;
  lastSyncedAt: string;
}

export interface KnownMaliciousStatus {
  total: number;
  sources: KnownMaliciousSource[];
}

export interface FeedSource {
  id: string;
  name: string;
  url: string;
  ecosystem: string;
  format: string;
  enabled: boolean;
  intervalSeconds: number;
  lastSyncedAt: string | null;
  lastStatus: string | null;
  createdAt: string;
}

export async function getKnownMalicious(search?: string): Promise<KnownMaliciousEntry[]> {
  const q = search && search.trim() ? `?search=${encodeURIComponent(search.trim())}` : '';
  return get<KnownMaliciousEntry[]>(`/known-malicious${q}`);
}

export async function getKnownMaliciousStatus(): Promise<KnownMaliciousStatus> {
  return get<KnownMaliciousStatus>('/known-malicious/status');
}

/** Add a manual npm block. Omit `version` (or pass '*') to block all versions. */
export async function addKnownMalicious(pkg: string, version?: string): Promise<void> {
  await send<void>('POST', '/known-malicious', { package: pkg, version });
}

export async function removeKnownMalicious(en: KnownMaliciousEntry): Promise<void> {
  await send<void>('POST', '/known-malicious/remove', {
    package: en.package,
    version: en.version,
    source: en.source,
    ecosystem: en.ecosystem,
  });
}

// Feed sources (runtime-managed) ------------------------------------------------

export async function getFeeds(): Promise<FeedSource[]> {
  return get<FeedSource[]>('/feeds');
}

export async function addFeed(
  name: string,
  url: string,
  ecosystem: string,
): Promise<FeedSource> {
  return send<FeedSource>('POST', '/feeds', { name, url, ecosystem });
}

export async function updateFeed(
  id: string,
  patch: { enabled?: boolean; intervalSeconds?: number },
): Promise<void> {
  await send<void>('PATCH', `/feeds/${encodeURIComponent(id)}`, patch);
}

export async function deleteFeed(id: string): Promise<void> {
  await send<void>('DELETE', `/feeds/${encodeURIComponent(id)}`);
}

/** Sync a single feed source now (admin). Returns rows written. */
export async function syncFeed(id: string): Promise<{ written: number }> {
  return send<{ written: number }>('POST', `/feeds/${encodeURIComponent(id)}/sync`);
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
