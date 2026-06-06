/** Format an ISO timestamp as a human-readable relative string. */
export function relativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60_000);
  const hours = Math.floor(diff / 3_600_000);
  const days = Math.floor(diff / 86_400_000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  if (hours < 24) return `${hours}h ago`;
  return `${days}d ago`;
}

/** Format an ISO timestamp as a short date string. */
export function shortDate(iso: string): string {
  return new Date(iso).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

/** Compute cooldown remaining from expiresAt. */
export function cooldownRemaining(expiresAt: string | null): string {
  if (!expiresAt) return '';
  const remaining = new Date(expiresAt).getTime() - Date.now();
  if (remaining <= 0) return 'expired';
  const hours = Math.ceil(remaining / 3_600_000);
  if (hours < 24) return `${hours}h`;
  const days = Math.ceil(hours / 24);
  return `${days}d`;
}

/** 0–1 fraction of cooldown elapsed. */
export function cooldownProgress(computedAt: string, expiresAt: string | null): number {
  if (!expiresAt) return 1;
  const total = new Date(expiresAt).getTime() - new Date(computedAt).getTime();
  const elapsed = Date.now() - new Date(computedAt).getTime();
  return Math.min(1, Math.max(0, elapsed / total));
}

/** Truncate a SHA hash for display. */
export function shortHash(hash: string | null): string {
  if (!hash) return '—';
  return hash.slice(0, 8);
}

/** Split a scoped package name into scope + name. */
export function parsePkg(pkg: string): { scope: string | null; name: string } {
  if (pkg.startsWith('@')) {
    const slash = pkg.indexOf('/');
    if (slash !== -1) {
      return { scope: pkg.slice(0, slash + 1), name: pkg.slice(slash + 1) };
    }
  }
  return { scope: null, name: pkg };
}
