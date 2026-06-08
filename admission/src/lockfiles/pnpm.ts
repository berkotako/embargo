import { load } from 'js-yaml';
import type { Dep } from '../types';

/**
 * Parse a pnpm-lock.yaml. The `packages` map is keyed by a dependency id:
 *   pnpm v9:  `lodash@4.17.21`, `@scope/name@1.0.0`, `react@18.2.0(peer@x)`
 *   pnpm v6:  `/lodash@4.17.21`, `/@scope/name@1.0.0`
 * We strip the leading slash, drop any `(peer…)` suffix, then split name@version.
 */
export function parsePnpm(content: string): Dep[] {
  const doc = load(content) as PnpmLock | undefined;
  if (!doc?.packages) return [];

  const deps: Dep[] = [];
  for (const rawKey of Object.keys(doc.packages)) {
    const parsed = parseKey(rawKey);
    if (parsed) deps.push(parsed);
  }
  return dedupe(deps);
}

interface PnpmLock {
  packages?: Record<string, unknown>;
}

/** Turn a pnpm dependency-id key into {name, version}. */
export function parseKey(rawKey: string): Dep | null {
  let key = rawKey.startsWith('/') ? rawKey.slice(1) : rawKey;
  // Drop pnpm peer-dependency suffix: `react@18.2.0(react-dom@18.2.0)` → `react@18.2.0`.
  const peer = key.indexOf('(');
  if (peer !== -1) key = key.slice(0, peer);

  // The version follows the LAST '@' that isn't the scope's leading '@'.
  const at = key.lastIndexOf('@');
  if (at <= 0) return null; // no version, or '@' only at position 0 (scope with no version)
  const name = key.slice(0, at);
  const version = key.slice(at + 1);
  if (!name || !version || version.includes('/')) return null;
  return { name, version };
}

function dedupe(deps: Dep[]): Dep[] {
  const seen = new Set<string>();
  const out: Dep[] = [];
  for (const d of deps) {
    const k = `${d.name}@${d.version}`;
    if (!seen.has(k)) {
      seen.add(k);
      out.push(d);
    }
  }
  return out;
}
