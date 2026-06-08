import type { Dep } from './types';
import { depKey } from './types';

/**
 * Diff-aware: return the deps present in `head` but not in `base`, keyed by
 * exact name@version. A bumped version shows up as a new key, so both added and
 * changed dependencies are captured; unchanged ones are skipped (keeps CI fast).
 */
export function changedDeps(base: Dep[], head: Dep[]): Dep[] {
  const baseKeys = new Set(base.map(depKey));
  const out: Dep[] = [];
  const seen = new Set<string>();
  for (const d of head) {
    const k = depKey(d);
    if (!baseKeys.has(k) && !seen.has(k)) {
      seen.add(k);
      out.push(d);
    }
  }
  return out;
}
