import { load } from 'js-yaml';
import type { Dep } from '../types';

/**
 * Parse a yarn.lock. Supports both classic (v1) and berry (v2+) formats.
 *
 * v1 — custom format:
 *   "lodash@^4.17.0", lodash@~4.17.0:
 *     version "4.17.21"
 *
 * berry — YAML with `__metadata`:
 *   "lodash@npm:^4.17.0":
 *     version: 4.17.21
 */
export function parseYarn(content: string): Dep[] {
  return content.includes('__metadata:') ? parseBerry(content) : parseClassic(content);
}

/** Berry lockfiles are YAML; keys are "name@npm:range[, …]", value.version is the resolved version. */
function parseBerry(content: string): Dep[] {
  const doc = load(content) as Record<string, { version?: string }> | undefined;
  if (!doc) return [];
  const deps: Dep[] = [];
  for (const [descriptors, meta] of Object.entries(doc)) {
    if (descriptors === '__metadata') continue;
    if (!meta || typeof meta.version !== 'string') continue;
    const name = nameFromDescriptors(descriptors);
    if (name) deps.push({ name, version: meta.version });
  }
  return dedupe(deps);
}

/** Classic v1 format: stanza header (descriptors) then an indented `version "x"` line. */
function parseClassic(content: string): Dep[] {
  const deps: Dep[] = [];
  let currentName: string | null = null;

  for (const rawLine of content.split('\n')) {
    if (!rawLine.trim() || rawLine.trimStart().startsWith('#')) continue;

    const indented = /^\s/.test(rawLine);
    if (!indented && rawLine.includes(':')) {
      // Stanza header: one or more comma-separated descriptors ending in ':'.
      const header = rawLine.replace(/:\s*$/, '');
      currentName = nameFromDescriptors(header);
    } else if (indented && currentName) {
      const m = rawLine.trim().match(/^version:?\s+"?([^"]+)"?$/);
      if (m && m[1]) {
        deps.push({ name: currentName, version: m[1] });
        currentName = null;
      }
    }
  }
  return dedupe(deps);
}

/**
 * Extract the package name from a descriptor list like
 * `"@scope/pkg@^1.0.0", "@scope/pkg@~1.2.0"` or `lodash@npm:^4`.
 * The name is everything before the LAST '@' of the first descriptor (the
 * leading '@' of a scope is preserved).
 */
export function nameFromDescriptors(header: string): string | null {
  const first = header.split(',')[0]?.trim().replace(/^"|"$/g, '');
  if (!first) return null;
  const at = first.lastIndexOf('@');
  if (at <= 0) return null;
  return first.slice(0, at);
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
