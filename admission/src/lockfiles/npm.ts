import type { Dep } from '../types';

/**
 * Parse a package-lock.json (npm). Handles lockfileVersion 2/3 (`packages`
 * keyed by install path) and falls back to v1 (`dependencies`, recursive).
 */
export function parseNpm(content: string): Dep[] {
  const json = JSON.parse(content) as NpmLock;
  const deps: Dep[] = [];

  if (json.packages) {
    for (const [path, meta] of Object.entries(json.packages)) {
      if (path === '') continue; // the root project itself
      const name = nameFromPath(path);
      if (name && meta && typeof meta.version === 'string') {
        deps.push({ name, version: meta.version });
      }
    }
  } else if (json.dependencies) {
    collectV1(json.dependencies, deps);
  }

  return dedupe(deps);
}

interface NpmLock {
  packages?: Record<string, { version?: string }>;
  dependencies?: Record<string, NpmV1Dep>;
}

interface NpmV1Dep {
  version?: string;
  dependencies?: Record<string, NpmV1Dep>;
}

/** `node_modules/@scope/name` → `@scope/name`; nested paths take the last segment. */
function nameFromPath(path: string): string | null {
  const idx = path.lastIndexOf('node_modules/');
  if (idx === -1) return null;
  return path.slice(idx + 'node_modules/'.length);
}

function collectV1(tree: Record<string, NpmV1Dep>, out: Dep[]): void {
  for (const [name, meta] of Object.entries(tree)) {
    if (meta && typeof meta.version === 'string') {
      out.push({ name, version: meta.version });
    }
    if (meta?.dependencies) {
      collectV1(meta.dependencies, out);
    }
  }
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
