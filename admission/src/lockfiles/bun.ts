import type { Dep } from '../types';

/**
 * Parse a `bun.lock` (the text/JSONC lockfile Bun 1.1+ writes). Its `packages`
 * map values are arrays whose first element is the `name@version` descriptor:
 *   "packages": { "lodash": ["lodash@4.17.21", "", {}, "sha512-…"] }
 *
 * The legacy binary `bun.lockb` is not parsed here — convert it first with
 * `bun bun.lockb` (or commit `bun.lock`). See README.
 */
export function parseBun(content: string): Dep[] {
  const json = JSON.parse(stripJsonComments(content)) as BunLock;
  if (!json.packages) return [];

  const deps: Dep[] = [];
  for (const value of Object.values(json.packages)) {
    const descriptor = Array.isArray(value) ? value[0] : undefined;
    if (typeof descriptor === 'string') {
      const dep = parseDescriptor(descriptor);
      if (dep) deps.push(dep);
    }
  }
  return dedupe(deps);
}

interface BunLock {
  packages?: Record<string, unknown[]>;
}

/** `@scope/name@1.2.3` / `lodash@4.17.21` → {name, version}. */
export function parseDescriptor(descriptor: string): Dep | null {
  const at = descriptor.lastIndexOf('@');
  if (at <= 0) return null;
  const name = descriptor.slice(0, at);
  const version = descriptor.slice(at + 1);
  if (!name || !version) return null;
  return { name, version };
}

/** Bun's lockfile is JSONC (trailing commas + // comments). Strip to plain JSON. */
function stripJsonComments(input: string): string {
  // Remove // line comments and /* */ block comments, then trailing commas.
  const noComments = input
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:"])\/\/.*$/gm, '$1');
  return noComments.replace(/,(\s*[}\]])/g, '$1');
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
