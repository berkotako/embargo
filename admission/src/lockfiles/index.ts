import type { Dep, LockfileFormat } from '../types';
import { parseNpm } from './npm';
import { parsePnpm } from './pnpm';
import { parseYarn } from './yarn';
import { parseBun } from './bun';

/** Map a lockfile filename to its format, or null if unrecognized. */
export function formatForFilename(filename: string): LockfileFormat | null {
  const base = filename.split('/').pop() ?? filename;
  switch (base) {
    case 'package-lock.json':
    case 'npm-shrinkwrap.json':
      return 'npm';
    case 'pnpm-lock.yaml':
      return 'pnpm';
    case 'yarn.lock':
      return 'yarn';
    case 'bun.lock':
      return 'bun';
    default:
      return null;
  }
}

/** Parse lockfile content of a known format into a deduped dep list. */
export function parseLockfile(format: LockfileFormat, content: string): Dep[] {
  switch (format) {
    case 'npm':
      return parseNpm(content);
    case 'pnpm':
      return parsePnpm(content);
    case 'yarn':
      return parseYarn(content);
    case 'bun':
      return parseBun(content);
  }
}

export { parseNpm, parsePnpm, parseYarn, parseBun };
