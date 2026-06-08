// ---------------------------------------------------------------------------
// Shared types for the admission gate.
// ---------------------------------------------------------------------------

export type Verdict = 'ALLOW' | 'HOLD' | 'DENY';

/** A resolved (package, version) entry from a lockfile. */
export interface Dep {
  name: string;
  version: string;
}

/** Canonical "name@version" key for set operations. */
export function depKey(d: Dep): string {
  return `${d.name}@${d.version}`;
}

export type LockfileFormat = 'npm' | 'pnpm' | 'yarn' | 'bun';

/** The engine's verdict for one dep, plus the context the report needs. */
export interface DepVerdict {
  dep: Dep;
  verdict: Verdict;
  reasons: string[];
  /** Console URL to request an exception, when held/denied. */
  approvalUrl?: string;
}

/** Result of evaluating a lockfile diff. */
export interface EvaluationResult {
  /** Every changed dep that did not resolve to ALLOW. */
  blocked: DepVerdict[];
  /** Count of changed deps evaluated. */
  evaluated: number;
  passed: boolean;
}

/** The engine call surface the gate depends on (mockable in tests). */
export interface EngineClient {
  resolve(dep: Dep): Promise<DepVerdict>;
}
