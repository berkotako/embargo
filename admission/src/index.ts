import type { Dep, EngineClient, EvaluationResult, LockfileFormat } from './types';
import { formatForFilename, parseLockfile } from './lockfiles';
import { changedDeps } from './diff';
import { evaluate } from './evaluate';

export * from './types';
export { formatForFilename, parseLockfile } from './lockfiles';
export { changedDeps } from './diff';
export { evaluate } from './evaluate';
export { toArtifact, toHuman, toAnnotations } from './report';
export { GrpcEngineClient } from './engine-client';

export interface GateInput {
  filename: string;
  baseContent: string | null; // null when the lockfile is newly added
  headContent: string;
}

/**
 * Core gate: parse a lockfile pair, compute the changed deps, and evaluate them
 * against the engine. Pure orchestration — I/O (git, files, gRPC) lives in the
 * CLI/Action and the injected engine client.
 */
export async function runGate(engine: EngineClient, input: GateInput): Promise<EvaluationResult> {
  const format: LockfileFormat | null = formatForFilename(input.filename);
  if (!format) {
    throw new Error(`unrecognized lockfile: ${input.filename}`);
  }

  const head: Dep[] = parseLockfile(format, input.headContent);
  const base: Dep[] = input.baseContent ? parseLockfile(format, input.baseContent) : [];
  const changed = changedDeps(base, head);

  return evaluate(engine, changed);
}
