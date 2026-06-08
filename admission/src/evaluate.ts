import type { Dep, EngineClient, EvaluationResult } from './types';

/**
 * Resolve every changed dep against the engine and collect the ones that did
 * not come back ALLOW. The engine's Resolve already applies the time-boxed
 * approval exception workflow, so a dep with an active, unexpired exception
 * resolves to ALLOW here and passes the gate — no separate exception lookup.
 *
 * Resolves are issued concurrently (bounded) since they are independent.
 */
export async function evaluate(
  engine: EngineClient,
  changed: Dep[],
  concurrency = 8,
): Promise<EvaluationResult> {
  const blocked: EvaluationResult['blocked'] = [];

  for (let i = 0; i < changed.length; i += concurrency) {
    const batch = changed.slice(i, i + concurrency);
    const verdicts = await Promise.all(batch.map((dep) => engine.resolve(dep)));
    for (const v of verdicts) {
      if (v.verdict !== 'ALLOW') blocked.push(v);
    }
  }

  return {
    blocked,
    evaluated: changed.length,
    passed: blocked.length === 0,
  };
}
