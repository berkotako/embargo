import type { EvaluationResult } from './types';

/** A machine-readable artifact summarizing the run. */
export interface ReportArtifact {
  passed: boolean;
  evaluated: number;
  blocked: Array<{
    package: string;
    version: string;
    verdict: string;
    reasons: string[];
    approvalUrl?: string;
  }>;
}

export function toArtifact(result: EvaluationResult): ReportArtifact {
  return {
    passed: result.passed,
    evaluated: result.evaluated,
    blocked: result.blocked.map((b) => ({
      package: b.dep.name,
      version: b.dep.version,
      verdict: b.verdict,
      reasons: b.reasons,
      ...(b.approvalUrl ? { approvalUrl: b.approvalUrl } : {}),
    })),
  };
}

/** Human-readable console report. */
export function toHuman(result: EvaluationResult): string {
  if (result.passed) {
    return `embargo: ${result.evaluated} changed dependencies evaluated — all ALLOW ✓`;
  }
  const lines: string[] = [
    `embargo: ${result.blocked.length} of ${result.evaluated} changed dependencies blocked by policy:`,
    '',
  ];
  for (const b of result.blocked) {
    lines.push(`  ✗ ${b.dep.name}@${b.dep.version}  [${b.verdict}]`);
    for (const r of b.reasons) lines.push(`      reason: ${r}`);
    if (b.approvalUrl) lines.push(`      request exception: ${b.approvalUrl}`);
  }
  lines.push('');
  lines.push('A HELD version may pass once its cooldown elapses; a DENY is permanent.');
  lines.push('Request a time-boxed exception via the approval link above.');
  return lines.join('\n');
}

/**
 * GitHub Actions annotations (one per blocked dep). The `::error::` workflow
 * command surfaces these inline on the PR.
 */
export function toAnnotations(result: EvaluationResult): string[] {
  return result.blocked.map((b) => {
    const reason = b.reasons[0] ?? 'violates policy';
    return `::error title=Embargo ${b.verdict}::${b.dep.name}@${b.dep.version} — ${reason}`;
  });
}
