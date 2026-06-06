import type { Verdict } from '../types/index.ts';

interface Props {
  verdict: Verdict;
}

export function VerdictBadge({ verdict }: Props) {
  const cls =
    verdict === 'ALLOW' ? 'badge badge-allow' :
    verdict === 'HOLD' ? 'badge badge-hold' :
    'badge badge-deny';
  return (
    <span className={cls}>
      <span className="dot" />
      {verdict}
    </span>
  );
}
