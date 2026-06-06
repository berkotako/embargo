import { cooldownProgress, cooldownRemaining } from '../lib/format.ts';

interface Props {
  computedAt: string;
  expiresAt: string | null;
}

export function CooldownBar({ computedAt, expiresAt }: Props) {
  const progress = cooldownProgress(computedAt, expiresAt);
  const label = cooldownRemaining(expiresAt);
  return (
    <span className="cooldown">
      <span className="cd-bar">
        <span className="cd-fill" style={{ width: `${Math.round(progress * 100)}%` }} />
      </span>
      {label}
    </span>
  );
}
