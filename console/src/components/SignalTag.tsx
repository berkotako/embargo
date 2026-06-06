import type { Signal } from '../types/index.ts';

interface Props {
  signal: Signal;
}

const LABEL_MAP: Record<string, string> = {
  new_lifecycle_script: 'lifecycle script',
  binding_gyp: 'binding.gyp',
  capability_dep: 'capability dep',
  republish: 'republish',
  maintainer_change: 'maintainer Δ',
  tarball_mismatch: 'tarball mismatch',
  obfuscation: 'obfuscation',
  advisory_match: 'advisory',
  sandbox_egress_attempt: 'sandbox egress',
  ebpf_compromise_chain: 'eBPF chain',
};

export function SignalTag({ signal }: Props) {
  const label = LABEL_MAP[signal.type] ?? signal.type;
  const sev =
    signal.severity === 'critical' || signal.severity === 'high' ? 'sev-high' :
    signal.severity === 'medium' ? 'sev-med' :
    'sev-low';
  return (
    <span className={`tag ${sev}`}>
      <span className="tdot" />
      {label}
    </span>
  );
}
