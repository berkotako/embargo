import type { Provenance } from '../types/index.ts';

interface Props {
  provenance: Provenance | null;
}

export function ProvenancePill({ provenance }: Props) {
  if (!provenance || provenance.status === 'absent') {
    return <span className="prov missing">✕ absent</span>;
  }
  if (provenance.status === 'invalid') {
    return <span className="prov partial">⚠ invalid</span>;
  }
  return (
    <span className="prov ok" title={`${provenance.workflow} — ${provenance.repo}`}>
      ✓ verified
    </span>
  );
}
