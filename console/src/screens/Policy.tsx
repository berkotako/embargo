import { useEffect, useState } from 'react';
import type { CurrentUser, PolicyRule } from '../types/index.ts';
import { getDryRun, getPolicies } from '../data/api.ts';
import { can } from '../lib/rbac.ts';

function SpecificityDots({ score }: { score: number }) {
  return (
    <span className="specificity">
      {[0, 1, 2, 3].map((i) => (
        <i key={i} className={i < score ? 'on' : ''} />
      ))}
    </span>
  );
}

interface Props {
  user: CurrentUser;
}

export function ScreenPolicy({ user }: Props) {
  const [rules, setRules] = useState<PolicyRule[]>([]);
  const [selected, setSelected] = useState<PolicyRule | null>(null);
  const [dryRun, setDryRun] = useState<{ total: number; nowBlocked: number; wouldRelease: number } | null>(null);
  const [loading, setLoading] = useState(true);

  const canEdit = can(user.role, 'write:policies');

  useEffect(() => {
    Promise.all([getPolicies(), getDryRun()]).then(([r, dr]) => {
      setRules(r);
      setSelected(r[0] ?? null);
      setDryRun(dr);
      setLoading(false);
    });
  }, []);

  if (loading) {
    return <div className="content-pad"><div className="skel skel-line" style={{ width: 300, height: 20 }} /></div>;
  }

  return (
    <div className="content-pad fade-in">
      <div className="policy-layout">
        {/* Rule list */}
        <div className="panel" style={{ overflow: 'hidden' }}>
          <div className="panel-head">
            <h2>Rules</h2>
            <span className="ph-sub">most-specific-wins</span>
            {canEdit && <button className="btn btn-sm btn-primary" style={{ marginLeft: 'auto' }}>+ Add rule</button>}
          </div>
          {rules.map((rule) => (
            <div
              key={rule.id}
              className={`rule-item${selected?.id === rule.id ? ' active' : ''}`}
              onClick={() => setSelected(rule)}
            >
              <span className="rule-spec"><SpecificityDots score={rule.specificity} /></span>
              <div className="rule-scope mono">{rule.scope}</div>
              <div className="rule-meta">
                <span>{rule.cooldownHours}h cooldown</span>
                {rule.requireProvenance && <span>provenance required</span>}
                {!rule.enabled && <span style={{ color: 'var(--text-faint)' }}>disabled</span>}
              </div>
            </div>
          ))}
        </div>

        {/* Rule editor */}
        <div>
          {selected && (
            <div className="panel">
              <div className="panel-head">
                <h2 className="mono">{selected.scope}</h2>
                {canEdit && <button className="btn btn-sm" style={{ marginLeft: 'auto' }}>Save</button>}
              </div>
              <div className="panel-body">
                <div className="form-grid">
                  <div className="form-row">
                    <label>Scope (glob)</label>
                    <input
                      className="field"
                      defaultValue={selected.scope}
                      readOnly={!canEdit}
                    />
                    <span className="hint">Comma-separated globs. Most-specific rule wins.</span>
                  </div>
                  <div className="form-row">
                    <label>Cooldown (hours)</label>
                    <input
                      className="field"
                      type="number"
                      defaultValue={selected.cooldownHours}
                      readOnly={!canEdit}
                    />
                  </div>
                </div>

                <div style={{ marginTop: 16 }}>
                  <div className="toggle-row">
                    <div>
                      <div className="tr-label">Require provenance</div>
                      <div className="tr-sub">Deny versions without SLSA attestation</div>
                    </div>
                    <div
                      className={`switch${selected.requireProvenance ? ' on' : ''}`}
                      style={{ pointerEvents: canEdit ? 'auto' : 'none', opacity: canEdit ? 1 : 0.6 }}
                    />
                  </div>
                  <div className="toggle-row">
                    <div>
                      <div className="tr-label">Enabled</div>
                      <div className="tr-sub">Disabled rules are skipped during resolution</div>
                    </div>
                    <div
                      className={`switch${selected.enabled ? ' on' : ''}`}
                      style={{ pointerEvents: canEdit ? 'auto' : 'none', opacity: canEdit ? 1 : 0.6 }}
                    />
                  </div>
                </div>

                <div className="form-row" style={{ marginTop: 16 }}>
                  <label>On hard signal</label>
                  <select className="field" defaultValue={selected.onHardSignal} disabled={!canEdit}>
                    <option value="deny">deny (permanent)</option>
                    <option value="hold">hold (manual review)</option>
                  </select>
                </div>

                {selected.fastTrack.length > 0 && (
                  <div className="form-row" style={{ marginTop: 16 }}>
                    <label>Fast-track packages</label>
                    <div className="tagrow" style={{ marginTop: 4 }}>
                      {selected.fastTrack.map((pkg) => (
                        <span key={pkg} className="tag mono">{pkg}</span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Dry-run preview */}
          {dryRun && (
            <div className="dryrun" style={{ marginTop: 14 }}>
              <div style={{ fontSize: 11.5, color: 'var(--text-dim)' }}>
                DRY-RUN IMPACT — changes to this rule would affect:
              </div>
              <div className="dryrun-stat">
                <div className="drs">
                  <div className="drs-num" style={{ color: 'var(--text)' }}>{dryRun.total}</div>
                  <div className="drs-lbl">Total pkgs</div>
                </div>
                <div className="drs">
                  <div className="drs-num" style={{ color: 'var(--deny)' }}>{dryRun.nowBlocked}</div>
                  <div className="drs-lbl">Now blocked</div>
                </div>
                <div className="drs">
                  <div className="drs-num" style={{ color: 'var(--allow)' }}>{dryRun.wouldRelease}</div>
                  <div className="drs-lbl">Would release</div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
