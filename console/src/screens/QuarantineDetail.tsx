import { useState } from 'react';
import type { CurrentUser, VersionVerdict } from '../types/index.ts';
import { VerdictBadge } from '../components/VerdictBadge.tsx';
import { SignalTag } from '../components/SignalTag.tsx';
import { ProvenancePill } from '../components/ProvenancePill.tsx';
import { CooldownBar } from '../components/CooldownBar.tsx';
import { parsePkg, relativeTime } from '../lib/format.ts';
import { can } from '../lib/rbac.ts';
import { createApproval } from '../data/api.ts';

interface Props {
  verdict: VersionVerdict | null;
  user: CurrentUser;
  onClose: () => void;
}

export function Detail({ verdict, user, onClose }: Props) {
  const [approving, setApproving] = useState(false);
  const [justification, setJustification] = useState('');
  const [ttlHours, setTtlHours] = useState(168);
  const [submitting, setSubmitting] = useState(false);

  const open = verdict !== null;
  const canApprove = can(user.role, 'write:approvals');

  async function handleApprove() {
    if (!verdict) return;
    setSubmitting(true);
    await createApproval(verdict.package, verdict.version, justification, ttlHours);
    setSubmitting(false);
    setApproving(false);
    setJustification('');
    onClose();
  }

  const { scope, name } = verdict ? parsePkg(verdict.package) : { scope: null, name: '' };

  return (
    <>
      <div className={`drawer-scrim${open ? ' open' : ''}`} onClick={onClose} />
      <div className={`drawer${open ? ' open' : ''}`}>
        {verdict && (
          <>
            <div className="drawer-head">
              <div className="dh-top">
                <div>
                  <div className="dh-pkg mono">
                    {scope && <span style={{ color: 'var(--text-dim)' }}>{scope}</span>}
                    {name}
                    {' '}
                    <span className="ver">{verdict.version}</span>
                  </div>
                  <div className="dh-meta">
                    <VerdictBadge verdict={verdict.verdict} />
                    <span>{relativeTime(verdict.computedAt)}</span>
                  </div>
                </div>
                <button className="btn btn-sm btn-ghost" onClick={onClose}>✕</button>
              </div>
            </div>

            <div className="drawer-body">
              {/* Reasons */}
              <div className="dsec">
                <div className="dsec-title">Reasons <span className="ds-line" /></div>
                {verdict.reasons.map((r, i) => (
                  <div key={i} className="req-row">
                    <span className="req-ico">⚠</span>
                    <span>{r}</span>
                  </div>
                ))}
                {verdict.reasons.length === 0 && (
                  <span className="dim">No explicit reasons recorded.</span>
                )}
              </div>

              {/* Signals */}
              {verdict.signals.length > 0 && (
                <div className="dsec">
                  <div className="dsec-title">Signals ({verdict.signals.length}) <span className="ds-line" /></div>
                  {verdict.signals.map((s) => (
                    <div key={s.id} className="sig-row">
                      <div className="sig-name">
                        <SignalTag signal={s} />
                        <span>{s.type}</span>
                      </div>
                      <div className="sig-weight">
                        <div className="sig-wbar">
                          <div
                            className="sig-wfill"
                            style={{ width: `${s.weight}%`, background: s.severity === 'critical' ? 'var(--deny)' : 'var(--hold)' }}
                          />
                        </div>
                        <span className="sig-wval mono">{s.weight}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* Provenance */}
              <div className="dsec">
                <div className="dsec-title">Provenance <span className="ds-line" /></div>
                <ProvenancePill provenance={verdict.provenance} />
                {verdict.provenance?.status === 'verified' && (
                  <div className="kv" style={{ marginTop: 10 }}>
                    <dt>Workflow</dt>
                    <dd>{verdict.provenance.workflow}</dd>
                    <dt>Repository</dt>
                    <dd>{verdict.provenance.repo}</dd>
                  </div>
                )}
              </div>

              {/* Cooldown */}
              {verdict.expiresAt && (
                <div className="dsec">
                  <div className="dsec-title">Cooldown <span className="ds-line" /></div>
                  <CooldownBar computedAt={verdict.computedAt} expiresAt={verdict.expiresAt} />
                </div>
              )}

              {/* Approval form */}
              {canApprove && approving && (
                <div className="dsec">
                  <div className="dsec-title">Fast-track approval <span className="ds-line" /></div>
                  <div className="warn-banner warn" style={{ marginBottom: 12 }}>
                    ⚠ Approval bypasses the cooldown window. Ensure this version is safe.
                  </div>
                  <label style={{ fontSize: 11.5, color: 'var(--text-dim)' }}>Justification</label>
                  <textarea
                    className="field"
                    style={{ marginTop: 6 }}
                    rows={3}
                    placeholder="Reason for fast-tracking this version…"
                    value={justification}
                    onChange={(e) => setJustification(e.target.value)}
                  />
                  <label style={{ fontSize: 11.5, color: 'var(--text-dim)', marginTop: 10, display: 'block' }}>TTL</label>
                  <select
                    className="field"
                    style={{ marginTop: 6 }}
                    value={ttlHours}
                    onChange={(e) => setTtlHours(Number(e.target.value))}
                  >
                    <option value={24}>24 hours</option>
                    <option value={72}>3 days</option>
                    <option value={168}>7 days</option>
                    <option value={720}>30 days</option>
                  </select>
                </div>
              )}
            </div>

            <div className="drawer-foot">
              {canApprove && !approving && (
                <button className="btn btn-allow" onClick={() => setApproving(true)}>
                  Approve exception
                </button>
              )}
              {canApprove && approving && (
                <>
                  <button
                    className="btn btn-primary"
                    disabled={!justification.trim() || submitting}
                    onClick={handleApprove}
                  >
                    {submitting ? 'Approving…' : 'Confirm approval'}
                  </button>
                  <button className="btn btn-ghost" onClick={() => setApproving(false)}>
                    Cancel
                  </button>
                </>
              )}
              {!approving && (
                <button className="btn btn-deny">Permanently deny</button>
              )}
            </div>
          </>
        )}
      </div>
    </>
  );
}
