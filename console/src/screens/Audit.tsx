import { useEffect, useState } from 'react';
import type { AuditEntry } from '../types/index.ts';
import { getAuditLog } from '../data/api.ts';
import { relativeTime, shortHash } from '../lib/format.ts';

const ACTION_ICONS: Record<string, string> = {
  verdict_computed: '⊙',
  verdict_overridden: '⊜',
  policy_updated: '⊟',
  policy_created: '⊞',
  policy_deleted: '⊠',
  approval_granted: '✓',
  approval_revoked: '✕',
  approval_expired: '⊘',
  signal_reported: '⚡',
  containment_event: '⊗',
};

export function ScreenAudit() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getAuditLog(100).then((e) => {
      setEntries(e);
      setLoading(false);
    });
  }, []);

  return (
    <div className="content-pad fade-in">
      <div className="tbl-meta">
        <span>Hash-chained, tamper-evident. Each entry's SHA-256 chains to its predecessor.</span>
      </div>
      {loading ? (
        <div className="skel skel-line" style={{ height: 20 }} />
      ) : (
        <div className="tbl-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>Time</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Target</th>
                <th>Hash</th>
              </tr>
            </thead>
            <tbody className="stagger">
              {entries.map((entry) => (
                <tr key={entry.id} className="audit-row">
                  <td className="dim mono nowrap">{relativeTime(entry.timestamp)}</td>
                  <td>
                    <div className="actor">
                      {entry.actor.type === 'user' && (
                        <div
                          className="avatar-sm"
                          style={{ background: 'linear-gradient(135deg, var(--accent), #2c5fd6)' }}
                        >
                          {(entry.actor.name ?? 'U').charAt(0).toUpperCase()}
                        </div>
                      )}
                      <span className="mono" style={{ fontSize: 11.5 }}>
                        {entry.actor.email ?? entry.actor.name ?? entry.actor.type}
                      </span>
                    </div>
                  </td>
                  <td>
                    <span className="audit-action">
                      {ACTION_ICONS[entry.action] ?? '·'}{' '}
                      {entry.action.replace(/_/g, ' ')}
                    </span>
                  </td>
                  <td className="mono" style={{ fontSize: 11.5 }}>
                    {entry.target.type === 'package_version'
                      ? `${entry.target.package}@${entry.target.version}`
                      : entry.target.type === 'policy'
                      ? `policy:${entry.target.scope}`
                      : `approval:${entry.target.id?.slice(0, 8)}`}
                  </td>
                  <td className="hashcell mono">
                    <span title={entry.contentHash}>{shortHash(entry.contentHash)}</span>
                    {entry.prevHash && (
                      <span style={{ marginLeft: 4, color: 'var(--text-faint)' }}>
                        ← {shortHash(entry.prevHash)}
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
