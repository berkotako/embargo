import { useEffect, useState } from 'react';
import type { Approval, CurrentUser } from '../types/index.ts';
import { getApprovals, revokeApproval } from '../data/api.ts';
import { VerdictBadge } from '../components/VerdictBadge.tsx';
import { EmptyState } from '../components/EmptyState.tsx';
import { relativeTime, shortDate } from '../lib/format.ts';
import { can } from '../lib/rbac.ts';

interface Props {
  user: CurrentUser;
}

export function ScreenApprovals({ user }: Props) {
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [loading, setLoading] = useState(true);
  const [revoking, setRevoking] = useState<string | null>(null);

  const canApprove = can(user.role, 'write:approvals');

  useEffect(() => {
    getApprovals().then((a) => {
      setApprovals(a);
      setLoading(false);
    });
  }, []);

  async function handleRevoke(id: string) {
    setRevoking(id);
    await revokeApproval(id, 'Revoked via console');
    setApprovals((prev) => prev.filter((a) => a.id !== id));
    setRevoking(null);
  }

  if (loading) {
    return <div className="content-pad"><div className="skel skel-line" style={{ width: 300, height: 20 }} /></div>;
  }

  if (approvals.length === 0) {
    return (
      <div className="content-pad">
        <EmptyState icon="✓" title="No active approvals" body="Time-boxed exceptions will appear here. Approvals are audited and auto-expire." />
      </div>
    );
  }

  return (
    <div className="content-pad fade-in">
      <div className="tbl-meta">
        <span><b>{approvals.length}</b> approvals</span>
      </div>
      <div className="tbl-wrap">
        <table className="tbl">
          <thead>
            <tr>
              <th>Package</th>
              <th>Status</th>
              <th>Justification</th>
              <th>Expires</th>
              <th>Created</th>
              {canApprove && <th />}
            </tr>
          </thead>
          <tbody className="stagger">
            {approvals.map((a) => (
              <tr key={a.id}>
                <td>
                  <div className="cell-pkg mono">
                    {a.package}
                    {' '}
                    <span className="ver">{a.version}</span>
                  </div>
                </td>
                <td>
                  <span className={`badge ${a.status === 'active' ? 'badge-allow' : a.status === 'pending' ? 'badge-hold' : 'badge-neutral'}`}>
                    <span className="dot" />
                    {a.status}
                  </span>
                </td>
                <td style={{ maxWidth: 320 }}>
                  <span style={{ fontSize: 12 }}>{a.justification}</span>
                </td>
                <td className="dim mono">{a.expiresAt ? shortDate(a.expiresAt) : '—'}</td>
                <td className="dim">{relativeTime(a.createdAt)}</td>
                {canApprove && (
                  <td>
                    {a.status === 'active' && (
                      <button
                        className="btn btn-sm btn-deny"
                        disabled={revoking === a.id}
                        onClick={() => handleRevoke(a.id)}
                      >
                        {revoking === a.id ? '…' : 'Revoke'}
                      </button>
                    )}
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
