import { useEffect, useState } from 'react';
import type { Approval, CurrentUser } from '../types/index.ts';
import {
  approveApproval,
  getApprovals,
  rejectApproval,
  revokeApproval,
} from '../data/api.ts';
import { EmptyState } from '../components/EmptyState.tsx';
import { relativeTime, shortDate } from '../lib/format.ts';
import { can } from '../lib/rbac.ts';

interface Props {
  user: CurrentUser;
}

export function ScreenApprovals({ user }: Props) {
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Responders can revoke active exceptions; only admins approve/reject pending
  // requests (separation of duties — the engine also forbids self-approval).
  const canRevoke = can(user.role, 'write:approvals');
  const canApprove = can(user.role, 'approve:exceptions');

  function reload() {
    getApprovals().then((a) => {
      setApprovals(a);
      setLoading(false);
    });
  }

  useEffect(reload, []);

  async function handleRevoke(id: string) {
    setBusy(id);
    await revokeApproval(id, 'Revoked via console');
    setApprovals((prev) => prev.filter((a) => a.id !== id));
    setBusy(null);
  }

  async function handleApprove(id: string) {
    setBusy(id);
    setError(null);
    try {
      await approveApproval(id);
      reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'approval failed');
    }
    setBusy(null);
  }

  async function handleReject(id: string) {
    setBusy(id);
    setError(null);
    try {
      await rejectApproval(id, 'Rejected via console');
      reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'reject failed');
    }
    setBusy(null);
  }

  const showActions = canRevoke || canApprove;

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
        {error && <span className="dim" style={{ color: 'var(--deny, #c0392b)' }}>{error}</span>}
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
              {showActions && <th />}
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
                {showActions && (
                  <td>
                    <div style={{ display: 'flex', gap: 6 }}>
                      {a.status === 'pending' && canApprove && (
                        <>
                          <button
                            className="btn btn-sm btn-allow"
                            disabled={busy === a.id}
                            onClick={() => handleApprove(a.id)}
                          >
                            {busy === a.id ? '…' : 'Approve'}
                          </button>
                          <button
                            className="btn btn-sm btn-deny"
                            disabled={busy === a.id}
                            onClick={() => handleReject(a.id)}
                          >
                            Reject
                          </button>
                        </>
                      )}
                      {a.status === 'active' && canRevoke && (
                        <button
                          className="btn btn-sm btn-deny"
                          disabled={busy === a.id}
                          onClick={() => handleRevoke(a.id)}
                        >
                          {busy === a.id ? '…' : 'Revoke'}
                        </button>
                      )}
                    </div>
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
