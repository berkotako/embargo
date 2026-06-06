import { useEffect, useState } from 'react';
import type { CurrentUser, VersionVerdict } from '../types/index.ts';
import { getDeniedVersions, getHeldVersions } from '../data/api.ts';
import { VerdictBadge } from '../components/VerdictBadge.tsx';
import { SignalTag } from '../components/SignalTag.tsx';
import { CooldownBar } from '../components/CooldownBar.tsx';
import { ProvenancePill } from '../components/ProvenancePill.tsx';
import { SkeletonTable } from '../components/SkeletonTable.tsx';
import { EmptyState } from '../components/EmptyState.tsx';
import { parsePkg, relativeTime } from '../lib/format.ts';
import { can } from '../lib/rbac.ts';
import { Detail } from './QuarantineDetail.tsx';

type Tab = 'hold' | 'deny';

interface Props {
  user: CurrentUser;
}

export function ScreenQuarantine({ user }: Props) {
  const [tab, setTab] = useState<Tab>('hold');
  const [held, setHeld] = useState<VersionVerdict[]>([]);
  const [denied, setDenied] = useState<VersionVerdict[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<VersionVerdict | null>(null);

  useEffect(() => {
    setLoading(true);
    Promise.all([getHeldVersions(), getDeniedVersions()]).then(([h, d]) => {
      setHeld(h);
      setDenied(d);
      setLoading(false);
    });
  }, []);

  const rows = tab === 'hold' ? held : denied;

  return (
    <div className="content-pad fade-in">
      <div className="toolbar">
        <div className="seg">
          <button className={tab === 'hold' ? 'on hold' : ''} onClick={() => setTab('hold')}>
            HOLD <span className="cnt">{held.length}</span>
          </button>
          <button className={tab === 'deny' ? 'on deny' : ''} onClick={() => setTab('deny')}>
            DENY <span className="cnt">{denied.length}</span>
          </button>
        </div>
        <div className="topbar-spacer" />
        {can(user.role, 'write:approvals') && (
          <button className="btn btn-sm btn-primary">+ Fast-track</button>
        )}
      </div>

      {loading ? (
        <SkeletonTable cols={5} rows={5} />
      ) : rows.length === 0 ? (
        <EmptyState
          icon="✓"
          title={tab === 'hold' ? 'No versions in quarantine' : 'No denied versions'}
          body={tab === 'hold' ? 'All resolved versions are within policy.' : 'No versions have been permanently denied.'}
        />
      ) : (
        <div className="tbl-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>Package</th>
                <th>Verdict</th>
                <th>Signals</th>
                <th>Cooldown</th>
                <th>Provenance</th>
                <th>Age</th>
              </tr>
            </thead>
            <tbody className="stagger">
              {rows.map((v) => {
                const { scope, name } = parsePkg(v.package);
                return (
                  <tr
                    key={`${v.package}@${v.version}`}
                    className={selected?.package === v.package && selected?.version === v.version ? 'sel' : ''}
                    onClick={() => setSelected(v)}
                  >
                    <td>
                      <div className="cell-pkg">
                        {scope && <span className="scope">{scope}</span>}
                        {name}
                        {' '}
                        <span className="ver">{v.version}</span>
                      </div>
                    </td>
                    <td><VerdictBadge verdict={v.verdict} /></td>
                    <td>
                      <div className="tagrow">
                        {v.signals.slice(0, 3).map((s) => (
                          <SignalTag key={s.id} signal={s} />
                        ))}
                        {v.signals.length > 3 && (
                          <span className="tag">+{v.signals.length - 3}</span>
                        )}
                      </div>
                    </td>
                    <td>
                      {v.expiresAt ? (
                        <CooldownBar computedAt={v.computedAt} expiresAt={v.expiresAt} />
                      ) : (
                        <span className="dim">—</span>
                      )}
                    </td>
                    <td><ProvenancePill provenance={v.provenance} /></td>
                    <td className="dim">{relativeTime(v.computedAt)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      <Detail
        verdict={selected}
        user={user}
        onClose={() => setSelected(null)}
      />
    </div>
  );
}
