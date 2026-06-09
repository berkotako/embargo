import { useCallback, useEffect, useState, type FormEvent } from 'react';
import type { CurrentUser } from '../types/index.ts';
import {
  addKnownMalicious,
  getKnownMalicious,
  getKnownMaliciousStatus,
  removeKnownMalicious,
  syncKnownMalicious,
  type KnownMaliciousEntry,
  type KnownMaliciousStatus,
} from '../data/api.ts';
import { EmptyState } from '../components/EmptyState.tsx';
import { relativeTime } from '../lib/format.ts';
import { can } from '../lib/rbac.ts';

interface Props {
  user: CurrentUser;
}

/**
 * Known Packages — view and control the known-malicious blocklist: entries from
 * the external feed (e.g. Datadog) plus operator-added manual blocks. Any match
 * is an immediate DENY at resolve time.
 */
export function ScreenKnownPackages({ user }: Props) {
  const canManage = can(user.role, 'manage:known-malicious');

  const [status, setStatus] = useState<KnownMaliciousStatus | null>(null);
  const [entries, setEntries] = useState<KnownMaliciousEntry[]>([]);
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [newPkg, setNewPkg] = useState('');
  const [newVer, setNewVer] = useState('');

  const refresh = useCallback(async (q: string) => {
    const [st, list] = await Promise.all([getKnownMaliciousStatus(), getKnownMalicious(q)]);
    setStatus(st);
    setEntries(list);
    setLoading(false);
  }, []);

  useEffect(() => {
    refresh('').catch((e: unknown) => {
      setNotice(e instanceof Error ? e.message : 'failed to load');
      setLoading(false);
    });
  }, [refresh]);

  async function onSearch(e: FormEvent) {
    e.preventDefault();
    setLoading(true);
    await refresh(search).catch(() => setLoading(false));
  }

  async function onAdd(e: FormEvent) {
    e.preventDefault();
    if (!newPkg.trim()) return;
    setBusy('add');
    setNotice(null);
    try {
      await addKnownMalicious(newPkg.trim(), newVer.trim() || undefined);
      setNewPkg('');
      setNewVer('');
      await refresh(search);
      setNotice('Block added.');
    } catch (err) {
      setNotice(err instanceof Error ? err.message : 'add failed');
    } finally {
      setBusy(null);
    }
  }

  async function onRemove(en: KnownMaliciousEntry) {
    const key = `${en.source}:${en.package}@${en.version}`;
    setBusy(key);
    setNotice(null);
    try {
      await removeKnownMalicious(en.package, en.version, en.source);
      await refresh(search);
    } catch (err) {
      setNotice(err instanceof Error ? err.message : 'remove failed');
    } finally {
      setBusy(null);
    }
  }

  async function onSync() {
    setBusy('sync');
    setNotice(null);
    try {
      const r = await syncKnownMalicious();
      await refresh(search);
      setNotice(`Feed synced — ${r.written.toLocaleString()} entries.`);
    } catch (err) {
      setNotice(err instanceof Error ? err.message : 'sync failed');
    } finally {
      setBusy(null);
    }
  }

  if (loading && !status) {
    return (
      <div className="content-pad">
        <div className="skel skel-line" style={{ width: 300, height: 20 }} />
      </div>
    );
  }

  const intervalHrs = Math.round((status?.feedIntervalSecs ?? 0) / 3600);

  return (
    <div className="content-pad fade-in">
      {/* Status tiles */}
      <div className="dryrun-stat" style={{ marginBottom: 16 }}>
        <div className="drs">
          <div className="drs-num">{(status?.total ?? 0).toLocaleString()}</div>
          <div className="drs-lbl">Blocked entries</div>
        </div>
        <div className="drs">
          <div className="drs-num" style={{ fontSize: 15, lineHeight: '32px' }}>
            <span className={`badge ${status?.feedEnabled ? 'badge-allow' : 'badge-neutral'}`}>
              <span className="dot" />
              {status?.feedEnabled ? 'enabled' : 'disabled'}
            </span>
          </div>
          <div className="drs-lbl">
            Auto-sync · {status?.feedSource}
            {intervalHrs > 0 ? ` · every ${intervalHrs}h` : ''}
          </div>
        </div>
        {(status?.sources ?? []).map((s) => (
          <div className="drs" key={s.source}>
            <div className="drs-num" style={{ color: 'var(--deny)' }}>{s.count.toLocaleString()}</div>
            <div className="drs-lbl">
              {s.source} · synced {relativeTime(s.lastSyncedAt)}
            </div>
          </div>
        ))}
      </div>

      {notice && (
        <div className="panel" style={{ marginBottom: 14 }}>
          <div className="panel-body" style={{ fontSize: 13, padding: '10px 14px' }}>{notice}</div>
        </div>
      )}

      {/* Controls (admin) */}
      {canManage && (
        <form onSubmit={onAdd} style={{ display: 'flex', gap: 8, marginBottom: 14, flexWrap: 'wrap' }}>
          <input
            className="field mono"
            placeholder="package name (e.g. left-pad or @scope/name)"
            value={newPkg}
            onChange={(e) => setNewPkg(e.target.value)}
            style={{ flex: '1 1 280px', minWidth: 220 }}
          />
          <input
            className="field mono"
            placeholder="version (blank = all versions)"
            value={newVer}
            onChange={(e) => setNewVer(e.target.value)}
            style={{ flex: '0 1 210px' }}
          />
          <button className="btn btn-deny" type="submit" disabled={busy === 'add' || !newPkg.trim()}>
            {busy === 'add' ? '…' : 'Block package'}
          </button>
          <button className="btn" type="button" onClick={onSync} disabled={busy === 'sync'}>
            {busy === 'sync' ? 'Syncing…' : 'Sync feed now'}
          </button>
        </form>
      )}

      {/* Search */}
      <form onSubmit={onSearch} style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
        <input
          className="field mono"
          placeholder="search package…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{ flex: '1 1 320px' }}
        />
        <button className="btn" type="submit">Search</button>
      </form>

      {entries.length === 0 ? (
        <EmptyState
          icon="⛔"
          title="No known-malicious packages"
          body={
            canManage
              ? 'Add a manual block above, or enable + sync the feed to import a curated malware dataset.'
              : 'Entries from the feed and operator blocks will appear here.'
          }
        />
      ) : (
        <div className="tbl-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>Package</th>
                <th>Version</th>
                <th>Source</th>
                <th>Added</th>
                {canManage && <th />}
              </tr>
            </thead>
            <tbody className="stagger">
              {entries.map((en) => {
                const key = `${en.source}:${en.package}@${en.version}`;
                return (
                  <tr key={key}>
                    <td className="cell-pkg mono">{en.package}</td>
                    <td>
                      {en.version === '*' ? (
                        <span className="badge badge-deny"><span className="dot" />all versions</span>
                      ) : (
                        <span className="ver mono">{en.version}</span>
                      )}
                    </td>
                    <td>
                      <span className={`badge ${en.source === 'manual' ? 'badge-hold' : 'badge-neutral'}`}>
                        <span className="dot" />
                        {en.source}
                      </span>
                    </td>
                    <td className="dim">{relativeTime(en.syncedAt)}</td>
                    {canManage && (
                      <td>
                        <button
                          className="btn btn-sm"
                          disabled={busy === key}
                          onClick={() => onRemove(en)}
                        >
                          {busy === key ? '…' : 'Remove'}
                        </button>
                      </td>
                    )}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
