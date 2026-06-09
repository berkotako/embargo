import { useCallback, useEffect, useState, type FormEvent } from 'react';
import type { CurrentUser } from '../types/index.ts';
import {
  addFeed,
  addKnownMalicious,
  deleteFeed,
  getFeeds,
  getKnownMalicious,
  getKnownMaliciousStatus,
  removeKnownMalicious,
  syncFeed,
  updateFeed,
  type FeedSource,
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
 * Known Packages — control the known-malicious blocklist and the feed sources
 * that populate it. Operators can add curated dataset feeds at runtime, toggle
 * them, sync now, add manual blocks, and search. Any npm match is an immediate
 * DENY at resolve time.
 */
export function ScreenKnownPackages({ user }: Props) {
  const canManage = can(user.role, 'manage:known-malicious');

  const [status, setStatus] = useState<KnownMaliciousStatus | null>(null);
  const [feeds, setFeeds] = useState<FeedSource[]>([]);
  const [entries, setEntries] = useState<KnownMaliciousEntry[]>([]);
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const [newPkg, setNewPkg] = useState('');
  const [newVer, setNewVer] = useState('');
  const [feedName, setFeedName] = useState('');
  const [feedUrl, setFeedUrl] = useState('');
  const [feedEco, setFeedEco] = useState('npm');

  const refresh = useCallback(async (q: string) => {
    const [st, fs, list] = await Promise.all([
      getKnownMaliciousStatus(),
      getFeeds().catch(() => [] as FeedSource[]),
      getKnownMalicious(q),
    ]);
    setStatus(st);
    setFeeds(fs);
    setEntries(list);
    setLoading(false);
  }, []);

  useEffect(() => {
    refresh('').catch((e: unknown) => {
      setNotice(e instanceof Error ? e.message : 'failed to load');
      setLoading(false);
    });
  }, [refresh]);

  async function run(key: string, fn: () => Promise<void>, ok?: string) {
    setBusy(key);
    setNotice(null);
    try {
      await fn();
      await refresh(search);
      if (ok) setNotice(ok);
    } catch (err) {
      setNotice(err instanceof Error ? err.message : 'action failed');
    } finally {
      setBusy(null);
    }
  }

  async function onSearch(e: FormEvent) {
    e.preventDefault();
    setLoading(true);
    await refresh(search).catch(() => setLoading(false));
  }

  async function onAddBlock(e: FormEvent) {
    e.preventDefault();
    if (!newPkg.trim()) return;
    await run(
      'add-block',
      async () => {
        await addKnownMalicious(newPkg.trim(), newVer.trim() || undefined);
        setNewPkg('');
        setNewVer('');
      },
      'Block added.',
    );
  }

  async function onAddFeed(e: FormEvent) {
    e.preventDefault();
    if (!feedName.trim() || !feedUrl.trim()) return;
    await run(
      'add-feed',
      async () => {
        await addFeed(feedName.trim(), feedUrl.trim(), feedEco);
        setFeedName('');
        setFeedUrl('');
      },
      'Feed source added (disabled). Enable it to start syncing.',
    );
  }

  if (loading && !status) {
    return (
      <div className="content-pad">
        <div className="skel skel-line" style={{ width: 300, height: 20 }} />
      </div>
    );
  }

  return (
    <div className="content-pad fade-in">
      {/* Counts per source/ecosystem */}
      <div className="dryrun-stat" style={{ marginBottom: 16, flexWrap: 'wrap' }}>
        <div className="drs">
          <div className="drs-num">{(status?.total ?? 0).toLocaleString()}</div>
          <div className="drs-lbl">Blocked entries</div>
        </div>
        {(status?.sources ?? []).map((s) => (
          <div className="drs" key={`${s.source}/${s.ecosystem}`}>
            <div className="drs-num" style={{ color: 'var(--deny)' }}>{s.count.toLocaleString()}</div>
            <div className="drs-lbl">
              {s.source} · {s.ecosystem} · {relativeTime(s.lastSyncedAt)}
            </div>
          </div>
        ))}
        {(status?.sources?.length ?? 0) === 0 && (
          <div className="drs">
            <div className="drs-num" style={{ color: 'var(--text-dim)' }}>0</div>
            <div className="drs-lbl">No sources synced yet</div>
          </div>
        )}
      </div>

      {notice && (
        <div className="panel" style={{ marginBottom: 14 }}>
          <div className="panel-body" style={{ fontSize: 13, padding: '10px 14px' }}>{notice}</div>
        </div>
      )}

      {/* Feed sources */}
      <div className="panel" style={{ marginBottom: 16 }}>
        <div className="panel-head">
          <h2>Feed sources</h2>
          <span className="ph-sub">curated datasets synced into the blocklist</span>
        </div>
        <div className="panel-body">
          {feeds.length === 0 ? (
            <div className="dim" style={{ fontSize: 13 }}>No feed sources.</div>
          ) : (
            <div className="tbl-wrap">
              <table className="tbl">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Ecosystem</th>
                    <th>Status</th>
                    <th>Last sync</th>
                    {canManage && <th />}
                  </tr>
                </thead>
                <tbody>
                  {feeds.map((f) => (
                    <tr key={f.id}>
                      <td className="mono" style={{ maxWidth: 280 }}>
                        {f.name}
                        <div className="dim" style={{ fontSize: 11, overflow: 'hidden', textOverflow: 'ellipsis' }}>{f.url}</div>
                      </td>
                      <td><span className="badge badge-neutral"><span className="dot" />{f.ecosystem}</span></td>
                      <td>
                        <span className={`badge ${f.enabled ? 'badge-allow' : 'badge-neutral'}`}>
                          <span className="dot" />{f.enabled ? 'enabled' : 'disabled'}
                        </span>
                      </td>
                      <td className="dim" style={{ fontSize: 12 }}>
                        {f.lastSyncedAt ? relativeTime(f.lastSyncedAt) : 'never'}
                        {f.lastStatus ? ` · ${f.lastStatus}` : ''}
                      </td>
                      {canManage && (
                        <td style={{ whiteSpace: 'nowrap' }}>
                          <button
                            className="btn btn-sm"
                            disabled={busy === `feed-${f.id}`}
                            onClick={() => run(`feed-${f.id}`, () => updateFeed(f.id, { enabled: !f.enabled }))}
                          >
                            {f.enabled ? 'Disable' : 'Enable'}
                          </button>{' '}
                          <button
                            className="btn btn-sm"
                            disabled={busy === `sync-${f.id}`}
                            onClick={() => run(`sync-${f.id}`, async () => { await syncFeed(f.id); }, `Synced ${f.name}.`)}
                          >
                            {busy === `sync-${f.id}` ? '…' : 'Sync'}
                          </button>{' '}
                          <button
                            className="btn btn-sm btn-deny"
                            disabled={busy === `del-${f.id}`}
                            onClick={() => run(`del-${f.id}`, () => deleteFeed(f.id))}
                          >
                            Remove
                          </button>
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {canManage && (
            <form onSubmit={onAddFeed} style={{ display: 'flex', gap: 8, marginTop: 12, flexWrap: 'wrap' }}>
              <input className="field mono" placeholder="source name" value={feedName} onChange={(e) => setFeedName(e.target.value)} style={{ flex: '0 1 160px' }} />
              <input className="field mono" placeholder="manifest URL (https://…)" value={feedUrl} onChange={(e) => setFeedUrl(e.target.value)} style={{ flex: '1 1 280px' }} />
              <select className="field" value={feedEco} onChange={(e) => setFeedEco(e.target.value)}>
                <option value="npm">npm</option>
                <option value="pypi">pypi</option>
              </select>
              <button className="btn" type="submit" disabled={busy === 'add-feed' || !feedName.trim() || !feedUrl.trim()}>
                {busy === 'add-feed' ? '…' : 'Add feed'}
              </button>
            </form>
          )}
        </div>
      </div>

      {/* Manual blocks */}
      {canManage && (
        <form onSubmit={onAddBlock} style={{ display: 'flex', gap: 8, marginBottom: 12, flexWrap: 'wrap' }}>
          <input className="field mono" placeholder="block a package (e.g. left-pad or @scope/name)" value={newPkg} onChange={(e) => setNewPkg(e.target.value)} style={{ flex: '1 1 280px', minWidth: 220 }} />
          <input className="field mono" placeholder="version (blank = all)" value={newVer} onChange={(e) => setNewVer(e.target.value)} style={{ flex: '0 1 190px' }} />
          <button className="btn btn-deny" type="submit" disabled={busy === 'add-block' || !newPkg.trim()}>
            {busy === 'add-block' ? '…' : 'Block package'}
          </button>
        </form>
      )}

      {/* Search + entries */}
      <form onSubmit={onSearch} style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
        <input className="field mono" placeholder="search blocked package…" value={search} onChange={(e) => setSearch(e.target.value)} style={{ flex: '1 1 320px' }} />
        <button className="btn" type="submit">Search</button>
      </form>

      {entries.length === 0 ? (
        <EmptyState
          icon="⛔"
          title="No known-malicious packages"
          body={canManage ? 'Enable a feed source above, add a manual block, or sync to import a dataset.' : 'Entries from feeds and operator blocks will appear here.'}
        />
      ) : (
        <div className="tbl-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>Package</th>
                <th>Version</th>
                <th>Ecosystem</th>
                <th>Source</th>
                <th>Added</th>
                {canManage && <th />}
              </tr>
            </thead>
            <tbody className="stagger">
              {entries.map((en) => {
                const key = `${en.ecosystem}:${en.source}:${en.package}@${en.version}`;
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
                    <td className="dim mono">{en.ecosystem}</td>
                    <td>
                      <span className={`badge ${en.source === 'manual' ? 'badge-hold' : 'badge-neutral'}`}>
                        <span className="dot" />{en.source}
                      </span>
                    </td>
                    <td className="dim">{relativeTime(en.syncedAt)}</td>
                    {canManage && (
                      <td>
                        <button className="btn btn-sm" disabled={busy === key} onClick={() => run(key, () => removeKnownMalicious(en))}>
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
