import { useEffect, useState } from 'react';
import type { DashboardStats } from '../types/index.ts';
import { getDashboardStats } from '../data/api.ts';
import { relativeTime } from '../lib/format.ts';

function Sparkline({ values, color }: { values: number[]; color: string }) {
  const max = Math.max(...values, 1);
  return (
    <div className="spark" style={{ color }}>
      {values.map((v, i) => (
        <i key={i} style={{ height: `${Math.round((v / max) * 100)}%` }} />
      ))}
    </div>
  );
}

export function ScreenDashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null);

  useEffect(() => {
    getDashboardStats().then(setStats);
  }, []);

  if (!stats) {
    return (
      <div className="content-pad">
        <div className="stat-grid stagger">
          {[0, 1, 2, 3].map((i) => (
            <div key={i} className="stat">
              <div className="skel skel-line" style={{ width: '50%' }} />
              <div className="skel skel-line" style={{ width: '30%', height: 34, marginTop: 12 }} />
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="content-pad fade-in">
      <div className="stat-grid stagger">
        <div className="stat hold">
          <div className="stat-top">
            <div className="stat-label">Held</div>
            <Sparkline values={stats.heldTrend} color="var(--hold)" />
          </div>
          <div className="stat-num">{stats.held}</div>
          <div className="stat-foot">versions in cooldown</div>
        </div>
        <div className="stat deny">
          <div className="stat-top">
            <div className="stat-label">Denied</div>
          </div>
          <div className="stat-num">{stats.denied}</div>
          <div className="stat-foot">{stats.advisoryMatches} advisory matches</div>
        </div>
        <div className="stat allow">
          <div className="stat-top">
            <div className="stat-label">Allowed</div>
          </div>
          <div className="stat-num">{stats.allowed.toLocaleString()}</div>
          <div className="stat-foot">versions served today</div>
        </div>
        <div className="stat">
          <div className="stat-top">
            <div className="stat-label">Signals</div>
          </div>
          <div className="stat-num" style={{ color: 'var(--accent-2)' }}>
            {stats.topSignals.reduce((a, s) => a + s.count, 0)}
          </div>
          <div className="stat-foot">active signal findings</div>
        </div>
      </div>

      <div className="dash-grid">
        {/* Top signals */}
        <div className="panel">
          <div className="panel-head">
            <h2>Top signals this week</h2>
          </div>
          <div className="panel-body">
            <div className="barlist">
              {stats.topSignals.map((s) => (
                <div key={s.type} className="bl-row">
                  <div className="bl-top">
                    <span className="bl-name mono">{s.type.replace(/_/g, ' ')}</span>
                    <span className="bl-val">{s.count}</span>
                  </div>
                  <div className="bl-track">
                    <div className="bl-fill" style={{ width: `${Math.round(s.share * 100)}%` }} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Containment events */}
        <div className="panel">
          <div className="panel-head">
            <h2>Containment events</h2>
            <span className="ph-sub">{stats.recentEvents.length} recent</span>
          </div>
          <div className="panel-body">
            {stats.recentEvents.length === 0 ? (
              <span className="dim">No containment events.</span>
            ) : (
              stats.recentEvents.map((evt) => (
                <div key={evt.id} className="evt">
                  <div className="evt-ico">⊘</div>
                  <div className="evt-body">
                    <div className="evt-title">
                      <b>{evt.pkg}</b> → <b>{evt.host}</b>
                    </div>
                    <div className="evt-meta">
                      {evt.pipeline} · {evt.repo} · {relativeTime(evt.time)}
                      {evt.note && ` · ${evt.note}`}
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
