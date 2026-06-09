import { useEffect, useState } from 'react';
import { BrowserRouter, Link, Navigate, Route, Routes, useLocation } from 'react-router-dom';
import type { CurrentUser } from './types/index.ts';
import { ScreenQuarantine } from './screens/Quarantine.tsx';
import { ScreenDashboard } from './screens/Dashboard.tsx';
import { ScreenPolicy } from './screens/Policy.tsx';
import { ScreenApprovals } from './screens/Approvals.tsx';
import { ScreenAudit } from './screens/Audit.tsx';
import { ScreenKnownPackages } from './screens/KnownPackages.tsx';
import { LoginScreen } from './screens/Login.tsx';
import { whoami } from './data/api.ts';
import { handleOidcCallback, hasCredentials, logout } from './lib/auth.ts';

const NAV = [
  { path: '/quarantine', label: 'Quarantine', icon: '⊘', countKey: 'held' },
  { path: '/dashboard', label: 'Dashboard', icon: '▦' },
  { path: '/policy', label: 'Policy', icon: '⊟' },
  { path: '/known-packages', label: 'Known Packages', icon: '⛔' },
  { path: '/approvals', label: 'Approvals', icon: '✓', countKey: 'approvals' },
  { path: '/audit', label: 'Audit Log', icon: '≡' },
];

function Sidebar({ user }: { user: CurrentUser }) {
  const location = useLocation();
  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-mark">
          <svg width="22" height="22" viewBox="0 0 22 22" fill="none">
            <rect width="22" height="22" rx="6" fill="#4d8dff" opacity=".15" />
            <path d="M6 11h10M11 6v10" stroke="#4d8dff" strokeWidth="2" strokeLinecap="round" />
          </svg>
        </div>
        <div>
          <div className="brand-name">em<b>bargo</b></div>
          <div className="brand-tag">dependency firewall</div>
        </div>
      </div>

      <nav className="nav">
        <div className="nav-label">Enforcement</div>
        {NAV.map((item) => (
          <Link
            key={item.path}
            to={item.path}
            className={`nav-item${location.pathname === item.path ? ' active' : ''}`}
            style={{ textDecoration: 'none' }}
          >
            <span className="nav-ico">{item.icon}</span>
            {item.label}
          </Link>
        ))}
      </nav>

      <div className="sidebar-foot">
        <div>
          <span className="health-dot" /> engine healthy
        </div>
        <div>{user.email}</div>
        <div style={{ color: 'var(--accent-2)' }}>{user.role}</div>
        <div
          onClick={logout}
          style={{ cursor: 'pointer', color: 'var(--text-dim)', marginTop: 2 }}
        >
          sign out
        </div>
      </div>
    </aside>
  );
}

function TopBar({ title, sub }: { title: string; sub?: string }) {
  return (
    <header className="topbar">
      <div>
        <div className="topbar-title">{title}</div>
        {sub && <div className="topbar-sub">{sub}</div>}
      </div>
      <div className="topbar-spacer" />
      <div className="env-pill">
        <span className="health-dot" />
        production
      </div>
    </header>
  );
}

const PAGE_META: Record<string, { title: string; sub: string }> = {
  '/quarantine': { title: 'Quarantine', sub: 'Versions held or denied by policy' },
  '/dashboard': { title: 'Dashboard', sub: 'Signal activity and hold trends' },
  '/policy': { title: 'Policy', sub: 'Per-scope rules — most-specific-wins' },
  '/known-packages': { title: 'Known Packages', sub: 'Known-malicious blocklist & feed' },
  '/approvals': { title: 'Approvals', sub: 'Time-boxed exception workflow' },
  '/audit': { title: 'Audit Log', sub: 'Tamper-evident, hash-chained log' },
};

function Layout({ user }: { user: CurrentUser }) {
  const location = useLocation();
  const meta = PAGE_META[location.pathname] ?? { title: 'Embargo', sub: '' };
  return (
    <div className="app">
      <Sidebar user={user} />
      <div className="main">
        <TopBar title={meta.title} sub={meta.sub} />
        <main className="content">
          <Routes>
            <Route path="/" element={<Navigate to="/quarantine" replace />} />
            <Route path="/quarantine" element={<ScreenQuarantine user={user} />} />
            <Route path="/dashboard" element={<ScreenDashboard />} />
            <Route path="/policy" element={<ScreenPolicy user={user} />} />
            <Route path="/known-packages" element={<ScreenKnownPackages user={user} />} />
            <Route path="/approvals" element={<ScreenApprovals user={user} />} />
            <Route path="/audit" element={<ScreenAudit />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}

type SessionState =
  | { status: 'loading' }
  | { status: 'login'; error?: string }
  | { status: 'ready'; user: CurrentUser };

export default function App() {
  const [session, setSession] = useState<SessionState>({ status: 'loading' });

  async function establish() {
    try {
      const user = await whoami();
      setSession({ status: 'ready', user });
    } catch (err) {
      // Only surface an error when we actually had credentials that were rejected;
      // an unauthenticated first load just needs the login screen.
      if (hasCredentials()) {
        const msg = err instanceof Error ? err.message : 'sign-in required';
        setSession({ status: 'login', error: msg });
      } else {
        setSession({ status: 'login' });
      }
    }
  }

  useEffect(() => {
    (async () => {
      try {
        // Complete an OIDC redirect if we're returning from the IdP.
        await handleOidcCallback();
      } catch (err) {
        setSession({ status: 'login', error: err instanceof Error ? err.message : 'login failed' });
        return;
      }
      await establish();
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (session.status === 'loading') {
    return (
      <div style={{ height: '100vh', display: 'grid', placeItems: 'center', color: 'var(--text-dim)' }}>
        connecting to engine…
      </div>
    );
  }

  if (session.status === 'login') {
    return <LoginScreen onAuthenticated={establish} error={session.error ?? null} />;
  }

  return (
    <BrowserRouter>
      <Layout user={session.user} />
    </BrowserRouter>
  );
}
