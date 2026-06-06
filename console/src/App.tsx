import { useState } from 'react';
import { BrowserRouter, Link, Navigate, Route, Routes, useLocation } from 'react-router-dom';
import type { CurrentUser } from './types/index.ts';
import { ScreenQuarantine } from './screens/Quarantine.tsx';
import { ScreenDashboard } from './screens/Dashboard.tsx';
import { ScreenPolicy } from './screens/Policy.tsx';
import { ScreenApprovals } from './screens/Approvals.tsx';
import { ScreenAudit } from './screens/Audit.tsx';

const MOCK_USER: CurrentUser = {
  id: 'u-alice',
  email: 'alice@example.com',
  name: 'Alice',
  role: 'admin',
  avatarInitials: 'A',
};

const NAV = [
  { path: '/quarantine', label: 'Quarantine', icon: '⊘', countKey: 'held' },
  { path: '/dashboard', label: 'Dashboard', icon: '▦' },
  { path: '/policy', label: 'Policy', icon: '⊟' },
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
            <Route path="/approvals" element={<ScreenApprovals user={user} />} />
            <Route path="/audit" element={<ScreenAudit />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}

export default function App() {
  const [user] = useState<CurrentUser>(MOCK_USER);
  return (
    <BrowserRouter>
      <Layout user={user} />
    </BrowserRouter>
  );
}
