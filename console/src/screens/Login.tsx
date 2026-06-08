import { useState } from 'react';
import type { UserRole } from '../types/index.ts';
import { authMode, beginOidcLogin, devLogin } from '../lib/auth.ts';

interface Props {
  /** Called after a credential is set so the app can re-establish the session. */
  onAuthenticated: () => void;
  error?: string | null;
}

const DEV_ROLES: { role: UserRole; label: string; desc: string }[] = [
  { role: 'viewer', label: 'Viewer', desc: 'read-only: quarantine, policy, audit' },
  { role: 'responder', label: 'Responder', desc: 'viewer + approve/revoke exceptions' },
  { role: 'admin', label: 'Admin', desc: 'full access incl. policy authoring' },
];

export function LoginScreen({ onAuthenticated, error }: Props) {
  const mode = authMode();
  const [email, setEmail] = useState('dev@localhost');
  const [busy, setBusy] = useState(false);

  async function signInOidc() {
    setBusy(true);
    try {
      await beginOidcLogin();
    } catch {
      setBusy(false);
    }
  }

  function pickRole(role: UserRole) {
    devLogin(role, email);
    onAuthenticated();
  }

  return (
    <div
      style={{
        height: '100vh',
        display: 'grid',
        placeItems: 'center',
        background: 'var(--bg)',
      }}
    >
      <div className="panel" style={{ width: 420, padding: 0, overflow: 'hidden' }}>
        <div className="panel-head" style={{ gap: 10 }}>
          <svg width="22" height="22" viewBox="0 0 22 22" fill="none">
            <rect width="22" height="22" rx="6" fill="#4d8dff" opacity=".15" />
            <path d="M6 11h10M11 6v10" stroke="#4d8dff" strokeWidth="2" strokeLinecap="round" />
          </svg>
          <div>
            <h2 style={{ margin: 0 }}>
              em<b style={{ color: 'var(--accent-2)' }}>bargo</b> console
            </h2>
            <div className="ph-sub">sign in to continue</div>
          </div>
        </div>

        <div className="panel-body">
          {error && (
            <div className="warn-banner deny" style={{ marginBottom: 14 }}>
              {error}
            </div>
          )}

          {mode === 'oidc' && (
            <button className="btn btn-primary" style={{ width: '100%' }} disabled={busy} onClick={signInOidc}>
              {busy ? 'Redirecting…' : 'Sign in with SSO'}
            </button>
          )}

          {mode === 'dev' && (
            <>
              <div className="warn-banner warn" style={{ marginBottom: 14 }}>
                Dev auth — pick a role to impersonate. Not for production.
              </div>
              <label style={{ fontSize: 11.5, color: 'var(--text-dim)' }}>Email</label>
              <input
                className="field"
                style={{ marginTop: 6, marginBottom: 14 }}
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
              <div className="col" style={{ gap: 8 }}>
                {DEV_ROLES.map((r) => (
                  <button
                    key={r.role}
                    className="btn"
                    style={{ justifyContent: 'flex-start', flexDirection: 'column', alignItems: 'flex-start', gap: 2, padding: '10px 13px' }}
                    onClick={() => pickRole(r.role)}
                  >
                    <span style={{ fontWeight: 600 }}>{r.label}</span>
                    <span style={{ fontSize: 11, color: 'var(--text-dim)' }}>{r.desc}</span>
                  </button>
                ))}
              </div>
            </>
          )}

          {mode === 'disabled' && (
            <>
              <div className="warn-banner warn" style={{ marginBottom: 14 }}>
                Auth is disabled on the engine — entering as admin.
              </div>
              <button className="btn btn-primary" style={{ width: '100%' }} onClick={onAuthenticated}>
                Enter console
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
