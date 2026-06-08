// ---------------------------------------------------------------------------
// Console authentication. Mirrors the engine's facade auth (auth.rs):
//   - oidc:     OIDC Authorization Code + PKCE; attach `Authorization: Bearer`.
//   - dev:      pick a role; attach `X-Embargo-Role` / `X-Embargo-Email`.
//   - disabled: no credentials (engine treats every request as admin).
//
// The engine is the source of truth for the role — after authenticating we call
// /api/whoami and the UI reflects whatever the server says.
// ---------------------------------------------------------------------------

import type { UserRole } from '../types/index.ts';

export type AuthMode = 'oidc' | 'dev' | 'disabled';

const MODE = ((import.meta.env.VITE_AUTH_MODE as string | undefined) ?? 'disabled') as AuthMode;

// OIDC config (only used when MODE === 'oidc').
const OIDC = {
  authority: (import.meta.env.VITE_OIDC_AUTHORITY as string | undefined) ?? '',
  clientId: (import.meta.env.VITE_OIDC_CLIENT_ID as string | undefined) ?? '',
  scope: (import.meta.env.VITE_OIDC_SCOPE as string | undefined) ?? 'openid email profile',
  redirectUri: window.location.origin + '/',
};

const TOKEN_KEY = 'embargo.token';
const DEV_KEY = 'embargo.dev';
const PKCE_KEY = 'embargo.pkce';

export function authMode(): AuthMode {
  return MODE;
}

interface DevIdentity {
  role: UserRole;
  email: string;
}

// --- credential injection (used by data/api.ts) -----------------------------

/** Headers to attach to every admin API request for the current session. */
export function authHeaders(): Record<string, string> {
  if (MODE === 'oidc') {
    const t = sessionStorage.getItem(TOKEN_KEY);
    return t ? { Authorization: `Bearer ${t}` } : {};
  }
  if (MODE === 'dev') {
    const dev = readDev();
    return dev ? { 'X-Embargo-Role': dev.role, 'X-Embargo-Email': dev.email } : {};
  }
  return {};
}

/** Whether we have credentials to even attempt an authenticated request. */
export function hasCredentials(): boolean {
  if (MODE === 'oidc') return !!sessionStorage.getItem(TOKEN_KEY);
  if (MODE === 'dev') return !!readDev();
  return true; // disabled
}

export function logout(): void {
  sessionStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(DEV_KEY);
  if (MODE === 'oidc' && OIDC.authority) {
    window.location.href = `${OIDC.authority.replace(/\/$/, '')}/protocol/openid-connect/logout`;
  } else {
    window.location.reload();
  }
}

// --- dev mode ---------------------------------------------------------------

function readDev(): DevIdentity | null {
  try {
    const raw = localStorage.getItem(DEV_KEY);
    return raw ? (JSON.parse(raw) as DevIdentity) : null;
  } catch {
    return null;
  }
}

export function devLogin(role: UserRole, email: string): void {
  localStorage.setItem(DEV_KEY, JSON.stringify({ role, email }));
}

// --- OIDC Authorization Code + PKCE -----------------------------------------

/** Begin OIDC login: build a PKCE challenge and redirect to the IdP. */
export async function beginOidcLogin(): Promise<void> {
  const verifier = randomString(64);
  const challenge = await pkceChallenge(verifier);
  const state = randomString(24);
  sessionStorage.setItem(PKCE_KEY, JSON.stringify({ verifier, state }));

  const url = new URL(`${OIDC.authority.replace(/\/$/, '')}/protocol/openid-connect/auth`);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', OIDC.clientId);
  url.searchParams.set('redirect_uri', OIDC.redirectUri);
  url.searchParams.set('scope', OIDC.scope);
  url.searchParams.set('state', state);
  url.searchParams.set('code_challenge', challenge);
  url.searchParams.set('code_challenge_method', 'S256');
  window.location.href = url.toString();
}

/**
 * If the current URL is an OIDC redirect (has ?code=...), exchange the code for
 * a token and store it. Returns true if a callback was handled.
 */
export async function handleOidcCallback(): Promise<boolean> {
  if (MODE !== 'oidc') return false;
  const params = new URLSearchParams(window.location.search);
  const code = params.get('code');
  const state = params.get('state');
  if (!code) return false;

  const saved = JSON.parse(sessionStorage.getItem(PKCE_KEY) ?? '{}') as {
    verifier?: string;
    state?: string;
  };
  if (!saved.verifier || saved.state !== state) {
    throw new Error('OIDC state mismatch');
  }

  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: OIDC.redirectUri,
    client_id: OIDC.clientId,
    code_verifier: saved.verifier,
  });
  const res = await fetch(`${OIDC.authority.replace(/\/$/, '')}/protocol/openid-connect/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body,
  });
  if (!res.ok) throw new Error(`OIDC token exchange failed (${res.status})`);
  const json = (await res.json()) as { access_token?: string };
  if (!json.access_token) throw new Error('OIDC response had no access_token');

  sessionStorage.setItem(TOKEN_KEY, json.access_token);
  sessionStorage.removeItem(PKCE_KEY);
  // Strip the code/state from the URL.
  window.history.replaceState({}, '', window.location.pathname);
  return true;
}

// --- PKCE helpers ------------------------------------------------------------

export function randomString(len: number): string {
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  return base64url(bytes).slice(0, len);
}

export async function pkceChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return base64url(new Uint8Array(digest));
}

function base64url(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
