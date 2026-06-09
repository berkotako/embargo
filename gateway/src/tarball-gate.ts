import type { GateNext, GateRequest, GateResponse, VersionResolver } from './types';
import { buildHeldError } from './packument';

/**
 * L1 tarball gate.
 *
 * Packument rewriting strips HOLD/DENY versions from resolution, but a client
 * installing from a lockfile (`npm ci`) fetches the tarball *directly* by URL and
 * never re-resolves — so without this gate a pinned-but-held version still
 * installs. This middleware intercepts tarball GETs, asks the engine for the
 * version's verdict, and refuses to serve anything that isn't ALLOW with a clear
 * Embargo error (reason + approval link) rather than a cryptic resolver failure.
 */

/**
 * Parse a registry tarball request path into its package + version.
 * Returns null for non-tarball paths (the gate then passes them through).
 *
 * Handles both unscoped (`/lodash/-/lodash-4.17.21.tgz`) and scoped
 * (`/@scope/name/-/name-1.2.3.tgz`) layouts; the tarball filename always uses
 * the *unscoped* package basename.
 */
export function parseTarballPath(rawPath: string): { pkg: string; version: string } | null {
  let path: string;
  try {
    path = decodeURIComponent((rawPath.split('?')[0] ?? '').trim());
  } catch {
    return null; // malformed percent-encoding
  }
  const m = path.match(/^\/?((?:@[^/]+\/)?[^/]+)\/-\/(.+)\.tgz$/);
  if (!m) return null;
  const pkg = m[1]!;
  const file = m[2]!;
  const basename = pkg.includes('/') ? pkg.slice(pkg.indexOf('/') + 1) : pkg;
  const prefix = `${basename}-`;
  if (!file.startsWith(prefix)) return null;
  const version = file.slice(prefix.length);
  if (!version) return null;
  return { pkg, version };
}

/**
 * Build the Verdaccio middleware. `failClosed` decides behavior when the engine
 * is unreachable: closed → refuse the tarball (503); open → serve it (matches
 * the packument filter's configured availability posture).
 */
export function tarballGate(
  engine: VersionResolver,
  consoleBaseUrl: string,
  failClosed: boolean,
): (req: GateRequest, res: GateResponse, next: GateNext) => void {
  return (req, res, next) => {
    if ((req.method ?? 'GET') !== 'GET') {
      next();
      return;
    }
    const parsed = parseTarballPath(req.path ?? req.url ?? '');
    if (!parsed) {
      next();
      return;
    }

    engine
      .resolveVersion(parsed.pkg, parsed.version)
      .then((verdict) => {
        if (verdict.verdict === 'ALLOW') {
          next();
          return;
        }
        // Stripped: refuse the tarball with an actionable Embargo error.
        res
          .status(403)
          .json(
            buildHeldError(parsed.pkg, parsed.version, verdict.reasons, consoleBaseUrl, verdict.verdict),
          );
      })
      .catch((err: unknown) => {
        console.error(
          `[embargo] tarball gate engine error for ${parsed.pkg}@${parsed.version}: ${String(err)}`,
        );
        if (failClosed) {
          res.status(503).json({ error: 'embargo engine unavailable; refusing tarball (fail-closed)' });
          return;
        }
        next();
      });
  };
}
