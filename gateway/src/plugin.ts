import type {
  EmbargoPluginConfig,
  GateNext,
  GateRequest,
  GateResponse,
  Packument,
  PackumentResolver,
  VersionResolver,
} from './types';
import { EngineClient } from './engine-client';
import { rewritePackument } from './packument';
import { tarballGate } from './tarball-gate';

/**
 * Embargo as a Verdaccio **storage filter** plugin.
 *
 * Verdaccio calls `filter_metadata(packument)` after fetching a package's
 * metadata from the uplink, before resolving. We strip HOLD/DENY versions from
 * the `versions` / `time` maps so the client's resolver never sees them — the
 * core packument-rewriting mechanism, uniform across npm/pnpm/yarn/bun.
 *
 * See https://verdaccio.org/docs/plugin-storage/#metadata-filters
 */
export class EmbargoStorageFilter {
  private engine: PackumentResolver & Partial<VersionResolver>;
  private cfg: EmbargoPluginConfig;
  private consoleBaseUrl: string;
  private failClosed: boolean;

  constructor(
    config: unknown,
    _options?: unknown,
    engine?: PackumentResolver & Partial<VersionResolver>,
  ) {
    const c = (config ?? {}) as Record<string, unknown>;
    this.cfg = {
      engineAddr: str(c['engine-addr'] ?? c['engineAddr'], 'localhost:50051'),
      tlsCert: str(c['tls-cert'] ?? c['tlsCert'], ''),
      tlsKey: str(c['tls-key'] ?? c['tlsKey'], ''),
      tlsCa: str(c['tls-ca'] ?? c['tlsCa'], ''),
      callerService: 'gateway',
      timeoutMs: num(c['timeout-ms'] ?? c['timeoutMs'], 5000),
    };
    this.consoleBaseUrl = str(c['console-url'] ?? c['consoleBaseUrl'], 'http://localhost:4000');
    // Fail closed by default: when the engine can't be reached, refuse to serve
    // rather than open the gate. Set `fail-closed: false` explicitly (dev only)
    // to prefer availability over enforcement.
    this.failClosed = bool(c['fail-closed'] ?? c['failClosed'], true);
    this.engine = engine ?? new EngineClient(this.cfg);
  }

  /** Verdaccio metadata filter: returns the rewritten packument. */
  async filter_metadata(packument: Packument): Promise<Packument> {
    try {
      return await rewritePackument(
        packument,
        this.engine,
        this.cfg.callerService,
        this.consoleBaseUrl,
      );
    } catch (err) {
      console.error(`[embargo] engine error for ${packument.name}: ${String(err)}`);
      if (this.failClosed) {
        // Refuse to serve any version rather than open the gate.
        return { ...packument, versions: {}, 'dist-tags': {} };
      }
      return packument;
    }
  }

  /**
   * Verdaccio middleware hook. Installs the tarball gate so direct tarball
   * fetches (e.g. `npm ci` from a lockfile) are also subject to verdicts — not
   * just packument resolution. Registering the plugin under `middlewares` in the
   * Verdaccio config activates this; if the engine client can't resolve a single
   * version, the gate is skipped with a warning rather than breaking startup.
   *
   * Typed loosely (the Verdaccio app is an Express instance) to avoid an express
   * type dependency.
   */
  register_middlewares(
    app: { use(fn: (req: GateRequest, res: GateResponse, next: GateNext) => void): void },
    _auth?: unknown,
    _storage?: unknown,
  ): void {
    if (typeof this.engine.resolveVersion !== 'function') {
      console.warn('[embargo] engine has no resolveVersion; tarball gate not installed');
      return;
    }
    const engine = this.engine as VersionResolver;
    app.use(tarballGate(engine, this.consoleBaseUrl, this.failClosed));
  }
}

function str(v: unknown, fallback: string): string {
  return typeof v === 'string' && v.length > 0 ? v : fallback;
}

function num(v: unknown, fallback: number): number {
  const n = typeof v === 'string' ? Number(v) : v;
  return typeof n === 'number' && Number.isFinite(n) && n > 0 ? n : fallback;
}

/** YAML configs may hand us a string — `"false"` must not coerce to true. */
function bool(v: unknown, fallback: boolean): boolean {
  if (typeof v === 'boolean') return v;
  if (typeof v === 'string') return v.trim().toLowerCase() !== 'false';
  return fallback;
}
