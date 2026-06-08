import type { EmbargoPluginConfig, Packument, PackumentResolver } from './types';
import { EngineClient } from './engine-client';
import { rewritePackument } from './packument';

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
  private engine: PackumentResolver;
  private cfg: EmbargoPluginConfig;
  private consoleBaseUrl: string;
  private failClosed: boolean;

  constructor(config: unknown, _options?: unknown, engine?: PackumentResolver) {
    const c = (config ?? {}) as Record<string, unknown>;
    this.cfg = {
      engineAddr: str(c['engine-addr'] ?? c['engineAddr'], 'localhost:50051'),
      tlsCert: str(c['tls-cert'] ?? c['tlsCert'], ''),
      tlsKey: str(c['tls-key'] ?? c['tlsKey'], ''),
      tlsCa: str(c['tls-ca'] ?? c['tlsCa'], ''),
      callerService: 'gateway',
    };
    this.consoleBaseUrl = str(c['console-url'] ?? c['consoleBaseUrl'], 'http://localhost:4000');
    // Fail-open (serve unfiltered) by default for availability; set fail-closed
    // to refuse to serve when the engine can't be reached — the gate stays shut.
    this.failClosed = Boolean(c['fail-closed'] ?? c['failClosed'] ?? false);
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
}

function str(v: unknown, fallback: string): string {
  return typeof v === 'string' && v.length > 0 ? v : fallback;
}
