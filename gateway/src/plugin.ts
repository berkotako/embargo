import type { EmbargoPluginConfig, Packument } from './types';
import { EngineClient } from './engine-client';
import { rewritePackument } from './packument';

/**
 * Verdaccio middleware plugin.
 *
 * Verdaccio calls `afterGetPackage` after fetching from upstream.
 * We intercept the packument there and strip HOLD/DENY versions.
 */
export class EmbargoPlugin {
  private engine: EngineClient;
  private cfg: EmbargoPluginConfig;
  private consoleBaseUrl: string;

  constructor(config: unknown, _options: unknown) {
    const c = config as Record<string, unknown>;
    this.cfg = {
      engineAddr: (c['engineAddr'] as string | undefined) ?? 'localhost:50051',
      tlsCert: (c['tlsCert'] as string | undefined) ?? '',
      tlsKey: (c['tlsKey'] as string | undefined) ?? '',
      tlsCa: (c['tlsCa'] as string | undefined) ?? '',
      callerService: 'gateway',
    };
    this.consoleBaseUrl =
      (c['consoleBaseUrl'] as string | undefined) ?? 'http://localhost:4000';
    this.engine = new EngineClient(this.cfg);
  }

  /**
   * Called by Verdaccio after fetching the packument from upstream.
   * Returns the rewritten packument (HOLD/DENY versions stripped).
   */
  async afterGetPackage(
    pkg: string,
    packument: Packument,
  ): Promise<Packument> {
    try {
      return await rewritePackument(
        packument,
        this.engine,
        this.cfg.callerService,
        this.consoleBaseUrl,
      );
    } catch (err) {
      // Never break the proxy if the engine is unreachable — log + pass through.
      // In production, alert on this; it means the gate is open.
      console.error(`[embargo] engine error for ${pkg}: ${String(err)}`);
      return packument;
    }
  }
}
