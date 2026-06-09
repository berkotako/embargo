import { rewritePackument, buildHeldError } from '../src/packument';
import type { EngineClient } from '../src/engine-client';
import type { Packument } from '../src/types';

// Mock engine client.
function makeEngine(allowedVersions: string[], stripped: Map<string, { verdict: 'HOLD' | 'DENY'; reasons: string[] }>): EngineClient {
  return {
    resolvePackument: jest.fn().mockResolvedValue({ allowedVersions, stripped }),
  } as unknown as EngineClient;
}

const BASE_URL = 'https://embargo.example.com';

function makePackument(versions: Record<string, Date>): Packument {
  const pkgVersions: Record<string, unknown> = {};
  const time: Record<string, string> = { created: '2024-01-01T00:00:00Z', modified: '2024-06-01T00:00:00Z' };
  for (const [ver, date] of Object.entries(versions)) {
    pkgVersions[ver] = { name: 'testpkg', version: ver, dist: { shasum: 'abc', tarball: '' } };
    time[ver] = date.toISOString();
  }
  return {
    name: 'testpkg',
    'dist-tags': { latest: Object.keys(versions).at(-1) ?? '0.0.1' },
    versions: pkgVersions as Record<string, import('../src/types').PackumentVersion>,
    time,
  };
}

describe('rewritePackument', () => {
  test('strips HOLD and DENY versions from versions map', async () => {
    const packument = makePackument({ '1.0.0': new Date('2024-01-01'), '1.1.0': new Date() });
    const stripped = new Map([['1.1.0', { verdict: 'HOLD' as const, reasons: ['cooldown: 71h remaining'] }]]);
    const engine = makeEngine(['1.0.0'], stripped);

    const result = await rewritePackument(packument, engine, 'gateway', BASE_URL);

    expect(Object.keys(result.versions)).toEqual(['1.0.0']);
    expect(result.versions['1.1.0']).toBeUndefined();
  });

  test('preserves time metadata for allowed versions only', async () => {
    const packument = makePackument({ '1.0.0': new Date('2024-01-01'), '1.1.0': new Date() });
    const stripped = new Map([['1.1.0', { verdict: 'HOLD' as const, reasons: ['cooldown'] }]]);
    const engine = makeEngine(['1.0.0'], stripped);

    const result = await rewritePackument(packument, engine, 'gateway', BASE_URL);

    expect(result.time['1.0.0']).toBeDefined();
    expect(result.time['1.1.0']).toBeUndefined();
    // Non-version time keys are preserved.
    expect(result.time['created']).toBeDefined();
    expect(result.time['modified']).toBeDefined();
  });

  test('strips dist-tag pointing to a stripped version', async () => {
    const packument = makePackument({ '1.0.0': new Date('2024-01-01'), '1.1.0': new Date() });
    (packument as Packument)['dist-tags'] = { latest: '1.1.0', stable: '1.0.0' };
    const stripped = new Map([['1.1.0', { verdict: 'HOLD' as const, reasons: ['cooldown'] }]]);
    const engine = makeEngine(['1.0.0'], stripped);

    const result = await rewritePackument(packument, engine, 'gateway', BASE_URL);

    expect(result['dist-tags']['latest']).toBeUndefined();
    expect(result['dist-tags']['stable']).toBe('1.0.0');
  });

  test('attaches _embargo metadata with held versions and approval links', async () => {
    const packument = makePackument({ '1.0.0': new Date('2024-01-01'), '1.1.0': new Date() });
    const stripped = new Map([['1.1.0', { verdict: 'HOLD' as const, reasons: ['cooldown: 71h remaining'] }]]);
    const engine = makeEngine(['1.0.0'], stripped);

    const result = await rewritePackument(packument, engine, 'gateway', BASE_URL);

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const meta = (result as any)._embargo;
    expect(meta).toBeDefined();
    expect(meta.heldVersions['1.1.0']).toBeDefined();
    expect(meta.heldVersions['1.1.0'].approvalUrl).toContain('1.1.0');
    expect(meta.heldVersions['1.1.0'].approvalUrl).toContain(BASE_URL);
    // The link must pre-fill the package too, not just the version.
    expect(meta.heldVersions['1.1.0'].approvalUrl).toContain('package=testpkg');
  });

  test('passes through empty packument unchanged', async () => {
    const packument = makePackument({});
    const engine = makeEngine([], new Map());

    const result = await rewritePackument(packument, engine, 'gateway', BASE_URL);

    expect(result).toMatchObject(packument);
    // Engine should not be called for empty packuments.
    expect(engine.resolvePackument).not.toHaveBeenCalled();
  });
});

describe('buildHeldError', () => {
  test('includes clear reason and approval link — never a cryptic error', () => {
    const err = buildHeldError('lodash', '4.17.21', ['cooldown: 71h remaining'], BASE_URL);
    expect(err.package).toBe('lodash');
    expect(err.version).toBe('4.17.21');
    expect(err.reasons).toContain('cooldown: 71h remaining');
    expect(err.approvalUrl).toContain(BASE_URL);
    expect(err.approvalUrl).toContain('lodash');
    expect(err.approvalUrl).toContain('4.17.21');
  });
});
