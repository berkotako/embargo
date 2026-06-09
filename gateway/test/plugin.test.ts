import { EmbargoStorageFilter } from '../src/plugin';
import type { Packument, PackumentResolver, PackumentVersion } from '../src/types';

function makeEngine(
  allowedVersions: string[],
  stripped: Map<string, { verdict: 'HOLD' | 'DENY'; reasons: string[] }>,
): PackumentResolver {
  return {
    resolvePackument: jest.fn().mockResolvedValue({ allowedVersions, stripped }),
  };
}

function failingEngine(): PackumentResolver {
  return {
    resolvePackument: jest.fn().mockRejectedValue(new Error('engine unreachable')),
  };
}

function makePackument(versions: string[]): Packument {
  const pkgVersions: Record<string, PackumentVersion> = {};
  const time: Record<string, string> = {};
  for (const v of versions) {
    pkgVersions[v] = { name: 'testpkg', version: v, dist: { shasum: 'x', tarball: '' } };
    time[v] = '2024-01-01T00:00:00Z';
  }
  return {
    name: 'testpkg',
    'dist-tags': { latest: versions.at(-1) ?? '1.0.0' },
    versions: pkgVersions,
    time,
  };
}

describe('EmbargoStorageFilter.filter_metadata', () => {
  test('strips HELD versions from the packument', async () => {
    const engine = makeEngine(['1.0.0'], new Map([['1.1.0', { verdict: 'HOLD', reasons: ['cooldown'] }]]));
    const filter = new EmbargoStorageFilter({ 'engine-addr': 'x:1' }, {}, engine);

    const out = await filter.filter_metadata(makePackument(['1.0.0', '1.1.0']));
    expect(Object.keys(out.versions)).toEqual(['1.0.0']);
  });

  test('fail-closed (default): serves no versions when the engine errors', async () => {
    const filter = new EmbargoStorageFilter({}, {}, failingEngine());
    const out = await filter.filter_metadata(makePackument(['1.0.0', '1.1.0']));
    expect(Object.keys(out.versions)).toHaveLength(0);
    expect(Object.keys(out['dist-tags'])).toHaveLength(0);
  });

  test('fail-open (explicit opt-out): serves the unfiltered packument when the engine errors', async () => {
    const filter = new EmbargoStorageFilter({ 'fail-closed': false }, {}, failingEngine());
    const pkg = makePackument(['1.0.0', '1.1.0']);
    const out = await filter.filter_metadata(pkg);
    expect(Object.keys(out.versions)).toEqual(['1.0.0', '1.1.0']);
  });

  test('fail-closed: a YAML string "false" opts out (no truthy-string coercion)', async () => {
    const filter = new EmbargoStorageFilter({ 'fail-closed': 'false' }, {}, failingEngine());
    const out = await filter.filter_metadata(makePackument(['1.0.0']));
    expect(Object.keys(out.versions)).toEqual(['1.0.0']);
  });

  test('reads kebab-case config keys (Verdaccio yaml style)', () => {
    // Constructing with kebab keys must not throw and should not need an engine.
    const engine = makeEngine([], new Map());
    expect(
      () => new EmbargoStorageFilter({ 'engine-addr': 'h:2', 'console-url': 'https://c' }, {}, engine),
    ).not.toThrow();
  });
});
