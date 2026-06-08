import { parseNpm, parsePnpm, parseYarn, parseBun, formatForFilename } from '../src/lockfiles';
import { parseKey } from '../src/lockfiles/pnpm';
import { nameFromDescriptors } from '../src/lockfiles/yarn';

function has(deps: { name: string; version: string }[], name: string, version: string): boolean {
  return deps.some((d) => d.name === name && d.version === version);
}

describe('formatForFilename', () => {
  test('maps known lockfiles', () => {
    expect(formatForFilename('package-lock.json')).toBe('npm');
    expect(formatForFilename('a/b/pnpm-lock.yaml')).toBe('pnpm');
    expect(formatForFilename('yarn.lock')).toBe('yarn');
    expect(formatForFilename('bun.lock')).toBe('bun');
    expect(formatForFilename('Cargo.lock')).toBeNull();
  });
});

describe('npm package-lock.json', () => {
  test('parses lockfileVersion 3 packages map', () => {
    const content = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { name: 'root' },
        'node_modules/lodash': { version: '4.17.21' },
        'node_modules/@scope/pkg': { version: '1.2.3' },
        'node_modules/a/node_modules/b': { version: '2.0.0' },
      },
    });
    const deps = parseNpm(content);
    expect(has(deps, 'lodash', '4.17.21')).toBe(true);
    expect(has(deps, '@scope/pkg', '1.2.3')).toBe(true);
    expect(has(deps, 'b', '2.0.0')).toBe(true);
    expect(deps.some((d) => d.name === 'root')).toBe(false);
  });

  test('parses lockfileVersion 1 nested dependencies', () => {
    const content = JSON.stringify({
      lockfileVersion: 1,
      dependencies: {
        lodash: { version: '4.17.21' },
        chalk: { version: '5.0.0', dependencies: { 'ansi-styles': { version: '6.0.0' } } },
      },
    });
    const deps = parseNpm(content);
    expect(has(deps, 'lodash', '4.17.21')).toBe(true);
    expect(has(deps, 'ansi-styles', '6.0.0')).toBe(true);
  });
});

describe('pnpm-lock.yaml', () => {
  test('parses v9 keys (name@version) with peers and scopes', () => {
    const content = [
      'lockfileVersion: "9.0"',
      'packages:',
      '  lodash@4.17.21:',
      '    resolution: {integrity: sha512-x}',
      "  '@scope/pkg@1.2.3':",
      '    resolution: {integrity: sha512-y}',
      '  react@18.2.0(react-dom@18.2.0):',
      '    resolution: {integrity: sha512-z}',
    ].join('\n');
    const deps = parsePnpm(content);
    expect(has(deps, 'lodash', '4.17.21')).toBe(true);
    expect(has(deps, '@scope/pkg', '1.2.3')).toBe(true);
    expect(has(deps, 'react', '18.2.0')).toBe(true);
  });

  test('parses v6 keys with leading slash', () => {
    const content = ['packages:', '  /lodash@4.17.21:', '    dev: false'].join('\n');
    expect(has(parsePnpm(content), 'lodash', '4.17.21')).toBe(true);
  });

  test('parseKey handles scope + peer suffix', () => {
    expect(parseKey('/@scope/name@1.0.0(react@18)')).toEqual({
      name: '@scope/name',
      version: '1.0.0',
    });
  });
});

describe('yarn.lock', () => {
  test('parses classic v1 format', () => {
    const content = [
      '# yarn lockfile v1',
      '',
      'lodash@^4.17.0, lodash@~4.17.20:',
      '  version "4.17.21"',
      '  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"',
      '',
      '"@scope/pkg@^1.0.0":',
      '  version "1.2.3"',
    ].join('\n');
    const deps = parseYarn(content);
    expect(has(deps, 'lodash', '4.17.21')).toBe(true);
    expect(has(deps, '@scope/pkg', '1.2.3')).toBe(true);
  });

  test('parses berry v2+ format', () => {
    const content = [
      '__metadata:',
      '  version: 6',
      '',
      '"lodash@npm:^4.17.0":',
      '  version: 4.17.21',
      '  resolution: "lodash@npm:4.17.21"',
      '',
      '"@scope/pkg@npm:^1.0.0":',
      '  version: 1.2.3',
    ].join('\n');
    const deps = parseYarn(content);
    expect(has(deps, 'lodash', '4.17.21')).toBe(true);
    expect(has(deps, '@scope/pkg', '1.2.3')).toBe(true);
  });

  test('nameFromDescriptors keeps scope and drops range', () => {
    expect(nameFromDescriptors('"@scope/pkg@^1.0.0", "@scope/pkg@~1.2.0"')).toBe('@scope/pkg');
    expect(nameFromDescriptors('lodash@npm:^4')).toBe('lodash');
  });
});

describe('bun.lock', () => {
  test('parses JSONC packages map', () => {
    const content = `{
      // bun lockfile
      "lockfileVersion": 0,
      "packages": {
        "lodash": ["lodash@4.17.21", "", {}, "sha512-x"],
        "@scope/pkg": ["@scope/pkg@1.2.3", "", {}, "sha512-y"],
      },
    }`;
    const deps = parseBun(content);
    expect(has(deps, 'lodash', '4.17.21')).toBe(true);
    expect(has(deps, '@scope/pkg', '1.2.3')).toBe(true);
  });
});
