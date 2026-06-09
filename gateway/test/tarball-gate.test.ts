import { parseTarballPath, tarballGate } from '../src/tarball-gate';
import type { GateRequest, GateResponse, VersionResolver, VersionVerdict } from '../src/types';

describe('parseTarballPath', () => {
  test('parses unscoped tarball paths', () => {
    expect(parseTarballPath('/lodash/-/lodash-4.17.21.tgz')).toEqual({
      pkg: 'lodash',
      version: '4.17.21',
    });
  });

  test('parses scoped tarball paths (filename uses unscoped basename)', () => {
    expect(parseTarballPath('/@acme/widget/-/widget-1.2.3.tgz')).toEqual({
      pkg: '@acme/widget',
      version: '1.2.3',
    });
  });

  test('handles prerelease/build versions and query strings', () => {
    expect(parseTarballPath('/pkg/-/pkg-1.0.0-rc.1.tgz?foo=bar')).toEqual({
      pkg: 'pkg',
      version: '1.0.0-rc.1',
    });
  });

  test('returns null for non-tarball paths', () => {
    expect(parseTarballPath('/lodash')).toBeNull();
    expect(parseTarballPath('/lodash/-/notes.txt')).toBeNull();
    expect(parseTarballPath('/-/ping')).toBeNull();
  });
});

// --- middleware ------------------------------------------------------------

function mockRes(): GateResponse & { code?: number; body?: unknown } {
  const res: GateResponse & { code?: number; body?: unknown } = {
    status(code: number) {
      res.code = code;
      return res;
    },
    json(body: unknown) {
      res.body = body;
    },
  };
  return res;
}

function engineReturning(verdict: VersionVerdict): VersionResolver {
  return { resolveVersion: jest.fn().mockResolvedValue(verdict) };
}

describe('tarballGate', () => {
  const req = (path: string): GateRequest => ({ method: 'GET', path });

  test('passes ALLOW tarballs through to Verdaccio', async () => {
    const engine = engineReturning({ verdict: 'ALLOW', reasons: [] });
    const next = jest.fn();
    const res = mockRes();
    tarballGate(engine, 'https://console', false)(req('/lodash/-/lodash-4.17.21.tgz'), res, next);
    await new Promise(setImmediate);
    expect(next).toHaveBeenCalled();
    expect(res.code).toBeUndefined();
  });

  test('refuses a HELD tarball with 403 + actionable Embargo error', async () => {
    const engine = engineReturning({ verdict: 'HOLD', reasons: ['cooldown: 40h remaining'] });
    const next = jest.fn();
    const res = mockRes();
    tarballGate(engine, 'https://console', false)(req('/evil/-/evil-9.9.9.tgz'), res, next);
    await new Promise(setImmediate);
    expect(next).not.toHaveBeenCalled();
    expect(res.code).toBe(403);
    expect(res.body).toMatchObject({
      package: 'evil',
      version: '9.9.9',
      verdict: 'HOLD',
      reasons: ['cooldown: 40h remaining'],
    });
    expect((res.body as { approvalUrl: string }).approvalUrl).toContain('https://console');
  });

  test('non-tarball requests pass through without calling the engine', async () => {
    const engine = engineReturning({ verdict: 'DENY', reasons: [] });
    const next = jest.fn();
    tarballGate(engine, 'https://console', false)(req('/lodash'), mockRes(), next);
    await new Promise(setImmediate);
    expect(next).toHaveBeenCalled();
    expect(engine.resolveVersion).not.toHaveBeenCalled();
  });

  test('fail-open: serves the tarball when the engine errors', async () => {
    const engine: VersionResolver = {
      resolveVersion: jest.fn().mockRejectedValue(new Error('engine down')),
    };
    const next = jest.fn();
    const res = mockRes();
    tarballGate(engine, 'https://console', false)(req('/lodash/-/lodash-4.17.21.tgz'), res, next);
    await new Promise(setImmediate);
    expect(next).toHaveBeenCalled();
    expect(res.code).toBeUndefined();
  });

  test('fail-closed: refuses the tarball (503) when the engine errors', async () => {
    const engine: VersionResolver = {
      resolveVersion: jest.fn().mockRejectedValue(new Error('engine down')),
    };
    const next = jest.fn();
    const res = mockRes();
    tarballGate(engine, 'https://console', true)(req('/lodash/-/lodash-4.17.21.tgz'), res, next);
    await new Promise(setImmediate);
    expect(next).not.toHaveBeenCalled();
    expect(res.code).toBe(503);
  });
});
