import { changedDeps } from '../src/diff';
import { evaluate } from '../src/evaluate';
import { runGate } from '../src/index';
import { toHuman, toAnnotations, toArtifact } from '../src/report';
import type { Dep, DepVerdict, EngineClient, Verdict } from '../src/types';

/** Mock engine: verdicts keyed by name@version, default ALLOW. */
class MockEngine implements EngineClient {
  constructor(private verdicts: Record<string, { verdict: Verdict; reasons?: string[] }>) {}
  resolve(dep: Dep): Promise<DepVerdict> {
    const v = this.verdicts[`${dep.name}@${dep.version}`] ?? { verdict: 'ALLOW' as Verdict };
    const out: DepVerdict = { dep, verdict: v.verdict, reasons: v.reasons ?? [] };
    if (v.verdict !== 'ALLOW') out.approvalUrl = `https://console/approvals?p=${dep.name}`;
    return Promise.resolve(out);
  }
}

describe('changedDeps', () => {
  test('returns only added/changed deps, skipping unchanged', () => {
    const base: Dep[] = [
      { name: 'lodash', version: '4.17.20' },
      { name: 'react', version: '18.2.0' },
    ];
    const head: Dep[] = [
      { name: 'lodash', version: '4.17.21' }, // bumped → changed
      { name: 'react', version: '18.2.0' }, // unchanged → skipped
      { name: 'axios', version: '1.7.0' }, // new → added
    ];
    const changed = changedDeps(base, head);
    expect(changed).toHaveLength(2);
    expect(changed).toContainEqual({ name: 'lodash', version: '4.17.21' });
    expect(changed).toContainEqual({ name: 'axios', version: '1.7.0' });
  });

  test('all deps are changed when base is empty (new lockfile)', () => {
    const head: Dep[] = [{ name: 'lodash', version: '4.17.21' }];
    expect(changedDeps([], head)).toHaveLength(1);
  });
});

describe('evaluate', () => {
  const changed: Dep[] = [
    { name: 'lodash', version: '4.17.21' },
    { name: 'evil', version: '1.0.0' },
    { name: 'held', version: '2.0.0' },
  ];

  test('passes when all changed deps ALLOW', async () => {
    const engine = new MockEngine({});
    const result = await evaluate(engine, changed);
    expect(result.passed).toBe(true);
    expect(result.evaluated).toBe(3);
    expect(result.blocked).toHaveLength(0);
  });

  test('fails on a HELD dep', async () => {
    const engine = new MockEngine({ 'held@2.0.0': { verdict: 'HOLD', reasons: ['cooldown: 40h'] } });
    const result = await evaluate(engine, changed);
    expect(result.passed).toBe(false);
    expect(result.blocked).toHaveLength(1);
    expect(result.blocked[0]?.dep.name).toBe('held');
  });

  test('fails on a DENY (advisory) dep regardless', async () => {
    const engine = new MockEngine({
      'evil@1.0.0': { verdict: 'DENY', reasons: ['advisory: GHSA-x'] },
    });
    const result = await evaluate(engine, changed);
    expect(result.passed).toBe(false);
    expect(result.blocked.map((b) => b.dep.name)).toContain('evil');
  });

  test('an exception that the engine resolves to ALLOW passes the gate', async () => {
    // The engine applies the approval workflow; a previously-held dep now ALLOWs.
    const engine = new MockEngine({ 'held@2.0.0': { verdict: 'ALLOW' } });
    const result = await evaluate(engine, changed);
    expect(result.passed).toBe(true);
  });
});

describe('runGate', () => {
  test('parses lockfile pair and blocks a held bump', async () => {
    const base = JSON.stringify({
      lockfileVersion: 3,
      packages: { 'node_modules/lodash': { version: '4.17.20' } },
    });
    const head = JSON.stringify({
      lockfileVersion: 3,
      packages: { 'node_modules/lodash': { version: '4.17.21' } },
    });
    const engine = new MockEngine({
      'lodash@4.17.21': { verdict: 'HOLD', reasons: ['cooldown: 70h remaining'] },
    });
    const result = await runGate(engine, {
      filename: 'package-lock.json',
      baseContent: base,
      headContent: head,
    });
    expect(result.passed).toBe(false);
    expect(result.blocked[0]?.dep).toEqual({ name: 'lodash', version: '4.17.21' });
  });

  test('throws on an unrecognized lockfile', async () => {
    const engine = new MockEngine({});
    await expect(
      runGate(engine, { filename: 'Cargo.lock', baseContent: null, headContent: '{}' }),
    ).rejects.toThrow(/unrecognized lockfile/);
  });
});

describe('report', () => {
  test('human + annotations + artifact for a blocked result', () => {
    const result = {
      evaluated: 2,
      passed: false,
      blocked: [
        {
          dep: { name: 'evil', version: '1.0.0' },
          verdict: 'DENY' as Verdict,
          reasons: ['advisory: GHSA-x'],
          approvalUrl: 'https://console/approvals?p=evil',
        },
      ],
    };
    expect(toHuman(result)).toContain('evil@1.0.0');
    expect(toHuman(result)).toContain('advisory: GHSA-x');
    expect(toAnnotations(result)[0]).toContain('::error');
    const artifact = toArtifact(result);
    expect(artifact.passed).toBe(false);
    expect(artifact.blocked[0]?.package).toBe('evil');
  });

  test('human report for a passing result', () => {
    const result = { evaluated: 5, passed: true, blocked: [] };
    expect(toHuman(result)).toContain('all ALLOW');
  });
});
