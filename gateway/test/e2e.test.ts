// End-to-end: the gateway's packument rewrite calling a LIVE engine over mTLS
// gRPC. Gated on EMBARGO_E2E so the normal suite stays hermetic; a dedicated
// run sets it against a running engine.
//
//   EMBARGO_E2E=1 EMBARGO_ENGINE_ADDR=localhost:50051 EMBARGO_CERTS=/path \
//     npm test -- e2e
import * as fs from 'fs';
import * as path from 'path';
import { EngineClient } from '../src/engine-client';
import { rewritePackument } from '../src/packument';
import type { Packument } from '../src/types';

const run = process.env.EMBARGO_E2E ? describe : describe.skip;

run('gateway ⇄ engine (mTLS)', () => {
  const certs = process.env.EMBARGO_CERTS ?? '/tmp/e2e-certs';
  const engineAddr = process.env.EMBARGO_ENGINE_ADDR ?? 'localhost:50051';

  function client(withCert: boolean): EngineClient {
    return new EngineClient({
      engineAddr,
      callerService: 'gateway',
      tlsCa: fs.readFileSync(path.join(certs, 'ca.crt'), 'utf8'),
      tlsCert: withCert ? fs.readFileSync(path.join(certs, 'gateway.crt'), 'utf8') : '',
      tlsKey: withCert ? fs.readFileSync(path.join(certs, 'gateway.key'), 'utf8') : '',
    });
  }

  // A packument with an aged version (ALLOW) and a fresh one (HOLD under the
  // default 72h-cooldown bootstrap policy).
  function packument(): Packument {
    const old = new Date(Date.now() - 200 * 3600_000).toISOString();
    const fresh = new Date(Date.now() - 1 * 3600_000).toISOString();
    return {
      name: 'e2e-demo-pkg',
      'dist-tags': { latest: '2.0.0' },
      versions: {
        '1.0.0': { name: 'e2e-demo-pkg', version: '1.0.0', dist: { shasum: 'a', tarball: '' } },
        '2.0.0': { name: 'e2e-demo-pkg', version: '2.0.0', dist: { shasum: 'b', tarball: '' } },
      },
      time: { '1.0.0': old, '2.0.0': fresh },
    };
  }

  test('strips the fresh (HELD) version, keeps the aged one', async () => {
    const out = await rewritePackument(
      packument(),
      client(true),
      'gateway',
      'http://localhost:4000',
    );
    expect(Object.keys(out.versions).sort()).toEqual(['1.0.0']);
    // dist-tags pointing at the stripped version are dropped.
    expect(out['dist-tags']['latest']).toBeUndefined();
    // _embargo metadata surfaces the held version + approval link.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const meta = (out as any)._embargo;
    expect(meta.heldVersions['2.0.0']).toBeDefined();
  }, 15000);

  test('mTLS is enforced: a client without a cert is rejected', async () => {
    await expect(
      rewritePackument(packument(), client(false), 'gateway', 'http://localhost:4000'),
    ).rejects.toBeDefined();
  }, 15000);
});
