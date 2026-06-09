import * as fs from 'fs';
import * as path from 'path';
import * as core from '@actions/core';
import { execFileSync } from 'child_process';
import { runGate } from './index';
import { GrpcEngineClient } from './engine-client';
import { toAnnotations, toArtifact, toHuman } from './report';

// Inputs come from the workflow (PR-controllable in some trigger setups), so
// constrain them: refs to plain revision names (no leading '-', no '..'
// range syntax), lockfiles to repo-relative paths without traversal.
const SAFE_REF = /^[A-Za-z0-9][A-Za-z0-9._/-]*$/;

function isSafeRef(ref: string): boolean {
  return SAFE_REF.test(ref) && !ref.includes('..');
}

function isSafeLockfilePath(p: string): boolean {
  return !path.isAbsolute(p) && !p.split(/[\\/]/).includes('..');
}

function gitShow(ref: string, file: string): string | null {
  try {
    return execFileSync('git', ['show', `${ref}:${file}`], { encoding: 'utf8' });
  } catch {
    return null;
  }
}

/** GitHub Action entry: reads inputs, evaluates the lockfile diff, sets outputs. */
export async function run(): Promise<void> {
  const lockfile = core.getInput('lockfile') || 'package-lock.json';
  const base = core.getInput('base-ref') || 'origin/main';
  const engineAddr = core.getInput('engine-addr') || process.env.EMBARGO_ENGINE_ADDR || '';
  const consoleBaseUrl = core.getInput('console-url') || 'http://localhost:4000';

  if (!engineAddr) {
    core.setFailed('embargo: engine-addr input (or EMBARGO_ENGINE_ADDR) is required');
    return;
  }
  if (!isSafeRef(base)) {
    core.setFailed(`embargo: base-ref is not a plain git ref: ${base}`);
    return;
  }
  if (!isSafeLockfilePath(lockfile)) {
    core.setFailed(`embargo: lockfile must be a repo-relative path without '..': ${lockfile}`);
    return;
  }
  if (!fs.existsSync(lockfile)) {
    core.setFailed(`embargo: lockfile not found: ${lockfile}`);
    return;
  }

  const engine = new GrpcEngineClient({
    engineAddr,
    callerService: 'admission-action',
    consoleBaseUrl,
    ...readTls(),
  });

  let result;
  try {
    result = await runGate(engine, {
      filename: lockfile,
      baseContent: gitShow(base, lockfile),
      headContent: fs.readFileSync(lockfile, 'utf8'),
    });
  } catch (err) {
    core.setFailed(`embargo: ${err instanceof Error ? err.message : String(err)}`);
    return;
  }

  core.info(toHuman(result));
  core.setOutput('passed', String(result.passed));
  core.setOutput('blocked-count', String(result.blocked.length));
  core.setOutput('report', JSON.stringify(toArtifact(result)));

  if (!result.passed) {
    // Emit inline annotations and fail the check.
    for (const a of toAnnotations(result)) core.info(a);
    for (const b of result.blocked) {
      core.error(`${b.dep.name}@${b.dep.version} [${b.verdict}] ${b.reasons[0] ?? ''}`, {
        title: `Embargo ${b.verdict}`,
      });
    }
    core.setFailed(`embargo: ${result.blocked.length} dependency(ies) blocked by policy`);
  }
}

function readTls(): { tls?: { cert: string; key: string; ca: string } } {
  const cert = core.getInput('tls-cert');
  const key = core.getInput('tls-key');
  const ca = core.getInput('tls-ca');
  if (cert && key && ca) {
    return {
      tls: {
        cert: fs.readFileSync(cert, 'utf8'),
        key: fs.readFileSync(key, 'utf8'),
        ca: fs.readFileSync(ca, 'utf8'),
      },
    };
  }
  return {};
}

run();
