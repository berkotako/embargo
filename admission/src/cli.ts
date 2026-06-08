#!/usr/bin/env node
import * as fs from 'fs';
import { execFileSync } from 'child_process';
import { runGate } from './index';
import { GrpcEngineClient } from './engine-client';
import { toAnnotations, toArtifact, toHuman } from './report';

interface CliArgs {
  lockfile: string;
  base: string;
  engineAddr: string;
  consoleBaseUrl: string;
  reportPath?: string;
}

function parseArgs(argv: string[]): CliArgs {
  const get = (flag: string, fallback?: string): string => {
    const i = argv.indexOf(flag);
    if (i !== -1 && argv[i + 1]) return argv[i + 1] as string;
    if (fallback !== undefined) return fallback;
    throw new Error(`missing required argument ${flag}`);
  };
  const reportIdx = argv.indexOf('--report');
  return {
    lockfile: get('--lockfile', 'package-lock.json'),
    base: get('--base', 'HEAD~1'),
    engineAddr: get('--engine', process.env.EMBARGO_ENGINE_ADDR ?? 'localhost:50051'),
    consoleBaseUrl: get('--console', process.env.EMBARGO_CONSOLE_URL ?? 'http://localhost:4000'),
    ...(reportIdx !== -1 && argv[reportIdx + 1] ? { reportPath: argv[reportIdx + 1] } : {}),
  };
}

/** Read a file's content at a git ref, or null if it didn't exist there. */
function gitShow(ref: string, file: string): string | null {
  try {
    return execFileSync('git', ['show', `${ref}:${file}`], { encoding: 'utf8' });
  } catch {
    return null; // newly added lockfile
  }
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));

  if (!fs.existsSync(args.lockfile)) {
    console.error(`embargo: lockfile not found: ${args.lockfile}`);
    process.exit(2);
  }

  const engine = new GrpcEngineClient({
    engineAddr: args.engineAddr,
    callerService: 'admission-cli',
    consoleBaseUrl: args.consoleBaseUrl,
    ...readTls(),
  });

  const result = await runGate(engine, {
    filename: args.lockfile,
    baseContent: gitShow(args.base, args.lockfile),
    headContent: fs.readFileSync(args.lockfile, 'utf8'),
  });

  console.log(toHuman(result));
  if (args.reportPath) {
    fs.writeFileSync(args.reportPath, JSON.stringify(toArtifact(result), null, 2));
  }
  if (!result.passed) {
    for (const a of toAnnotations(result)) console.log(a);
    process.exit(1);
  }
}

function readTls(): { tls?: { cert: string; key: string; ca: string } } {
  const { EMBARGO_TLS_CERT, EMBARGO_TLS_KEY, EMBARGO_TLS_CA } = process.env;
  if (EMBARGO_TLS_CERT && EMBARGO_TLS_KEY && EMBARGO_TLS_CA) {
    return {
      tls: {
        cert: fs.readFileSync(EMBARGO_TLS_CERT, 'utf8'),
        key: fs.readFileSync(EMBARGO_TLS_KEY, 'utf8'),
        ca: fs.readFileSync(EMBARGO_TLS_CA, 'utf8'),
      },
    };
  }
  return {};
}

main().catch((err) => {
  console.error(`embargo: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(2);
});
