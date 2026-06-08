import type {
  HeldVersionError,
  Packument,
  PackumentResolver,
  PackumentVersion,
  VersionInfo,
} from './types';

/**
 * Core packument rewriting logic.
 *
 * Intercepts the upstream packument and strips HOLD/DENY versions so the
 * client's resolver never sees them. Protocol-level enforcement — uniform
 * across npm/pnpm/yarn/bun with one .npmrc line.
 */
export async function rewritePackument(
  packument: Packument,
  engine: PackumentResolver,
  callerService: string,
  consoleBaseUrl: string,
): Promise<Packument> {
  const pkg = packument.name;
  const time = packument.time ?? {};

  const versions: VersionInfo[] = Object.keys(packument.versions).map((ver) => ({
    package: pkg,
    version: ver,
    publishedAt: new Date(time[ver] ?? Date.now()),
  }));

  if (versions.length === 0) {
    return packument;
  }

  const { allowedVersions, stripped } = await engine.resolvePackument(
    pkg,
    versions,
    callerService,
  );

  const allowedSet = new Set(allowedVersions);
  const newVersions: Record<string, PackumentVersion> = {};
  const newTime: Record<string, string> = {};

  // Keep only allowed versions in the map.
  for (const [ver, meta] of Object.entries(packument.versions)) {
    if (allowedSet.has(ver)) {
      newVersions[ver] = meta;
      if (time[ver] != null) newTime[ver] = time[ver]!;
    }
  }

  // Preserve time metadata entries that aren't version strings (e.g. 'created', 'modified').
  for (const [k, v] of Object.entries(time)) {
    if (!packument.versions[k]) {
      newTime[k] = v;
    }
  }

  // Rewrite dist-tags: if a dist-tag points to a stripped version, remove the tag.
  const newDistTags: Record<string, string> = {};
  for (const [tag, ver] of Object.entries(packument['dist-tags'])) {
    if (allowedSet.has(ver)) {
      newDistTags[tag] = ver;
    }
    // Stripped dist-tags are omitted; client resolvers will use whatever is left.
  }

  const result: Packument = {
    ...packument,
    'dist-tags': newDistTags,
    versions: newVersions,
    time: newTime,
    // Attach Embargo metadata so clients can surface a clear message.
    _embargo: buildEmbargoMeta(stripped, consoleBaseUrl),
  };

  return result;
}

/**
 * Generate a clear Embargo error for a pinned-but-held version.
 * Must never produce a cryptic ETARGET — always include reason + approval link.
 */
export function buildHeldError(
  pkg: string,
  version: string,
  reasons: string[],
  consoleBaseUrl: string,
): HeldVersionError {
  return {
    package: pkg,
    version,
    verdict: 'HOLD',
    reasons,
    approvalUrl: `${consoleBaseUrl}/approvals/request?package=${encodeURIComponent(pkg)}&version=${encodeURIComponent(version)}`,
  };
}

function buildEmbargoMeta(
  stripped: Map<string, { verdict: string; reasons: string[] }>,
  consoleBaseUrl: string,
): Record<string, unknown> {
  const held: Record<string, unknown> = {};
  for (const [ver, info] of stripped.entries()) {
    held[ver] = {
      verdict: info.verdict,
      reasons: info.reasons,
      approvalUrl: `${consoleBaseUrl}/approvals/request?version=${encodeURIComponent(ver)}`,
    };
  }
  return { heldVersions: held };
}
