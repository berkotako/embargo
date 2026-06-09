// ---------------------------------------------------------------------------
// Types mirroring the engine's gRPC contract (hand-coded for M1;
// M2 will generate these from proto using @grpc/proto-loader types).
// ---------------------------------------------------------------------------

export type Verdict = 'ALLOW' | 'HOLD' | 'DENY';

export interface VersionInfo {
  package: string;
  version: string;
  publishedAt: Date;
}

export interface VersionVerdict {
  verdict: Verdict;
  reasons: string[];
  expiresAt?: Date;
}

export interface PackumentResponse {
  /** Versions the engine says are safe to serve. */
  allowedVersions: string[];
  /** Map of version → verdict for versions that were stripped. */
  stripped: Map<string, VersionVerdict>;
}

// Minimal packument shape (npm registry protocol).
export interface Packument {
  name: string;
  'dist-tags': Record<string, string>;
  versions: Record<string, PackumentVersion>;
  time: Record<string, string>;
  [key: string]: unknown;
}

export interface PackumentVersion {
  name: string;
  version: string;
  dist: {
    shasum: string;
    tarball: string;
    integrity?: string;
  };
  scripts?: Record<string, string>;
  [key: string]: unknown;
}

export interface EmbargoPluginConfig {
  engineAddr: string;
  tlsCert: string;
  tlsKey: string;
  tlsCa: string;
  callerService: string;
  /** Per-RPC deadline in ms; without one a sick engine stalls every install. */
  timeoutMs: number;
}

/** The engine surface the packument rewrite depends on (mockable in tests). */
export interface PackumentResolver {
  resolvePackument(
    pkg: string,
    versions: VersionInfo[],
    callerService: string,
  ): Promise<PackumentResponse>;
}

/** The engine surface the tarball gate depends on: a single-version verdict. */
export interface VersionResolver {
  resolveVersion(pkg: string, version: string): Promise<VersionVerdict>;
}

/** Minimal Express-style request/response so we don't depend on @types/express. */
export interface GateRequest {
  method?: string;
  url?: string;
  path?: string;
}
export interface GateResponse {
  status(code: number): GateResponse;
  json(body: unknown): void;
}
export type GateNext = () => void;

export interface HeldVersionError {
  package: string;
  version: string;
  verdict: 'HOLD' | 'DENY';
  reasons: string[];
  approvalUrl: string;
}
