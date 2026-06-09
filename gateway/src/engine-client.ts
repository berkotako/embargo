import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import * as path from 'path';
import type {
  EmbargoPluginConfig,
  PackumentResponse,
  VersionInfo,
  VersionVerdict,
} from './types';

// The proto dir: a monorepo-relative default, overridable for containers via
// EMBARGO_PROTO_DIR (the gateway image bundles the proto next to the plugin).
const PROTO_DIR =
  process.env.EMBARGO_PROTO_DIR ?? path.resolve(__dirname, '../../engine/proto');
const PROTO_PATH = path.join(PROTO_DIR, 'embargo.proto');

export class EngineClient {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- grpc dynamic service
  private client: any;

  constructor(cfg: EmbargoPluginConfig) {
    const pkgDef = protoLoader.loadSync(PROTO_PATH, {
      keepCase: false,
      longs: String,
      enums: String,
      defaults: true,
      oneofs: true,
      includeDirs: [PROTO_DIR],
    });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- grpc dynamic type
    const proto = grpc.loadPackageDefinition(pkgDef) as any;

    // mTLS when a client cert+key are provided; otherwise server-auth only
    // (the engine, configured with a client CA, will reject the handshake).
    const ca = cfg.tlsCa ? Buffer.from(cfg.tlsCa) : null;
    const creds =
      cfg.tlsCert && cfg.tlsKey
        ? grpc.credentials.createSsl(ca, Buffer.from(cfg.tlsKey), Buffer.from(cfg.tlsCert))
        : grpc.credentials.createSsl(ca);

    this.client = new proto.embargo.v1.EngineService(cfg.engineAddr, creds);
  }

  async resolvePackument(
    pkg: string,
    versions: VersionInfo[],
    callerService: string,
  ): Promise<PackumentResponse> {
    return new Promise((resolve, reject) => {
      const req = {
        package: pkg,
        versions: versions.map((v) => ({
          package: v.package,
          version: v.version,
          publishedAt: toTimestamp(v.publishedAt),
        })),
        callerService,
      };

      this.client.resolvePackument(
        req,
        (err: grpc.ServiceError | null, res: ResolvePackumentProtoResponse) => {
          if (err) { reject(err); return; }
          const stripped = new Map<string, VersionVerdict>();
          const strippedMap = (res.stripped ?? {}) as Record<string, StrippedProto>;
          for (const [ver, vr] of Object.entries(strippedMap)) {
            const vv: VersionVerdict = {
              verdict: protoVerdictToStr(vr.verdict),
              reasons: vr.reasons ?? [],
            };
            // exactOptionalPropertyTypes: only set expiresAt when present.
            if (vr.expiresAt) vv.expiresAt = fromTimestamp(vr.expiresAt);
            stripped.set(ver, vv);
          }
          resolve({ allowedVersions: res.allowedVersions ?? [], stripped });
        },
      );
    });
  }

  /**
   * Resolve a single (package, version) to its verdict. Used by the tarball
   * gate. No publish time is sent: the engine returns the verdict already
   * computed during packument resolution (the tarball fetch must enforce exactly
   * what the packument rewrite decided).
   */
  async resolveVersion(pkg: string, version: string): Promise<VersionVerdict> {
    return new Promise((resolve, reject) => {
      this.client.resolve(
        { versionInfo: { package: pkg, version }, callerService: 'gateway-tarball' },
        (err: grpc.ServiceError | null, res: ResolveProtoResponse) => {
          if (err) {
            reject(err);
            return;
          }
          resolve({
            verdict: protoVerdictToStr(res.verdict),
            reasons: res.reasons ?? [],
          });
        },
      );
    });
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- proto shape
type ResolveProtoResponse = any;

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- proto shape
type ResolvePackumentProtoResponse = any;

interface ProtoTimestamp {
  seconds: string | number;
  nanos: number;
}

interface StrippedProto {
  verdict: string | number;
  reasons?: string[];
  expiresAt?: ProtoTimestamp;
}

function toTimestamp(d: Date): { seconds: number; nanos: number } {
  return { seconds: Math.floor(d.getTime() / 1000), nanos: 0 };
}

function fromTimestamp(ts: { seconds: string | number; nanos: number }): Date {
  return new Date(Number(ts.seconds) * 1000);
}

function protoVerdictToStr(v: string | number): 'ALLOW' | 'HOLD' | 'DENY' {
  if (v === 'ALLOW' || v === 1) return 'ALLOW';
  if (v === 'DENY' || v === 3) return 'DENY';
  return 'HOLD';
}
