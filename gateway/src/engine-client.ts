import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import * as path from 'path';
import type {
  EmbargoPluginConfig,
  PackumentResponse,
  VersionInfo,
  VersionVerdict,
} from './types';

const PROTO_PATH = path.resolve(__dirname, '../../engine/proto/embargo.proto');

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
      includeDirs: [path.resolve(__dirname, '../../engine/proto')],
    });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- grpc dynamic type
    const proto = grpc.loadPackageDefinition(pkgDef) as any;

    const creds = grpc.credentials.createSsl(
      Buffer.from(cfg.tlsCa),
      Buffer.from(cfg.tlsKey),
      Buffer.from(cfg.tlsCert),
    );

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
}

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
