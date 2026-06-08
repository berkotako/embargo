import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import * as path from 'path';
import type { Dep, DepVerdict, EngineClient, Verdict } from './types';

const PROTO_PATH = path.resolve(__dirname, '../../engine/proto/embargo.proto');

export interface GrpcEngineOptions {
  /** host:port of the engine's EngineService. */
  engineAddr: string;
  /** Caller identity recorded in the engine audit log. */
  callerService: string;
  consoleBaseUrl: string;
  /** mTLS material; when omitted, an insecure channel is used (dev only). */
  tls?: { cert: string; key: string; ca: string };
}

/**
 * gRPC client for the engine's Resolve RPC. The admission gate never
 * re-implements scoring — it asks the engine for the verdict.
 */
export class GrpcEngineClient implements EngineClient {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- grpc dynamic service
  private client: any;
  private callerService: string;
  private consoleBaseUrl: string;

  constructor(opts: GrpcEngineOptions) {
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

    const creds = opts.tls
      ? grpc.credentials.createSsl(
          Buffer.from(opts.tls.ca),
          Buffer.from(opts.tls.key),
          Buffer.from(opts.tls.cert),
        )
      : grpc.credentials.createInsecure();

    this.client = new proto.embargo.v1.EngineService(opts.engineAddr, creds);
    this.callerService = opts.callerService;
    this.consoleBaseUrl = opts.consoleBaseUrl;
  }

  async resolve(dep: Dep): Promise<DepVerdict> {
    const req = {
      versionInfo: { package: dep.name, version: dep.version },
      callerService: this.callerService,
    };
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- proto response
    const res: any = await new Promise((resolve, reject) => {
      this.client.resolve(req, (err: grpc.ServiceError | null, r: unknown) => {
        if (err) reject(err);
        else resolve(r);
      });
    });

    const verdict = toVerdict(res.verdict);
    const out: DepVerdict = {
      dep,
      verdict,
      reasons: res.reasons ?? [],
    };
    if (verdict !== 'ALLOW') {
      out.approvalUrl =
        `${this.consoleBaseUrl}/approvals/request` +
        `?package=${encodeURIComponent(dep.name)}&version=${encodeURIComponent(dep.version)}`;
    }
    return out;
  }
}

function toVerdict(v: string | number): Verdict {
  if (v === 'ALLOW' || v === 1) return 'ALLOW';
  if (v === 'DENY' || v === 3) return 'DENY';
  return 'HOLD';
}
