import http from 'node:http';
import { isIP } from 'node:net';
import { z } from 'zod';

/**
 * Client of the recording sinkhole's admin API (step 4.6 X5, X6;
 * `infrastructure/sandbox/sinkhole/sinkhole.mjs`). The admin endpoint listens only on the
 * sinkhole's `sandbox-control` address (never on the detonation network the runners use) and
 * requires the bearer token `SANDBOX_SINKHOLE_ADMIN_TOKEN`, which runners never see.
 *
 *   GET    /records?ip=<runner ip>&since=<epoch ms>   → { records: SinkholeRecord[], dropped }
 *   DELETE /records?ip=<runner ip>                    → { deleted }
 *   GET    /stats                                     → { total, sources }
 *   GET    /health                                    → { ok: true }
 *
 * The response is parsed strictly and bounded: the records describe what an untrusted sample
 * asked for (names, hosts, SNI) and become evidence only.
 */

export const SINKHOLE_MAX_RECORDS = 1_000;
const HOST = z
  .string()
  .max(253)
  .regex(/^[a-z0-9_]([a-z0-9_-]{0,62})(\.[a-z0-9_]([a-z0-9_-]{0,62}))*\.?$/);
const SHA = z.string().regex(/^[0-9a-f]{64}$/);
const AT = z.number().int().nonnegative();

export const sinkholeRecordSchema = z.discriminatedUnion('kind', [
  z.strictObject({
    kind: z.literal('dns'),
    at: AT,
    name: HOST,
    type: z.enum(['A', 'AAAA', 'MX', 'TXT', 'other']),
    transport: z.enum(['udp', 'tcp']),
  }),
  z.strictObject({
    kind: z.literal('http'),
    at: AT,
    host: HOST.nullable(),
    port: z.number().int().min(1).max(65_535),
    method: z.enum(['GET', 'POST', 'HEAD', 'PUT', 'OTHER']),
    pathSha256: SHA,
    userAgentSha256: SHA.nullable(),
  }),
  z.strictObject({
    kind: z.literal('tls'),
    at: AT,
    sni: HOST.nullable(),
    port: z.number().int().min(1).max(65_535),
  }),
]);
export type SinkholeRecord = z.infer<typeof sinkholeRecordSchema>;

const recordsResponseSchema = z.strictObject({
  records: z.array(z.unknown()).max(SINKHOLE_MAX_RECORDS),
  dropped: z.number().int().nonnegative(),
});

export interface SinkholeRequest {
  method: 'GET' | 'DELETE';
  /** Path and query, e.g. `/records?ip=…`. */
  path: string;
  headers: Record<string, string>;
}

export interface SinkholeResponse {
  status: number;
  body: string;
}

/**
 * Sends one admin request. The default speaks HTTP to `adminUrl`; host-run tests (where the
 * internal `sandbox-control` network is not routable from the host) inject a transport that
 * relays the same request through the sinkhole container.
 */
export type SinkholeTransport = (request: SinkholeRequest) => Promise<SinkholeResponse>;

export interface SinkholeClientOptions {
  /** `SANDBOX_SINKHOLE_ADMIN_URL`, e.g. `http://172.31.252.53:3094`. */
  adminUrl: string;
  /** `SANDBOX_SINKHOLE_ADMIN_TOKEN` (never logged). */
  token: string;
  timeoutMs?: number;
  maxResponseBytes?: number;
  transport?: SinkholeTransport;
}

export class SinkholeError extends Error {
  constructor(
    readonly operation: string,
    readonly status: number | null,
  ) {
    super(`sinkhole ${operation} failed${status === null ? '' : ` (${status})`}`);
    this.name = 'SinkholeError';
  }
}

export interface SinkholeRecords {
  records: SinkholeRecord[];
  /** Records the sinkhole dropped (ring bound) plus entries that failed validation here. */
  dropped: number;
}

export class SinkholeClient {
  private readonly transport: SinkholeTransport;

  constructor(private readonly options: SinkholeClientOptions) {
    if (options.token.length < 16) throw new Error('sinkhole admin token too short');
    const url = new URL(options.adminUrl);
    if (url.protocol !== 'http:') throw new Error('sinkhole admin URL must be http://');
    this.transport =
      options.transport ??
      httpTransport(url, options.timeoutMs ?? 5_000, options.maxResponseBytes ?? 2 * 1024 * 1024);
  }

  async health(): Promise<boolean> {
    try {
      const res = await this.send('GET', '/health');
      return res.status === 200;
    } catch {
      return false;
    }
  }

  /** Records of `ip` at or after `sinceMs` (strictly validated; invalid entries are counted). */
  async fetchRecords(ip: string, sinceMs: number): Promise<SinkholeRecords> {
    assertIp(ip);
    const since = Math.max(0, Math.floor(sinceMs));
    const res = await this.send('GET', `/records?ip=${encodeURIComponent(ip)}&since=${since}`);
    if (res.status !== 200) throw new SinkholeError('fetch', res.status);
    let parsed: z.infer<typeof recordsResponseSchema>;
    try {
      parsed = recordsResponseSchema.parse(JSON.parse(res.body));
    } catch {
      throw new SinkholeError('fetch', res.status);
    }
    const records: SinkholeRecord[] = [];
    let invalid = 0;
    for (const entry of parsed.records) {
      const record = sinkholeRecordSchema.safeParse(entry);
      if (record.success) records.push(record.data);
      else invalid += 1;
    }
    return { records, dropped: parsed.dropped + invalid };
  }

  /** How many records the sinkhole holds and for how many source addresses. */
  async stats(): Promise<{ total: number; sources: number }> {
    const res = await this.send('GET', '/stats');
    if (res.status !== 200) throw new SinkholeError('stats', res.status);
    try {
      return z
        .strictObject({
          total: z.number().int().nonnegative(),
          sources: z.number().int().nonnegative(),
        })
        .parse(JSON.parse(res.body));
    } catch {
      throw new SinkholeError('stats', res.status);
    }
  }

  /** Deletes every record of `ip`; returns how many were deleted. */
  async clearRecords(ip: string): Promise<number> {
    assertIp(ip);
    const res = await this.send('DELETE', `/records?ip=${encodeURIComponent(ip)}`);
    if (res.status !== 200) throw new SinkholeError('clear', res.status);
    try {
      const body = z
        .strictObject({ deleted: z.number().int().nonnegative() })
        .parse(JSON.parse(res.body));
      return body.deleted;
    } catch {
      throw new SinkholeError('clear', res.status);
    }
  }

  private send(method: 'GET' | 'DELETE', path: string): Promise<SinkholeResponse> {
    return this.transport({
      method,
      path,
      headers: { authorization: `Bearer ${this.options.token}`, accept: 'application/json' },
    });
  }
}

function assertIp(ip: string): void {
  if (isIP(ip) === 0) throw new Error('invalid runner ip');
}

function httpTransport(base: URL, timeoutMs: number, maxBytes: number): SinkholeTransport {
  return (request) =>
    new Promise<SinkholeResponse>((resolve, reject) => {
      const req = http.request(
        {
          host: base.hostname,
          port: base.port || 80,
          method: request.method,
          path: request.path,
          headers: request.headers,
          timeout: timeoutMs,
        },
        (res) => {
          const chunks: Buffer[] = [];
          let size = 0;
          res.on('data', (chunk: Buffer) => {
            size += chunk.length;
            if (size > maxBytes) {
              res.removeAllListeners('data');
              res.destroy();
              reject(new SinkholeError('response_too_large', res.statusCode ?? null));
              return;
            }
            chunks.push(chunk);
          });
          res.on('end', () =>
            resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }),
          );
          res.on('error', () => reject(new SinkholeError('response', res.statusCode ?? null)));
        },
      );
      req.on('timeout', () => req.destroy(new SinkholeError('timeout', null)));
      req.on('error', (error) =>
        reject(error instanceof SinkholeError ? error : new SinkholeError('request', null)),
      );
      req.end();
    });
}
