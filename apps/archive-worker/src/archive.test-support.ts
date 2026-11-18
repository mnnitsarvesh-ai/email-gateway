/* eslint-disable @typescript-eslint/require-await -- the fakes implement the async ArchiveStorage interface */
import { randomBytes } from 'node:crypto';
import { Readable } from 'node:stream';
import { inflateRawSync } from 'node:zlib';
import { MetricsService } from '@email-gateway/common';
import { createLogger, type Logger } from '@email-gateway/logger';
import { ArchiveMetrics } from './metrics/archive-metrics';
import type {
  ArchiveStorage,
  DeleteVersionResult,
  ListedVersion,
  ObjectLockSpec,
  StoredVersion,
} from './storage/archive-storage';

/** Test-only helpers of the unit suites (fakes of S3, metrics, logger). */

export const silentLogger: Logger = createLogger({
  service: 'archive-worker-test',
  level: 'fatal',
});

let metricsSeq = 0;
export function testMetrics(): { metrics: ArchiveMetrics; service: MetricsService } {
  metricsSeq += 1;
  const service = new MetricsService({ service: `archive-worker-unit-${metricsSeq}` });
  return { metrics: new ArchiveMetrics(service), service };
}

/** Reads a counter/gauge value (labels matched as a subset) from the exposition text. */
export async function metricValue(
  service: MetricsService,
  name: string,
  labels: Record<string, string> = {},
): Promise<number> {
  const text = await service.metrics();
  let total = 0;
  for (const line of text.split('\n')) {
    if (!line.startsWith(`${name}{`) && !line.startsWith(`${name} `)) continue;
    if (Object.entries(labels).every(([k, v]) => line.includes(`${k}="${v}"`))) {
      total += Number(line.slice(line.lastIndexOf(' ') + 1));
    }
  }
  return total;
}

interface FakeVersion {
  key: string;
  versionId: string;
  body: Buffer;
  lock: ObjectLockSpec | null;
  lastModified: Date;
  tagging?: string;
}

/**
 * An in-memory, versioned, Object-Lock-aware stand-in for `ArchiveStorage` (unit tests only):
 * a version under a running lock refuses deletion (governance unless bypassed; compliance
 * always), retention only grows, and every call is logged in order.
 */
export class FakeStorage {
  readonly buckets = { mail: 'mail', archive: 'archive' };
  readonly calls: string[] = [];
  readonly objects = new Map<string, FakeVersion[]>();
  failUpload: Error | null = null;
  now: () => Date = () => new Date();

  private list(bucket: string, key: string): FakeVersion[] {
    const k = `${bucket}\0${key}`;
    let l = this.objects.get(k);
    if (!l) {
      l = [];
      this.objects.set(k, l);
    }
    return l;
  }

  seed(bucket: string, key: string, body: Buffer, lock: ObjectLockSpec | null = null): string {
    const versionId = randomBytes(8).toString('hex');
    this.list(bucket, key).push({ key, versionId, body, lock, lastModified: this.now() });
    return versionId;
  }

  versions(bucket: string, prefix = ''): FakeVersion[] {
    const out: FakeVersion[] = [];
    for (const [k, l] of this.objects) {
      const [b, key] = k.split('\0') as [string, string];
      if (b === bucket && key.startsWith(prefix)) out.push(...l);
    }
    return out;
  }

  async probeObjectLock(): Promise<boolean> {
    return true;
  }

  async uploadStream(input: {
    bucket?: string;
    key: string;
    body: Readable;
    lock?: ObjectLockSpec | null;
    tagging?: string;
  }): Promise<StoredVersion> {
    this.calls.push(`upload:${input.key}:${input.lock?.mode ?? 'none'}`);
    const chunks: Buffer[] = [];
    for await (const c of input.body) {
      chunks.push(Buffer.from(c as Buffer));
      if (this.failUpload) throw this.failUpload;
    }
    const bucket = input.bucket ?? this.buckets.archive;
    const versionId = this.seed(bucket, input.key, Buffer.concat(chunks), input.lock ?? null);
    const last = this.list(bucket, input.key).at(-1)!;
    if (input.tagging) last.tagging = input.tagging;
    return { key: input.key, versionId };
  }

  async putBuffer(input: {
    key: string;
    body: Buffer;
    lock?: ObjectLockSpec | null;
  }): Promise<StoredVersion> {
    this.calls.push(`put:${input.key}:${input.lock?.mode ?? 'none'}`);
    return {
      key: input.key,
      versionId: this.seed(this.buckets.archive, input.key, input.body, input.lock ?? null),
    };
  }

  private find(bucket: string, key: string, versionId?: string | null): FakeVersion | undefined {
    const l = this.objects.get(`${bucket}\0${key}`) ?? [];
    return versionId ? l.find((v) => v.versionId === versionId) : l.at(-1);
  }

  async getStream(bucket: string, key: string, versionId?: string | null): Promise<Readable> {
    const v = this.find(bucket, key, versionId);
    if (!v)
      throw Object.assign(new Error('missing'), {
        name: 'NoSuchKey',
        $metadata: { httpStatusCode: 404 },
      });
    return Readable.from([v.body]);
  }

  async getBuffer(bucket: string, key: string, versionId?: string | null): Promise<Buffer> {
    const v = this.find(bucket, key, versionId);
    if (!v)
      throw Object.assign(new Error('missing'), {
        name: 'NoSuchKey',
        $metadata: { httpStatusCode: 404 },
      });
    return v.body;
  }

  async readRange(
    bucket: string,
    key: string,
    maxBytes: number,
  ): Promise<{ bytes: Buffer; truncated: boolean }> {
    const v = this.find(bucket, key);
    if (!v)
      throw Object.assign(new Error('missing'), {
        name: 'NoSuchKey',
        $metadata: { httpStatusCode: 404 },
      });
    return { bytes: v.body.subarray(0, maxBytes), truncated: v.body.length > maxBytes };
  }

  async exists(bucket: string, key: string, versionId?: string | null): Promise<boolean> {
    return this.find(bucket, key, versionId) !== undefined;
  }

  async deleteVersion(
    bucket: string,
    key: string,
    versionId: string,
    options: { bypassGovernance?: boolean } = {},
  ): Promise<DeleteVersionResult> {
    this.calls.push(`delete:${key}:${options.bypassGovernance ? 'bypass' : 'plain'}`);
    const l = this.objects.get(`${bucket}\0${key}`) ?? [];
    const i = l.findIndex((v) => v.versionId === versionId);
    if (i < 0) return 'missing';
    const v = l[i]!;
    if (v.lock && v.lock.until.getTime() > this.now().getTime()) {
      if (v.lock.mode === 'compliance' || !options.bypassGovernance) return 'locked';
    }
    l.splice(i, 1);
    return 'deleted';
  }

  async *listVersions(bucket: string, prefix: string): AsyncGenerator<ListedVersion> {
    for (const v of this.versions(bucket, prefix)) {
      yield {
        key: v.key,
        versionId: v.versionId,
        lastModified: v.lastModified,
        deleteMarker: false,
      };
    }
  }

  async putRetention(
    bucket: string,
    key: string,
    versionId: string | null,
    lock: ObjectLockSpec,
    options: { bypassGovernance?: boolean } = {},
  ): Promise<void> {
    this.calls.push(
      `retention:${key}:${lock.mode}:${options.bypassGovernance ? 'bypass' : 'plain'}`,
    );
    const v = this.find(bucket, key, versionId);
    if (!v)
      throw Object.assign(new Error('missing'), {
        name: 'NoSuchKey',
        $metadata: { httpStatusCode: 404 },
      });
    if (v.lock && lock.until.getTime() < v.lock.until.getTime())
      throw new Error('shortening refused');
    if (v.lock?.mode === 'governance' && lock.mode === 'compliance' && !options.bypassGovernance) {
      throw new Error('mode upgrade needs bypass');
    }
    v.lock = { ...lock };
  }

  async getRetention(
    bucket: string,
    key: string,
    versionId: string | null,
  ): Promise<{ mode: 'governance' | 'compliance'; until: Date } | null> {
    const v = this.find(bucket, key, versionId);
    return v?.lock ? { mode: v.lock.mode, until: v.lock.until } : null;
  }

  /** Typed as the real class for constructors that take one. */
  asStorage(): ArchiveStorage {
    return this as unknown as ArchiveStorage;
  }
}

/**
 * A minimal ZIP reader for the export verification (no new dependency): reads the central
 * directory and returns every entry's bytes (stored or deflated; ZIP64 not needed for the
 * suite's small packages). TEST-ONLY.
 */
export function readZip(zip: Buffer): Map<string, Buffer> {
  const EOCD = 0x06054b50;
  let eocd = -1;
  for (let i = zip.length - 22; i >= Math.max(0, zip.length - 65_557); i -= 1) {
    if (zip.readUInt32LE(i) === EOCD) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error('not a zip file');
  const entries = zip.readUInt16LE(eocd + 10);
  let offset = zip.readUInt32LE(eocd + 16);
  const out = new Map<string, Buffer>();
  for (let n = 0; n < entries; n += 1) {
    if (zip.readUInt32LE(offset) !== 0x02014b50) throw new Error('bad central directory');
    const method = zip.readUInt16LE(offset + 10);
    const compressed = zip.readUInt32LE(offset + 20);
    const nameLen = zip.readUInt16LE(offset + 28);
    const extraLen = zip.readUInt16LE(offset + 30);
    const commentLen = zip.readUInt16LE(offset + 32);
    const local = zip.readUInt32LE(offset + 42);
    const name = zip.subarray(offset + 46, offset + 46 + nameLen).toString('utf8');
    const lNameLen = zip.readUInt16LE(local + 26);
    const lExtraLen = zip.readUInt16LE(local + 28);
    const start = local + 30 + lNameLen + lExtraLen;
    const data = zip.subarray(start, start + compressed);
    out.set(name, method === 8 ? inflateRawSync(data) : Buffer.from(data));
    offset += 46 + nameLen + extraLen + commentLen;
  }
  return out;
}
