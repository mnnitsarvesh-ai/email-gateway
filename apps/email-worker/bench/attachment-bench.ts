/**
 * Attachment engine benchmark (step 4.2 A20, docs/performance/attachment-scanning.md).
 *
 *   pnpm --filter @email-gateway/email-worker bench:attachments -- [--duration=10]
 *     [--concurrency=4] [--sizes=10k,100k,1m,5m,25m] [--kinds=plain,zip,nested3,gzip]
 *     [--cache=off,on] [--pool=2] [--child=dist|src]
 *
 * Drives the real components: the AttachmentEngine adapter (verdict mapping, byte budget, cache,
 * metrics) with the real InspectorPool (YARA-X children; the compiled `dist` child under Node's
 * permission model when built, else the TypeScript source through tsx) and the real ClamdClient
 * against the local clamd (CLAMAV_HOST/CLAMAV_PORT of .env), and, with `--cache=on`, the real
 * Redis content cache (REDIS_URL). Part reads and the MySQL catalog lookups are in-memory fakes
 * (S3 and MySQL are not what this measures). Every size class and kind runs for a fixed duration
 * at a fixed concurrency (messages of one attachment each); cache-off runs use a fresh file per
 * call (no hits), cache-on runs repeat one file per worker (hits after the first). Prints one
 * JSON line per run: attachments/sec, MiB/s and p50/p95 per stage (ms). Built without Nest DI
 * (tsx emits no decorator metadata).
 */
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import * as corpus from '@email-gateway/attachment-corpus';
import { ClamdClient } from '@email-gateway/clamav';
import { MetricsService, RedisService } from '@email-gateway/common';
import { createLogger } from '@email-gateway/logger';
import {
  ATTACHMENT_PLATFORM_DEFAULTS,
  resolveAttachmentSettings,
} from '@email-gateway/security-contracts';
import type { EngineScanContext } from '../src/scanning/engine';
import {
  AttachmentEngine,
  type Inspector,
} from '../src/scanning/engines/attachment/attachment.engine';
import { AttachmentMetrics } from '../src/scanning/engines/attachment/attachment-metrics';
import type {
  AttachmentRow,
  AttachmentStore,
} from '../src/scanning/engines/attachment/attachment-store';
import { ByteBudget } from '../src/scanning/engines/attachment/byte-budget';
import { ClamavVersionProvider } from '../src/scanning/engines/attachment/clamav-versions';
import type { InspectLimits } from '../src/scanning/engines/attachment/content';
import { CACHE_PREFIX, ContentCache } from '../src/scanning/engines/attachment/content-cache';
import { BUNDLED_RULES_DIR, bundleIdOf } from '../src/scanning/engines/attachment/inspector/bundle';
import { InspectorPool } from '../src/scanning/engines/attachment/inspector/pool';
import type { PartSource } from '../src/scanning/engines/attachment/part-reader';

const envFile = resolve(__dirname, '../../../.env');
if (existsSync(envFile)) process.loadEnvFile(envFile);

const KiB = 1024;
const MiB = 1024 * 1024;
const SIZES: Record<string, number> = {
  '10k': 10 * KiB,
  '100k': 100 * KiB,
  '1m': MiB,
  '5m': 5 * MiB,
  '25m': 25 * MiB,
};
type Kind = 'plain' | 'zip' | 'nested3' | 'gzip';

function arg(name: string, fallback: string): string {
  const hit = process.argv.find((a) => a.startsWith(`--${name}=`));
  return hit ? hit.slice(name.length + 3) : fallback;
}

const LIMITS: InspectLimits = {
  archiveMaxDepth: 3,
  archiveMaxEntries: 1000,
  maxEntryBytes: 26_214_400,
  maxDecompressedBytes: 104_857_600,
  maxCompressionRatio: 100,
  maxEntryFindings: 20,
  yaraTimeoutMs: 10_000,
  cpuSeconds: 10,
  maxRssMb: 384,
};

let seed = 1;
/** A file of the kind whose total size stays at or below `size` (≤ ATTACHMENT_MAX_BYTES). */
async function file(kind: Kind, size: number): Promise<Buffer> {
  seed += 1;
  // Archive overhead is small; keep the payload a little below the class size.
  const payload = kind === 'plain' ? size : Math.max(1024, size - 16 * KiB);
  const data = corpus.pdfLike(payload, seed);
  switch (kind) {
    case 'plain':
      return data;
    case 'zip':
      return corpus.zip([{ name: 'report.pdf', data, compress: true }]);
    case 'nested3':
      return corpus.nestedZip(3, { name: 'report.pdf', data });
    case 'gzip':
      return corpus.gzip(data);
  }
}

const sha = (b: Buffer) => createHash('sha256').update(b).digest('hex');

/**
 * A distinct but still valid file (cache-off runs: neither our cache nor clamd's internal
 * clean-file cache may hit): a PDF gets 8 bytes of its filler replaced, a gzip one more member,
 * a zip an 8-byte archive comment in its end record.
 */
function uniquify(kind: Kind, bytes: Buffer, tag: Buffer): Buffer {
  if (kind === 'gzip') return Buffer.concat([bytes, corpus.gzip(tag)]);
  const copy = Buffer.from(bytes);
  if (kind === 'plain') {
    tag.copy(copy, Math.floor(copy.length / 2));
    return copy;
  }
  // yazl writes no comment: the end record's comment length is the last two bytes.
  copy.writeUInt16LE(tag.length, copy.length - 2);
  return Buffer.concat([copy, tag]);
}

class MemoryParts implements PartSource {
  readonly objects = new Map<string, Buffer>();
  read(key: string): Promise<{ kind: 'ok'; bytes: Buffer } | { kind: 'missing' }> {
    const bytes = this.objects.get(key);
    return Promise.resolve(bytes ? { kind: 'ok', bytes } : { kind: 'missing' });
  }
}

class MemoryStore implements AttachmentStore {
  readonly rows = new Map<bigint, AttachmentRow[]>();
  loadParse(messageId: bigint) {
    return Promise.resolve({
      status: 'parsed',
      limitsExceeded: [],
      attachmentCount: this.rows.get(messageId)?.length ?? 0,
    });
  }
  loadAttachments(messageId: bigint) {
    return Promise.resolve(this.rows.get(messageId) ?? []);
  }
  knownHashes() {
    return Promise.resolve(new Map());
  }
}

/** Raw per-stage durations (the engine's histograms keep buckets only). */
class Timings {
  readonly stages = new Map<string, number[]>();
  add(stage: string, ms: number) {
    const list = this.stages.get(stage) ?? [];
    list.push(ms);
    this.stages.set(stage, list);
  }
  quantiles(): Record<string, { p50: number; p95: number; n: number }> {
    const out: Record<string, { p50: number; p95: number; n: number }> = {};
    for (const [stage, values] of this.stages) {
      const sorted = [...values].sort((a, b) => a - b);
      const q = (p: number) =>
        sorted[Math.min(sorted.length - 1, Math.floor(p * sorted.length))] ?? 0;
      out[stage] = {
        p50: Math.round(q(0.5) * 10) / 10,
        p95: Math.round(q(0.95) * 10) / 10,
        n: sorted.length,
      };
    }
    return out;
  }
}

async function main(): Promise<void> {
  const duration = Number(arg('duration', '10')) * 1000;
  const concurrency = Number(arg('concurrency', '4'));
  const sizes = arg('sizes', '10k,100k,1m,5m,25m').split(',');
  const kinds = arg('kinds', 'plain,zip,nested3,gzip').split(',') as Kind[];
  const caches = arg('cache', 'off,on').split(',');
  const poolSize = Number(arg('pool', '2'));
  const distChild = resolve(__dirname, '../dist/scanning/engines/attachment/inspector/child.js');
  const child = arg('child', existsSync(distChild) ? 'dist' : 'src');
  const logger = createLogger({ service: 'attachment-bench', level: 'warn' });
  const clamd = new ClamdClient({
    host: process.env.CLAMAV_HOST ?? '127.0.0.1',
    port: Number(process.env.CLAMAV_PORT ?? 3310),
    timeoutMs: 60_000,
    maxConnections: Number(process.env.CLAMAV_MAX_CONNECTIONS ?? 4),
  });
  const tmp = mkdtempSync(join(tmpdir(), 'eg-bench-'));
  const timings = new Timings();
  const pool = new InspectorPool({
    size: poolSize,
    maxJobs: 500,
    heapMb: 192,
    rlimits: process.platform === 'linux' ? 'required' : 'best_effort',
    tmpDir: tmp,
    wallTimeoutMs: 30_000,
    cpuSeconds: 10,
    maxRssMb: 384,
    rulesDir: BUNDLED_RULES_DIR,
    yaraTimeoutMs: 10_000,
    expectedBundleId: bundleIdOf(BUNDLED_RULES_DIR).bundleId,
    selftest: false,
    nodeEnv: 'production',
    maxWaiting: 64,
    logger,
    ...(child === 'dist' ? { childEntry: distChild } : {}),
  });
  const inspector: Inspector = {
    start: () => pool.start(),
    stop: () => pool.stop(),
    get readyCount() {
      return pool.readyCount;
    },
    get rlimitMode() {
      return pool.rlimitMode;
    },
    inspect: async (bytes, limits, signal) => {
      const t = performance.now();
      const outcome = await pool.inspect(bytes, limits, signal);
      timings.add('inspect', performance.now() - t);
      return outcome;
    },
  };
  const timedClamd = {
    ping: (signal?: AbortSignal) => clamd.ping(signal),
    version: (signal?: AbortSignal) => clamd.version(signal),
    scan: async (input: Uint8Array, signal?: AbortSignal) => {
      const t = performance.now();
      const result = await clamd.scan(input, signal);
      timings.add('clamav', performance.now() - t);
      return result;
    },
  };
  const redis = caches.includes('on')
    ? new RedisService({ url: process.env.REDIS_URL ?? 'redis://127.0.0.1:6379' })
    : null;
  const settings = (() => {
    const r = resolveAttachmentSettings(ATTACHMENT_PLATFORM_DEFAULTS, null);
    if (!r.ok) throw new Error('platform defaults invalid');
    return r.settings;
  })();
  const bundle = bundleIdOf(BUNDLED_RULES_DIR);
  await pool.start();
  const version = await clamd.version();
  process.stderr.write(
    `bench: clamd ${version.engine}/${String(version.dbVersion)}, pool ${String(poolSize)} (${child}, rlimits ${pool.rlimitMode}, permission model ${String(pool.permissionModel)}), concurrency ${String(concurrency)}, ${String(duration / 1000)} s per run\n`,
  );
  try {
    for (const cacheMode of caches) {
      for (const sizeName of sizes) {
        for (const kind of kinds) {
          const size = SIZES[sizeName];
          if (!size) throw new Error(`unknown size ${sizeName}`);
          const store = new MemoryStore();
          const parts = new MemoryParts();
          const registry = new MetricsService({ service: `bench-${randomUUID().slice(0, 6)}` });
          const engine = new AttachmentEngine({
            store,
            parts,
            clamd: timedClamd,
            versions: new ClamavVersionProvider(timedClamd, 300_000),
            inspector,
            cache:
              cacheMode === 'on' && redis
                ? new ContentCache(
                    redis.client,
                    { cleanSeconds: 600, maliciousSeconds: 600, otherSeconds: 600 },
                    200,
                    randomBytes(24).toString('hex'),
                  )
                : null,
            budget: new ByteBudget(134_217_728),
            metrics: AttachmentMetrics.for(registry),
            logger,
            bundleId: bundle.bundleId,
            yaraXVersion: bundle.yaraX,
            limits: LIMITS,
            maxPerMessage: 100,
            parallelism: 2,
            sandbox: { enabled: true, maxPerMessage: 5 },
            poolSize,
          });
          timings.stages.clear();
          // Pre-generate distinct files (cache off: a fresh file per call, recycled after use).
          const files = await Promise.all(
            Array.from({ length: concurrency * 2 }, () => file(kind, size)),
          );
          let next = 0n;
          let count = 0;
          let bytes = 0;
          const verdicts = new Map<string, number>();
          const deadline = performance.now() + duration;
          const worker = async (w: number) => {
            while (performance.now() < deadline) {
              const bytesOf = cacheMode === 'on' ? files[w]! : files[(count + w) % files.length]!;
              const unique =
                cacheMode === 'on'
                  ? bytesOf
                  : uniquify(
                      kind,
                      bytesOf,
                      Buffer.from(randomUUID().replace(/-/g, '').slice(0, 8), 'latin1'),
                    );
              const messageId = ++next;
              const key = `org/1/part/2026/11/05/${messageId.toString()}/1.att`;
              parts.objects.set(key, unique);
              store.rows.set(messageId, [
                {
                  id: messageId,
                  partIndex: 1,
                  filename: kind === 'plain' ? 'r.pdf' : 'r.zip',
                  declaredContentType: null,
                  sizeBytes: unique.length,
                  sha256: sha(unique),
                  objectKey: key,
                  flags: [],
                },
              ]);
              const ctx: EngineScanContext = {
                organizationId: 1n,
                messageId,
                receivedAt: new Date(),
                round: 0,
                direction: 'inbound',
                envelope: {
                  clientIp: null,
                  clientHelo: null,
                  clientName: null,
                  envelopeFrom: 'b@b.test',
                  recipients: [],
                  queueId: null,
                },
                eml: {
                  key: 'org/1/eml/x',
                  sizeBytes: 0,
                  open: () => Promise.reject(new Error('unused')),
                },
                settings,
                settingsVersion: 'attachment-map/1;p=000000000000;t=none',
              };
              const t = performance.now();
              const outcome = await engine.scan(ctx, AbortSignal.timeout(180_000));
              timings.add('total', performance.now() - t);
              parts.objects.delete(key);
              store.rows.delete(messageId);
              const label =
                outcome.kind === 'definite'
                  ? outcome.result.outcome
                  : `failure:${outcome.errorCode}`;
              verdicts.set(label, (verdicts.get(label) ?? 0) + 1);
              count += 1;
              bytes += unique.length;
            }
          };
          const started = performance.now();
          await Promise.all(Array.from({ length: concurrency }, (_, w) => worker(w)));
          const seconds = (performance.now() - started) / 1000;
          if (redis && cacheMode === 'on') {
            for (const f of files) {
              const [, keys] = await redis.client.scan(
                '0',
                'MATCH',
                `${CACHE_PREFIX}${sha(f)}:*`,
                'COUNT',
                1000,
              );
              if (keys.length > 0) await redis.client.unlink(...keys);
            }
          }
          process.stdout.write(
            `${JSON.stringify({
              size: sizeName,
              kind,
              cache: cacheMode,
              concurrency,
              attachments: count,
              seconds: Math.round(seconds * 100) / 100,
              attachmentsPerSec: Math.round((count / seconds) * 100) / 100,
              mibPerSec: Math.round((bytes / MiB / seconds) * 100) / 100,
              verdicts: Object.fromEntries(verdicts),
              stagesMs: timings.quantiles(),
            })}\n`,
          );
        }
      }
    }
  } finally {
    await pool.stop();
    await redis?.onModuleDestroy();
    rmSync(tmp, { recursive: true, force: true });
  }
}

void main().catch((error: unknown) => {
  process.stderr.write(`bench failed: ${(error as Error).message}\n`);
  process.exit(1);
});
