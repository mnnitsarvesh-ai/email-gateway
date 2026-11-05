import { PutObjectCommand } from '@aws-sdk/client-s3';
import { createHash, randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  AdvisoryLocks,
  type HandleOutcome,
  MetricsService,
  RedisService,
} from '@email-gateway/common';
import type { EventEnvelope } from '@email-gateway/event-contracts';
import type { Prisma, PrismaClient } from '@email-gateway/database';
import type { WorkerConfig } from '../../src/config';
import { EngineAttemptFailedError } from '../../src/scanning/engine';
import type { AttachmentEngine } from '../../src/scanning/engines/attachment/attachment.engine';
import type { ClamdScanner } from '../../src/scanning/engines/attachment/attachment.engine';
import type { ClamdVersionSource } from '../../src/scanning/engines/attachment/clamav-versions';
import { CACHE_PREFIX } from '../../src/scanning/engines/attachment/content-cache';
import {
  attachmentRegistration,
  createAttachmentEngine,
  createClamdClient,
  type InspectorOverrides,
} from '../../src/scanning/engines/attachment/registration';
import type { ScanTriggerPayload } from '../../src/scanning/round-service';
import { ScanMetrics } from '../../src/scanning/scan-metrics';
import {
  createEngineBreaker,
  createRoundService,
  createScanInfrastructure,
} from '../../src/scanning/scanning.module';
import { requireEnv, silentLogger, workerConfig } from './fixtures';
import { type ScanFixtures, type ScanMessage } from './scan';

export const sha256 = (bytes: Buffer): string => createHash('sha256').update(bytes).digest('hex');

export interface AttachmentSpec {
  bytes: Buffer;
  filename?: string | null;
  declaredContentType?: string | null;
  /** false: the part is not stored (`not_stored_size_limit`, object key NULL). */
  stored?: boolean;
  flags?: string[];
  /** Upload other bytes than the row says (integrity tests). */
  uploadBytes?: Buffer;
  /** Skip the upload (NoSuchKey). */
  upload?: boolean;
}

export interface ParseSpec {
  status?: 'parsed' | 'parsed_with_defects' | 'parse_limit_exceeded' | 'parse_failed';
  limitsExceeded?: string[];
}

export interface AttachmentMessage extends ScanMessage {
  attachments: Array<{ id: bigint; partIndex: number; sha256: string; objectKey: string | null }>;
}

/** Base overrides of every attachment suite: the attachment engine alone decides a round. */
export const ATTACHMENT_ONLY: Record<string, string> = {
  SCAN_ENGINES: 'attachment',
  SCAN_CONSUMERS: 'attachment',
  SCAN_SETTINGS_CACHE_TTL_MS: '0',
  SCAN_RETRY_BASE_MS: '100',
  SCAN_RETRY_MAX_MS: '200',
  SCAN_ATTACHMENT_TIMEOUT_MS: '120000',
  SCAN_ROUND_DEADLINE_SECONDS: '1800',
  ATTACHMENT_INSPECTOR_POOL_SIZE: '2',
  ATTACHMENT_SIGNATURE_RESCAN: 'rescan',
};

/**
 * The attachment rows of the scan fixtures (step 4.2 §9 package integration): parse rows,
 * `email_attachments` rows with their part objects in MinIO (org-prefixed keys as step 3.1
 * writes them), known-threat hashes, cache keys of the test files, and the cleanup of every row
 * the attachment engine, the watcher and the runner write for the run.
 */
export class AttachmentFixtures {
  readonly hashes = new Set<string>();
  readonly jobIds = new Set<bigint>();
  readonly signatureEngine: string;
  private readonly redis = new RedisService({ url: requireEnv('REDIS_URL') });

  constructor(readonly fx: ScanFixtures) {
    this.signatureEngine = `it-${fx.suffix}`;
  }

  get prisma(): PrismaClient {
    return this.fx.prisma;
  }

  /** A persisted message with its parse row and attachments (parts uploaded to MinIO). */
  async message(
    organizationId: bigint,
    attachments: AttachmentSpec[],
    parse: ParseSpec = {},
    at?: Date,
  ): Promise<AttachmentMessage> {
    const message = await this.fx.message(organizationId, {
      eml: Buffer.from('From: a@b.test\r\nSubject: it\r\n\r\nbody\r\n'),
      ...(at ? { receivedAt: at } : {}),
    });
    const { messageId, receivedAt } = message;
    await this.prisma.emailMessageParse.create({
      data: {
        receivedAt,
        messageId,
        organizationId,
        status: parse.status ?? 'parsed',
        parserVersion: '1.0.0',
        limitsExceeded: parse.limitsExceeded ?? [],
        attachmentCount: attachments.length,
        startedAt: receivedAt,
        completedAt: receivedAt,
      },
    });
    const d = receivedAt;
    const date = `${d.getUTCFullYear()}/${String(d.getUTCMonth() + 1).padStart(2, '0')}/${String(d.getUTCDate()).padStart(2, '0')}`;
    const rows: AttachmentMessage['attachments'] = [];
    for (const [index, spec] of attachments.entries()) {
      const partIndex = index + 1;
      const stored = spec.stored !== false;
      const objectKey = stored
        ? `org/${organizationId.toString()}/part/${date}/${messageId.toString()}/${String(partIndex)}.att`
        : null;
      if (objectKey && spec.upload !== false) {
        await this.fx.s3.client.send(
          new PutObjectCommand({
            Bucket: this.fx.s3.mailBucket,
            Key: objectKey,
            Body: spec.uploadBytes ?? spec.bytes,
          }),
        );
      }
      const digest = sha256(spec.bytes);
      const row = await this.prisma.emailAttachment.create({
        data: {
          receivedAt,
          messageId,
          organizationId,
          partIndex,
          partPath: `1.${String(partIndex)}`,
          depth: 1,
          disposition: 'attachment',
          filename: spec.filename === undefined ? `file-${String(partIndex)}.bin` : spec.filename,
          declaredContentType:
            spec.declaredContentType === undefined
              ? 'application/octet-stream'
              : spec.declaredContentType,
          sizeBytes: spec.bytes.length,
          sha256: digest,
          objectKey,
          flags: spec.flags ?? (stored ? [] : ['not_stored_size_limit']),
        },
        select: { id: true },
      });
      rows.push({ id: row.id, partIndex, sha256: digest, objectKey });
    }
    return { ...message, attachments: rows };
  }

  /** Removes cached content results of these bytes (the cache is shared across runs). */
  async uncache(...files: Buffer[]): Promise<void> {
    for (const file of files) {
      const pattern = `${CACHE_PREFIX}${sha256(file)}:*`;
      let cursor = '0';
      do {
        const [next, keys] = await this.redis.client.scan(cursor, 'MATCH', pattern, 'COUNT', 100);
        cursor = next;
        if (keys.length > 0) await this.redis.client.unlink(...keys);
      } while (cursor !== '0');
    }
  }

  /** The raw value of a cache key (tests of the value authentication, A10). */
  rawCacheValue(key: string): Promise<string | null> {
    return this.redis.client.get(key);
  }

  /** Writes a raw value under a cache key, as any client of the shared Redis could. */
  async plantCacheValue(key: string, value: string): Promise<void> {
    await this.redis.client.set(key, value, 'EX', 300);
  }

  async cachedKeys(file: Buffer): Promise<string[]> {
    const found: string[] = [];
    let cursor = '0';
    do {
      const [next, keys] = await this.redis.client.scan(
        cursor,
        'MATCH',
        `${CACHE_PREFIX}${sha256(file)}:*`,
        'COUNT',
        1000,
      );
      cursor = next;
      found.push(...keys);
    } while (cursor !== '0');
    return found.sort();
  }

  async ttlOf(key: string): Promise<number> {
    return this.redis.client.ttl(key);
  }

  /** A known-threat hash as the api's threat-hash route writes it (A17). */
  async knownHash(
    bytes: Buffer,
    severity: 'low' | 'medium' | 'high' | 'critical',
  ): Promise<string> {
    const digest = sha256(bytes);
    const now = new Date();
    await this.prisma.malwareSignature.create({
      data: {
        sha256: digest,
        severity,
        family: 'IT.Test',
        source: 'analyst',
        reason: 'it',
        firstSeenAt: now,
        lastSeenAt: now,
      },
    });
    this.hashes.add(digest);
    return digest;
  }

  async removeHash(digest: string): Promise<void> {
    await this.prisma.malwareSignature.deleteMany({ where: { sha256: digest } });
  }

  async tenantSettings(organizationId: bigint, value: Record<string, unknown>): Promise<void> {
    const settings = value as Prisma.InputJsonObject;
    await this.prisma.scanEngineSetting.upsert({
      where: { organizationId_engine: { organizationId, engine: 'attachment' } },
      create: { organizationId, engine: 'attachment', settings },
      update: { settings, version: { increment: 1 } },
    });
  }

  results(message: ScanMessage) {
    return this.prisma.attachmentScanResult.findMany({
      where: { messageId: message.messageId, receivedAt: message.receivedAt },
      orderBy: [{ scanId: 'asc' }, { partIndex: 'asc' }],
    });
  }

  submissions(message: ScanMessage) {
    return this.prisma.sandboxSubmission.findMany({
      where: { messageId: message.messageId, receivedAt: message.receivedAt },
      orderBy: { partIndex: 'asc' },
    });
  }

  sandboxEvents(organizationId: bigint) {
    return this.prisma.messageOutbox.findMany({
      where: { organizationId, eventType: 'mail.attachment.sandbox_requested.v1' },
      orderBy: { id: 'asc' },
    });
  }

  async finalOf(message: ScanMessage, round = 0) {
    const scan = await this.prisma.emailScan.findFirstOrThrow({
      where: {
        messageId: message.messageId,
        receivedAt: message.receivedAt,
        lifecycleRound: round,
      },
    });
    const rows = await this.prisma.scanEngineResult.findMany({
      where: { scanId: scan.id, receivedAt: scan.receivedAt, engine: 'attachment' },
      orderBy: { attempt: 'asc' },
    });
    return { scan, rows, final: rows.find((r) => r.isFinal) ?? null };
  }

  async cleanup(): Promise<void> {
    const ids = this.fx.organizationIds;
    try {
      if (ids.length > 0) {
        const where = { organizationId: { in: ids } };
        await this.prisma.attachmentScanResult.deleteMany({ where });
        await this.prisma.sandboxSubmission.deleteMany({ where });
        await this.prisma.emailAttachment.deleteMany({ where });
        await this.prisma.emailMessageParse.deleteMany({ where });
        await this.prisma.attachmentRescanJob.deleteMany({ where });
      }
      if (this.jobIds.size > 0) {
        await this.prisma.attachmentRescanJob.deleteMany({
          where: { id: { in: [...this.jobIds] } },
        });
      }
      await this.prisma.attachmentRescanJob.deleteMany({
        where: { dedupeKey: { startsWith: `sig:clamav_db:it-${this.fx.suffix}` } },
      });
      await this.prisma.scanSignatureVersion.deleteMany({
        where: { engine: this.signatureEngine },
      });
      if (this.hashes.size > 0) {
        await this.prisma.malwareSignature.deleteMany({
          where: { sha256: { in: [...this.hashes] } },
        });
      }
    } finally {
      await this.redis.onModuleDestroy();
    }
  }
}

/** The real clamd client with an optional database version offset (simulated update). */
export function clamdWithOffset(
  config: Readonly<WorkerConfig>,
  offset: { db: number },
): ClamdScanner & ClamdVersionSource {
  const real = createClamdClient(config);
  return {
    ping: (signal) => real.ping(signal),
    version: async (signal) => {
      const v = await real.version(signal);
      return { ...v, dbVersion: v.dbVersion + offset.db };
    },
    scan: async (input, signal) => {
      const r = await real.scan(input, signal);
      return { ...r, dbVersion: r.dbVersion + offset.db };
    },
  };
}

export interface AttachmentPipelineOptions {
  overrides?: Record<string, string>;
  consumer?: string;
  inspector?: InspectorOverrides;
  clamd?: ClamdScanner & ClamdVersionSource;
  breakerNow?: () => number;
}

/**
 * The attachment engine wired as ScanningModule wires it (registration, round service, settings
 * resolver, writer store) against the real clamd, MinIO, Redis and MySQL writer, with its own
 * inspector pool (best-effort rlimits on the macOS host; a per-run private tmpdir). Deliveries
 * are handled in-process (`handle`), retrying `EngineAttemptFailedError` like the consumer.
 */
export class AttachmentPipeline {
  private constructor(
    readonly config: Readonly<WorkerConfig>,
    readonly registry: MetricsService,
    readonly metrics: ScanMetrics,
    readonly engine: AttachmentEngine,
    readonly service: ReturnType<typeof createRoundService>['service'],
    readonly breaker: ReturnType<typeof createRoundService>['breaker'],
    readonly consumer: string,
    private readonly redis: RedisService,
    private readonly tmp: string,
  ) {}

  static async start(
    fx: ScanFixtures,
    options: AttachmentPipelineOptions = {},
  ): Promise<AttachmentPipeline> {
    const config = workerConfig({ ...ATTACHMENT_ONLY, ...options.overrides });
    const registry = new MetricsService({ service: `email-worker-it-${randomUUID().slice(0, 6)}` });
    const metrics = new ScanMetrics(registry);
    const redis = new RedisService({ url: requireEnv('REDIS_URL') });
    const tmp = mkdtempSync(join(tmpdir(), 'eg-it-inspect-'));
    const consumer = options.consumer ?? fx.consumer(`attachment-${randomUUID().slice(0, 4)}`);
    const infra = createScanInfrastructure({
      config,
      prisma: fx.prisma,
      s3: fx.s3,
      metrics,
      logger: silentLogger,
    });
    const engine = createAttachmentEngine(
      { config, logger: silentLogger, prisma: fx.prisma, s3: fx.s3, redis, metrics, registry },
      {
        inspector: { tmpDir: tmp, ...options.inspector },
        ...(options.clamd ? { clamd: options.clamd } : {}),
      },
    );
    const breaker = options.breakerNow
      ? createEngineBreaker(config, 'attachment', metrics, silentLogger, options.breakerNow)
      : undefined;
    const { service, breaker: used } = createRoundService({
      config,
      registration: attachmentRegistration,
      ...infra,
      metrics,
      logger: silentLogger,
      deps: { prisma: fx.prisma, s3: fx.s3, redis, registry },
      adapter: engine,
      consumer,
      ...(breaker ? { breaker } : {}),
    });
    await engine.start();
    return new AttachmentPipeline(
      config,
      registry,
      metrics,
      engine,
      service,
      used,
      consumer,
      redis,
      tmp,
    );
  }

  /** One delivery (an attempt failure surfaces as EngineAttemptFailedError). */
  handleOnce(event: EventEnvelope<ScanTriggerPayload>): Promise<HandleOutcome> {
    return this.service.handle(event);
  }

  /** Redelivers until the engine finalized (the consumer's hold retries without the delay). */
  async handle(
    event: EventEnvelope<ScanTriggerPayload>,
    maxDeliveries = 12,
  ): Promise<{ outcome: HandleOutcome; attempts: number }> {
    for (let attempt = 1; ; attempt += 1) {
      try {
        return { outcome: await this.service.handle(event), attempts: attempt };
      } catch (error) {
        if (!(error instanceof EngineAttemptFailedError) || attempt >= maxDeliveries) throw error;
      }
    }
  }

  text(): Promise<string> {
    return this.registry.metrics();
  }

  async counter(name: string, labels: Record<string, string>): Promise<number> {
    const text = await this.text();
    const wanted = Object.entries(labels).map(([k, v]) => `${k}="${v}"`);
    for (const line of text.split('\n')) {
      if (!line.startsWith(`${name}{`)) continue;
      if (wanted.every((w) => line.includes(w)))
        return Number(line.slice(line.lastIndexOf(' ') + 1));
    }
    return 0;
  }

  async stop(): Promise<void> {
    await this.engine.stop();
    await this.redis.onModuleDestroy();
    rmSync(this.tmp, { recursive: true, force: true });
  }
}

/** A per-run advisory lock connection (leader locks of the watcher and the runner). */
export const testLocks = (): AdvisoryLocks => new AdvisoryLocks(requireEnv('DATABASE_URL'));
