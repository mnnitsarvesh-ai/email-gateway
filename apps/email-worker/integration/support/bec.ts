import { randomUUID } from 'node:crypto';
import { type HandleOutcome, MetricsService, RedisService, uuidv7 } from '@email-gateway/common';
import type { Prisma, PrismaClient } from '@email-gateway/database';
import {
  type EventEnvelope,
  EventTypes,
  messageReceivedV1,
  messageScanStageReadyV1,
} from '@email-gateway/event-contracts';
import type { WorkerConfig } from '../../src/config';
import { createMimeIngestionService } from '../../src/mime-ingestion/mime-ingestion.module';
import { MimeMetrics } from '../../src/mime-ingestion/mime-metrics';
import { EngineAttemptFailedError, type ScanEngineAdapter } from '../../src/scanning/engine';
import { BecMetrics } from '../../src/scanning/engines/bec/bec-metrics';
import {
  becRegistration,
  type BecEngineOverrides,
  createBecEngine,
} from '../../src/scanning/engines/bec/registration';
import { rspamdRegistration } from '../../src/scanning/engines/rspamd/registration';
import { createUrlEngine, urlRegistration } from '../../src/scanning/engines/url/registration';
import type { ScanEngineRegistration } from '../../src/scanning/registry';
import type { ScanTriggerPayload } from '../../src/scanning/round-service';
import { ScanMetrics } from '../../src/scanning/scan-metrics';
import { createRoundService, createScanInfrastructure } from '../../src/scanning/scanning.module';
import { requireEnv, silentLogger, workerConfig } from './fixtures';
import type { ScanFixtures, ScanMessage } from './scan';
import { urlOnly } from './urls';

/** A message envelope of a bec suite (the trusted envelope Rspamd evaluates). */
export interface BecEnvelope {
  direction?: 'inbound' | 'outbound' | 'internal';
  ip?: string;
  helo?: string;
  hostname?: string;
  from?: string;
  rcpt?: string[];
}

/** Rows of one message the bec suites assert on. */
export interface BecState {
  scans: Prisma.EmailScanGetPayload<object>[];
  finals: Prisma.ScanEngineResultGetPayload<object>[];
  attempts: Prisma.ScanEngineResultGetPayload<object>[];
  auth: Prisma.EmailAuthResultGetPayload<object>[];
  bec: Prisma.BecScanResultGetPayload<object>[];
  stageEvents: Prisma.MessageOutboxGetPayload<object>[];
  message: { status: string; lifecycleRound: number };
}

/**
 * Per-run BEC fixtures (step 4.4 §9 package integration) on top of the scan fixtures: messages
 * parsed by the real MIME stage with a chosen trusted envelope, tenant data (active domains,
 * executive/vendor profiles, trusted senders, suppressions as the api's repositories write them),
 * `bec` and `url` scan settings, and the cleanup of every BEC row and LLM budget key of the run.
 */
export class BecFixtures {
  readonly redis = new RedisService({ url: requireEnv('REDIS_URL') });
  private readonly mimeConsumer: string;

  constructor(readonly fx: ScanFixtures) {
    this.mimeConsumer = fx.consumer('bec-mime');
  }

  get prisma(): PrismaClient {
    return this.fx.prisma;
  }

  /** A persisted message (the envelope as smtp-adapter writes it) parsed by the MIME stage. */
  async message(
    organizationId: bigint,
    eml: string | Buffer,
    envelope: BecEnvelope = {},
  ): Promise<ScanMessage> {
    const message = await this.fx.message(organizationId, { eml: Buffer.from(eml), envelope });
    const mime = createMimeIngestionService({
      config: workerConfig({ SCAN_ENGINES: 'rspamd' }),
      prisma: this.prisma,
      s3: this.fx.s3,
      metrics: new MimeMetrics(
        new MetricsService({ service: `it-bec-mime-${randomUUID().slice(0, 6)}` }),
      ),
      logger: silentLogger,
      consumer: this.mimeConsumer,
    });
    const outcome = await mime.handle({
      eventId: uuidv7(),
      eventType: EventTypes.MessageReceived,
      occurredAt: new Date().toISOString(),
      correlationId: `it-bec-${this.fx.suffix}-received`,
      organizationId: organizationId.toString(),
      payload: messageReceivedV1.parse({
        messageId: message.messageId.toString(),
        receivedAt: message.receivedAt.toISOString(),
        direction: message.direction,
        emlS3Key: message.emlObjectKey,
        sizeBytes: message.sizeBytes,
        envelopeFrom: envelope.from ?? 'alice@clean.scan.test',
        recipientCount: (envelope.rcpt ?? ['bob@customer.scan.test']).length,
      }),
    });
    if (outcome !== 'handled') throw new Error(`MIME stage did not handle the message: ${outcome}`);
    return message;
  }

  async domain(organizationId: bigint, name: string): Promise<void> {
    await this.prisma.domain.create({
      data: { organizationId, name, status: 'active', activatedAt: new Date() },
    });
  }

  async executive(
    organizationId: bigint,
    displayName: string,
    knownAddresses: string[] = [],
  ): Promise<string> {
    const publicId = uuidv7();
    await this.prisma.becExecutiveProfile.create({
      data: {
        publicId,
        organizationId,
        displayName,
        normalizedName: displayName.toLowerCase(),
        aliases: [],
        knownAddresses,
      },
    });
    return publicId;
  }

  async trustedSender(
    organizationId: bigint,
    kind: 'address' | 'domain',
    value: string,
  ): Promise<void> {
    await this.prisma.becTrustedSender.create({
      data: { publicId: uuidv7(), organizationId, kind, value, reason: 'it-bec trusted sender' },
    });
  }

  /** A suppression row as the api writes it from a false-positive feedback (B11). */
  async suppression(
    organizationId: bigint,
    reasonCode: string,
    senderScope: 'address' | 'domain',
    senderValue: string,
  ): Promise<void> {
    await this.prisma.becSuppressionRule.create({
      data: {
        publicId: uuidv7(),
        organizationId,
        reasonCode,
        senderScope,
        senderValue,
        expiresAt: new Date(Date.now() + 30 * 86_400_000),
      },
    });
  }

  async settings(organizationId: bigint, value: Record<string, unknown>): Promise<void> {
    const settings = value as Prisma.InputJsonObject;
    await this.prisma.scanEngineSetting.upsert({
      where: { organizationId_engine: { organizationId, engine: 'bec' } },
      create: { organizationId, engine: 'bec', settings },
      update: { settings, version: { increment: 1 } },
    });
  }

  async state(message: ScanMessage): Promise<BecState> {
    const where = { messageId: message.messageId, receivedAt: message.receivedAt };
    const [scans, results, auth, bec, stageEvents, row] = await Promise.all([
      this.prisma.emailScan.findMany({ where, orderBy: { lifecycleRound: 'asc' } }),
      this.prisma.scanEngineResult.findMany({
        where,
        orderBy: [{ scanId: 'asc' }, { engine: 'asc' }, { attempt: 'asc' }],
      }),
      this.prisma.emailAuthResult.findMany({ where, orderBy: { scanId: 'asc' } }),
      this.prisma.becScanResult.findMany({ where, orderBy: { scanId: 'asc' } }),
      this.prisma.messageOutbox.findMany({
        where: {
          organizationId: message.organizationId,
          aggregateId: message.messageId.toString(),
          eventType: EventTypes.MessageScanStageReady,
        },
        orderBy: { id: 'asc' },
      }),
      this.prisma.emailMessage.findFirstOrThrow({
        where: { id: message.messageId, receivedAt: message.receivedAt },
        select: { status: true, lifecycleRound: true },
      }),
    ]);
    return {
      scans,
      finals: results.filter((r) => r.isFinal),
      attempts: results.filter((r) => !r.isFinal),
      auth,
      bec,
      stageEvents,
      message: row,
    };
  }

  /** The `scan_stage_ready.v1` outbox rows of a message as the event-relay would publish them. */
  async stageEvents(message: ScanMessage): Promise<EventEnvelope<ScanTriggerPayload>[]> {
    const rows = await this.prisma.messageOutbox.findMany({
      where: {
        organizationId: message.organizationId,
        aggregateId: message.messageId.toString(),
        eventType: EventTypes.MessageScanStageReady,
      },
      orderBy: { id: 'asc' },
    });
    return rows.map((row) => ({
      eventId: row.eventId,
      eventType: EventTypes.MessageScanStageReady,
      occurredAt: row.createdAt.toISOString(),
      correlationId: row.correlationId,
      organizationId: row.organizationId.toString(),
      payload: messageScanStageReadyV1.parse(row.payload),
    }));
  }

  historyRows(organizationId: bigint) {
    return this.prisma.becContactHistory.findMany({
      where: { organizationId },
      orderBy: [{ scope: 'asc' }, { keyHash: 'asc' }],
    });
  }

  async cleanup(): Promise<void> {
    const ids = this.fx.organizationIds;
    try {
      if (ids.length > 0) {
        const where = { organizationId: { in: ids } };
        await this.prisma.becScanResult.deleteMany({ where });
        await this.prisma.becContactHistory.deleteMany({ where });
        await this.prisma.becSuppressionRule.deleteMany({ where });
        await this.prisma.becTrustedSender.deleteMany({ where });
        await this.prisma.becExecutiveProfile.deleteMany({ where });
        await this.prisma.becVendorProfile.deleteMany({ where });
        await this.prisma.becFeedback.deleteMany({ where });
        for (const id of ids) {
          let cursor = '0';
          do {
            const [next, keys] = await this.redis.client.scan(
              cursor,
              'MATCH',
              `eg:bec:llm:t:${id.toString()}:*`,
              'COUNT',
              100,
            );
            cursor = next;
            if (keys.length > 0) await this.redis.client.unlink(...keys);
          } while (cursor !== '0');
        }
      }
    } finally {
      await this.redis.onModuleDestroy();
    }
  }
}

interface EngineService {
  handle(event: EventEnvelope<ScanTriggerPayload>): Promise<HandleOutcome>;
}

/**
 * The three engines of a BEC round wired as ScanningModule wires them (registrations, round
 * services, shared settings resolver and S3 EML reads) on the suite's writer, MinIO and Redis:
 * the real Rspamd (`SCAN_RSPAMD_URL`), the url engine on dns-sink/url-test, and the bec engine
 * with `BEC_LLM_PROVIDER=fake`. Rounds require `rspamd,url,bec`. Called directly (no broker):
 * `deliver` retries retryable attempt failures as the consumer's hold retry does.
 */
export class BecPipeline {
  private constructor(
    readonly config: Readonly<WorkerConfig>,
    readonly registry: MetricsService,
    readonly metrics: ScanMetrics,
    readonly becMetrics: BecMetrics,
    private readonly services: Map<string, EngineService>,
    readonly consumers: Map<string, string>,
    readonly redis: RedisService,
  ) {}

  static start(
    fx: ScanFixtures,
    caFile: string,
    options: {
      overrides?: Record<string, string>;
      bec?: BecEngineOverrides;
      adapters?: Partial<Record<string, ScanEngineAdapter>>;
    } = {},
  ): BecPipeline {
    const config = workerConfig({
      ...urlOnly(caFile),
      SCAN_ENGINES: 'rspamd,url,bec',
      SCAN_CONSUMERS: '',
      SCAN_RSPAMD_MAX_ATTEMPTS: '2',
      SCAN_BEC_MAX_ATTEMPTS: '3',
      BEC_TENANT_DATA_CACHE_TTL_MS: '0',
      BEC_LLM_PROVIDER: 'fake',
      BEC_LLM_MODE: 'active',
      ...options.overrides,
    });
    const registry = new MetricsService({
      service: `email-worker-it-bec-${randomUUID().slice(0, 6)}`,
    });
    const metrics = new ScanMetrics(registry);
    const redis = new RedisService({ url: requireEnv('REDIS_URL') });
    const infra = createScanInfrastructure({
      config,
      prisma: fx.prisma,
      s3: fx.s3,
      metrics,
      logger: silentLogger,
      registry,
    });
    const deps = { prisma: fx.prisma, s3: fx.s3, redis, registry };
    const services = new Map<string, EngineService>();
    const consumers = new Map<string, string>();
    const registrations: ScanEngineRegistration[] = [
      rspamdRegistration,
      urlRegistration,
      becRegistration,
    ];
    for (const registration of registrations) {
      const name = registration.catalog.name;
      const consumer = fx.consumer(`${name}-${randomUUID().slice(0, 4)}`);
      const adapter =
        options.adapters?.[name] ??
        (name === 'url'
          ? createUrlEngine({ config, logger: silentLogger, metrics, ...deps })
          : name === 'bec'
            ? createBecEngine({ config, logger: silentLogger, metrics, ...deps }, options.bec ?? {})
            : undefined);
      const { service } = createRoundService({
        config,
        registration,
        ...infra,
        metrics,
        logger: silentLogger,
        consumer,
        deps,
        ...(adapter ? { adapter } : {}),
      });
      services.set(name, service);
      consumers.set(name, consumer);
    }
    return new BecPipeline(
      config,
      registry,
      metrics,
      BecMetrics.for(registry),
      services,
      consumers,
      redis,
    );
  }

  /** Handles the event on one engine, retrying a retryable attempt failure (hold retry). */
  async deliver(
    engine: 'rspamd' | 'url' | 'bec',
    event: EventEnvelope<ScanTriggerPayload>,
    maxTries = 10,
  ): Promise<HandleOutcome> {
    const service = this.services.get(engine)!;
    for (let i = 1; ; i += 1) {
      try {
        return await service.handle(event);
      } catch (error) {
        if (!(error instanceof EngineAttemptFailedError) || i >= maxTries) throw error;
      }
    }
  }

  /** The round service of one engine (the broker suite starts consumers on it). */
  service(engine: 'rspamd' | 'url' | 'bec'): EngineService {
    return this.services.get(engine)!;
  }

  /** One handling without retries (attempt failures surface). */
  handle(
    engine: 'rspamd' | 'url' | 'bec',
    event: EventEnvelope<ScanTriggerPayload>,
  ): Promise<HandleOutcome> {
    return this.services.get(engine)!.handle(event);
  }

  text(): Promise<string> {
    return this.registry.metrics();
  }

  async close(): Promise<void> {
    await this.redis.onModuleDestroy();
  }
}

/** A plain-text EML (CRLF) with the given headers and body. */
export function plainEml(headers: Record<string, string>, body: string): string {
  return [
    ...Object.entries(headers).map(([name, value]) => `${name}: ${value}`),
    `Message-ID: <it-bec-${randomUUID()}@bec.scan.test>`,
    'Date: Fri, 06 Nov 2026 10:00:00 +0000',
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: 8bit',
    '',
    body,
    '',
  ].join('\r\n');
}
