import { DeleteObjectCommand, ListObjectsV2Command, PutObjectCommand } from '@aws-sdk/client-s3';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer, type Server, type Socket } from 'node:net';
import { resolve } from 'node:path';
import {
  AdvisoryLocks,
  AmqpConnection,
  ConfirmPublisher,
  createMessagingMetrics,
  type HandleOutcome,
  MetricsService,
  type QueueConsumer,
  RedisService,
  S3Service,
  uuidv7,
} from '@email-gateway/common';
import {
  type EmailAuthResult,
  type EmailMessageStatusHistory,
  type EmailScan,
  type MessageDirection,
  type MessageOutbox,
  type Prisma,
  PrismaClient,
  type ScanEngineResult,
} from '@email-gateway/database';
import {
  type EventEnvelope,
  EventTypes,
  messageParsedV1,
  messageRescanRequestedV1,
} from '@email-gateway/event-contracts';
import { transitionMessageWithRetry } from '@email-gateway/message-lifecycle';
import { RspamdClient } from '@email-gateway/rspamd';
import type { WorkerConfig } from '../../src/config';
import type { CircuitBreaker } from '../../src/scanning/circuit-breaker';
import { DeadlineSweeper } from '../../src/scanning/deadline-sweeper';
import { createEngineConsumer } from '../../src/scanning/engine-consumer';
import { rspamdRegistration } from '../../src/scanning/engines/rspamd/registration';
import { createRiskScorer } from '../../src/scanning/risk/risk-scorer';
import type { ScanTriggerPayload } from '../../src/scanning/round-service';
import { ScanMetrics } from '../../src/scanning/scan-metrics';
import { ScanRepository } from '../../src/scanning/scan-repository';
import {
  createEngineBreaker,
  createRoundService,
  createScanInfrastructure,
} from '../../src/scanning/scanning.module';
import { createTestVhost, eventually, type TestVhost } from './broker';
import { requireEnv, s3Config, silentLogger, workerConfig } from './fixtures';

const REPO_ROOT = resolve(__dirname, '../../../..');
export const CORPUS_DIR = resolve(REPO_ROOT, 'tests/fixtures/scan-corpus');

export interface CorpusFixture {
  file: string;
  class: string;
  description: string;
  envelope: {
    direction: 'inbound' | 'outbound' | 'internal';
    ip: string;
    helo: string;
    hostname: string;
    from: string;
    rcpt: string[];
  };
  expect: {
    verdict: string;
    reasonCodes: string[];
    /** Reason codes the mapping must not give (e.g. the ARC trust code for an untrusted sealer). */
    absentReasonCodes?: string[];
    symbols: string[];
    absentSymbols?: string[];
    auth?: Record<string, Record<string, unknown>>;
    scoreRange: [number, number];
  };
}

/** `tests/fixtures/scan-corpus/manifest.json` (WP2). */
export function loadCorpus(): CorpusFixture[] {
  const manifest = JSON.parse(readFileSync(resolve(CORPUS_DIR, 'manifest.json'), 'utf8')) as {
    fixtures: CorpusFixture[];
  };
  return manifest.fixtures;
}

export const corpusEml = (fixture: CorpusFixture): Buffer =>
  readFileSync(resolve(CORPUS_DIR, fixture.file));

export interface ScanMessage {
  messageId: bigint;
  receivedAt: Date;
  organizationId: bigint;
  direction: MessageDirection;
  emlObjectKey: string;
  sizeBytes: number;
}

export interface ScanMessageOptions {
  eml: Buffer;
  envelope?: Partial<CorpusFixture['envelope']>;
  upload?: boolean;
  emlObjectKey?: string;
  /** Default now; an older value models a message received days ago (e.g. a late rescan). */
  receivedAt?: Date;
}

export interface ScanState {
  message: { status: string; lifecycleRound: number; version: number };
  scans: EmailScan[];
  results: ScanEngineResult[];
  auth: EmailAuthResult[];
  history: EmailMessageStatusHistory[];
  scanned: MessageOutbox[];
}

/**
 * Per-run fixtures of the scan suites in `it-scan-<suffix>-*` organizations on the real MySQL
 * writer and MinIO: messages as smtp-adapter commits them (`persisted`, version 1, the trusted
 * envelope, recipients by `rcpt_seq`), trigger envelopes, and cleanup of every row the scan
 * stage writes (rounds, results, auth rows, settings, history, outbox, ledger).
 */
export class ScanFixtures {
  readonly prisma: PrismaClient = new PrismaClient({ datasourceUrl: requireEnv('DATABASE_URL') });
  readonly s3 = new S3Service(s3Config());
  readonly suffix = randomUUID().slice(0, 8);
  readonly organizationIds: bigint[] = [];
  private readonly consumers = new Set<string>();
  private readonly eventIds = new Set<string>();
  private planId: bigint | undefined;

  consumer(label: string): string {
    const name = `it-scan-${this.suffix}.${label}`;
    this.consumers.add(name);
    return name;
  }

  async organization(label: string): Promise<bigint> {
    if (this.planId === undefined) {
      const plan = await this.prisma.organizationPlan.create({
        data: {
          code: `it-scan-${this.suffix}`,
          name: 'email-worker scan integration',
          defaultLimits: {},
          defaultFeatures: {},
        },
      });
      this.planId = plan.id;
    }
    const org = await this.prisma.organization.create({
      data: {
        slug: `it-scan-${this.suffix}-${label}`,
        name: `Scan ${label}`,
        planId: this.planId,
        dataRegion: 'ap-south-1',
        status: 'active',
      },
    });
    this.organizationIds.push(org.id);
    return org.id;
  }

  async message(organizationId: bigint, options: ScanMessageOptions): Promise<ScanMessage> {
    const d = new Date();
    const date = `${d.getUTCFullYear()}/${String(d.getUTCMonth() + 1).padStart(2, '0')}/${String(d.getUTCDate()).padStart(2, '0')}`;
    const emlObjectKey =
      options.emlObjectKey ?? `org/${organizationId.toString()}/eml/${date}/it-${randomUUID()}.eml`;
    if (options.upload !== false) {
      await this.s3.client.send(
        new PutObjectCommand({ Bucket: this.s3.mailBucket, Key: emlObjectKey, Body: options.eml }),
      );
    }
    const envelope = {
      direction: 'inbound' as const,
      ip: '192.0.2.10',
      helo: 'mx.clean.scan.test',
      hostname: 'mx.clean.scan.test',
      from: 'alice@clean.scan.test',
      rcpt: ['bob@customer.scan.test'],
      ...options.envelope,
    };
    const receivedAt = options.receivedAt ?? new Date();
    const identity = await this.prisma.messageIdentity.create({
      data: { organizationId, ingestKey: `it-scan-${randomUUID()}`, receivedAt },
      select: { id: true },
    });
    const messageId = identity.id;
    await this.prisma.emailMessage.create({
      data: {
        id: messageId,
        receivedAt,
        organizationId,
        direction: envelope.direction,
        // As the SMTP commit creates it (step 3.3 L2): persisted, version 1, round 0.
        status: 'persisted',
        version: 1,
        lifecycleRound: 0,
        statusReason: 'committed',
        statusChangedAt: receivedAt,
        envelopeFrom: envelope.from,
        headerFrom: envelope.from,
        subject: 'it-scan',
        sizeBytes: options.eml.length,
        recipientCount: envelope.rcpt.length,
        emlObjectKey,
        emlSha256: createHash('sha256').update(options.eml).digest('hex'),
        clientIp: envelope.ip,
        clientHelo: envelope.helo,
        clientName: envelope.hostname,
        mtaQueueId: `IT${randomBytes(5).toString('hex').toUpperCase()}`,
      },
    });
    for (const [rcptSeq, address] of envelope.rcpt.entries()) {
      await this.prisma.emailRecipient.create({
        data: {
          receivedAt,
          messageId,
          organizationId,
          rcptSeq,
          address,
          direction: envelope.direction,
          // Never `pending`: a live delivery-worker must not plan deliveries for fixtures.
          status: 'discarded',
        },
      });
    }
    return {
      messageId,
      receivedAt,
      organizationId,
      direction: envelope.direction,
      emlObjectKey,
      sizeBytes: options.eml.length,
    };
  }

  /** A `mail.message.parsed.v1` envelope as the MIME stage writes it (tracked for cleanup). */
  parsed(message: ScanMessage, eventId: string = uuidv7()): EventEnvelope<ScanTriggerPayload> {
    this.eventIds.add(eventId);
    return {
      eventId,
      eventType: EventTypes.MessageParsed,
      occurredAt: new Date().toISOString(),
      correlationId: `it-scan-${this.suffix}-parsed`,
      organizationId: message.organizationId.toString(),
      payload: messageParsedV1.parse({
        messageId: message.messageId.toString(),
        receivedAt: message.receivedAt.toISOString(),
        direction: message.direction,
        emlS3Key: message.emlObjectKey,
        parseStatus: 'parsed',
        parserVersion: '1.0.0',
        limitsExceeded: [],
        defects: [],
        textBody: null,
        htmlBody: null,
        attachmentCount: 0,
        flaggedAttachmentCount: 0,
        attachmentFlags: [],
        partCount: 1,
        maxDepth: 0,
        headerCount: 8,
      }),
    };
  }

  /**
   * The api's administrative rescan (step 3.3 L10.2): E19 through the transition service, then
   * the `mail.message.rescan_requested.v1` envelope of the new round.
   */
  async rescan(message: ScanMessage): Promise<EventEnvelope<ScanTriggerPayload>> {
    const outcome = await transitionMessageWithRetry(
      this.prisma,
      {
        message: {
          id: message.messageId,
          receivedAt: message.receivedAt,
          organizationId: message.organizationId,
        },
        to: 'scanning',
        reason: 'admin_rescan',
        actor: { role: 'operator', service: 'api', type: 'user', id: 'it-scan' },
        transitionKey: `it-rescan:${message.messageId.toString()}:${randomUUID()}`,
      },
      { timeoutMs: 15_000 },
    );
    if (outcome.result !== 'applied') throw new Error(`rescan not applied: ${outcome.result}`);
    const eventId = uuidv7();
    this.eventIds.add(eventId);
    return {
      eventId,
      eventType: EventTypes.MessageRescanRequested,
      occurredAt: new Date().toISOString(),
      correlationId: `it-scan-${this.suffix}-rescan`,
      organizationId: message.organizationId.toString(),
      payload: messageRescanRequestedV1.parse({
        messageId: message.messageId.toString(),
        receivedAt: message.receivedAt.toISOString(),
        direction: message.direction,
        emlS3Key: message.emlObjectKey,
        lifecycleRound: outcome.round,
        scanKind: 'rescan',
        requestedAt: new Date().toISOString(),
        requestedBy: 'user',
      }),
    };
  }

  async settings(organizationId: bigint, value: Record<string, unknown>): Promise<void> {
    const settings = value as Prisma.InputJsonObject;
    await this.prisma.scanEngineSetting.upsert({
      where: { organizationId_engine: { organizationId, engine: 'rspamd' } },
      create: { organizationId, engine: 'rspamd', settings },
      update: { settings, version: { increment: 1 } },
    });
  }

  async state(message: ScanMessage): Promise<ScanState> {
    const where = { messageId: message.messageId, receivedAt: message.receivedAt };
    const [row, scans, results, auth, history, scanned] = await Promise.all([
      this.prisma.emailMessage.findFirstOrThrow({
        where: { id: message.messageId, receivedAt: message.receivedAt },
        select: { status: true, lifecycleRound: true, version: true },
      }),
      this.prisma.emailScan.findMany({ where, orderBy: { lifecycleRound: 'asc' } }),
      this.prisma.scanEngineResult.findMany({
        where,
        orderBy: [{ scanId: 'asc' }, { attempt: 'asc' }],
      }),
      this.prisma.emailAuthResult.findMany({ where, orderBy: { scanId: 'asc' } }),
      this.prisma.emailMessageStatusHistory.findMany({ where, orderBy: { version: 'asc' } }),
      this.prisma.messageOutbox.findMany({
        where: {
          organizationId: message.organizationId,
          aggregateId: message.messageId.toString(),
          eventType: EventTypes.MessageScanned,
        },
        orderBy: { id: 'asc' },
      }),
    ]);
    return { message: row, scans, results, auth, history, scanned };
  }

  ledgerRows(consumer: string, eventIds: string[]): Promise<number> {
    return this.prisma.messageIdempotency.count({ where: { consumer, eventId: { in: eventIds } } });
  }

  async cleanup(): Promise<void> {
    const ids = this.organizationIds;
    try {
      if (ids.length > 0) {
        const where = { organizationId: { in: ids } };
        await this.prisma.messageOutbox.deleteMany({ where });
        // Step 5.1: every completed round has risk rows; profiles before the organization (FK).
        await this.prisma.messageRiskScore.deleteMany({ where });
        await this.prisma.riskScoringProfileVersion.deleteMany({ where });
        await this.prisma.riskScoringProfile.deleteMany({ where });
        await this.prisma.emailAuthResult.deleteMany({ where });
        await this.prisma.scanEngineResult.deleteMany({ where });
        await this.prisma.emailScan.deleteMany({ where });
        await this.prisma.scanEngineSetting.deleteMany({ where });
        await this.prisma.emailMessageStatusHistory.deleteMany({ where });
        await this.prisma.emailEvent.deleteMany({ where });
        await this.prisma.emailRecipient.deleteMany({ where });
        await this.prisma.emailMessage.deleteMany({ where });
        await this.prisma.messageIdentity.deleteMany({ where });
        await this.prisma.organization.deleteMany({ where: { id: { in: ids } } });
      }
      if (this.eventIds.size > 0) {
        await this.prisma.messageIdempotency.deleteMany({
          where: { eventId: { in: [...this.eventIds] } },
        });
        await this.prisma.messageConsumerProgress
          .deleteMany({ where: { eventId: { in: [...this.eventIds] } } })
          .catch(() => undefined);
      }
      for (const consumer of this.consumers) {
        await this.prisma.messageIdempotency.deleteMany({ where: { consumer } });
      }
      if (this.planId !== undefined) {
        await this.prisma.organizationPlan.deleteMany({ where: { id: this.planId } });
      }
      for (const id of ids) await this.deletePrefix(`org/${id.toString()}/`);
    } finally {
      await this.prisma.$disconnect();
      this.s3.onModuleDestroy();
    }
  }

  private async deletePrefix(prefix: string): Promise<void> {
    let token: string | undefined;
    do {
      const page = await this.s3.client.send(
        new ListObjectsV2Command({
          Bucket: this.s3.mailBucket,
          Prefix: prefix,
          ContinuationToken: token,
        }),
      );
      for (const item of page.Contents ?? []) {
        if (item.Key) {
          await this.s3.client.send(
            new DeleteObjectCommand({ Bucket: this.s3.mailBucket, Key: item.Key }),
          );
        }
      }
      token = page.IsTruncated ? page.NextContinuationToken : undefined;
    } while (token);
  }
}

/** The broker side: a throwaway vhost with the full topology and a relay-like publisher. */
export class ScanBroker {
  private constructor(
    readonly vhost: TestVhost,
    private readonly connection: AmqpConnection,
    private readonly relay: ConfirmPublisher,
  ) {}

  static async start(): Promise<ScanBroker> {
    const vhost = await createTestVhost();
    const connection = new AmqpConnection({
      urls: [vhost.adminUrl],
      connectionName: 'it-event-relay',
      logger: silentLogger,
      reconnect: { baseMs: 50, maxMs: 500 },
    });
    connection.start();
    await connection.waitUntilConnected(15_000);
    const relay = new ConfirmPublisher({
      connection,
      logger: silentLogger,
      appId: 'event-relay',
      confirmTimeoutMs: 15_000,
      maxMessageBytes: 131_072,
    });
    return new ScanBroker(vhost, connection, relay);
  }

  /** Publishes as the event-relay does (registry exchange, `org.<id>.<type>`, confirmed). */
  async publish(events: EventEnvelope<ScanTriggerPayload>[]): Promise<void> {
    const results = await this.relay.publishBatch(events.map((envelope) => ({ envelope })));
    const failed = results.filter((r) => r.outcome !== 'confirmed');
    if (failed.length > 0)
      throw new Error(`publish not confirmed: ${failed.map((f) => f.outcome).join(',')}`);
  }

  async close(): Promise<void> {
    await this.relay.close();
    await this.connection.close();
    await this.vhost.cleanup();
  }
}

export interface ScanPipelineOptions {
  overrides?: Record<string, string>;
  consumer?: string;
  breakerNow?: () => number;
}

/**
 * The scan stage wired as ScanningModule wires it (registry registration, round service,
 * engine consumer, settings resolver, S3 EML reads, breaker) against the suite's vhost, with a
 * recorder of outcomes and failures per event id.
 */
export class ScanPipeline {
  private readonly outcomes = new Map<string, HandleOutcome[]>();
  private readonly failures = new Map<string, unknown[]>();

  private constructor(
    readonly config: Readonly<WorkerConfig>,
    readonly registry: MetricsService,
    readonly metrics: ScanMetrics,
    readonly breaker: CircuitBreaker,
    readonly consumerName: string,
    private readonly consumer: QueueConsumer<ScanTriggerPayload>,
    private readonly connection: AmqpConnection,
    private readonly publisher: ConfirmPublisher,
  ) {}

  static async start(
    fx: ScanFixtures,
    broker: ScanBroker,
    options: ScanPipelineOptions = {},
  ): Promise<ScanPipeline> {
    // The step 4.1 suites exercise the Rspamd engine and the generic orchestrator: rounds of
    // this pipeline require `rspamd` only (step 4.2: the attachment engine has its own suites,
    // attachment-*.test.ts; the stack suites run both).
    const config = workerConfig({
      SCAN_ENGINES: 'rspamd',
      SCAN_SETTINGS_CACHE_TTL_MS: '0',
      ...options.overrides,
    });
    const registry = new MetricsService({ service: `email-worker-it-${randomUUID().slice(0, 6)}` });
    const metrics = new ScanMetrics(registry);
    const messaging = createMessagingMetrics(registry);
    const consumerName = options.consumer ?? fx.consumer(`rspamd-${randomUUID().slice(0, 4)}`);
    const infra = createScanInfrastructure({
      config,
      prisma: fx.prisma,
      s3: fx.s3,
      metrics,
      logger: silentLogger,
    });
    const breaker = createEngineBreaker(
      config,
      'rspamd',
      metrics,
      silentLogger,
      options.breakerNow,
    );
    const { service } = createRoundService({
      config,
      registration: rspamdRegistration,
      ...infra,
      metrics,
      logger: silentLogger,
      breaker,
      consumer: consumerName,
      deps: { prisma: fx.prisma, s3: fx.s3, redis: null, registry },
    });
    const connection = new AmqpConnection({
      urls: [broker.vhost.adminUrl],
      connectionName: 'email-worker-scanner',
      logger: silentLogger,
      metrics: messaging,
      reconnect: { baseMs: 50, maxMs: 500 },
    });
    const publisher = new ConfirmPublisher({
      connection,
      logger: silentLogger,
      metrics: messaging,
      appId: 'email-worker',
      confirmTimeoutMs: 15_000,
      maxMessageBytes: 131_072,
    });
    const consumer = createEngineConsumer({
      config,
      registration: rspamdRegistration,
      connection,
      publisher,
      logger: silentLogger,
      metrics: messaging,
      consumer: consumerName,
    });
    const pipeline = new ScanPipeline(
      config,
      registry,
      metrics,
      breaker,
      consumerName,
      consumer,
      connection,
      publisher,
    );
    consumer.start(async (event) => {
      try {
        const outcome = await service.handle(event);
        pipeline.push(pipeline.outcomes, event.eventId, outcome);
        return outcome;
      } catch (error) {
        pipeline.push(pipeline.failures, event.eventId, error);
        throw error;
      }
    });
    connection.start();
    await connection.waitUntilConnected(15_000);
    await eventually(
      async () =>
        /amqp_consumer_active\{[^}]*queue="scan.spam"[^}]*\} 1/.test(await registry.metrics()),
      15_000,
      'the scan.spam consumer to subscribe',
    );
    return pipeline;
  }

  private push<T>(map: Map<string, T[]>, key: string, value: T): void {
    const list = map.get(key) ?? [];
    list.push(value);
    map.set(key, list);
  }

  outcomesOf(eventId: string): HandleOutcome[] {
    return this.outcomes.get(eventId) ?? [];
  }

  failuresOf(eventId: string): unknown[] {
    return this.failures.get(eventId) ?? [];
  }

  async outcome(eventId: string, count = 1, timeoutMs = 60_000): Promise<HandleOutcome> {
    await eventually(
      () => this.outcomesOf(eventId).length >= count,
      timeoutMs,
      `scan event ${eventId} to be handled`,
    );
    return this.outcomesOf(eventId)[0]!;
  }

  async deliver(broker: ScanBroker, event: EventEnvelope<ScanTriggerPayload>, timeoutMs = 60_000) {
    await broker.publish([event]);
    return this.outcome(event.eventId, 1, timeoutMs);
  }

  text(): Promise<string> {
    return this.registry.metrics();
  }

  async stop(): Promise<void> {
    await this.consumer.stop();
    await this.publisher.close();
    await this.connection.close();
  }
}

export async function withScanPipeline<R>(
  fx: ScanFixtures,
  broker: ScanBroker,
  options: ScanPipelineOptions,
  fn: (pipeline: ScanPipeline) => Promise<R>,
): Promise<R> {
  const pipeline = await ScanPipeline.start(fx, broker, options);
  try {
    return await fn(pipeline);
  } finally {
    await pipeline.stop();
  }
}

/** The deadline sweeper on the suite's writer, with a per-run lock name. */
export function sweeper(fx: ScanFixtures, metrics: ScanMetrics, config: Readonly<WorkerConfig>) {
  const locks = new AdvisoryLocks(requireEnv('DATABASE_URL'));
  const store = new ScanRepository(
    fx.prisma,
    config.SCAN_DB_TIMEOUT_MS,
    createRiskScorer({ config, metrics: metrics.risk, logger: silentLogger }),
    metrics.lifecycle,
  );
  const instance = new DeadlineSweeper({
    store,
    locks,
    metrics,
    logger: silentLogger,
    intervalMs: 200,
    lookbackHours: 48,
    batchSize: 200,
    lockName: `it-scan:deadline:${fx.suffix}`,
    organizationIds: fx.organizationIds,
  });
  return { sweeper: instance, store, locks };
}

/** A controller client of the real rspamd (enable password: Bayes and fuzzy training). */
export function trainingClient(): RspamdClient {
  return new RspamdClient({
    baseUrl: requireEnv('SCAN_RSPAMD_URL'),
    controllerUrl: requireEnv('RSPAMD_CONTROLLER_URL'),
    controllerPassword: requireEnv('RSPAMD_CONTROLLER_PASSWORD'),
    controllerEnablePassword: requireEnv('RSPAMD_CONTROLLER_ENABLE_PASSWORD'),
    timeoutMs: 20_000,
  });
}

/** Redis DB `RSPAMD_REDIS_DB` of the shared instance (Rspamd state), from REDIS_URL. */
export function rspamdRedis(): RedisService {
  const url = new URL(requireEnv('REDIS_URL'));
  url.pathname = `/${process.env.RSPAMD_REDIS_DB ?? '1'}`;
  return new RedisService({ url: url.toString() });
}

/** A TCP server that accepts connections and never answers (a hanging Rspamd). */
export class HangingServer {
  connections = 0;
  /** HTTP requests seen (request lines `POST /checkv2`). */
  requests = 0;
  private readonly sockets = new Set<Socket>();
  private constructor(
    private readonly server: Server,
    readonly port: number,
  ) {}

  static async start(): Promise<HangingServer> {
    const ref: { s?: HangingServer } = {};
    const server = createServer((socket) => {
      ref.s!.connections += 1;
      ref.s!.sockets.add(socket);
      socket.on('error', () => undefined);
      socket.on('close', () => ref.s!.sockets.delete(socket));
      socket.on('data', (chunk: Buffer) => {
        ref.s!.requests += chunk.toString('latin1').split('POST /checkv2 ').length - 1;
      });
    });
    await new Promise<void>((done) => server.listen(0, '127.0.0.1', () => done()));
    const address = server.address();
    if (address === null || typeof address === 'string') throw new Error('no port');
    ref.s = new HangingServer(server, address.port);
    return ref.s;
  }

  async close(): Promise<void> {
    for (const s of this.sockets) s.destroy();
    await new Promise<void>((done) => this.server.close(() => done()));
  }
}
