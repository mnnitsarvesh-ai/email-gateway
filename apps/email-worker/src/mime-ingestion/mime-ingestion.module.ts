import {
  type DynamicModule,
  Inject,
  Injectable,
  Module,
  type OnApplicationBootstrap,
  type OnModuleDestroy,
} from '@nestjs/common';
import {
  AdvisoryLocks,
  type EventFeed,
  MetricsService,
  PrismaService,
  S3Service,
  ShardedOutboxFeed,
} from '@email-gateway/common';
import {
  EventTypes,
  messageReceivedV1,
  type MessageReceivedV1,
} from '@email-gateway/event-contracts';
import type { PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import type { WorkerConfig } from '../config';
import { S3EmlSource } from './eml-source';
import { mimeLimitsFromConfig } from './limits';
import { MIME_CONSUMER, MimeIngestionService } from './mime-ingestion.service';
import { MimeMetrics } from './mime-metrics';
import { MimeRepository } from './mime-repository';
import { S3PartSink } from './s3-part-sink';

/** Advisory lock namespace of this worker: `ew:outbox:<consumer>[#i/n]` (M2). */
export const OUTBOX_LOCK_PREFIX = 'ew';
export const MIME_FEED = Symbol('MIME_FEED');
export const MIME_LOGGER = Symbol('MIME_LOGGER');

/** Builds the shared outbox feed of the consumer (M2); step 3.2 swaps it for a queue consumer. */
export function createMimeFeed(options: {
  config: Readonly<WorkerConfig>;
  prisma: PrismaClient;
  locks: AdvisoryLocks;
  metrics: MimeMetrics;
  logger: Logger;
  consumer?: string;
}): ShardedOutboxFeed<MessageReceivedV1> {
  const { config } = options;
  return new ShardedOutboxFeed<MessageReceivedV1>({
    prisma: options.prisma,
    locks: options.locks,
    logger: options.logger,
    metrics: options.metrics.outboxPoller(),
    consumer: options.consumer ?? MIME_CONSUMER,
    eventType: EventTypes.MessageReceived,
    schema: messageReceivedV1,
    // Every received message must be parsed; the ledger and parse rows make re-reads free.
    initialPosition: 'oldest',
    pollIntervalMs: config.MIME_OUTBOX_POLL_INTERVAL_MS,
    safetyLagMs: config.MIME_OUTBOX_SAFETY_LAG_MS,
    batchSize: config.MIME_OUTBOX_BATCH_SIZE,
    lockPrefix: OUTBOX_LOCK_PREFIX,
    concurrency: config.MIME_CONCURRENCY,
    shards: config.MIME_OUTBOX_SHARDS,
    maxHeldLocks: config.MIME_OUTBOX_MAX_HELD_SHARDS,
    failureBackoff: { baseMs: config.MIME_RETRY_BASE_MS, maxMs: config.MIME_RETRY_MAX_MS },
  });
}

/** Builds the stage's service on the writer and the mail bucket (also used by the integration tests). */
export function createMimeIngestionService(options: {
  config: Readonly<WorkerConfig>;
  prisma: PrismaClient;
  s3: Pick<S3Service, 'client' | 'mailBucket'>;
  metrics: MimeMetrics;
  logger: Logger;
  consumer?: string;
}): MimeIngestionService {
  const { config, s3 } = options;
  return new MimeIngestionService({
    store: new MimeRepository(options.prisma, config.MIME_DB_TIMEOUT_MS),
    emlSource: new S3EmlSource(s3.client, s3.mailBucket, config.MIME_S3_TIMEOUT_MS),
    sinkFor: (target) =>
      new S3PartSink({
        client: s3.client,
        bucket: s3.mailBucket,
        target,
        partSizeBytes: config.MIME_S3_PART_SIZE_BYTES,
        queueSize: config.MIME_S3_QUEUE_SIZE,
        timeoutMs: config.MIME_S3_TIMEOUT_MS,
      }),
    metrics: options.metrics,
    logger: options.logger,
    limits: mimeLimitsFromConfig(config),
    maxAttempts: config.MIME_MAX_ATTEMPTS,
    ...(options.consumer ? { consumer: options.consumer } : {}),
  });
}

/**
 * Starts the feed after the application bootstrapped (clients connected) and stops it, then the
 * lock connection, before the database closes (non-global module, destroyed before
 * DatabaseModule; the delivery-worker `WorkerRuntime` pattern).
 */
@Injectable()
export class MimeIngestionRuntime implements OnApplicationBootstrap, OnModuleDestroy {
  private started = false;

  constructor(
    @Inject(MIME_FEED) private readonly feed: EventFeed<MessageReceivedV1>,
    @Inject(MimeIngestionService) private readonly service: MimeIngestionService,
    @Inject(AdvisoryLocks) private readonly locks: AdvisoryLocks,
    @Inject(MIME_LOGGER) private readonly logger: Logger,
  ) {}

  get running(): boolean {
    return this.started;
  }

  onApplicationBootstrap(): void {
    this.feed.start((event) => this.service.handle(event));
    this.started = true;
    this.logger.info({ consumer: this.service.consumer }, 'MIME ingestion started');
  }

  async onModuleDestroy(): Promise<void> {
    if (this.started) {
      this.started = false;
      try {
        await this.feed.stop();
      } catch (err) {
        this.logger.warn({ errName: (err as Error).name }, 'MIME feed did not stop cleanly');
      }
    }
    await this.locks.close().catch(() => this.logger.warn('lock connection close failed'));
  }
}

/**
 * The post-queue MIME ingestion stage of step 3.1 (docs/plan/steps/06-mime-ingestion.md):
 * `mail.message.received.v1` from the shared outbox feed (M2) → `MimeIngestionService` (M3) →
 * parse rows, headers, attachments, S3 part objects and the parse events. Components are plain
 * classes wired here, so the integration tests build the same graph without Nest. Imported by
 * `AppModule` only when `MIME_INGESTION_ENABLED` is true.
 */
@Module({})
export class MimeIngestionModule {
  static forRoot(config: Readonly<WorkerConfig>, logger: Logger): DynamicModule {
    return {
      module: MimeIngestionModule,
      providers: [
        { provide: MIME_LOGGER, useValue: logger },
        {
          provide: MimeMetrics,
          useFactory: (metrics: MetricsService) => new MimeMetrics(metrics),
          inject: [MetricsService],
        },
        { provide: AdvisoryLocks, useFactory: () => new AdvisoryLocks(config.DATABASE_URL) },
        {
          provide: MIME_FEED,
          useFactory: (prisma: PrismaService, locks: AdvisoryLocks, metrics: MimeMetrics) =>
            createMimeFeed({ config, prisma, locks, metrics, logger }),
          inject: [PrismaService, AdvisoryLocks, MimeMetrics],
        },
        {
          provide: MimeIngestionService,
          useFactory: (prisma: PrismaService, s3: S3Service, metrics: MimeMetrics) =>
            createMimeIngestionService({ config, prisma, s3, metrics, logger }),
          inject: [PrismaService, S3Service, MimeMetrics],
        },
        MimeIngestionRuntime,
      ],
      exports: [MimeMetrics, MimeIngestionRuntime],
    };
  }
}
