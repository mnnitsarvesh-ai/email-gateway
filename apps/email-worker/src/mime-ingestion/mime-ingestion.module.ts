import {
  type DynamicModule,
  Inject,
  Injectable,
  Module,
  type OnApplicationBootstrap,
  type OnModuleDestroy,
} from '@nestjs/common';
import {
  AMQP_MESSAGING_METRICS,
  AmqpConnection,
  ConfirmPublisher,
  type ConsumerProgressRecorder,
  type EventFeed,
  type FailureClass,
  type MessagingMetrics,
  MetricsService,
  PrismaConsumerProgress,
  PrismaService,
  QueueConsumer,
  S3Service,
} from '@email-gateway/common';
import { EventTypes, type MessageReceivedV1 } from '@email-gateway/event-contracts';
import type { PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import { MIME_QUEUE, type WorkerConfig } from '../config';
import { S3EmlSource } from './eml-source';
import { errorFields, isTransientFailure } from './error-fields';
import { mimeLimitsFromConfig } from './limits';
import { MIME_CONSUMER, MimeIngestionService } from './mime-ingestion.service';
import { MimeMetrics } from './mime-metrics';
import { MimeRepository } from './mime-repository';
import { S3PartSink } from './s3-part-sink';

export const MIME_FEED = Symbol('MIME_FEED');
export const MIME_LOGGER = Symbol('MIME_LOGGER');

/**
 * How the `email.received` consumer treats a failed attempt (step 3.2 Q13): the stage's own
 * transient check (3.1 M3.10: MySQL, S3 or network outage; the attempt was given back) →
 * `transient` (retried with backoff, no attempt consumed, bounded by the retry age); anything
 * else → `retryable` (`x-eg-attempt + 1`). The stage's poison guard finalizes
 * `max_attempts_exceeded` after MIME_MAX_ATTEMPTS, below the queue's attempt limit, so a
 * deterministic failure ends with a parse row, not a dead letter.
 */
export function classifyMimeFailure(error: unknown): FailureClass {
  return isTransientFailure(error) ? 'transient' : 'retryable';
}

/**
 * The stage's feed (step 3.2 Q13): a `QueueConsumer` of `email.received` accepting
 * `mail.message.received.v1`, prefetch = MIME_CONCURRENCY, `hold` retries with the MIME backoff
 * (`MIME_RETRY_BASE_MS` / `MIME_RETRY_MAX_MS`) and `classifyMimeFailure`, and `progress`
 * (`message_consumer_progress`, so the outbox reconciler leaves retrying and dead-lettered events
 * alone). Also used by the integration tests (with a per-run consumer name).
 */
export function createMimeConsumer(options: {
  config: Readonly<WorkerConfig>;
  connection: AmqpConnection;
  publisher: ConfirmPublisher;
  logger: Logger;
  metrics?: MessagingMetrics;
  consumer?: string;
  progress?: ConsumerProgressRecorder;
}): QueueConsumer<MessageReceivedV1> {
  const { config } = options;
  return new QueueConsumer<MessageReceivedV1>({
    connection: options.connection,
    publisher: options.publisher,
    queue: MIME_QUEUE,
    consumer: options.consumer ?? MIME_CONSUMER,
    eventTypes: [EventTypes.MessageReceived],
    prefetch: config.MIME_CONCURRENCY,
    retry: { baseDelayMs: config.MIME_RETRY_BASE_MS, maxDelayMs: config.MIME_RETRY_MAX_MS },
    classify: classifyMimeFailure,
    logger: options.logger,
    ...(options.metrics ? { metrics: options.metrics } : {}),
    ...(options.progress ? { progress: options.progress } : {}),
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
 * Starts the consumer after the application bootstrapped (clients connected) and, on shutdown,
 * stops it (no new deliveries; in-flight handlers finish, held retries are requeued), then closes
 * the AMQP publisher and connection, all before the database closes (non-global module,
 * destroyed before DatabaseModule; `AmqpModule`'s own close afterwards is a no-op).
 */
@Injectable()
export class MimeIngestionRuntime implements OnApplicationBootstrap, OnModuleDestroy {
  private started = false;

  constructor(
    @Inject(MIME_FEED) private readonly feed: EventFeed<MessageReceivedV1>,
    @Inject(MimeIngestionService) private readonly service: MimeIngestionService,
    @Inject(AmqpConnection) private readonly connection: AmqpConnection,
    @Inject(ConfirmPublisher) private readonly publisher: ConfirmPublisher,
    @Inject(MIME_LOGGER) private readonly logger: Logger,
  ) {}

  get running(): boolean {
    return this.started;
  }

  onApplicationBootstrap(): void {
    this.feed.start((event) => this.service.handle(event));
    this.started = true;
    this.logger.info(
      { consumer: this.service.consumer, queue: MIME_QUEUE },
      'MIME ingestion started',
    );
  }

  async onModuleDestroy(): Promise<void> {
    if (this.started) {
      this.started = false;
      try {
        await this.feed.stop();
      } catch (err) {
        this.logger.warn(errorFields(err), 'MIME consumer did not stop cleanly');
      }
    }
    await this.publisher.close().catch(() => this.logger.warn('AMQP publisher close failed'));
    await this.connection.close().catch(() => this.logger.warn('AMQP connection close failed'));
  }
}

/**
 * The post-queue MIME ingestion stage of step 3.1 (docs/plan/steps/06-mime-ingestion.md) on
 * RabbitMQ (step 3.2 Q13, docs/plan/steps/07-rabbitmq.md): `mail.message.received.v1` from queue
 * `email.received` (`createMimeConsumer`) → `MimeIngestionService` (M3, unchanged) → parse rows,
 * headers, attachments, S3 part objects and the parse events (outbox → event-relay). Components
 * are plain classes wired here, so the integration tests build the same graph without Nest.
 * Imported by `AppModule` only when `MIME_INGESTION_ENABLED` is true; needs the global
 * `AmqpModule`.
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
        {
          provide: MIME_FEED,
          useFactory: (
            connection: AmqpConnection,
            publisher: ConfirmPublisher,
            metrics: MessagingMetrics | null,
            prisma: PrismaService,
          ) =>
            createMimeConsumer({
              config,
              connection,
              publisher,
              logger,
              ...(metrics ? { metrics } : {}),
              progress: new PrismaConsumerProgress(prisma),
            }),
          inject: [AmqpConnection, ConfirmPublisher, AMQP_MESSAGING_METRICS, PrismaService],
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
