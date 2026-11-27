import {
  type DynamicModule,
  Inject,
  Injectable,
  Module,
  type OnApplicationBootstrap,
  type OnModuleDestroy,
  Optional,
} from '@nestjs/common';
import {
  AdvisoryLocks,
  AMQP_MESSAGING_METRICS,
  AmqpConnection,
  AmqpModule,
  ConfirmPublisher,
  CorrelationModule,
  DatabaseModule,
  HealthModule,
  type MessagingMetrics,
  MetricsModule,
  MetricsService,
  PrismaConsumerProgress,
  PrismaService,
  QueueConsumer,
  RedisModule,
  RedisService,
  S3Module,
  S3Service,
} from '@email-gateway/common';
import { createLogger, type Logger } from '@email-gateway/logger';
import { MailboxComponents } from './components';
import { hasRole, type WorkerConfig } from './config';
import { COPIES_CONSUMER, COPIES_EVENT_TYPES, COPIES_QUEUE } from './copies/copies.handler';
import { MailboxMetrics } from './metrics/mailbox-metrics';
import type { MailboxRedis } from './runtime/redis-stores';

export const SERVICE_NAME = 'mailbox-worker';
export const MAILBOX_COMPONENTS = Symbol('MAILBOX_COMPONENTS');
/** The leader-lock connection (GET_LOCK on its own connection). */
export const MAILBOX_LOCKS = Symbol('MAILBOX_LOCKS');
export const MAILBOX_FEED = Symbol('MAILBOX_FEED');
/** Concurrent copy events per replica (the queue's prefetch). */
export const COPIES_PREFETCH = 16;
/** Writer pool per replica: copies (prefetch 16) and feed syncs (≤ 16, short statements) share it; Prisma queues beyond it (pool timeout 30 s). */
export const DATABASE_CONNECTION_LIMIT = 20;

/** Starts the role loops and the copies consumer; stops them on shutdown (consumer first). */
@Injectable()
export class MailboxRuntime implements OnApplicationBootstrap, OnModuleDestroy {
  constructor(
    @Inject(MAILBOX_COMPONENTS) private readonly components: MailboxComponents,
    @Inject(MAILBOX_LOCKS) private readonly locks: AdvisoryLocks,
    @Optional() @Inject(MAILBOX_FEED) private readonly feed: QueueConsumer<unknown> | null,
  ) {}

  onApplicationBootstrap(): void {
    this.components.start();
    this.feed?.start(this.components.copies.handle);
  }

  async onModuleDestroy(): Promise<void> {
    await this.feed?.stop();
    await this.components.stop();
    await this.locks.close().catch(() => undefined);
  }
}

/**
 * mailbox-worker (step API-1 D5, ADR-0100; step API-2 ADR-0101/0102;
 * docs/deployment/mailbox-worker.md). Roles (`MAILBOX_WORKER_ROLES`, default
 * `copies,feeds,inventory,health,remediate`): `copies` consumes `email.mailbox` as `eg-mailbox`
 * (ledger `mailbox-worker.copies`, reconciled: retry and dead-letter hops are recorded) and takes
 * the remediation decision in the same transaction, `feeds`, `inventory` and `remediate` call
 * provider mailbox APIs with the decrypted `*.mailbox_remediation` grants (`remediate` claims
 * `api_remediation_actions` from MySQL; no broker), `health` is leader-locked. Readiness is the
 * same for every role: MySQL writer, Redis and S3 (plus the broker with `copies`). HTTP
 * `MAILBOX_WORKER_HTTP_PORT` (3087) serves `/health/live`, `/health/ready` and `/metrics` only.
 * Data plane: the MySQL writer only (ADR-0014), Redis, the mail bucket; every outbound event is an
 * outbox row relayed by the event-relay (the worker publishes only its own retry hops).
 */
@Module({})
export class AppModule {
  static forRoot(config: Readonly<WorkerConfig>): DynamicModule {
    const logger: Logger = createLogger({
      service: SERVICE_NAME,
      level: config.LOG_LEVEL,
      version: config.SERVICE_VERSION,
    });
    const copies = hasRole(config, 'copies');
    return {
      module: AppModule,
      imports: [
        CorrelationModule,
        DatabaseModule.forRoot({
          url: config.DATABASE_URL,
          connectionLimit: DATABASE_CONNECTION_LIMIT,
          poolTimeoutSeconds: 30,
        }),
        RedisModule.forRoot({ url: config.REDIS_URL }),
        S3Module.forRoot(config),
        MetricsModule.forRoot({ service: SERVICE_NAME }),
        ...(copies
          ? [
              AmqpModule.forRoot({
                urls: config.RABBITMQ_MAILBOX_URL ?? [],
                connectionName: SERVICE_NAME,
                appId: SERVICE_NAME,
                logger,
                verify: { exchanges: ['email.security', 'email.events'], queues: [COPIES_QUEUE] },
              }),
            ]
          : []),
        HealthModule.forRoot({
          service: { name: SERVICE_NAME, version: config.SERVICE_VERSION },
          indicators: [PrismaService, RedisService, S3Service, ...(copies ? [AmqpConnection] : [])],
        }),
      ],
      providers: [
        {
          provide: MailboxMetrics,
          useFactory: (metrics: MetricsService) => new MailboxMetrics(metrics),
          inject: [MetricsService],
        },
        { provide: MAILBOX_LOCKS, useFactory: () => new AdvisoryLocks(config.DATABASE_URL) },
        {
          provide: MAILBOX_COMPONENTS,
          useFactory: (
            prisma: PrismaService,
            redis: RedisService,
            s3: S3Service,
            locks: AdvisoryLocks,
            metrics: MailboxMetrics,
          ) =>
            new MailboxComponents(config, {
              prisma,
              redis: redis.client as unknown as MailboxRedis,
              locks,
              s3: s3.client,
              mailBucket: s3.mailBucket,
              metrics,
              logger,
            }),
          inject: [PrismaService, RedisService, S3Service, MAILBOX_LOCKS, MailboxMetrics],
        },
        ...(copies
          ? [
              {
                provide: MAILBOX_FEED,
                useFactory: (
                  prisma: PrismaService,
                  connection: AmqpConnection,
                  publisher: ConfirmPublisher,
                  messaging: MessagingMetrics | null,
                ) =>
                  new QueueConsumer<unknown>({
                    connection,
                    publisher,
                    queue: COPIES_QUEUE,
                    consumer: COPIES_CONSUMER,
                    eventTypes: [...COPIES_EVENT_TYPES],
                    prefetch: COPIES_PREFETCH,
                    logger,
                    ...(messaging ? { metrics: messaging } : {}),
                    // email.mailbox is reconciled by the event-relay (RECONCILE_QUEUES, topology v17).
                    progress: new PrismaConsumerProgress(prisma),
                  }),
                inject: [PrismaService, AmqpConnection, ConfirmPublisher, AMQP_MESSAGING_METRICS],
              },
            ]
          : []),
        MailboxRuntime,
      ],
      exports: [MAILBOX_COMPONENTS],
    };
  }
}
