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
  OpenSearchModule,
  OpenSearchService,
  PrismaConsumerProgress,
  PrismaService,
  QueueConsumer,
  S3Module,
  S3Service,
} from '@email-gateway/common';
import { createLogger, type Logger } from '@email-gateway/logger';
import { ARCHIVE_CONSUMER, ARCHIVE_EVENT_TYPES, ARCHIVE_QUEUE } from './capture/consumer';
import { ArchiveComponents } from './components';
import { hasRole, type WorkerConfig } from './config';
import { ArchiveMetrics } from './metrics/archive-metrics';

export const SERVICE_NAME = 'archive-worker';
export const ARCHIVE_COMPONENTS = Symbol('ARCHIVE_COMPONENTS');
/** The leader-lock connection (GET_LOCK on its own connection; tests override it). */
export const ARCHIVE_LOCKS = Symbol('ARCHIVE_LOCKS');
export const ARCHIVE_FEED = Symbol('ARCHIVE_FEED');

/** Whether this process talks to OpenSearch (index, ediscovery; lifecycle when configured). */
export function usesSearch(config: Readonly<WorkerConfig>): boolean {
  return (
    hasRole(config, 'index') ||
    hasRole(config, 'ediscovery') ||
    (hasRole(config, 'lifecycle') && config.ARCHIVE_SEARCH_URL !== undefined)
  );
}

/** Starts the loops (after the Object Lock probe) and the consumer; stops both on shutdown. */
@Injectable()
export class ArchiveRuntime implements OnApplicationBootstrap, OnModuleDestroy {
  constructor(
    @Inject(ARCHIVE_COMPONENTS) private readonly components: ArchiveComponents,
    @Inject(ARCHIVE_LOCKS) private readonly locks: AdvisoryLocks,
    @Optional() @Inject(ARCHIVE_FEED) private readonly feed: QueueConsumer<unknown> | null,
  ) {}

  async onApplicationBootstrap(): Promise<void> {
    await this.components.start();
    if (this.feed && this.components.capture)
      this.feed.start(this.components.capture.consumer.handle);
  }

  async onModuleDestroy(): Promise<void> {
    if (this.feed) await this.feed.stop();
    await this.components.stop();
    await this.locks.close().catch(() => undefined);
  }
}

/**
 * Archive Service (step 8.1, docs/plan/steps/23-journaling-archiving.md A1, ADR-0064..0069).
 * Roles (`ARCHIVE_WORKER_ROLES`): `capture` (the `email.archive` consumer as `eg-archive`, the
 * journal completeness sweep, the policy reconciler, the capture scheduler and outcome refresh),
 * `index` (OpenSearch sync, per-day reconciliation), `lifecycle` (expiry, disposal pipeline, lock
 * pass, orphans, disposal verification, root re-wrap) and `ediscovery` (case searches, exports,
 * export expiry). HTTP port 3060 serves probes and `/metrics` only.
 *
 * Data plane: the MySQL **writer** only (never `PrismaReadService`, ADR-0014); S3 (mail bucket
 * read, archive bucket write); RabbitMQ for the capture role; OpenSearch for index/ediscovery
 * (and lifecycle when configured). Readiness: mysql, s3 and, with the capture role, rabbitmq
 * (`email.archive` and `email.events` verified passively); OpenSearch is deliberately not a
 * readiness check (capture must keep working while the search index is down, A16). Compose runs
 * every role in one container; Kubernetes runs `archive-worker` (capture,index) and
 * `archive-jobs` (lifecycle,ediscovery) from the same image.
 */
@Module({})
export class AppModule {
  static forRoot(config: Readonly<WorkerConfig>): DynamicModule {
    const logger: Logger = createLogger({
      service: SERVICE_NAME,
      level: config.LOG_LEVEL,
      version: config.SERVICE_VERSION,
    });
    const capture = hasRole(config, 'capture');
    const search = usesSearch(config);
    return {
      module: AppModule,
      imports: [
        CorrelationModule,
        DatabaseModule.forRoot({ url: config.DATABASE_URL }),
        S3Module.forRoot(config),
        MetricsModule.forRoot({ service: SERVICE_NAME }),
        ...(capture
          ? [
              AmqpModule.forRoot({
                urls: config.RABBITMQ_ARCHIVE_URL ?? [],
                connectionName: SERVICE_NAME,
                appId: SERVICE_NAME,
                logger,
                verify: { exchanges: ['email.archive', 'email.events'], queues: [ARCHIVE_QUEUE] },
              }),
            ]
          : []),
        ...(search && config.ARCHIVE_SEARCH_URL
          ? [
              OpenSearchModule.forRoot({
                url: config.ARCHIVE_SEARCH_URL,
                username: config.ARCHIVE_SEARCH_USERNAME,
                password: config.ARCHIVE_SEARCH_PASSWORD,
                timeoutMs: config.ARCHIVE_SEARCH_TIMEOUT_MS,
              }),
            ]
          : []),
        HealthModule.forRoot({
          service: { name: SERVICE_NAME, version: config.SERVICE_VERSION },
          indicators: [PrismaService, S3Service, ...(capture ? [AmqpConnection] : [])],
        }),
      ],
      providers: [
        {
          provide: ArchiveMetrics,
          useFactory: (metrics: MetricsService) => new ArchiveMetrics(metrics),
          inject: [MetricsService],
        },
        { provide: ARCHIVE_LOCKS, useFactory: () => new AdvisoryLocks(config.DATABASE_URL) },
        {
          provide: ARCHIVE_COMPONENTS,
          useFactory: (
            prisma: PrismaService,
            s3: S3Service,
            locks: AdvisoryLocks,
            metrics: ArchiveMetrics,
            openSearch: OpenSearchService | null,
          ) =>
            new ArchiveComponents(config, {
              prisma,
              s3: s3.client,
              search: openSearch ?? null,
              locks,
              metrics,
              logger,
            }),
          inject: [
            PrismaService,
            S3Service,
            ARCHIVE_LOCKS,
            ArchiveMetrics,
            { token: OpenSearchService, optional: true },
          ],
        },
        ...(capture
          ? [
              {
                provide: ARCHIVE_FEED,
                useFactory: (
                  prisma: PrismaService,
                  connection: AmqpConnection,
                  publisher: ConfirmPublisher,
                  messaging: MessagingMetrics | null,
                ) =>
                  new QueueConsumer<unknown>({
                    connection,
                    publisher,
                    queue: ARCHIVE_QUEUE,
                    consumer: ARCHIVE_CONSUMER,
                    eventTypes: [...ARCHIVE_EVENT_TYPES],
                    prefetch: config.ARCHIVE_PREFETCH,
                    logger,
                    ...(messaging ? { metrics: messaging } : {}),
                    progress: new PrismaConsumerProgress(prisma),
                  }),
                inject: [PrismaService, AmqpConnection, ConfirmPublisher, AMQP_MESSAGING_METRICS],
              },
            ]
          : []),
        ArchiveRuntime,
      ],
      exports: [ARCHIVE_COMPONENTS],
    };
  }
}
