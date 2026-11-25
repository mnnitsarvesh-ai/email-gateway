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
} from '@email-gateway/common';
import { createLogger, type Logger } from '@email-gateway/logger';
import { AtoComponents } from './components';
import { hasRole, type WorkerConfig } from './config';
import {
  EVENTS_CONSUMER,
  EVENTS_EVENT_TYPES,
  EVENTS_QUEUE,
  MAIL_CONSUMER,
  MAIL_EVENT_TYPES,
  MAIL_QUEUE,
  RESPONSES_CONSUMER,
  RESPONSES_EVENT_TYPES,
  RESPONSES_QUEUE,
} from './detect/consumers';
import { AtoMetrics } from './metrics/ato-metrics';
import { IdpMetrics } from './metrics/idp-metrics';

export const SERVICE_NAME = 'ato-worker';
export const ATO_COMPONENTS = Symbol('ATO_COMPONENTS');
/** The leader-lock connection (GET_LOCK on its own connection; tests override it). */
export const ATO_LOCKS = Symbol('ATO_LOCKS');
export const ATO_FEEDS = Symbol('ATO_FEEDS');

interface Feeds {
  events: QueueConsumer<unknown> | null;
  mail: QueueConsumer<unknown> | null;
  responses: QueueConsumer<unknown> | null;
}

/** Starts the role loops and consumers; stops them on shutdown (consumers first). */
@Injectable()
export class AtoRuntime implements OnApplicationBootstrap, OnModuleDestroy {
  constructor(
    @Inject(ATO_COMPONENTS) private readonly components: AtoComponents,
    @Inject(ATO_LOCKS) private readonly locks: AdvisoryLocks,
    @Optional() @Inject(ATO_FEEDS) private readonly feeds: Feeds | null,
  ) {}

  async onApplicationBootstrap(): Promise<void> {
    await this.components.start();
    this.feeds?.events?.start(this.components.eventsConsumer.handle);
    this.feeds?.mail?.start(this.components.mailConsumer.handle);
    this.feeds?.responses?.start(this.components.respond.handle);
  }

  async onModuleDestroy(): Promise<void> {
    await Promise.all([
      this.feeds?.events?.stop(),
      this.feeds?.mail?.stop(),
      this.feeds?.responses?.stop(),
    ]);
    await this.components.stop();
    await this.locks.close().catch(() => undefined);
  }
}

/**
 * ATO worker (step 8.4, docs/plan/steps/24-account-takeover-core.md D3, ADR-0070..0075). Roles
 * (`ATO_WORKER_ROLES`): `detect` (`ato.events` and the lossy `ato.mail` as `eg-ato`), `respond`
 * (`ato.responses`: provider actions through the registry), `maintenance` (leader-elected jobs:
 * mail catch-up, decay, baselines, expiry, provider confirmations, digests, retention, retirement,
 * status and capabilities) and `provider` (the ingestion runner; idle until 8.5 binds adapters).
 * HTTP port 3085 serves probes and `/metrics` only.
 *
 * Data plane: the MySQL **writer** only (ADR-0014), Redis (windows, attribution, the `ato`
 * reputation cache namespace; required for readiness), RabbitMQ for detect and respond, no object
 * storage, no Internet egress except DNS for the DNSBL zones. Compose runs every role in one
 * container; Kubernetes runs `ato-detect` (detect) and `ato-respond`
 * (respond,maintenance,provider) from the same image.
 */
@Module({})
export class AppModule {
  static forRoot(config: Readonly<WorkerConfig>): DynamicModule {
    const logger: Logger = createLogger({
      service: SERVICE_NAME,
      level: config.LOG_LEVEL,
      version: config.SERVICE_VERSION,
    });
    const detect = hasRole(config, 'detect');
    const respond = hasRole(config, 'respond');
    const broker = detect || respond;
    const queues = [
      ...(detect ? [EVENTS_QUEUE, MAIL_QUEUE] : []),
      ...(respond ? [RESPONSES_QUEUE] : []),
    ];
    const feed = (
      connection: AmqpConnection,
      publisher: ConfirmPublisher,
      messaging: MessagingMetrics | null,
      prisma: PrismaService,
      queue: typeof EVENTS_QUEUE | typeof MAIL_QUEUE | typeof RESPONSES_QUEUE,
    ): QueueConsumer<unknown> => {
      const spec =
        queue === EVENTS_QUEUE
          ? {
              consumer: EVENTS_CONSUMER,
              types: EVENTS_EVENT_TYPES,
              prefetch: config.ATO_EVENTS_PREFETCH,
            }
          : queue === MAIL_QUEUE
            ? {
                consumer: MAIL_CONSUMER,
                types: MAIL_EVENT_TYPES,
                prefetch: config.ATO_MAIL_PREFETCH,
              }
            : {
                consumer: RESPONSES_CONSUMER,
                types: RESPONSES_EVENT_TYPES,
                prefetch: config.ATO_RESPONSES_PREFETCH,
              };
      return new QueueConsumer<unknown>({
        connection,
        publisher,
        queue,
        consumer: spec.consumer,
        eventTypes: [...spec.types],
        prefetch: spec.prefetch,
        logger,
        ...(messaging ? { metrics: messaging } : {}),
        // ato.responses is reconciled by the event-relay (RECONCILE_QUEUES): retry and
        // dead-letter hops are recorded for it; the other two are not reconciled (D3).
        ...(queue === RESPONSES_QUEUE ? { progress: new PrismaConsumerProgress(prisma) } : {}),
      });
    };
    return {
      module: AppModule,
      imports: [
        CorrelationModule,
        // Step AI-4 D14: the writer pool is sized for the queue handlers, IdP polls/probes and
        // maintenance jobs, with a pool timeout ≥ the transaction maxWait (AdvisoryLocks keeps
        // its own connection_limit=1 client).
        DatabaseModule.forRoot({
          url: config.DATABASE_URL,
          connectionLimit: config.ATO_DATABASE_CONNECTION_LIMIT,
          poolTimeoutSeconds: config.ATO_DATABASE_POOL_TIMEOUT_SECONDS,
        }),
        RedisModule.forRoot({ url: config.REDIS_URL }),
        MetricsModule.forRoot({ service: SERVICE_NAME }),
        ...(broker
          ? [
              AmqpModule.forRoot({
                urls: config.RABBITMQ_ATO_URL ?? [],
                connectionName: SERVICE_NAME,
                appId: SERVICE_NAME,
                logger,
                verify: { exchanges: ['email.security', 'email.events'], queues },
              }),
            ]
          : []),
        HealthModule.forRoot({
          service: { name: SERVICE_NAME, version: config.SERVICE_VERSION },
          indicators: [PrismaService, RedisService, ...(broker ? [AmqpConnection] : [])],
        }),
      ],
      providers: [
        {
          provide: AtoMetrics,
          useFactory: (metrics: MetricsService) => new AtoMetrics(metrics),
          inject: [MetricsService],
        },
        { provide: ATO_LOCKS, useFactory: () => new AdvisoryLocks(config.DATABASE_URL) },
        {
          provide: IdpMetrics,
          useFactory: (metrics: MetricsService) => new IdpMetrics(metrics),
          inject: [MetricsService],
        },
        {
          provide: ATO_COMPONENTS,
          useFactory: (
            prisma: PrismaService,
            redis: RedisService,
            locks: AdvisoryLocks,
            metrics: AtoMetrics,
            idpMetrics: IdpMetrics,
          ) =>
            AtoComponents.create(config, {
              prisma,
              redis: redis.client,
              locks,
              metrics,
              idpMetrics,
              logger,
            }),
          inject: [PrismaService, RedisService, ATO_LOCKS, AtoMetrics, IdpMetrics],
        },
        ...(broker
          ? [
              {
                provide: ATO_FEEDS,
                useFactory: (
                  prisma: PrismaService,
                  connection: AmqpConnection,
                  publisher: ConfirmPublisher,
                  messaging: MessagingMetrics | null,
                ): Feeds => ({
                  events: detect
                    ? feed(connection, publisher, messaging, prisma, EVENTS_QUEUE)
                    : null,
                  mail: detect ? feed(connection, publisher, messaging, prisma, MAIL_QUEUE) : null,
                  responses: respond
                    ? feed(connection, publisher, messaging, prisma, RESPONSES_QUEUE)
                    : null,
                }),
                inject: [PrismaService, AmqpConnection, ConfirmPublisher, AMQP_MESSAGING_METRICS],
              },
            ]
          : []),
        AtoRuntime,
      ],
      exports: [ATO_COMPONENTS],
    };
  }
}
