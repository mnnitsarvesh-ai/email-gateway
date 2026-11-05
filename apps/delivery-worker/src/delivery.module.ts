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
  AMQP_MESSAGING_METRICS,
  AmqpConnection,
  ConfirmPublisher,
  type MessagingMetrics,
  MetricsService,
  OutboxPoller,
  PrismaConsumerProgress,
  PrismaService,
  RedisService,
  S3Service,
  withTransactionDefaults,
} from '@email-gateway/common';
import {
  EventTypes,
  messageScannedV1,
  type MessageScannedV1,
} from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import { createApprovalFeed } from './approvals/approval-feed';
import { DeliveryApprovalConsumer } from './approvals/delivery-approval.consumer';
import {
  DEV_PASSTHROUGH_CONSUMER,
  DevPassThroughApprover,
} from './approvals/dev-passthrough.approver';
import {
  DEFAULT_DELIVERY_DB_TX_TIMEOUT_MS,
  WORKER_CONFIG,
  WORKER_LOGGER,
  type WorkerConfig,
} from './config';
import { DeliveryMetrics } from './metrics/delivery-metrics';
import { DeliveryPlanner } from './planning/delivery-planner';
import { OutboundRateLimiter } from './rate-limit/outbound-rate-limiter';
import { DeliveryReconciler } from './reconciler/delivery-reconciler';
import { ReinjectionScheduler } from './reinjection/reinjection-scheduler';
import { ReinjectionStore } from './reinjection/reinjection-store';
import { Reinjector } from './reinjection/reinjector';
import { PostfixLogTailer } from './status/postfix-log-tailer';
import { StatusSignalApplier } from './status/status-signal-applier';
import { WorkerLifecycle } from './worker-lifecycle';

/**
 * Default writer-transaction budgets (= `DELIVERY_DB_TX_TIMEOUT_MS` default, step 4.2 §6.2): one
 * approval (planning up to 1000 recipients) and one signal or result commit. The module uses the
 * configured `DELIVERY_DB_TX_TIMEOUT_MS` for both; tests use these defaults. Before step 4.2 they
 * were 60 s and 15 s, and the claim ran with Prisma's 5 s default: a writer stall or lock wait
 * longer than that expired transactions with a statement in flight (§12 WP4).
 */
export const PLANNING_TX_TIMEOUT_MS = DEFAULT_DELIVERY_DB_TX_TIMEOUT_MS;
export const RECORDER_TX_TIMEOUT_MS = DEFAULT_DELIVERY_DB_TX_TIMEOUT_MS;
/** Advisory lock namespace of this worker's outbox poller (dev pass-through): `dw:outbox:<consumer>` (R6). */
export const OUTBOX_LOCK_PREFIX = 'dw';

/**
 * Runs the lifecycle from Nest's hooks (non-global module: stopped before the DB closes). On
 * shutdown: the roles (consumers first, then the lock connection), then the AMQP publisher and
 * connection, then (DatabaseModule) the writer; `AmqpModule`'s own close afterwards is a no-op.
 */
@Injectable()
export class WorkerRuntime implements OnApplicationBootstrap, OnModuleDestroy {
  constructor(
    @Inject(WorkerLifecycle) private readonly lifecycle: WorkerLifecycle,
    @Inject(AmqpConnection) private readonly connection: AmqpConnection,
    @Inject(ConfirmPublisher) private readonly publisher: ConfirmPublisher,
  ) {}

  onApplicationBootstrap(): void {
    this.lifecycle.start();
  }

  async onModuleDestroy(): Promise<void> {
    await this.lifecycle.stop();
    await this.publisher.close().catch(() => undefined);
    await this.connection.close().catch(() => undefined);
  }
}

/**
 * The delivery pipeline of step 2.3 (docs/plan/steps/05-routing.md): approvals feed (RabbitMQ
 * queue `email.delivery.pending` since step 3.2 Q13, needs the global `AmqpModule`; the dev
 * pass-through stays on the shared outbox poller) → planner (R7) → reinjection
 * scheduler and reinjector (R8, R10, R11) → Postfix delivery-log tailer (R9) → reconciler (R12),
 * with the metrics of R14. Components are plain classes wired here, so the integration tests
 * build the same graph without Nest.
 */
@Module({})
export class DeliveryModule {
  static forRoot(config: Readonly<WorkerConfig>, logger: Logger): DynamicModule {
    // Every data-plane interactive transaction of this worker gets the same budget (§6.2 F2):
    // explicit options below, and `writer(prisma)` for every `$transaction(fn)` without options.
    const txBudgetMs = config.DELIVERY_DB_TX_TIMEOUT_MS;
    const writer = (prisma: PrismaService) =>
      withTransactionDefaults(prisma, { timeoutMs: txBudgetMs });
    const providers = [
      { provide: WORKER_CONFIG, useValue: config },
      { provide: WORKER_LOGGER, useValue: logger },
      {
        provide: DeliveryMetrics,
        useFactory: (metrics: MetricsService) => new DeliveryMetrics(metrics),
        inject: [MetricsService],
      },
      { provide: AdvisoryLocks, useFactory: () => new AdvisoryLocks(config.DATABASE_URL) },
      {
        provide: DeliveryPlanner,
        useFactory: (metrics: DeliveryMetrics) =>
          new DeliveryPlanner({
            logger,
            metrics,
            config,
            recorderTimeoutMs: txBudgetMs,
          }),
        inject: [DeliveryMetrics],
      },
      {
        provide: DeliveryApprovalConsumer,
        useFactory: (
          prisma: PrismaService,
          connection: AmqpConnection,
          publisher: ConfirmPublisher,
          messaging: MessagingMetrics | null,
          planner: DeliveryPlanner,
        ) =>
          new DeliveryApprovalConsumer(
            createApprovalFeed({
              connection,
              publisher,
              prefetch: config.DELIVERY_APPROVAL_PREFETCH,
              logger,
              ...(messaging ? { metrics: messaging } : {}),
              progress: new PrismaConsumerProgress(prisma),
            }),
            planner,
            prisma,
            txBudgetMs,
          ),
        inject: [
          PrismaService,
          AmqpConnection,
          ConfirmPublisher,
          AMQP_MESSAGING_METRICS,
          DeliveryPlanner,
        ],
      },
      {
        provide: DevPassThroughApprover,
        useFactory: (prisma: PrismaService, locks: AdvisoryLocks, metrics: DeliveryMetrics) =>
          new DevPassThroughApprover(
            // Step 4.1 S15: approve after the scan (mail.message.scanned.v1), never before it.
            new OutboxPoller<MessageScannedV1>({
              prisma,
              locks,
              logger,
              metrics: metrics.outboxPoller(),
              consumer: DEV_PASSTHROUGH_CONSUMER,
              eventType: EventTypes.MessageScanned,
              schema: messageScannedV1,
              initialPosition: 'latest',
              pollIntervalMs: config.DELIVERY_OUTBOX_POLL_INTERVAL_MS,
              safetyLagMs: config.DELIVERY_OUTBOX_SAFETY_LAG_MS,
              batchSize: config.DELIVERY_OUTBOX_BATCH_SIZE,
              lockPrefix: OUTBOX_LOCK_PREFIX,
              concurrency: 1,
            }),
            prisma,
            txBudgetMs,
            logger,
            metrics,
          ),
        inject: [PrismaService, AdvisoryLocks, DeliveryMetrics],
      },
      {
        provide: ReinjectionScheduler,
        useFactory: (
          prisma: PrismaService,
          redis: RedisService,
          s3: S3Service,
          metrics: DeliveryMetrics,
        ) => {
          const txPrisma = writer(prisma);
          const store = new ReinjectionStore(txPrisma, { txTimeoutMs: txBudgetMs });
          const reinjector = new Reinjector({
            prisma: txPrisma,
            store,
            s3: s3.client,
            bucket: s3.mailBucket,
            limiter: new OutboundRateLimiter(txPrisma, redis.client, config),
            metrics,
            logger,
            config,
            txTimeoutMs: txBudgetMs,
          });
          return new ReinjectionScheduler(store, reinjector, config, logger);
        },
        inject: [PrismaService, RedisService, S3Service, DeliveryMetrics],
      },
      {
        provide: PostfixLogTailer,
        useFactory: (prisma: PrismaService, locks: AdvisoryLocks, metrics: DeliveryMetrics) =>
          new PostfixLogTailer({
            prisma,
            locks,
            metrics,
            logger,
            path: config.DELIVERY_STATUS_LOG_PATH,
            sourceId: config.DELIVERY_STATUS_LOG_SOURCE_ID,
            pollMs: config.DELIVERY_STATUS_LOG_POLL_MS,
            applier: new StatusSignalApplier({
              prisma,
              metrics,
              logger,
              sourceId: config.DELIVERY_STATUS_LOG_SOURCE_ID,
              unmatchedRetryMs: config.DELIVERY_STATUS_UNMATCHED_RETRY_SECONDS * 1000,
              recorderTimeoutMs: txBudgetMs,
            }),
          }),
        inject: [PrismaService, AdvisoryLocks, DeliveryMetrics],
      },
      {
        provide: DeliveryReconciler,
        useFactory: (prisma: PrismaService, metrics: DeliveryMetrics) =>
          new DeliveryReconciler(writer(prisma), metrics, config, logger, txBudgetMs),
        inject: [PrismaService, DeliveryMetrics],
      },
      {
        provide: WorkerLifecycle,
        useFactory: (
          approvals: DeliveryApprovalConsumer,
          passThrough: DevPassThroughApprover,
          scheduler: ReinjectionScheduler,
          tailer: PostfixLogTailer,
          reconciler: DeliveryReconciler,
          locks: AdvisoryLocks,
        ) =>
          new WorkerLifecycle(
            { approvals, passThrough, scheduler, tailer, reconciler, locks },
            config,
            logger,
          ),
        inject: [
          DeliveryApprovalConsumer,
          DevPassThroughApprover,
          ReinjectionScheduler,
          PostfixLogTailer,
          DeliveryReconciler,
          AdvisoryLocks,
        ],
      },
      WorkerRuntime,
    ];
    return {
      module: DeliveryModule,
      providers,
      exports: [DeliveryMetrics, WorkerLifecycle],
    };
  }
}
