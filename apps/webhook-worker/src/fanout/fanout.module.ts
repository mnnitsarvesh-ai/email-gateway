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
  type MessagingMetrics,
  PrismaConsumerProgress,
  PrismaService,
  QueueConsumer,
} from '@email-gateway/common';
import type { RetryPolicy } from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import type { WorkerConfig } from '../config';
import { WebhookMetrics } from '../metrics/webhook-metrics';
import type { WebhookRead } from '../shared/errors';
import { FanoutReads } from './facts';
import { FANOUT_CONSUMER, FanoutService, PendingCounts } from './fanout.service';
import { FANOUT_SOURCE_TYPES } from './projection';
import { SubscriptionIndex } from './subscription-index';

/** The work queue of the fanout role (topology v11). */
export const WEBHOOKS_QUEUE = 'email.webhooks';

/**
 * The `QueueConsumer` of `email.webhooks` (W1): the eight bound source types, prefetch
 * `WEBHOOK_FANOUT_PREFETCH`, the topology's retry policy (`hold`, 10 attempts, 2 s – 1 min, 24 h),
 * default classification (database/network outages transient, `NonRetryableError` fatal → dead
 * letter, an `InconsistentReadError` retryable) and `PrismaConsumerProgress` for the operator
 * views (the queue is not reconciled, §4.3).
 */
export function createFanoutFeed(options: {
  connection: AmqpConnection;
  publisher: ConfirmPublisher;
  prefetch: number;
  logger: Logger;
  metrics?: MessagingMetrics;
  consumer?: string;
  retry?: Partial<RetryPolicy>;
  progress?: ConsumerProgressRecorder;
}): QueueConsumer<unknown> {
  return new QueueConsumer<unknown>({
    connection: options.connection,
    publisher: options.publisher,
    queue: WEBHOOKS_QUEUE,
    consumer: options.consumer ?? FANOUT_CONSUMER,
    eventTypes: [...FANOUT_SOURCE_TYPES],
    prefetch: options.prefetch,
    logger: options.logger,
    ...(options.metrics ? { metrics: options.metrics } : {}),
    ...(options.retry ? { retry: options.retry } : {}),
    ...(options.progress ? { progress: options.progress } : {}),
  });
}

/** Starts the consumer after bootstrap; stops it before the clients close. */
@Injectable()
export class FanoutRuntime implements OnApplicationBootstrap, OnModuleDestroy {
  constructor(
    @Inject(QueueConsumer) private readonly feed: QueueConsumer<unknown>,
    @Inject(FanoutService) private readonly service: FanoutService,
  ) {}

  onApplicationBootstrap(): void {
    this.feed.start(this.service.handle);
  }

  async onModuleDestroy(): Promise<void> {
    await this.feed.stop();
  }
}

/** The `fanout` role (W1): needs the global AmqpModule, DatabaseModule and MetricsModule. */
@Module({})
export class FanoutModule {
  static forRoot(config: Readonly<WorkerConfig>, logger: Logger): DynamicModule {
    return {
      module: FanoutModule,
      providers: [
        {
          provide: FanoutService,
          useFactory: (prisma: PrismaService, metrics: WebhookMetrics) => {
            const sink = (read: WebhookRead) => metrics.inconsistentReads.inc({ read });
            return new FanoutService({
              prisma,
              index: new SubscriptionIndex(
                prisma,
                config.WEBHOOK_SUBSCRIPTION_CACHE_SECONDS * 1000,
                sink,
                logger,
              ),
              reads: new FanoutReads(sink),
              pending: new PendingCounts(config.WEBHOOK_MAX_PENDING_PER_SUBSCRIPTION),
              metrics,
              logger: logger.child({ component: 'webhook-fanout' }),
              txTimeoutMs: config.WEBHOOK_FANOUT_TX_TIMEOUT_MS,
            });
          },
          inject: [PrismaService, WebhookMetrics],
        },
        {
          provide: QueueConsumer,
          useFactory: (
            prisma: PrismaService,
            connection: AmqpConnection,
            publisher: ConfirmPublisher,
            messaging: MessagingMetrics | null,
          ) =>
            createFanoutFeed({
              connection,
              publisher,
              prefetch: config.WEBHOOK_FANOUT_PREFETCH,
              logger,
              ...(messaging ? { metrics: messaging } : {}),
              progress: new PrismaConsumerProgress(prisma),
            }),
          inject: [PrismaService, AmqpConnection, ConfirmPublisher, AMQP_MESSAGING_METRICS],
        },
        FanoutRuntime,
      ],
      exports: [FanoutService],
    };
  }
}
