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
  type MessagingMetrics,
  MetricsService,
  PrismaConsumerProgress,
  PrismaService,
  processOnceHandler,
  QueueConsumer,
} from '@email-gateway/common';
import {
  type EventEnvelope,
  EventTypes,
  type PolicyNotificationRequestedV1,
  type QuarantineNotificationRequestedV1,
} from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import type { WorkerConfig } from '../config';
import { createNoticeMailer, type NoticeMailer } from './mailer';
import { NotificationMetrics } from './notification-metrics';
import { NotificationReads } from './notification-reads';
import {
  POLICY_NOTIFICATION_CONSUMER,
  PolicyNotificationHandler,
} from './policy-notification.handler';
import { QuarantineNotificationHandler } from './quarantine-notification.handler';
import { QuarantineNotificationReads } from './quarantine-reads';

/** The payloads consumed from `email.notifications` (step 5.2 policy, step 5.3 quarantine). */
export type NotificationPayload = PolicyNotificationRequestedV1 | QuarantineNotificationRequestedV1;

const isQuarantine = (
  event: EventEnvelope<NotificationPayload>,
): event is EventEnvelope<QuarantineNotificationRequestedV1> =>
  event.eventType === EventTypes.QuarantineNotificationRequested;

/** The queue of the policy notices (topology v9, P15). */
export const NOTIFICATION_QUEUE = 'email.notifications';

const NOTICE_MAILER = Symbol('NOTICE_MAILER');
const NOTICE_CONSUMER = Symbol('NOTICE_CONSUMER');

/** Builds the `QueueConsumer` of `email.notifications` with the handler inside `processOnce`. */
export function createNotificationConsumer(options: {
  connection: AmqpConnection;
  publisher: ConfirmPublisher;
  prisma: PrismaService;
  prefetch: number;
  txTimeoutMs: number;
  logger: Logger;
  metrics?: MessagingMetrics;
}): QueueConsumer<NotificationPayload> {
  const consumer = new QueueConsumer<NotificationPayload>({
    connection: options.connection,
    publisher: options.publisher,
    queue: NOTIFICATION_QUEUE,
    consumer: POLICY_NOTIFICATION_CONSUMER,
    eventTypes: [
      EventTypes.PolicyNotificationRequested,
      EventTypes.QuarantineNotificationRequested,
    ],
    prefetch: options.prefetch,
    logger: options.logger,
    ...(options.metrics ? { metrics: options.metrics } : {}),
    progress: new PrismaConsumerProgress(options.prisma),
  });
  return consumer;
}

/** Starts the consumer after bootstrap; stops it, the mailer and the broker on shutdown. */
@Injectable()
export class NotificationRuntime implements OnApplicationBootstrap, OnModuleDestroy {
  constructor(
    @Inject(NOTICE_CONSUMER)
    private readonly consumer: QueueConsumer<NotificationPayload>,
    @Inject(NOTICE_MAILER) private readonly mailer: NoticeMailer,
    @Inject(PrismaService) private readonly prisma: PrismaService,
    @Inject(PolicyNotificationHandler) private readonly handler: PolicyNotificationHandler,
    @Inject(QuarantineNotificationHandler)
    private readonly quarantine: QuarantineNotificationHandler,
    @Inject(AmqpConnection) private readonly connection: AmqpConnection,
    @Inject(ConfirmPublisher) private readonly publisher: ConfirmPublisher,
    @Inject('NOTIFICATION_TX_TIMEOUT_MS') private readonly txTimeoutMs: number,
  ) {}

  onApplicationBootstrap(): void {
    this.consumer.start(
      processOnceHandler<NotificationPayload>(
        this.prisma,
        POLICY_NOTIFICATION_CONSUMER,
        async (event, tx) => {
          if (isQuarantine(event)) await this.quarantine.handle(event, tx);
          else await this.handler.handle(event as EventEnvelope<PolicyNotificationRequestedV1>, tx);
        },
        { txTimeoutMs: this.txTimeoutMs },
      ),
    );
  }

  async onModuleDestroy(): Promise<void> {
    await this.consumer.stop();
    this.mailer.close();
    await this.publisher.close().catch(() => undefined);
    await this.connection.close().catch(() => undefined);
  }
}

/**
 * The policy notices of step 5.2 (P25) and the quarantine notices of step 5.3 (Q20): the
 * `email.notifications` consumer (ledger `notification-worker.policy`, retry and dead-letter per
 * topology v10), one handler per event type, the relay mailer and the metrics. Needs the global `AmqpModule`, `MetricsModule` and `DatabaseModule`.
 */
@Module({})
export class NotificationsModule {
  static forRoot(config: Readonly<WorkerConfig>, logger: Logger): DynamicModule {
    return {
      module: NotificationsModule,
      providers: [
        { provide: 'NOTIFICATION_TX_TIMEOUT_MS', useValue: config.NOTIFICATION_DB_TX_TIMEOUT_MS },
        { provide: NOTICE_MAILER, useFactory: () => createNoticeMailer(config) },
        {
          provide: NotificationMetrics,
          useFactory: (metrics: MetricsService) => new NotificationMetrics(metrics),
          inject: [MetricsService],
        },
        {
          provide: PolicyNotificationHandler,
          useFactory: (mailer: NoticeMailer, metrics: NotificationMetrics) =>
            new PolicyNotificationHandler(new NotificationReads(), mailer, metrics, logger, {
              maxRecipients: config.NOTIFICATION_MAX_RECIPIENTS,
              portalUrl: config.PORTAL_PUBLIC_URL,
            }),
          inject: [NOTICE_MAILER, NotificationMetrics],
        },
        {
          provide: QuarantineNotificationHandler,
          useFactory: (mailer: NoticeMailer, metrics: NotificationMetrics) =>
            new QuarantineNotificationHandler(
              new QuarantineNotificationReads(),
              new NotificationReads(),
              mailer,
              metrics,
              logger,
              {
                maxRecipients: config.NOTIFICATION_MAX_RECIPIENTS,
                portalUrl: config.PORTAL_PUBLIC_URL,
              },
            ),
          inject: [NOTICE_MAILER, NotificationMetrics],
        },
        {
          provide: NOTICE_CONSUMER,
          useFactory: (
            prisma: PrismaService,
            connection: AmqpConnection,
            publisher: ConfirmPublisher,
            messaging: MessagingMetrics | null,
          ) =>
            createNotificationConsumer({
              connection,
              publisher,
              prisma,
              prefetch: config.NOTIFICATION_PREFETCH,
              txTimeoutMs: config.NOTIFICATION_DB_TX_TIMEOUT_MS,
              logger,
              ...(messaging ? { metrics: messaging } : {}),
            }),
          inject: [PrismaService, AmqpConnection, ConfirmPublisher, AMQP_MESSAGING_METRICS],
        },
        NotificationRuntime,
      ],
    };
  }
}
