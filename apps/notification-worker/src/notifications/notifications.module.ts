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
  NonRetryableError,
  PrismaConsumerProgress,
  PrismaService,
  processOnceHandler,
  QueueConsumer,
} from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import {
  type EventEnvelope,
  EventTypes,
  type NotificationAlertRequestedV1,
  type PolicyNotificationRequestedV1,
  type QuarantineNotificationRequestedV1,
} from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import type { WorkerConfig } from '../config';
import { AlertNotificationHandler } from './alert-notification.handler';
import { SecurityAlertReads } from './alert-reads';
import { createNoticeMailer, type NoticeMailer } from './mailer';
import { NotificationMetrics } from './notification-metrics';
import { NotificationReads } from './notification-reads';
import {
  POLICY_NOTIFICATION_CONSUMER,
  PolicyNotificationHandler,
} from './policy-notification.handler';
import { PreferenceFilter } from './preference-filter';
import { QuarantineNotificationHandler } from './quarantine-notification.handler';
import { QuarantineNotificationReads } from './quarantine-reads';

/**
 * The payloads consumed from `email.notifications` (step 5.2 policy, step 5.3 quarantine, step
 * 6.2 security alerts).
 */
export type NotificationPayload =
  PolicyNotificationRequestedV1 | QuarantineNotificationRequestedV1 | NotificationAlertRequestedV1;

/** The event types of `email.notifications`, one handler each (dispatch by event type). */
export const NOTIFICATION_EVENT_TYPES = [
  EventTypes.PolicyNotificationRequested,
  EventTypes.QuarantineNotificationRequested,
  EventTypes.NotificationAlertRequested,
] as const;

/** The handlers `dispatchNotification` routes to. */
export interface NotificationHandlers {
  policy: Pick<PolicyNotificationHandler, 'handle'>;
  quarantine: Pick<QuarantineNotificationHandler, 'handle'>;
  alert: Pick<AlertNotificationHandler, 'handle'>;
}

/**
 * Routes one event of `email.notifications` to its handler by `eventType`. The consumer accepts
 * only `NOTIFICATION_EVENT_TYPES`; anything else here is a defect and is dead-lettered.
 */
export async function dispatchNotification(
  handlers: NotificationHandlers,
  event: EventEnvelope<NotificationPayload>,
  tx: Prisma.TransactionClient,
): Promise<void> {
  switch (event.eventType) {
    case EventTypes.PolicyNotificationRequested:
      await handlers.policy.handle(event as EventEnvelope<PolicyNotificationRequestedV1>, tx);
      return;
    case EventTypes.QuarantineNotificationRequested:
      await handlers.quarantine.handle(
        event as EventEnvelope<QuarantineNotificationRequestedV1>,
        tx,
      );
      return;
    case EventTypes.NotificationAlertRequested:
      await handlers.alert.handle(event as EventEnvelope<NotificationAlertRequestedV1>, tx);
      return;
    default:
      throw new NonRetryableError('unexpected_event_type');
  }
}

/** The queue of the policy, quarantine and security alert notices (topology v9–v11, P15). */
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
    eventTypes: [...NOTIFICATION_EVENT_TYPES],
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
    @Inject(AlertNotificationHandler) private readonly alert: AlertNotificationHandler,
    @Inject(AmqpConnection) private readonly connection: AmqpConnection,
    @Inject(ConfirmPublisher) private readonly publisher: ConfirmPublisher,
    @Inject('NOTIFICATION_TX_TIMEOUT_MS') private readonly txTimeoutMs: number,
  ) {}

  onApplicationBootstrap(): void {
    this.consumer.start(
      processOnceHandler<NotificationPayload>(
        this.prisma,
        POLICY_NOTIFICATION_CONSUMER,
        (event, tx) =>
          dispatchNotification(
            { policy: this.handler, quarantine: this.quarantine, alert: this.alert },
            event,
            tx,
          ),
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
 * The policy notices of step 5.2 (P25), the quarantine notices of step 5.3 (Q20) and the security
 * alerts of step 6.2 (N4): the `email.notifications` consumer (ledger
 * `notification-worker.policy`, retry and dead-letter per topology v11), one handler per event
 * type, the shared opt-out filter (`PreferenceFilter`), the relay mailer and the metrics. Needs
 * the global `AmqpModule`, `MetricsModule` and `DatabaseModule`.
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
          provide: PreferenceFilter,
          useFactory: (metrics: NotificationMetrics) => new PreferenceFilter(metrics, logger),
          inject: [NotificationMetrics],
        },
        {
          provide: PolicyNotificationHandler,
          useFactory: (
            mailer: NoticeMailer,
            metrics: NotificationMetrics,
            preferences: PreferenceFilter,
          ) =>
            new PolicyNotificationHandler(
              new NotificationReads(),
              mailer,
              metrics,
              logger,
              {
                maxRecipients: config.NOTIFICATION_MAX_RECIPIENTS,
                portalUrl: config.PORTAL_PUBLIC_URL,
              },
              preferences,
            ),
          inject: [NOTICE_MAILER, NotificationMetrics, PreferenceFilter],
        },
        {
          provide: AlertNotificationHandler,
          useFactory: (
            mailer: NoticeMailer,
            metrics: NotificationMetrics,
            preferences: PreferenceFilter,
          ) =>
            new AlertNotificationHandler(
              new SecurityAlertReads(),
              mailer,
              metrics,
              logger,
              {
                maxRecipients: config.NOTIFICATION_MAX_RECIPIENTS,
                portalUrl: config.PORTAL_PUBLIC_URL,
              },
              preferences,
            ),
          inject: [NOTICE_MAILER, NotificationMetrics, PreferenceFilter],
        },
        {
          provide: QuarantineNotificationHandler,
          useFactory: (
            mailer: NoticeMailer,
            metrics: NotificationMetrics,
            preferences: PreferenceFilter,
          ) =>
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
              preferences,
            ),
          inject: [NOTICE_MAILER, NotificationMetrics, PreferenceFilter],
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
