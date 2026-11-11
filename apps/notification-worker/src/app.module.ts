import { type DynamicModule, Module } from '@nestjs/common';
import {
  AmqpConnection,
  AmqpModule,
  CorrelationModule,
  DatabaseModule,
  HealthModule,
  MetricsModule,
  PrismaService,
} from '@email-gateway/common';
import { createLogger } from '@email-gateway/logger';
import type { WorkerConfig } from './config';
import { NOTIFICATION_QUEUE, NotificationsModule } from './notifications/notifications.module';

export const SERVICE_NAME = 'notification-worker';

/**
 * Notification Service. Step 5.2 (docs/plan/steps/16-policy-engine.md P25): the policy notices
 * only — ALERT actions (to the organization's policy administrators) and sender non-delivery
 * notices of rejected outbound/internal mail — consumed from `email.notifications` as the
 * least-privilege broker user `eg-notification` (`RABBITMQ_NOTIFICATION_URL`) and sent through
 * the `NOTIFY_SMTP_*` relay. Digests, webhooks and user preferences are step 6.2. Writer database
 * only; readiness checks mysql and rabbitmq (connected, not blocked, exchanges and queue verified
 * passively); Prometheus metrics on GET /metrics.
 */
@Module({})
export class AppModule {
  static forRoot(config: Readonly<WorkerConfig>): DynamicModule {
    const logger = createLogger({
      service: SERVICE_NAME,
      level: config.LOG_LEVEL,
      version: config.SERVICE_VERSION,
    });
    return {
      module: AppModule,
      imports: [
        CorrelationModule,
        DatabaseModule.forRoot({ url: config.DATABASE_URL }),
        AmqpModule.forRoot({
          urls: config.RABBITMQ_NOTIFICATION_URL,
          connectionName: SERVICE_NAME,
          appId: SERVICE_NAME,
          logger,
          verify: { exchanges: ['email.policy', 'email.events'], queues: [NOTIFICATION_QUEUE] },
        }),
        MetricsModule.forRoot({ service: SERVICE_NAME }),
        NotificationsModule.forRoot(config, logger),
        HealthModule.forRoot({
          service: { name: SERVICE_NAME, version: config.SERVICE_VERSION },
          indicators: [PrismaService, AmqpConnection],
        }),
      ],
    };
  }
}
