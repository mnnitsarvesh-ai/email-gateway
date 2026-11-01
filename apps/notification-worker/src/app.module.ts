import { type DynamicModule, Module } from '@nestjs/common';
import {
  CorrelationModule,
  DatabaseModule,
  HealthModule,
  PrismaService,
  RabbitMqModule,
  RabbitMqService,
} from '@email-gateway/common';
import { QUEUES } from '@email-gateway/event-contracts';
import type { WorkerConfig } from './config';

export const SERVICE_NAME = 'notification-worker';

/**
 * Notification Service: quarantine digests, admin alerts and end-user notifications.
 *
 * Phase 0: connects to its dependencies, asserts its queue topology and exposes health probes.
 * Consumers are added in later phases; each must ack only after its effects are committed and
 * use `processOnce` from @email-gateway/database for idempotency.
 */
@Module({})
export class AppModule {
  static forRoot(config: Readonly<WorkerConfig>): DynamicModule {
    return {
      module: AppModule,
      imports: [
        CorrelationModule,
        DatabaseModule.forRoot({ url: config.DATABASE_URL }),
        RabbitMqModule.forRoot({
          url: config.RABBITMQ_URL,
          prefetch: config.RABBITMQ_PREFETCH,
          queues: [QUEUES.notification],
          connectionName: SERVICE_NAME,
        }),
        HealthModule.forRoot({
          service: { name: SERVICE_NAME, version: config.SERVICE_VERSION },
          indicators: [PrismaService, RabbitMqService],
        }),
      ],
    };
  }
}
