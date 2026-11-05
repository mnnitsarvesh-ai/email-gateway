import { type DynamicModule, Module } from '@nestjs/common';
import {
  AmqpConnection,
  AmqpModule,
  CorrelationModule,
  DatabaseModule,
  HealthModule,
  MetricsModule,
  PrismaService,
  RedisModule,
  RedisService,
  S3Module,
  S3Service,
} from '@email-gateway/common';
import { createLogger } from '@email-gateway/logger';
import { APPROVAL_QUEUE } from './approvals/approval-feed';
import type { WorkerConfig } from './config';
import { DeliveryModule } from './delivery.module';

export const SERVICE_NAME = 'delivery-worker';

/**
 * Email Delivery Service (step 2.3, docs/plan/steps/05-routing.md): plans approved deliveries
 * per recipient, reinjects them into postfix-outbound (which owns every remote retry, ADR-0006),
 * and tracks per-recipient delivery status from Postfix's delivery log.
 *
 * Data plane: the MySQL **writer** only (no PrismaReadService, ADR-0014), Redis (rate limits),
 * S3 (EML stream), Prometheus metrics on GET /metrics. Approvals arrive over RabbitMQ (step 3.2
 * Q13): queue `email.delivery.pending` through `AmqpModule` with the worker's own role user
 * (`RABBITMQ_DELIVERY_WORKER_URL`: read `email.delivery.pending`, write `email.delivery` /
 * `email.events` for delay and dead-letter copies); readiness `rabbitmq` = connected, not
 * blocked, exchanges and queue verified passively (services never declare).
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
        DatabaseModule.forRoot({
          url: config.DATABASE_URL,
          socketTimeoutSeconds: config.DATABASE_SOCKET_TIMEOUT_SECONDS,
        }),
        AmqpModule.forRoot({
          urls: config.RABBITMQ_DELIVERY_WORKER_URL,
          connectionName: SERVICE_NAME,
          appId: SERVICE_NAME,
          logger,
          verify: { exchanges: ['email.delivery', 'email.events'], queues: [APPROVAL_QUEUE] },
        }),
        RedisModule.forRoot({ url: config.REDIS_URL }),
        S3Module.forRoot(config),
        MetricsModule.forRoot({ service: SERVICE_NAME }),
        DeliveryModule.forRoot(config, logger),
        HealthModule.forRoot({
          service: { name: SERVICE_NAME, version: config.SERVICE_VERSION },
          indicators: [PrismaService, AmqpConnection, RedisService, S3Service],
        }),
      ],
    };
  }
}
