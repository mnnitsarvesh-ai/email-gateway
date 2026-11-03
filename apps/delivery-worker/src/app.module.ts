import { type DynamicModule, Module } from '@nestjs/common';
import {
  CorrelationModule,
  DatabaseModule,
  HealthModule,
  MetricsModule,
  PrismaService,
  RabbitMqModule,
  RabbitMqService,
  RedisModule,
  RedisService,
  S3Module,
  S3Service,
} from '@email-gateway/common';
import { QUEUES } from '@email-gateway/event-contracts';
import { createLogger } from '@email-gateway/logger';
import type { WorkerConfig } from './config';
import { DeliveryModule } from './delivery.module';

export const SERVICE_NAME = 'delivery-worker';

/**
 * Email Delivery Service (step 2.3, docs/plan/steps/05-routing.md): plans approved deliveries
 * per recipient, reinjects them into postfix-outbound (which owns every remote retry, ADR-0006),
 * and tracks per-recipient delivery status from Postfix's delivery log.
 *
 * Data plane: the MySQL **writer** only (no PrismaReadService, ADR-0014), Redis (rate limits),
 * S3 (EML stream), Prometheus metrics on GET /metrics. The RabbitMQ connection and its
 * `QUEUES.delivery` assertion are kept exactly as in phase 0: step 2.3 adds no topology (the
 * approval transport is the outbox poller until step 3.2).
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
        RabbitMqModule.forRoot({
          url: config.RABBITMQ_URL,
          prefetch: config.RABBITMQ_PREFETCH,
          queues: [QUEUES.delivery],
          connectionName: SERVICE_NAME,
        }),
        RedisModule.forRoot({ url: config.REDIS_URL }),
        S3Module.forRoot(config),
        MetricsModule.forRoot({ service: SERVICE_NAME }),
        DeliveryModule.forRoot(config, logger),
        HealthModule.forRoot({
          service: { name: SERVICE_NAME, version: config.SERVICE_VERSION },
          indicators: [PrismaService, RabbitMqService, RedisService, S3Service],
        }),
      ],
    };
  }
}
