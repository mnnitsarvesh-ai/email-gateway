import { type DynamicModule, Module } from '@nestjs/common';
import {
  CorrelationModule,
  DatabaseModule,
  HealthModule,
  PrismaService,
  RabbitMqModule,
  RabbitMqService,
  RedisModule,
  RedisService,
  S3Module,
  S3Service,
} from '@email-gateway/common';
import { QUEUES } from '@email-gateway/event-contracts';
import type { WorkerConfig } from './config';

export const SERVICE_NAME = 'email-worker';

/**
 * Email Processing Service and Security Engine orchestration: parses messages from S3, fans out to
 * security engines (Rspamd, ClamAV, YARA, URL, BEC, DLP) and aggregates verdicts.
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
          queues: [QUEUES.emailProcessing],
          connectionName: SERVICE_NAME,
        }),
        RedisModule.forRoot({ url: config.REDIS_URL }),
        S3Module.forRoot(config),
        HealthModule.forRoot({
          service: { name: SERVICE_NAME, version: config.SERVICE_VERSION },
          indicators: [PrismaService, RabbitMqService, RedisService, S3Service],
        }),
      ],
    };
  }
}
