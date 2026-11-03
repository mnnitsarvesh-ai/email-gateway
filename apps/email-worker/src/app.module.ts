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
import { MimeIngestionModule } from './mime-ingestion/mime-ingestion.module';

export const SERVICE_NAME = 'email-worker';

/**
 * Email Processing Service: post-queue MIME ingestion (step 3.1,
 * docs/plan/steps/06-mime-ingestion.md) and, in later steps, the security engine orchestration
 * (Rspamd, ClamAV, YARA, URL, BEC, DLP) and verdict aggregation.
 *
 * Data plane: the MySQL **writer** only (no PrismaReadService, ADR-0014), S3 (EML reads and part
 * objects), Prometheus metrics on GET /metrics. RabbitMQ (`QUEUES.emailProcessing`) and Redis
 * stay connected and in readiness as in phase 0; the parse path uses neither (the transport is
 * the shared outbox feed until step 3.2).
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
          queues: [QUEUES.emailProcessing],
          connectionName: SERVICE_NAME,
        }),
        RedisModule.forRoot({ url: config.REDIS_URL }),
        S3Module.forRoot(config),
        MetricsModule.forRoot({ service: SERVICE_NAME }),
        ...(config.MIME_INGESTION_ENABLED ? [MimeIngestionModule.forRoot(config, logger)] : []),
        HealthModule.forRoot({
          service: { name: SERVICE_NAME, version: config.SERVICE_VERSION },
          indicators: [PrismaService, RabbitMqService, RedisService, S3Service],
        }),
      ],
    };
  }
}
