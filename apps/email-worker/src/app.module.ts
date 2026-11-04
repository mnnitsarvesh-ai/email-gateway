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
import { MIME_QUEUE, type WorkerConfig } from './config';
import { MimeIngestionModule } from './mime-ingestion/mime-ingestion.module';

export const SERVICE_NAME = 'email-worker';

/**
 * Email Processing Service: post-queue MIME ingestion (step 3.1,
 * docs/plan/steps/06-mime-ingestion.md) and, in later steps, the security engine orchestration
 * (Rspamd, ClamAV, YARA, URL, BEC, DLP) and verdict aggregation.
 *
 * Data plane: the MySQL **writer** only (no PrismaReadService, ADR-0014), S3 (EML reads and part
 * objects), Prometheus metrics on GET /metrics. Transport (step 3.2 Q13): RabbitMQ queue
 * `email.received` through `AmqpModule` with the worker's own role user
 * (`RABBITMQ_EMAIL_WORKER_URL`: read `email.received`, write `email.ingestion` / `email.events`
 * for retry and dead-letter copies); readiness `rabbitmq` = connected, not blocked, exchanges and
 * queue verified passively (services never declare). The parse events still go through the
 * outbox (the event-relay publishes them). Redis stays connected and in readiness as in phase 0.
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
          urls: config.RABBITMQ_EMAIL_WORKER_URL,
          connectionName: SERVICE_NAME,
          appId: SERVICE_NAME,
          logger,
          verify: { exchanges: ['email.ingestion', 'email.events'], queues: [MIME_QUEUE] },
        }),
        RedisModule.forRoot({ url: config.REDIS_URL }),
        S3Module.forRoot(config),
        MetricsModule.forRoot({ service: SERVICE_NAME }),
        ...(config.MIME_INGESTION_ENABLED ? [MimeIngestionModule.forRoot(config, logger)] : []),
        HealthModule.forRoot({
          service: { name: SERVICE_NAME, version: config.SERVICE_VERSION },
          indicators: [PrismaService, AmqpConnection, RedisService, S3Service],
        }),
      ],
    };
  }
}
