import { type DynamicModule, Module, type Type } from '@nestjs/common';
import {
  AmqpConnection,
  AmqpModule,
  CorrelationModule,
  DatabaseModule,
  type HealthIndicator,
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
import { runsAttachmentConsumer, runsBecConsumer, runsUrlConsumer } from './scanning/config';
import {
  BecEngineHealth,
  ClamavHealth,
  InspectorHealth,
  ScannerBrokerHealth,
  ScanningModule,
  UrlEngineHealth,
} from './scanning/scanning.module';

export const SERVICE_NAME = 'email-worker';

/**
 * Email Processing Service: post-queue MIME ingestion (step 3.1,
 * docs/plan/steps/06-mime-ingestion.md) and the security scan stage (step 4.1,
 * docs/plan/steps/09-rspamd.md: per-engine queues, scan rounds, Rspamd as the first engine).
 *
 * Two roles of one image (S1), switched by `MIME_INGESTION_ENABLED` and `SCAN_ENABLED` (locally
 * both in one process; production runs `email-worker` (MIME) and `email-worker-scan`):
 *
 * - MIME: queue `email.received` through the global `AmqpModule` with the worker's role user
 *   (`RABBITMQ_EMAIL_WORKER_URL`); readiness `rabbitmq` (exchanges and queue verified passively).
 *   The global AMQP client is imported only with this role.
 * - Scan: `ScanningModule` with its own connection and publisher (`RABBITMQ_SCANNER_URL`, user
 *   `eg-scanner`: read `scan.spam`, write `email.security` / `email.events`); readiness
 *   `rabbitmq-scanner`.
 *
 * Data plane: the MySQL **writer** only (no PrismaReadService, ADR-0014), S3 (EML reads and part
 * objects), Prometheus metrics on GET /metrics. Events are written to the outbox (the
 * event-relay publishes them). Redis stays connected and in readiness as in phase 0.
 */
@Module({})
export class AppModule {
  static forRoot(config: Readonly<WorkerConfig>): DynamicModule {
    const logger = createLogger({
      service: SERVICE_NAME,
      level: config.LOG_LEVEL,
      version: config.SERVICE_VERSION,
    });
    const mime = config.MIME_INGESTION_ENABLED && config.RABBITMQ_EMAIL_WORKER_URL !== undefined;
    // One module object: AppModule and HealthModule (for its indicator) share the instance.
    const scanning = config.SCAN_ENABLED ? ScanningModule.forRoot(config, logger) : null;
    const indicators: Type<HealthIndicator>[] = [PrismaService];
    if (mime) indicators.push(AmqpConnection);
    if (scanning) indicators.push(ScannerBrokerHealth);
    // Step 4.2 A12: clamd PING and the inspector pool on replicas running the attachment engine.
    if (scanning && runsAttachmentConsumer(config)) indicators.push(ClamavHealth, InspectorHealth);
    // Step 4.3 U3: Redis (URL cache) and the DNS resolver on replicas running the url engine.
    if (scanning && runsUrlConsumer(config)) indicators.push(UrlEngineHealth);
    // Step 4.4 B16: the packaged model and lexicons on replicas running the bec engine.
    if (scanning && runsBecConsumer(config)) indicators.push(BecEngineHealth);
    indicators.push(RedisService, S3Service);
    return {
      module: AppModule,
      imports: [
        CorrelationModule,
        DatabaseModule.forRoot({ url: config.DATABASE_URL }),
        ...(mime && config.RABBITMQ_EMAIL_WORKER_URL
          ? [
              AmqpModule.forRoot({
                urls: config.RABBITMQ_EMAIL_WORKER_URL,
                connectionName: SERVICE_NAME,
                appId: SERVICE_NAME,
                logger,
                verify: { exchanges: ['email.ingestion', 'email.events'], queues: [MIME_QUEUE] },
              }),
            ]
          : []),
        RedisModule.forRoot({ url: config.REDIS_URL }),
        S3Module.forRoot(config),
        MetricsModule.forRoot({ service: SERVICE_NAME }),
        ...(mime ? [MimeIngestionModule.forRoot(config, logger)] : []),
        ...(scanning ? [scanning] : []),
        HealthModule.forRoot({
          service: { name: SERVICE_NAME, version: config.SERVICE_VERSION },
          indicators,
          ...(scanning ? { imports: [scanning] } : {}),
        }),
      ],
    };
  }
}
