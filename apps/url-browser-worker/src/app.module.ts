import { type DynamicModule, Module } from '@nestjs/common';
import { AmqpConnection, AmqpModule, HealthModule, MetricsModule } from '@email-gateway/common';
import { createLogger } from '@email-gateway/logger';
import { BrowserPool } from './browser/browser-pool';
import type { WorkerConfig } from './config';
import { BrowserWorkerModule, INSPECT_QUEUE } from './worker/browser-worker.module';

export const SERVICE_NAME = 'url-browser-worker';

/**
 * url-browser-worker (step 4.3 U15, ADR-0032): headless Chromium in an isolated container (no
 * database, S3, Redis or token/cache secret; internal network shared only with the egress proxy
 * and RabbitMQ). Health (`browser` with the sandbox mode, `rabbitmq`) and metrics on
 * URL_BROWSER_HTTP_PORT.
 */
@Module({})
export class AppModule {
  static forRoot(config: Readonly<WorkerConfig>): DynamicModule {
    const logger = createLogger({
      service: SERVICE_NAME,
      level: config.LOG_LEVEL,
      version: config.SERVICE_VERSION,
    });
    // One module object for both imports: Nest deduplicates it, so there is ONE BrowserPool.
    const browserModule = BrowserWorkerModule.forRoot(config, logger);
    return {
      module: AppModule,
      imports: [
        AmqpModule.forRoot({
          urls: config.RABBITMQ_URL_BROWSER_URL,
          connectionName: SERVICE_NAME,
          appId: SERVICE_NAME,
          logger,
          verify: { exchanges: ['email.security', 'email.events'], queues: [INSPECT_QUEUE] },
        }),
        MetricsModule.forRoot({ service: SERVICE_NAME }),
        browserModule,
        HealthModule.forRoot({
          service: { name: SERVICE_NAME, version: config.SERVICE_VERSION },
          indicators: [AmqpConnection, BrowserPool],
          imports: [browserModule],
        }),
      ],
    };
  }
}
