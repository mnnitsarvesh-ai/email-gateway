import { type DynamicModule, Global, Module } from '@nestjs/common';
import {
  DatabaseModule,
  METRICS_OPTIONS,
  MetricsService,
  RedisModule,
} from '@email-gateway/common';
import type { Logger } from '@email-gateway/logger';
import { ClickModule } from './click/click.module';
import type { ClickConfig } from './config';

export const SERVICE_NAME = 'click-service';

/** MetricsService without MetricsModule's controller: /metrics lives on the admin listener only. */
@Global()
@Module({})
class MetricsRegistryModule {
  static forRoot(service: string): DynamicModule {
    return {
      module: MetricsRegistryModule,
      providers: [{ provide: METRICS_OPTIONS, useValue: { service } }, MetricsService],
      exports: [MetricsService],
    };
  }
}

/**
 * Time-of-click service (step 4.3 U14, ADR-0031): an anonymous, Internet-facing endpoint that
 * verifies click tokens, re-checks the stored URL and redirects, warns or blocks. Data access:
 * its own MySQL account `gateway_click` on the writer (CLICK_DATABASE_URL, table grants only),
 * Redis for rate limits and the authenticated URL cache. No S3, no RabbitMQ, no other secret.
 */
@Module({})
export class AppModule {
  static forRoot(config: Readonly<ClickConfig>, logger: Logger): DynamicModule {
    return {
      module: AppModule,
      imports: [
        DatabaseModule.forRoot({
          url: config.CLICK_DATABASE_URL,
          socketTimeoutSeconds: config.DATABASE_SOCKET_TIMEOUT_SECONDS,
        }),
        RedisModule.forRoot({ url: config.REDIS_URL }),
        MetricsRegistryModule.forRoot(SERVICE_NAME),
        ClickModule.forRoot(config, logger),
      ],
    };
  }
}
