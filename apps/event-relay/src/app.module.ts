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
import { EXCHANGE_NAMES } from '@email-gateway/event-contracts';
import { createLogger } from '@email-gateway/logger';
import type { RelayConfig } from './config';
import { EventRelayModule, RELAY_APP_ID } from './event-relay.module';

export const SERVICE_NAME = 'event-relay';

/**
 * event-relay (step 3.2 Q11/Q12, ADR-0023): the outbox relay publishes every `message_outbox`
 * row to RabbitMQ with publisher confirms and marks it published only after the confirm; the
 * reconciliation service reports outbox health and re-drives published events that a tracked
 * work queue's consumer never recorded in its ledger.
 *
 * Data plane: the MySQL **writer** only (ADR-0014), RabbitMQ as the publish-only user `eg-relay`
 * (`RABBITMQ_RELAY_URL`; exchanges verified passively, never declared), Prometheus metrics on
 * GET /metrics, readiness `mysql` + `rabbitmq`.
 */
@Module({})
export class AppModule {
  static forRoot(config: Readonly<RelayConfig>): DynamicModule {
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
        MetricsModule.forRoot({ service: SERVICE_NAME }),
        AmqpModule.forRoot({
          urls: config.RABBITMQ_RELAY_URL,
          connectionName: SERVICE_NAME,
          appId: RELAY_APP_ID,
          confirmTimeoutMs: config.RELAY_CONFIRM_TIMEOUT_MS,
          maxMessageBytes: config.RELAY_MAX_MESSAGE_BYTES,
          verify: { exchanges: [...EXCHANGE_NAMES] },
          logger,
        }),
        EventRelayModule.forRoot(config, logger),
        HealthModule.forRoot({
          service: { name: SERVICE_NAME, version: config.SERVICE_VERSION },
          indicators: [PrismaService, AmqpConnection],
        }),
      ],
    };
  }
}
