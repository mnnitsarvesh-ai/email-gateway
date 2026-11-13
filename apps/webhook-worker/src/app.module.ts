import { type DynamicModule, Global, Module } from '@nestjs/common';
import {
  AmqpConnection,
  AmqpModule,
  CorrelationModule,
  DatabaseModule,
  HealthModule,
  MetricsModule,
  MetricsService,
  PrismaService,
  RedisModule,
  RedisService,
} from '@email-gateway/common';
import { createLogger } from '@email-gateway/logger';
import { hasRole, type WorkerConfig } from './config';
import { DeliveryModule } from './delivery/delivery.module';
import { FanoutModule, WEBHOOKS_QUEUE } from './fanout/fanout.module';
import { WebhookMetrics } from './metrics/webhook-metrics';

export const SERVICE_NAME = 'webhook-worker';

/** The metrics both roles share (global: the role modules inject them). */
@Global()
@Module({
  providers: [
    {
      provide: WebhookMetrics,
      useFactory: (metrics: MetricsService) => new WebhookMetrics(metrics),
      inject: [MetricsService],
    },
  ],
  exports: [WebhookMetrics],
})
export class WebhookCoreModule {}

/**
 * Webhook Service (step 6.2, docs/plan/steps/19-webhooks-notifications.md W1, ADR-0055). Roles
 * (`WEBHOOK_WORKER_ROLES`): `fanout` consumes `email.webhooks` (topology v11, broker user
 * `eg-webhook`, ledger `webhook-worker.fanout`) and projects internal events to public webhook
 * events, deliveries and security alert requests; `delivery` signs and POSTs due deliveries
 * through the SSRF-guarded client, retries, dead-letters, auto-disables, runs range replays and
 * the leader-elected maintenance. HTTP port 3075 serves probes and `/metrics` only.
 *
 * Data plane: the MySQL **writer** only; RabbitMQ for the fanout role; Redis (in-flight and rate
 * counters) for the delivery role. Readiness: mysql, plus rabbitmq (fanout: `email.events` and
 * `email.webhooks` verified passively) and redis (delivery). Compose runs both roles in one
 * container; Kubernetes runs `webhook-fanout` and `webhook-delivery` from the same image.
 */
@Module({})
export class AppModule {
  static forRoot(config: Readonly<WorkerConfig>): DynamicModule {
    const logger = createLogger({
      service: SERVICE_NAME,
      level: config.LOG_LEVEL,
      version: config.SERVICE_VERSION,
    });
    const fanout = hasRole(config, 'fanout');
    const delivery = hasRole(config, 'delivery');
    return {
      module: AppModule,
      imports: [
        CorrelationModule,
        DatabaseModule.forRoot({ url: config.DATABASE_URL }),
        MetricsModule.forRoot({ service: SERVICE_NAME }),
        WebhookCoreModule,
        ...(fanout
          ? [
              AmqpModule.forRoot({
                urls: config.RABBITMQ_WEBHOOK_URL,
                connectionName: SERVICE_NAME,
                appId: SERVICE_NAME,
                logger,
                verify: { exchanges: ['email.events'], queues: [WEBHOOKS_QUEUE] },
              }),
              FanoutModule.forRoot(config, logger),
            ]
          : []),
        ...(delivery
          ? [RedisModule.forRoot({ url: config.REDIS_URL }), DeliveryModule.forRoot(config, logger)]
          : []),
        HealthModule.forRoot({
          service: { name: SERVICE_NAME, version: config.SERVICE_VERSION },
          indicators: [
            PrismaService,
            ...(fanout ? [AmqpConnection] : []),
            ...(delivery ? [RedisService] : []),
          ],
        }),
      ],
    };
  }
}
