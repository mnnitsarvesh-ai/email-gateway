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
import type { WorkerConfig } from './config';
import { EvaluationModule } from './evaluation/evaluation.module';
import { POLICY_EVALUATE_QUEUE } from './evaluation/policy-evaluate.consumer';

export const SERVICE_NAME = 'policy-engine';

/**
 * Policy Engine (step 5.2, docs/plan/steps/16-policy-engine.md P13, ADR-0043/0044/0045): the only
 * automatic producer of delivery approvals. Consumes `email.policy.evaluate`
 * (`mail.message.scanned.v1`, `mail.message.parse_failed.v1`) as its least-privilege role user
 * `eg-policy-engine` (`RABBITMQ_POLICY_ENGINE_URL`), evaluates the tenant's compiled policy
 * snapshot with `@email-gateway/policy-dsl` and commits, in one writer transaction, the evaluation
 * row, the lifecycle edges (E5/E8/E9 then E10–E13), the message's final columns and the outbox
 * events (decision, approvals, archive and notification requests). ALLOW with TAG/WARN header
 * edits delivers a policy copy written to the mail bucket.
 *
 * Data plane: the MySQL **writer** only (ADR-0014), S3 (mail bucket), Redis (readiness, as in
 * phase 0), Prometheus metrics on GET /metrics. Readiness: mysql, rabbitmq, redis, s3.
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
          urls: config.RABBITMQ_POLICY_ENGINE_URL,
          connectionName: SERVICE_NAME,
          appId: SERVICE_NAME,
          logger,
          verify: { exchanges: ['email.policy', 'email.events'], queues: [POLICY_EVALUATE_QUEUE] },
        }),
        RedisModule.forRoot({ url: config.REDIS_URL }),
        S3Module.forRoot(config),
        MetricsModule.forRoot({ service: SERVICE_NAME }),
        EvaluationModule.forRoot(config, logger),
        HealthModule.forRoot({
          service: { name: SERVICE_NAME, version: config.SERVICE_VERSION },
          indicators: [PrismaService, AmqpConnection, RedisService, S3Service],
        }),
      ],
    };
  }
}
