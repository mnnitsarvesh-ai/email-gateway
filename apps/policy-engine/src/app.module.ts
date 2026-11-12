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
import { hasRole, type WorkerConfig } from './config';
import { PolicyEngineCoreModule } from './core.module';
import { EvaluationModule } from './evaluation/evaluation.module';
import { POLICY_EVALUATE_QUEUE } from './evaluation/policy-evaluate.consumer';
import { QuarantineModule } from './quarantine/quarantine.module';
import { QUARANTINE_QUEUE } from './quarantine/release.consumer';

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
 * Step 5.3 (docs/plan/steps/17-quarantine.md Q28, ADR-0046): `POLICY_ENGINE_ROLES` selects the
 * modules: `evaluate` = the evaluation consumer above (per-recipient decisions, quarantine
 * entries, WARN banners and URL rewriting after the scan); `quarantine` = the release executor
 * on `email.quarantine` and the leader-elected sweeper (expiry, approvals, purge, adoption,
 * digests, retention). Compose runs both in one container; Kubernetes runs `policy-engine`
 * (evaluate) and `quarantine-worker` (quarantine) from the same image.
 *
 * Data plane: the MySQL **writer** only (ADR-0014), S3 (mail bucket), Redis (readiness, as in
 * phase 0), Prometheus metrics on GET /metrics. Readiness: mysql, rabbitmq (the role's queues
 * verified), redis, s3; the sweeper's leader state is a metric, not a readiness gate.
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
          verify: {
            exchanges: ['email.policy', 'email.events'],
            queues: [
              ...(hasRole(config, 'evaluate') ? [POLICY_EVALUATE_QUEUE] : []),
              ...(hasRole(config, 'quarantine') ? [QUARANTINE_QUEUE] : []),
            ],
          },
        }),
        RedisModule.forRoot({ url: config.REDIS_URL }),
        S3Module.forRoot(config),
        MetricsModule.forRoot({ service: SERVICE_NAME }),
        PolicyEngineCoreModule.forRoot(config, logger),
        ...(hasRole(config, 'evaluate') ? [EvaluationModule.forRoot(config, logger)] : []),
        ...(hasRole(config, 'quarantine') ? [QuarantineModule.forRoot(config, logger)] : []),
        HealthModule.forRoot({
          service: { name: SERVICE_NAME, version: config.SERVICE_VERSION },
          indicators: [PrismaService, AmqpConnection, RedisService, S3Service],
        }),
      ],
    };
  }
}
