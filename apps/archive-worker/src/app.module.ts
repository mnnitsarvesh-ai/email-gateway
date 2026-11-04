import { type DynamicModule, Module } from '@nestjs/common';
import {
  CorrelationModule,
  DatabaseModule,
  HealthModule,
  PrismaService,
  S3Module,
  S3Service,
} from '@email-gateway/common';
import type { WorkerConfig } from './config';

export const SERVICE_NAME = 'archive-worker';

/**
 * Archive Service: writes archive copies for tenants that enabled archiving (off by default).
 *
 * Phase 0: connects to its dependencies and exposes health probes. It consumes nothing yet, so
 * since step 3.2 (docs/plan/steps/07-rabbitmq.md Q10) it does not connect to RabbitMQ at all and
 * its readiness has no `rabbitmq` check. Its own step (8.1) adds a least-privilege role user and
 * its `QueueConsumer` of `email.archive` (`AmqpModule` from @email-gateway/common), which acks
 * only after its effects committed through `processOnce` (@email-gateway/database).
 */
@Module({})
export class AppModule {
  static forRoot(config: Readonly<WorkerConfig>): DynamicModule {
    return {
      module: AppModule,
      imports: [
        CorrelationModule,
        DatabaseModule.forRoot({ url: config.DATABASE_URL }),
        S3Module.forRoot(config),
        HealthModule.forRoot({
          service: { name: SERVICE_NAME, version: config.SERVICE_VERSION },
          indicators: [PrismaService, S3Service],
        }),
      ],
    };
  }
}
