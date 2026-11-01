import { type DynamicModule, Module } from '@nestjs/common';
import {
  CorrelationModule,
  DatabaseModule,
  HealthModule,
  PrismaService,
  RedisModule,
  RedisService,
} from '@email-gateway/common';
import type { SmtpAdapterConfig } from './config';
import { PolicyModule } from './policy/policy.module';
import { PolicyServerService } from './policy/policy-server.service';

export const SERVICE_NAME = 'smtp-adapter';

/**
 * SMTP Gateway adapter: the Node side of the Postfix integration.
 * - Postfix policy delegation server (in-session recipient/tenant/rate-limit checks).
 * - Later: LMTP listener for the Email Ingestion Service (post-queue handoff).
 */
@Module({})
export class AppModule {
  static forRoot(config: Readonly<SmtpAdapterConfig>): DynamicModule {
    return {
      module: AppModule,
      imports: [
        CorrelationModule,
        DatabaseModule.forRoot({ url: config.DATABASE_URL }),
        RedisModule.forRoot({ url: config.REDIS_URL }),
        PolicyModule.forRoot({
          host: config.POLICY_HOST,
          port: config.POLICY_PORT,
          logLevel: config.LOG_LEVEL,
        }),
        HealthModule.forRoot({
          service: { name: SERVICE_NAME, version: config.SERVICE_VERSION },
          indicators: [PrismaService, RedisService, PolicyServerService],
        }),
      ],
    };
  }
}
