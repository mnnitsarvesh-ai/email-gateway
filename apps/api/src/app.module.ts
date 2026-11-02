import { type DynamicModule, Module } from '@nestjs/common';
import {
  CorrelationModule,
  DatabaseModule,
  HealthModule,
  PrismaReadService,
  PrismaService,
  RedisModule,
  RedisService,
  S3Module,
  S3Service,
} from '@email-gateway/common';
import { ApiCommonModule } from './api-common.module';
import { API_CONFIG } from './api-config.token';
import type { ApiConfig } from './config';
import { MetaModule } from './meta/meta.module';
import { ApiKeysModule } from './modules/api-keys/api-keys.module';
import { AuthModule } from './modules/auth/auth.module';
import { LoginAuditModule } from './modules/login-audit/login-audit.module';
import { OrganizationsModule } from './modules/organizations/organizations.module';
import { RolesModule } from './modules/roles/roles.module';
import { TenantDataModule } from './modules/tenant-data/tenant-data.module';
import { UsersModule } from './modules/users/users.module';

export const SERVICE_NAME = 'api';

@Module({})
export class AppModule {
  static forRoot(config: Readonly<ApiConfig>): DynamicModule {
    return {
      module: AppModule,
      global: true,
      imports: [
        CorrelationModule,
        DatabaseModule.forRoot({
          url: config.DATABASE_URL,
          read: {
            url: config.DATABASE_READ_URL,
            maxLagSeconds: config.DATABASE_READ_MAX_LAG_SECONDS,
            lagCheckIntervalMs: config.DATABASE_READ_LAG_CHECK_INTERVAL_MS,
          },
        }),
        RedisModule.forRoot({ url: config.REDIS_URL }),
        S3Module.forRoot(config),
        HealthModule.forRoot({
          service: { name: SERVICE_NAME, version: config.SERVICE_VERSION },
          indicators: [PrismaService, PrismaReadService, RedisService, S3Service],
        }),
        ApiCommonModule,
        // Registers the global AuthGuard → PermissionsGuard and the override audit interceptor.
        AuthModule,
        MetaModule,
        UsersModule,
        RolesModule,
        ApiKeysModule,
        LoginAuditModule,
        TenantDataModule,
        OrganizationsModule,
      ],
      providers: [{ provide: API_CONFIG, useValue: config }],
      exports: [API_CONFIG],
    };
  }
}
