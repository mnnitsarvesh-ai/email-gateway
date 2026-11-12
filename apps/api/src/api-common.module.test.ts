import { Global, Module } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import {
  METRICS_OPTIONS,
  MetricsService,
  PrismaReadService,
  PrismaService,
  RedisService,
} from '@email-gateway/common';
import { describe, expect, it } from 'vitest';
import { RecordingEmailSender } from '../test/support/recording-email-sender';
import { ApiCommonModule } from './api-common.module';
import { API_CONFIG } from './api-config.token';
import { AuditService } from './audit/audit.service';
import { loadApiConfig } from './config';
import { PasswordHasher } from './crypto/password-hasher';
import { SecretBox } from './crypto/secret-box';
import { TokenHasher } from './crypto/tokens';
import { TransactionRunner } from './database/transaction-runner';
import { EmailSender } from './email/email-sender';
import { LogEmailSender } from './email/log-email-sender';
import { KeyValueStore } from './kv/key-value-store';
import { RedisKeyValueStore } from './kv/redis-key-value-store';
import { ApiConventionMetrics } from './http/api-metrics';
import { CursorCodec } from './http/cursor/cursor-codec';
import { IdempotencyReservationRepository } from './http/idempotency/idempotency-reservation.repository';
import { IdempotencyReservationService } from './http/idempotency/idempotency-reservation.service';
import { IdempotencyInterceptor } from './http/idempotency/idempotency.interceptor';
import { IdempotencyRepository } from './http/idempotency/idempotency.repository';
import { IdempotencyService } from './http/idempotency/idempotency.service';
import { RateLimitGuard } from './rate-limit/rate-limit.guard';
import { TenantRateLimitResolver } from './rate-limit/tenant-rate-limit.resolver';
import { OrganizationFeaturesService } from './tenancy/organization-features.service';
import { OrganizationLimitsService } from './tenancy/organization-limits.service';
import { TEST_DOMAIN_ENV } from '../test/support/test-env';

const config = loadApiConfig({
  ...TEST_DOMAIN_ENV,
  DATABASE_URL: 'mysql://u:p@mysql:3306/db',
  REDIS_URL: 'redis://redis:6379',
  S3_REGION: 'ap-south-1',
  S3_BUCKET_MAIL: 'mail',
  S3_BUCKET_ARCHIVE: 'archive',
  AUTH_JWT_SECRET: 'j'.repeat(64),
  AUTH_TOKEN_PEPPER: 'p'.repeat(64),
  DATA_ENCRYPTION_KEY: 'a'.repeat(64),
});

/** Stands in for the root module, which provides these globally in the app. */
@Global()
@Module({
  providers: [
    { provide: API_CONFIG, useValue: config },
    { provide: PrismaService, useValue: {} },
    { provide: RedisService, useValue: { client: {} } },
    { provide: PrismaReadService, useValue: {} },
    { provide: METRICS_OPTIONS, useValue: { service: 'api-test' } },
    MetricsService,
  ],
  exports: [API_CONFIG, PrismaService, RedisService, PrismaReadService, MetricsService],
})
class RootStub {}

async function compile(overrideEmail = false) {
  let builder = Test.createTestingModule({ imports: [RootStub, ApiCommonModule] });
  if (overrideEmail) {
    builder = builder.overrideProvider(EmailSender).useValue(new RecordingEmailSender());
  }
  return builder.compile();
}

describe('ApiCommonModule', () => {
  it('provides every shared building block', async () => {
    const moduleRef = await compile();
    expect(moduleRef.get(KeyValueStore)).toBeInstanceOf(RedisKeyValueStore);
    expect(moduleRef.get(EmailSender)).toBeInstanceOf(LogEmailSender);
    for (const token of [
      SecretBox,
      TokenHasher,
      PasswordHasher,
      AuditService,
      TransactionRunner,
      OrganizationLimitsService,
      OrganizationFeaturesService,
      RateLimitGuard,
      ApiConventionMetrics,
      CursorCodec,
      TenantRateLimitResolver,
      IdempotencyRepository,
      IdempotencyService,
      IdempotencyReservationRepository,
      IdempotencyReservationService,
      IdempotencyInterceptor,
    ]) {
      expect(moduleRef.get(token)).toBeInstanceOf(token);
    }
  });

  it('lets tests replace the email sender', async () => {
    const moduleRef = await compile(true);
    expect(moduleRef.get(EmailSender)).toBeInstanceOf(RecordingEmailSender);
  });
});
