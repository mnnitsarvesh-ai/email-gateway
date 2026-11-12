import { Global, Module } from '@nestjs/common';
import { AuditService } from './audit/audit.service';
import { PasswordHasher } from './crypto/password-hasher';
import { SecretBox } from './crypto/secret-box';
import { TokenHasher } from './crypto/tokens';
import { TransactionRunner } from './database/transaction-runner';
import { EmailSender } from './email/email-sender';
import { emailSenderProvider } from './email/email-sender.factory';
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

const shared = [
  SecretBox,
  TokenHasher,
  PasswordHasher,
  AuditService,
  TransactionRunner,
  OrganizationLimitsService,
  OrganizationFeaturesService,
  RateLimitGuard,
  // Step 6.1 conventions: metrics, v1 cursors, the global limiter's tenant limits and the
  // Idempotency-Key store + reservation interceptor, injectable from every feature module.
  ApiConventionMetrics,
  CursorCodec,
  TenantRateLimitResolver,
  IdempotencyRepository,
  IdempotencyService,
  IdempotencyReservationRepository,
  IdempotencyReservationService,
  IdempotencyInterceptor,
];

/**
 * Building blocks shared by every API feature module (D2). Global, so feature modules inject
 * them without importing this module. Relies on API_CONFIG, PrismaService and RedisService from
 * the root module (and, since step 6.1, MetricsService and PrismaReadService). Tests override
 * `KeyValueStore` and `EmailSender` with in-memory doubles.
 */
@Global()
@Module({
  providers: [
    { provide: KeyValueStore, useClass: RedisKeyValueStore },
    emailSenderProvider,
    ...shared,
  ],
  exports: [KeyValueStore, EmailSender, ...shared],
})
export class ApiCommonModule {}
