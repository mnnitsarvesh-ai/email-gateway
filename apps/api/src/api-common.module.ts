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
import { RateLimitGuard } from './rate-limit/rate-limit.guard';
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
];

/**
 * Building blocks shared by every API feature module (D2). Global, so feature modules inject
 * them without importing this module. Relies on API_CONFIG, PrismaService and RedisService from
 * the root module. Tests override `KeyValueStore` and `EmailSender` with in-memory doubles.
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
