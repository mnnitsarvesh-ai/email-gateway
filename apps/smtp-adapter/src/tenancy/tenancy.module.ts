import { Module } from '@nestjs/common';
import { DomainCacheInvalidator } from './domain-cache-invalidator.service';
import { DomainPolicyService } from './domain-policy.service';
import { RecipientValidator } from './recipient-validator.service';
import { RedisJsonCache } from './redis-json-cache';
import { TenantLimitsService } from './tenant-limits.service';

/**
 * Tenant resolution for the in-session services (step 2.2 D3, D5, D6): domain policy views,
 * organization limits, recipient allow-lists, their Redis cache and its invalidation.
 * Needs the global DatabaseModule (writer only), RedisModule, MetricsModule and the adapter's
 * ADAPTER_CONFIG / ADAPTER_LOGGER providers.
 */
@Module({
  providers: [
    RedisJsonCache,
    DomainPolicyService,
    DomainCacheInvalidator,
    TenantLimitsService,
    RecipientValidator,
  ],
  exports: [RedisJsonCache, DomainPolicyService, TenantLimitsService, RecipientValidator],
})
export class TenancyModule {}
