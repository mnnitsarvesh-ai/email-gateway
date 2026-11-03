import { Inject, Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import { z } from 'zod';
import { ADAPTER_CONFIG, type SmtpAdapterConfig } from '../config';
import { cacheKeys } from './cache-keys';
import { RedisJsonCache } from './redis-json-cache';

/** Per-organization limits enforced in-session (step 2.2 D4, D6, D11). */
export interface TenantLimits {
  inboundRecipientsPerMinute: number;
  outboundRecipientsPerMinute: number;
  outboundRecipientsPerDay: number;
  /** `organization_limits.max_message_size_bytes`; null = no organization-level limit. */
  maxMessageSizeBytes: number | null;
}

export const LIMITS_CACHE_TTL_SECONDS = 60;

const LIMIT_KEYS = {
  inboundRecipientsPerMinute: 'inbound_recipients_per_minute',
  outboundRecipientsPerMinute: 'outbound_recipients_per_minute',
  outboundRecipientsPerDay: 'outbound_recipients_per_day',
  maxMessageSizeBytes: 'max_message_size_bytes',
} as const;

const limitsDto = z.object({
  inboundRecipientsPerMinute: z.number().int().nonnegative(),
  outboundRecipientsPerMinute: z.number().int().nonnegative(),
  outboundRecipientsPerDay: z.number().int().nonnegative(),
  maxMessageSizeBytes: z.number().int().nonnegative().nullable(),
});

export type TenantLimitsConfig = Pick<
  SmtpAdapterConfig,
  | 'SMTP_RATE_TENANT_INBOUND_RCPT_PER_MINUTE'
  | 'SMTP_RATE_TENANT_OUTBOUND_RCPT_PER_MINUTE'
  | 'SMTP_RATE_TENANT_OUTBOUND_RCPT_PER_DAY'
>;

/**
 * Reads the organization's `organization_limits` rows (writer, one query on the unique
 * `(organization_id, limit_key)` prefix), cached in Redis under `sa:lim:{orgId}` for 60 s.
 * Missing rows use the SMTP_RATE_TENANT_* defaults (D6); a value of 0 means "no mail of that
 * kind". Cache errors fall back to the database; database errors propagate.
 */
@Injectable()
export class TenantLimitsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly cache: RedisJsonCache,
    @Inject(ADAPTER_CONFIG) private readonly config: TenantLimitsConfig,
  ) {}

  async get(organizationId: bigint): Promise<TenantLimits> {
    const limits = await this.cache.getOrLoad({
      cache: 'limits',
      key: cacheKeys.limits(organizationId),
      ttlSeconds: LIMITS_CACHE_TTL_SECONDS,
      negativeTtlSeconds: LIMITS_CACHE_TTL_SECONDS,
      schema: limitsDto,
      load: () => this.load(organizationId),
    });
    // load() never returns null; a cached `null` would only come from a foreign writer.
    return limits ?? this.defaults();
  }

  private async load(organizationId: bigint): Promise<TenantLimits> {
    const rows = await this.prisma.organizationLimit.findMany({
      where: { organizationId, limitKey: { in: Object.values(LIMIT_KEYS) } },
      select: { limitKey: true, limitValue: true },
    });
    const values = new Map(rows.map((row) => [row.limitKey, toSafeNumber(row.limitValue)]));
    const defaults = this.defaults();
    return {
      inboundRecipientsPerMinute:
        values.get(LIMIT_KEYS.inboundRecipientsPerMinute) ?? defaults.inboundRecipientsPerMinute,
      outboundRecipientsPerMinute:
        values.get(LIMIT_KEYS.outboundRecipientsPerMinute) ?? defaults.outboundRecipientsPerMinute,
      outboundRecipientsPerDay:
        values.get(LIMIT_KEYS.outboundRecipientsPerDay) ?? defaults.outboundRecipientsPerDay,
      maxMessageSizeBytes: values.get(LIMIT_KEYS.maxMessageSizeBytes) ?? null,
    };
  }

  private defaults(): TenantLimits {
    return {
      inboundRecipientsPerMinute: this.config.SMTP_RATE_TENANT_INBOUND_RCPT_PER_MINUTE,
      outboundRecipientsPerMinute: this.config.SMTP_RATE_TENANT_OUTBOUND_RCPT_PER_MINUTE,
      outboundRecipientsPerDay: this.config.SMTP_RATE_TENANT_OUTBOUND_RCPT_PER_DAY,
      maxMessageSizeBytes: null,
    };
  }
}

/** Limits are unsigned BIGINT; anything beyond 2^53 is effectively unlimited. */
function toSafeNumber(value: bigint): number {
  return value > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : Number(value);
}
