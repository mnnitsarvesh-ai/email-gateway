import { createHash } from 'node:crypto';
import type { PrismaClient } from '@email-gateway/database';

/**
 * Outbound recipient rate limits of the worker (step 2.3 R11), applied before a 10027
 * reinjection: fixed UTC-minute windows in Redis (consistent with step 2.2 D6), one atomic
 * check-and-increment over three keys, fail closed (a Redis error defers, never sends).
 *
 * KEYS[1..3]: tenant, tenant × destination domain, destination domain (gateway-wide).
 * ARGV[1]: the group's recipient count; ARGV[2..4]: the three limits; ARGV[5]: TTL in ms.
 * Increments all three **only if** the count fits under every limit (a deferred group does not
 * consume quota). Returns `{1, 0, 0}` when admitted, else `{0, scopeIndex, current}`.
 */
export const ADMIT_SCRIPT = `
local n = tonumber(ARGV[1])
for i = 1, 3 do
  local limit = tonumber(ARGV[i + 1])
  local current = tonumber(redis.call('GET', KEYS[i]) or '0')
  if current + n > limit then
    return {0, i, current}
  end
end
for i = 1, 3 do
  local value = redis.call('INCRBY', KEYS[i], n)
  if value == n then
    redis.call('PEXPIRE', KEYS[i], ARGV[5])
  end
end
return {1, 0, 0}
`;

/** Redis client subset (ioredis) the limiter needs. */
export interface ScriptClient {
  evalsha(sha: string, numKeys: number, ...args: (string | number)[]): Promise<unknown>;
  eval(script: string, numKeys: number, ...args: (string | number)[]): Promise<unknown>;
}

const SHA = createHash('sha1').update(ADMIT_SCRIPT).digest('hex');

/** Windows are kept 10 s longer than their length (step 2.2 D6). */
export const WINDOW_GRACE_MS = 10_000;
export const MINUTE_MS = 60_000;
/** organization_limits are cached in memory this long (R11). */
export const LIMITS_CACHE_MS = 60_000;

export const LIMIT_KEYS = {
  tenant: 'outbound_recipients_per_minute',
  tenantDomain: 'outbound_recipients_per_domain_per_minute',
} as const;

export type LimitScope = 'tenant' | 'tenant_domain' | 'destination_domain';
const SCOPES: readonly LimitScope[] = ['tenant', 'tenant_domain', 'destination_domain'];

export interface OutboundLimits {
  tenant: number;
  tenantDomain: number;
  destinationDomain: number;
}

export interface RateLimitDefaults {
  DELIVERY_RATE_TENANT_RCPT_PER_MINUTE: number;
  DELIVERY_RATE_TENANT_DOMAIN_RCPT_PER_MINUTE: number;
  DELIVERY_RATE_DESTINATION_DOMAIN_RCPT_PER_MINUTE: number;
}

export type AdmitResult =
  | { admitted: true; windowStart: Date }
  | { admitted: false; scope: LimitScope; limit: number; windowStart: Date };

/** UTC minute number (`floor(epochMs / 60000)`). */
export const minuteWindow = (now: Date): number => Math.floor(now.getTime() / MINUTE_MS);

/** The R11 keys (separate from the adapter's `sa:rl:*` submission counters). */
export function rateLimitKeys(
  organizationId: bigint,
  domain: string,
  now: Date,
): [string, string, string] {
  const minute = minuteWindow(now);
  const org = organizationId.toString();
  return [
    `dw:rl:out:${org}:${minute}`,
    `dw:rl:outd:${org}:${domain}:${minute}`,
    `dw:rl:dst:${domain}:${minute}`,
  ];
}

/** The largest chunk that can ever pass (the smallest limit), 0 = held. */
export const maxChunk = (limits: OutboundLimits): number =>
  Math.min(limits.tenant, limits.tenantDomain, limits.destinationDomain);

const toNumber = (value: bigint): number =>
  value > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : Number(value);

/**
 * Limits: `organization_limits.outbound_recipients_per_minute` and
 * `outbound_recipients_per_domain_per_minute` (cached per organization for 60 s), else the
 * DELIVERY_RATE_* defaults; the destination-domain limit is gateway-wide configuration. A
 * limit of 0 means hold (no outbound delivery for that tenant until the reinjection's max age).
 */
export class OutboundRateLimiter {
  private readonly cache = new Map<string, { limits: OutboundLimits; expiresAt: number }>();

  constructor(
    private readonly prisma: Pick<PrismaClient, 'organizationLimit'>,
    private readonly redis: ScriptClient,
    private readonly defaults: RateLimitDefaults,
    private readonly clock: () => number = Date.now,
  ) {}

  async limits(organizationId: bigint): Promise<OutboundLimits> {
    const key = organizationId.toString();
    const cached = this.cache.get(key);
    const now = this.clock();
    if (cached && cached.expiresAt > now) return cached.limits;
    const rows = await this.prisma.organizationLimit.findMany({
      where: { organizationId, limitKey: { in: Object.values(LIMIT_KEYS) } },
      select: { limitKey: true, limitValue: true },
    });
    const values = new Map(rows.map((row) => [row.limitKey, toNumber(row.limitValue)]));
    const limits: OutboundLimits = {
      tenant: values.get(LIMIT_KEYS.tenant) ?? this.defaults.DELIVERY_RATE_TENANT_RCPT_PER_MINUTE,
      tenantDomain:
        values.get(LIMIT_KEYS.tenantDomain) ??
        this.defaults.DELIVERY_RATE_TENANT_DOMAIN_RCPT_PER_MINUTE,
      destinationDomain: this.defaults.DELIVERY_RATE_DESTINATION_DOMAIN_RCPT_PER_MINUTE,
    };
    if (this.cache.size > 10_000) this.cache.clear();
    this.cache.set(key, { limits, expiresAt: now + LIMITS_CACHE_MS });
    return limits;
  }

  /**
   * Atomically admits `count` recipients of `organizationId` to `domain` in the current UTC
   * minute, or reports the first scope that would be exceeded. Redis errors propagate (the
   * caller defers with `gateway_rate_limit_unavailable`).
   */
  async admit(
    organizationId: bigint,
    domain: string,
    count: number,
    limits: OutboundLimits,
    now: Date = new Date(this.clock()),
  ): Promise<AdmitResult> {
    const windowStart = new Date(minuteWindow(now) * MINUTE_MS);
    const keys = rateLimitKeys(organizationId, domain.toLowerCase(), now);
    const args = [
      count,
      limits.tenant,
      limits.tenantDomain,
      limits.destinationDomain,
      MINUTE_MS + WINDOW_GRACE_MS,
    ];
    const params = [...keys, ...args.map(String)];
    let result: unknown;
    try {
      result = await this.redis.evalsha(SHA, keys.length, ...params);
    } catch (err) {
      if (!(err instanceof Error) || !err.message.includes('NOSCRIPT')) throw err;
      result = await this.redis.eval(ADMIT_SCRIPT, keys.length, ...params);
    }
    if (!Array.isArray(result) || result.length !== 3)
      throw new Error('unexpected rate limit script result');
    if (Number(result[0]) === 1) return { admitted: true, windowStart };
    const scope = SCOPES[Number(result[1]) - 1];
    if (!scope) throw new Error('unexpected rate limit script scope');
    const limit =
      scope === 'tenant'
        ? limits.tenant
        : scope === 'tenant_domain'
          ? limits.tenantDomain
          : limits.destinationDomain;
    return { admitted: false, scope, limit, windowStart };
  }
}
