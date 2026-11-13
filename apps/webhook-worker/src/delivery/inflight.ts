import { randomUUID } from 'node:crypto';

/**
 * Redis in-flight and rate counters of the delivery loop (step 6.2 W8): `wh:slots:org:<orgId>`
 * (cap WEBHOOK_MAX_INFLIGHT_PER_ORG), `wh:slots:sub:<subId>` (cap = the subscription's
 * `max_concurrency` ?? WEBHOOK_MAX_INFLIGHT_PER_SUBSCRIPTION) and `wh:rate:sub:<subId>:<minute>`
 * (WEBHOOK_RATE_PER_SUBSCRIPTION_PER_MINUTE). A reservation checks and takes the three atomically
 * (one Lua script, so concurrent replicas never overshoot a cap).
 *
 * In-flight slots are **one sorted-set member per reservation** (member = a random token, score =
 * the lease expiry in ms): every reserve and count first drops expired members, so the slots of a
 * process killed mid-attempt (SIGKILL, OOM: the release never runs) expire on their own after one
 * lease, however busy the organization or subscription stays. Rate keys are plain per-minute
 * counters with a two-minute TTL. Released (ZREM of the token) after the attempt is recorded.
 * Redis is never the source of truth: an outage makes the loop send nothing (fail closed).
 */

/** The subset of ioredis used (a fake implements it in unit tests). */
export interface CounterRedis {
  eval(script: string, numKeys: number, ...args: Array<string | number>): Promise<unknown>;
  ping(): Promise<string>;
}

export type ReserveResult = 'ok' | 'organization' | 'subscription' | 'subscription_rate';

/**
 * KEYS: org slots, sub slots, rate. ARGV: org cap, sub cap, rate cap, now (ms), lease expiry (ms),
 * rate TTL (ms), token, lease (ms).
 */
export const RESERVE_SCRIPT = `
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[4])
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', ARGV[4])
if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[1]) then return 1 end
if redis.call('ZCARD', KEYS[2]) >= tonumber(ARGV[2]) then return 2 end
local r = tonumber(redis.call('GET', KEYS[3]) or '0')
if r >= tonumber(ARGV[3]) then return 3 end
redis.call('ZADD', KEYS[1], ARGV[5], ARGV[7])
redis.call('PEXPIRE', KEYS[1], ARGV[8])
redis.call('ZADD', KEYS[2], ARGV[5], ARGV[7])
redis.call('PEXPIRE', KEYS[2], ARGV[8])
redis.call('INCR', KEYS[3])
redis.call('PEXPIRE', KEYS[3], ARGV[6])
return 0`;

/** KEYS: org slots, sub slots[, rate]. ARGV: token. The rate is given back only by `undo`. */
export const RELEASE_SCRIPT = `
redis.call('ZREM', KEYS[1], ARGV[1])
redis.call('ZREM', KEYS[2], ARGV[1])
if #KEYS >= 3 then
  local v = tonumber(redis.call('GET', KEYS[3]) or '0')
  if v > 0 then redis.call('DECR', KEYS[3]) end
end
return 0`;

/** KEYS: slots. ARGV: now (ms). Unexpired slots (read-only). */
export const COUNT_SCRIPT = `return redis.call('ZCOUNT', KEYS[1], '(' .. ARGV[1], '+inf')`;

const RESULTS: readonly ReserveResult[] = [
  'ok',
  'organization',
  'subscription',
  'subscription_rate',
];
const RATE_TTL_MS = 120_000;

export const orgKey = (organizationId: bigint): string => `wh:slots:org:${organizationId}`;
export const subKey = (subscriptionId: bigint): string => `wh:slots:sub:${subscriptionId}`;
export const rateKey = (subscriptionId: bigint, at: number): string =>
  `wh:rate:sub:${subscriptionId}:${Math.floor(at / 60_000)}`;

/** One reservation (what `release` / `undo` must give back). */
export interface Reservation {
  organizationId: bigint;
  subscriptionId: bigint;
  rateKey: string;
  /** The sorted-set member of this reservation in both slot keys. */
  token: string;
}

export class InflightCounters {
  constructor(
    private readonly redis: CounterRedis,
    private readonly options: {
      leaseMs: number;
      maxPerOrganization: number;
      ratePerMinute: number;
    },
    private readonly now: () => number = Date.now,
  ) {}

  /** Throws when Redis is unavailable (the tick then sends nothing). */
  async ping(): Promise<void> {
    await this.redis.ping();
  }

  /** Unexpired in-flight attempts of an organization across replicas. */
  async organization(organizationId: bigint): Promise<number> {
    return Number(await this.redis.eval(COUNT_SCRIPT, 1, orgKey(organizationId), this.now()));
  }

  async reserve(
    organizationId: bigint,
    subscriptionId: bigint,
    subscriptionCap: number,
  ): Promise<{ result: ReserveResult; reservation: Reservation | null }> {
    const now = this.now();
    const rate = rateKey(subscriptionId, now);
    const token = randomUUID();
    const code = Number(
      await this.redis.eval(
        RESERVE_SCRIPT,
        3,
        orgKey(organizationId),
        subKey(subscriptionId),
        rate,
        this.options.maxPerOrganization,
        subscriptionCap,
        this.options.ratePerMinute,
        now,
        now + this.options.leaseMs,
        RATE_TTL_MS,
        token,
        this.options.leaseMs,
      ),
    );
    const result = RESULTS[code] ?? 'organization';
    return {
      result,
      reservation:
        result === 'ok' ? { organizationId, subscriptionId, rateKey: rate, token } : null,
    };
  }

  /** After the attempt: frees the in-flight slots (the rate stays counted). */
  async release(reservation: Reservation): Promise<void> {
    await this.redis.eval(
      RELEASE_SCRIPT,
      2,
      orgKey(reservation.organizationId),
      subKey(reservation.subscriptionId),
      reservation.token,
    );
  }

  /** A reservation that was never used (claim rolled back or lost): gives everything back. */
  async undo(reservation: Reservation): Promise<void> {
    await this.redis.eval(
      RELEASE_SCRIPT,
      3,
      orgKey(reservation.organizationId),
      subKey(reservation.subscriptionId),
      reservation.rateKey,
      reservation.token,
    );
  }
}
