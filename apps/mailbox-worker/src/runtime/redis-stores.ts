import type { PrismaClient } from '@email-gateway/database';
import type { RateBudget } from '@email-gateway/idp-adapters';
import {
  MAILBOX_API_FAMILIES,
  MAX_THROTTLE_PAUSE_MS,
  parseMailboxBudgetId,
  type MailboxApiFamily,
  type ThrottleEvent,
  type ThrottleGate,
} from '@email-gateway/mailbox-api';
import type { Logger } from '@email-gateway/logger';
import { errorFields } from '../shared/errors';

/** The subset of ioredis the stores use (tests pass the real client). */
export interface MailboxRedis {
  eval(script: string, numKeys: number, ...args: (string | number)[]): Promise<unknown>;
  pttl(key: string): Promise<number>;
  scan(cursor: string | number, ...args: (string | number)[]): Promise<[string, string[]]>;
  del(...keys: string[]): Promise<number>;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const TAKE_SCRIPT = `
local n = redis.call('INCR', KEYS[1])
if n == 1 then redis.call('EXPIRE', KEYS[1], 5) end
return n`;

/**
 * `RateBudget` over Redis for the mailbox clients (D10.6, §5 "Redis"): per API connection, family
 * and epoch second one counter `mbx:rb:<apiConnectionPublicId>:<family>:s<epochSecond>` (INCR,
 * EXPIRE 5). A take above the family's per-second limit answers `exhausted` (the client waits
 * ≤ 1 s, then fails `rate_budget`). Shared by every replica, so one tenant's connection can never
 * use another's budget (per-connection isolation, N7). Wall-clock seconds, never a test clock.
 */
export class RedisRateBudget implements RateBudget {
  constructor(
    private readonly redis: MailboxRedis,
    private readonly limits: Readonly<Record<MailboxApiFamily, number>>,
    private readonly now: () => number = Date.now,
  ) {}

  static key(apiConnectionPublicId: string, family: MailboxApiFamily, epochSecond: number): string {
    return `mbx:rb:${apiConnectionPublicId}:${family}:s${String(epochSecond)}`;
  }

  async take(integrationId: string, family: string): Promise<'ok' | 'exhausted'> {
    const connection = parseMailboxBudgetId(integrationId);
    if (
      connection === null ||
      !UUID.test(connection) ||
      !(MAILBOX_API_FAMILIES as readonly string[]).includes(family)
    ) {
      throw new Error('rate_budget_key_invalid');
    }
    const fam = family as MailboxApiFamily;
    const key = RedisRateBudget.key(connection, fam, Math.floor(this.now() / 1000));
    const count = Number(await this.redis.eval(TAKE_SCRIPT, 1, key));
    if (!Number.isFinite(count)) throw new Error('rate_budget_unavailable');
    return count <= this.limits[fam] ? 'ok' : 'exhausted';
  }
}

const PAUSE_SCRIPT = `
local current = redis.call('PTTL', KEYS[1])
local wanted = tonumber(ARGV[1])
if current < wanted then
  redis.call('SET', KEYS[1], ARGV[2], 'PX', wanted)
  return 1
end
return 0`;

/** Side effects of one pause: `throttled_until`, the counters and the metric (D10.6). */
export type ThrottleRecorder = (event: ThrottleEvent) => Promise<void>;

/**
 * The shared throttle pause (D10.6): `mbx:throttle:<apiConnectionPublicId>:<family>` with TTL =
 * Retry-After (capped at 600 s; a longer existing pause is kept), consulted by every worker before
 * any call of that family. `pause` also runs the recorder (connection `throttled_until`, counters
 * `throttled_429` / `throttled_503`, `api_mode_throttled_total`); a recorder failure is logged and
 * never hides the provider's answer.
 */
export class RedisThrottleGate implements ThrottleGate {
  constructor(
    private readonly redis: MailboxRedis,
    private readonly recorder: ThrottleRecorder,
    private readonly logger: Logger,
  ) {}

  static key(apiConnectionPublicId: string, family: MailboxApiFamily): string {
    return `mbx:throttle:${apiConnectionPublicId}:${family}`;
  }

  async remainingMs(apiConnectionPublicId: string, family: MailboxApiFamily): Promise<number> {
    const ttl = await this.redis.pttl(RedisThrottleGate.key(apiConnectionPublicId, family));
    return ttl > 0 ? ttl : 0;
  }

  async pause(event: ThrottleEvent): Promise<void> {
    const ms = Math.max(1, Math.min(Math.ceil(event.retryAfterMs), MAX_THROTTLE_PAUSE_MS));
    await this.redis.eval(
      PAUSE_SCRIPT,
      1,
      RedisThrottleGate.key(event.apiConnectionPublicId, event.family),
      ms,
      event.code,
    );
    try {
      await this.recorder({ ...event, retryAfterMs: ms });
    } catch (error) {
      this.logger.warn(
        {
          apiConnectionId: event.apiConnectionPublicId,
          family: event.family,
          ...errorFields(error),
        },
        'throttle pause not recorded in MySQL',
      );
    }
  }
}

/** The integer columns of `api_mode_counters` the worker adds to (D3.2). */
export const COUNTER_FIELDS = [
  'journal_copies',
  'feed_copies',
  'duplicates',
  'skipped_internal',
  'too_large',
  'provider_requests',
  'throttled_429',
  'throttled_503',
  'provider_errors',
  'cursor_resets',
  'lag_count',
  'lag_le_60s',
  'lag_le_300s',
  'lag_le_900s',
  'lag_le_3600s',
  'lag_gt_3600s',
  'fetch_bytes',
  'lag_sum_ms',
  // Step API-2 (note 36 R14, migration 44).
  'remediation_succeeded',
  'remediation_failed',
  'remediation_skipped',
  'remediation_simulated',
  'restores_succeeded',
  'restores_failed',
  'remediation_throttled',
  'remediation_latency_count',
  'remediation_latency_sum_ms',
] as const;
export type CounterField = (typeof COUNTER_FIELDS)[number];
/** Maximum fields (kept with GREATEST, never summed). */
export const COUNTER_MAX_FIELDS = ['lag_max_ms', 'remediation_latency_max_ms'] as const;
export type CounterMaxField = (typeof COUNTER_MAX_FIELDS)[number];
export type CounterDelta = Partial<Record<CounterField | CounterMaxField, number>>;

const ADD_SCRIPT = `
for i = 1, #ARGV, 2 do
  local field = ARGV[i]
  local value = tonumber(ARGV[i + 1])
  if field == 'lag_max_ms' or field == 'remediation_latency_max_ms' then
    local current = tonumber(redis.call('HGET', KEYS[1], field) or '0')
    if value > current then redis.call('HSET', KEYS[1], field, value) end
  else
    redis.call('HINCRBY', KEYS[1], field, value)
  end
end
redis.call('EXPIRE', KEYS[1], 259200)
return 1`;

const TAKE_ALL_SCRIPT = `
local values = redis.call('HGETALL', KEYS[1])
redis.call('DEL', KEYS[1])
return values`;

/** UTC hour start of `at` (the counters' `hour`). */
export function hourOf(at: Date): Date {
  return new Date(Math.floor(at.getTime() / 3_600_000) * 3_600_000);
}

/** `yyyymmddhh` (UTC) of an hour. */
export function hourKey(at: Date): string {
  return at.toISOString().slice(0, 13).replace(/[-T]/g, '');
}

/** Parses a counter key back into (connection id, hour); null for anything else. */
export function parseCounterKey(key: string): { apiConnectionId: bigint; hour: Date } | null {
  const match = /^mbx:cnt:([1-9][0-9]{0,19}):(\d{4})(\d{2})(\d{2})(\d{2})$/.exec(key);
  if (!match) return null;
  const hour = new Date(`${match[2]}-${match[3]}-${match[4]}T${match[5]}:00:00.000Z`);
  if (Number.isNaN(hour.getTime())) return null;
  return { apiConnectionId: BigInt(match[1]!), hour };
}

export interface CounterFlushReport {
  keys: number;
  rows: number;
  dropped: number;
  failed: number;
}

/**
 * Hourly API-mode counters (D7.8, §5 "Redis"; the 8.6 counter pattern): increments land in the
 * Redis hash `mbx:cnt:<apiConnectionId>:<yyyymmddhh>` (TTL 3 days); the health leader flushes every
 * `API_MODE_COUNTER_FLUSH_SECONDS` by taking each hash atomically (HGETALL + DEL in one script)
 * and adding it to `api_mode_counters` (`INSERT … ON DUPLICATE KEY UPDATE col = col + VALUES(col)`,
 * `lag_max_ms` = GREATEST). A failed MySQL write puts the values back. Counters are best effort:
 * a crash between a commit and the increment loses that increment (never a copy row).
 */
export class CounterStore {
  constructor(
    private readonly redis: MailboxRedis,
    private readonly prisma: PrismaClient,
    private readonly logger: Logger,
    private readonly now: () => Date,
  ) {}

  static key(apiConnectionId: bigint, hour: Date): string {
    return `mbx:cnt:${apiConnectionId.toString()}:${hourKey(hour)}`;
  }

  /** Adds a delta to the connection's counters of the hour of `at` (default now). */
  async add(apiConnectionId: bigint, delta: CounterDelta, at?: Date): Promise<void> {
    const args: (string | number)[] = [];
    for (const [field, value] of Object.entries(delta)) {
      if (value === undefined || !Number.isFinite(value) || value <= 0) continue;
      args.push(field, Math.round(value));
    }
    if (args.length === 0) return;
    try {
      await this.redis.eval(
        ADD_SCRIPT,
        1,
        CounterStore.key(apiConnectionId, hourOf(at ?? this.now())),
        ...args,
      );
    } catch (error) {
      this.logger.warn(
        { apiConnectionId: apiConnectionId.toString(), ...errorFields(error) },
        'api-mode counters not incremented',
      );
    }
  }

  /** Flushes every counter hash (optionally only connections of these organizations). */
  async flush(organizationIds?: readonly bigint[]): Promise<CounterFlushReport> {
    const report: CounterFlushReport = { keys: 0, rows: 0, dropped: 0, failed: 0 };
    const orgOf = new Map<bigint, bigint | null>();
    let cursor = '0';
    do {
      const [next, keys] = await this.redis.scan(cursor, 'MATCH', 'mbx:cnt:*', 'COUNT', 500);
      cursor = next;
      for (const key of keys) {
        const parsed = parseCounterKey(key);
        if (!parsed) continue;
        let organizationId = orgOf.get(parsed.apiConnectionId);
        if (organizationId === undefined) {
          const row = await this.prisma.apiModeConnection.findUnique({
            where: { id: parsed.apiConnectionId },
            select: { organizationId: true },
          });
          organizationId = row?.organizationId ?? null;
          orgOf.set(parsed.apiConnectionId, organizationId);
        }
        if (
          organizationId !== null &&
          organizationIds &&
          !organizationIds.includes(organizationId)
        ) {
          continue;
        }
        report.keys += 1;
        const raw = (await this.redis.eval(TAKE_ALL_SCRIPT, 1, key)) as string[] | null;
        const delta = deltaOf(raw ?? []);
        if (organizationId === null) {
          report.dropped += 1;
          continue;
        }
        try {
          await this.upsert(organizationId, parsed.apiConnectionId, parsed.hour, delta);
          report.rows += 1;
        } catch (error) {
          report.failed += 1;
          this.logger.warn(
            { apiConnectionId: parsed.apiConnectionId.toString(), ...errorFields(error) },
            'api-mode counters not flushed; kept for the next flush',
          );
          await this.add(parsed.apiConnectionId, delta, parsed.hour);
        }
      }
    } while (cursor !== '0');
    return report;
  }

  private async upsert(
    organizationId: bigint,
    apiConnectionId: bigint,
    hour: Date,
    delta: CounterDelta,
  ): Promise<void> {
    const v = (field: CounterField): number => Math.max(0, Math.round(delta[field] ?? 0));
    const uint = (value: number | undefined): number =>
      Math.max(0, Math.min(4_294_967_295, Math.round(value ?? 0)));
    const max = uint(delta.lag_max_ms);
    const remediationMax = uint(delta.remediation_latency_max_ms);
    await this.prisma.$executeRaw`
      INSERT INTO api_mode_counters
        (organization_id, api_connection_id, hour, journal_copies, feed_copies, duplicates,
         skipped_internal, too_large, provider_requests, throttled_429, throttled_503,
         provider_errors, cursor_resets, lag_count, lag_le_60s, lag_le_300s, lag_le_900s,
         lag_le_3600s, lag_gt_3600s, lag_max_ms, fetch_bytes, lag_sum_ms,
         remediation_succeeded, remediation_failed, remediation_skipped, remediation_simulated,
         restores_succeeded, restores_failed, remediation_throttled, remediation_latency_count,
         remediation_latency_sum_ms, remediation_latency_max_ms, updated_at)
      VALUES (${organizationId}, ${apiConnectionId}, ${hour}, ${v('journal_copies')},
        ${v('feed_copies')}, ${v('duplicates')}, ${v('skipped_internal')}, ${v('too_large')},
        ${v('provider_requests')}, ${v('throttled_429')}, ${v('throttled_503')},
        ${v('provider_errors')}, ${v('cursor_resets')}, ${v('lag_count')}, ${v('lag_le_60s')},
        ${v('lag_le_300s')}, ${v('lag_le_900s')}, ${v('lag_le_3600s')}, ${v('lag_gt_3600s')},
        ${max}, ${v('fetch_bytes')}, ${v('lag_sum_ms')}, ${v('remediation_succeeded')},
        ${v('remediation_failed')}, ${v('remediation_skipped')}, ${v('remediation_simulated')},
        ${v('restores_succeeded')}, ${v('restores_failed')}, ${v('remediation_throttled')},
        ${v('remediation_latency_count')}, ${v('remediation_latency_sum_ms')}, ${remediationMax},
        NOW(3))
      ON DUPLICATE KEY UPDATE
        journal_copies = journal_copies + VALUES(journal_copies),
        feed_copies = feed_copies + VALUES(feed_copies),
        duplicates = duplicates + VALUES(duplicates),
        skipped_internal = skipped_internal + VALUES(skipped_internal),
        too_large = too_large + VALUES(too_large),
        provider_requests = provider_requests + VALUES(provider_requests),
        throttled_429 = throttled_429 + VALUES(throttled_429),
        throttled_503 = throttled_503 + VALUES(throttled_503),
        provider_errors = provider_errors + VALUES(provider_errors),
        cursor_resets = cursor_resets + VALUES(cursor_resets),
        lag_count = lag_count + VALUES(lag_count),
        lag_le_60s = lag_le_60s + VALUES(lag_le_60s),
        lag_le_300s = lag_le_300s + VALUES(lag_le_300s),
        lag_le_900s = lag_le_900s + VALUES(lag_le_900s),
        lag_le_3600s = lag_le_3600s + VALUES(lag_le_3600s),
        lag_gt_3600s = lag_gt_3600s + VALUES(lag_gt_3600s),
        lag_max_ms = GREATEST(lag_max_ms, VALUES(lag_max_ms)),
        fetch_bytes = fetch_bytes + VALUES(fetch_bytes),
        lag_sum_ms = lag_sum_ms + VALUES(lag_sum_ms),
        remediation_succeeded = remediation_succeeded + VALUES(remediation_succeeded),
        remediation_failed = remediation_failed + VALUES(remediation_failed),
        remediation_skipped = remediation_skipped + VALUES(remediation_skipped),
        remediation_simulated = remediation_simulated + VALUES(remediation_simulated),
        restores_succeeded = restores_succeeded + VALUES(restores_succeeded),
        restores_failed = restores_failed + VALUES(restores_failed),
        remediation_throttled = remediation_throttled + VALUES(remediation_throttled),
        remediation_latency_count = remediation_latency_count + VALUES(remediation_latency_count),
        remediation_latency_sum_ms =
          remediation_latency_sum_ms + VALUES(remediation_latency_sum_ms),
        remediation_latency_max_ms =
          GREATEST(remediation_latency_max_ms, VALUES(remediation_latency_max_ms)),
        updated_at = NOW(3)`;
  }
}

/** A counter hash (HGETALL's flat list) as a delta; unknown fields are ignored. */
export function deltaOf(flat: readonly string[]): CounterDelta {
  const delta: CounterDelta = {};
  for (let i = 0; i + 1 < flat.length; i += 2) {
    const field = flat[i]!;
    const value = Number(flat[i + 1]);
    if (!Number.isFinite(value) || value < 0) continue;
    if ((COUNTER_MAX_FIELDS as readonly string[]).includes(field)) {
      delta[field as CounterMaxField] = value;
    } else if ((COUNTER_FIELDS as readonly string[]).includes(field)) {
      delta[field as CounterField] = value;
    }
  }
  return delta;
}

/** Bounded integer of a raw COUNT/SUM. */
export const num = (value: unknown): number => Number(value ?? 0) || 0;
