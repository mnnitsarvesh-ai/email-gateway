import { Inject, Injectable, type OnModuleDestroy, type OnModuleInit } from '@nestjs/common';
import { PrismaService, RedisService } from '@email-gateway/common';
import type { Logger } from '@email-gateway/logger';
import { ADAPTER_CONFIG, ADAPTER_LOGGER } from '../config';
import { LuaScript } from '../rate-limit/lua-script';
import type { JournalIntakeConfig } from './journal-intake.config';
import { JournalIntakeMetrics } from './journal-intake.metrics';

/** The D2.8 counters (hash fields = `journal_intake_counters` columns). */
export const INTAKE_COUNTER_FIELDS = [
  'accepted',
  'duplicates',
  'bytes',
  'refused_address',
  'refused_network',
  'refused_tls',
  'refused_size',
  'refused_rate',
  'refused_unavailable',
  'dropped_proof',
  'unwrap_failed',
] as const;
export type IntakeCounterField = (typeof INTAKE_COUNTER_FIELDS)[number];

/** Counts are health evidence, not mail data: a key is dropped after this many failed flushes. */
export const MAX_FLUSH_FAILURES = 3;
/** The hash of a day lives three days (contracts §34); a flush normally empties it in seconds. */
export const COUNTER_TTL_SECONDS = 3 * 86_400;
/** Set of hash keys with unflushed counts. */
export const COUNTER_DIRTY_KEY = 'sa:jintake:cnt:dirty';

/** UTC day as `yyyymmdd`. */
export const counterDay = (at: Date): string => at.toISOString().slice(0, 10).replaceAll('-', '');

/** `sa:jintake:cnt:<sourceId>:<yyyymmdd>`. */
export const counterKey = (sourceId: bigint, at: Date): string =>
  `sa:jintake:cnt:${sourceId.toString()}:${counterDay(at)}`;

const KEY_PATTERN = /^sa:jintake:cnt:(\d{1,20}):(\d{4})(\d{2})(\d{2})$/;

/**
 * KEYS[1] hash, KEYS[2] dirty set; ARGV[1] TTL, ARGV[2] unused (kept for the argument layout),
 * ARGV[3] accepted-at ms or '', ARGV[4] refused-at ms or '', ARGV[5] refusal code or '',
 * ARGV[6..] field/increment pairs. `last_*` fields keep the latest instant (and its code).
 */
const RECORD = new LuaScript(`
local i = 6
while i < #ARGV do
  redis.call('HINCRBY', KEYS[1], ARGV[i], ARGV[i + 1])
  i = i + 2
end
if ARGV[3] ~= '' then
  local cur = tonumber(redis.call('HGET', KEYS[1], 'last_accepted_at') or '0')
  if tonumber(ARGV[3]) > cur then redis.call('HSET', KEYS[1], 'last_accepted_at', ARGV[3]) end
end
if ARGV[4] ~= '' then
  local cur = tonumber(redis.call('HGET', KEYS[1], 'last_refused_at') or '0')
  if tonumber(ARGV[4]) > cur then
    redis.call('HSET', KEYS[1], 'last_refused_at', ARGV[4], 'last_refusal_code', ARGV[5])
  end
end
redis.call('EXPIRE', KEYS[1], ARGV[1])
redis.call('SADD', KEYS[2], KEYS[1])
return 1
`);

/** Atomically reads and removes one hash (KEYS[1]) and its dirty entry (KEYS[2]). */
const TAKE = new LuaScript(`
local values = redis.call('HGETALL', KEYS[1])
redis.call('DEL', KEYS[1])
redis.call('SREM', KEYS[2], KEYS[1])
return values
`);

export interface CounterEvent {
  counts: Partial<Record<IntakeCounterField, number>>;
  acceptedAt?: Date;
  refusedAt?: Date;
  /** `last_refusal_code` with `refusedAt` (`refused_network`, `proof_tenant_header`, …). */
  refusalCode?: string;
}

/** One taken hash, parsed. */
export interface CounterBucket {
  key: string;
  sourceId: bigint;
  day: Date;
  counts: Record<IntakeCounterField, number>;
  lastAcceptedAt: Date | null;
  lastRefusedAt: Date | null;
  lastRefusalCode: string | null;
  failures: number;
}

const FAILURES_FIELD = 'failures';

/**
 * Per-source daily journal intake counters (step 8.6 D2.8; pattern of the 8.2
 * `RelayCountersService`, but in Redis so every adapter replica adds to one hash): recorded with
 * one atomic script per event (never awaited by a reply, never throws), flushed every
 * JOURNAL_INTAKE_COUNTER_FLUSH_SECONDS: each dirty hash is taken atomically, added to
 * `journal_intake_counters` (`INSERT … ON DUPLICATE KEY UPDATE col = col + ?`) and the source's
 * `last_accepted_at` / `last_refused_at` / `last_refusal_code` (latest wins). The first accepted
 * message sets `verified_at` and moves a `pending_verification` source to `active` (bumping
 * `row_version`, so a concurrent api edit sees the change). A failed write puts the counts back
 * (dropped after 3 failures; logged and counted).
 */
@Injectable()
export class JournalIntakeCountersService implements OnModuleInit, OnModuleDestroy {
  private readonly logger: Logger;
  private timer: NodeJS.Timeout | undefined;
  private flushing: Promise<void> | null = null;
  private lastRecordWarnAt = 0;

  constructor(
    private readonly prisma: PrismaService,
    private readonly redis: RedisService,
    private readonly metrics: JournalIntakeMetrics,
    @Inject(ADAPTER_CONFIG)
    private readonly config: Pick<JournalIntakeConfig, 'JOURNAL_INTAKE_COUNTER_FLUSH_SECONDS'>,
    @Inject(ADAPTER_LOGGER) logger: Logger,
  ) {
    this.logger = logger.child({ component: 'journal-intake-counters' });
  }

  onModuleInit(): void {
    this.timer = setInterval(() => {
      void this.flush();
    }, this.config.JOURNAL_INTAKE_COUNTER_FLUSH_SECONDS * 1000);
    this.timer.unref();
  }

  async onModuleDestroy(): Promise<void> {
    clearInterval(this.timer);
    await this.flush();
  }

  /** Fire and forget: never throws, never delays a reply. */
  record(sourceId: bigint, event: CounterEvent, at: Date = new Date()): void {
    void this.recordNow(sourceId, event, at);
  }

  /** The awaited form (tests). */
  async recordNow(sourceId: bigint, event: CounterEvent, at: Date): Promise<void> {
    const pairs: string[] = [];
    for (const [field, value] of Object.entries(event.counts)) {
      if (typeof value === 'number' && Number.isSafeInteger(value) && value > 0) {
        pairs.push(field, String(value));
      }
    }
    try {
      await RECORD.run(
        this.redis.client,
        [counterKey(sourceId, at), COUNTER_DIRTY_KEY],
        [
          COUNTER_TTL_SECONDS,
          '',
          event.acceptedAt ? String(event.acceptedAt.getTime()) : '',
          event.refusedAt ? String(event.refusedAt.getTime()) : '',
          event.refusedAt ? (event.refusalCode ?? '').slice(0, 64) : '',
          ...pairs,
        ],
      );
    } catch (err) {
      this.metrics.counterFlushFailed();
      const now = Date.now();
      if (now - this.lastRecordWarnAt >= 60_000) {
        this.lastRecordWarnAt = now;
        this.logger.warn({ err }, 'journal intake counters not recorded (Redis)');
      }
    }
  }

  /** Writes every dirty hash; concurrent calls share one flush. Never throws. */
  flush(): Promise<void> {
    this.flushing ??= this.flushAll().finally(() => {
      this.flushing = null;
    });
    return this.flushing;
  }

  private async flushAll(): Promise<void> {
    let keys: string[];
    try {
      keys = await this.redis.client.smembers(COUNTER_DIRTY_KEY);
    } catch (err) {
      this.metrics.counterFlushFailed();
      this.logger.warn({ err }, 'journal intake counter flush could not list keys');
      return;
    }
    for (const key of keys) {
      let bucket: CounterBucket | null;
      try {
        const raw = await TAKE.run(this.redis.client, [key, COUNTER_DIRTY_KEY], []);
        bucket = parseBucket(key, raw);
      } catch (err) {
        this.metrics.counterFlushFailed();
        this.logger.warn({ err }, 'journal intake counter hash could not be taken');
        continue;
      }
      if (bucket === null) continue;
      try {
        await this.write(bucket);
      } catch (err) {
        this.metrics.counterFlushFailed();
        const failures = bucket.failures + 1;
        if (failures >= MAX_FLUSH_FAILURES) {
          this.logger.error(
            { err, sourceId: bucket.sourceId.toString(), failures },
            'journal intake counters dropped after repeated flush failures',
          );
          continue;
        }
        this.logger.warn(
          { err, sourceId: bucket.sourceId.toString(), failures },
          'journal intake counter flush failed; retrying later',
        );
        await this.putBack(bucket, failures);
      }
    }
  }

  private async putBack(bucket: CounterBucket, failures: number): Promise<void> {
    try {
      const pairs: string[] = [FAILURES_FIELD, String(failures)];
      for (const field of INTAKE_COUNTER_FIELDS) {
        if (bucket.counts[field] > 0) pairs.push(field, String(bucket.counts[field]));
      }
      await RECORD.run(
        this.redis.client,
        [bucket.key, COUNTER_DIRTY_KEY],
        [
          COUNTER_TTL_SECONDS,
          '',
          bucket.lastAcceptedAt ? String(bucket.lastAcceptedAt.getTime()) : '',
          bucket.lastRefusedAt ? String(bucket.lastRefusedAt.getTime()) : '',
          bucket.lastRefusedAt ? (bucket.lastRefusalCode ?? '') : '',
          ...pairs,
        ],
      );
    } catch (err) {
      this.logger.error({ err }, 'journal intake counters lost (Redis unavailable)');
    }
  }

  private async write(bucket: CounterBucket): Promise<void> {
    const c = bucket.counts;
    const total = INTAKE_COUNTER_FIELDS.reduce((sum, field) => sum + c[field], 0);
    if (total > 0) {
      // The organization comes from the source row (no row: the source is gone, nothing to add).
      await this.prisma.$executeRaw`
        INSERT INTO journal_intake_counters
          (organization_id, source_id, day, accepted, duplicates, refused_address, refused_network,
           refused_tls, refused_size, refused_rate, refused_unavailable, dropped_proof,
           unwrap_failed, bytes, updated_at)
        SELECT s.organization_id, s.id, ${bucket.day}, ${c.accepted}, ${c.duplicates},
               ${c.refused_address}, ${c.refused_network}, ${c.refused_tls}, ${c.refused_size},
               ${c.refused_rate}, ${c.refused_unavailable}, ${c.dropped_proof},
               ${c.unwrap_failed}, ${c.bytes}, CURRENT_TIMESTAMP(3)
        FROM journal_intake_sources s
        WHERE s.id = ${bucket.sourceId}
        ON DUPLICATE KEY UPDATE
          accepted = accepted + ${c.accepted},
          duplicates = duplicates + ${c.duplicates},
          refused_address = refused_address + ${c.refused_address},
          refused_network = refused_network + ${c.refused_network},
          refused_tls = refused_tls + ${c.refused_tls},
          refused_size = refused_size + ${c.refused_size},
          refused_rate = refused_rate + ${c.refused_rate},
          refused_unavailable = refused_unavailable + ${c.refused_unavailable},
          dropped_proof = dropped_proof + ${c.dropped_proof},
          unwrap_failed = unwrap_failed + ${c.unwrap_failed},
          bytes = bytes + ${c.bytes},
          updated_at = CURRENT_TIMESTAMP(3)`;
    }
    // Source facts after the counts; a failure here must not re-add counts that were written.
    try {
      if (bucket.lastAcceptedAt !== null) {
        const at = bucket.lastAcceptedAt;
        await this.prisma.$executeRaw`
          UPDATE journal_intake_sources
          SET last_accepted_at = ${at}
          WHERE id = ${bucket.sourceId}
            AND (last_accepted_at IS NULL OR last_accepted_at < ${at})`;
        // D1: the first accepted message verifies the source. row_version is assigned first:
        // MySQL evaluates single-table SET assignments left to right.
        await this.prisma.$executeRaw`
          UPDATE journal_intake_sources
          SET row_version = row_version + IF(status = 'pending_verification', 1, 0),
              status = IF(status = 'pending_verification', 'active', status),
              verified_at = COALESCE(verified_at, ${at}),
              updated_at = CURRENT_TIMESTAMP(3)
          WHERE id = ${bucket.sourceId}
            AND (verified_at IS NULL OR status = 'pending_verification')`;
      }
      if (bucket.lastRefusedAt !== null) {
        const at = bucket.lastRefusedAt;
        await this.prisma.$executeRaw`
          UPDATE journal_intake_sources
          SET last_refused_at = ${at}, last_refusal_code = ${bucket.lastRefusalCode}
          WHERE id = ${bucket.sourceId}
            AND (last_refused_at IS NULL OR last_refused_at < ${at})`;
      }
    } catch (err) {
      this.metrics.counterFlushFailed();
      this.logger.warn(
        { err, sourceId: bucket.sourceId.toString() },
        'could not update the journal intake source facts',
      );
    }
  }
}

/** HGETALL reply (flat field/value list) of a counter hash → bucket; null when empty. */
export function parseBucket(key: string, raw: unknown): CounterBucket | null {
  const match = KEY_PATTERN.exec(key);
  if (!match || !Array.isArray(raw) || raw.length === 0) return null;
  const fields = new Map<string, string>();
  for (let i = 0; i + 1 < raw.length; i += 2) fields.set(String(raw[i]), String(raw[i + 1]));
  const number = (name: string): number => {
    const value = Number(fields.get(name) ?? '0');
    return Number.isSafeInteger(value) && value > 0 ? value : 0;
  };
  const instant = (name: string): Date | null => {
    const value = Number(fields.get(name) ?? '');
    return Number.isSafeInteger(value) && value > 0 ? new Date(value) : null;
  };
  const counts = Object.fromEntries(INTAKE_COUNTER_FIELDS.map((f) => [f, number(f)])) as Record<
    IntakeCounterField,
    number
  >;
  const lastRefusedAt = instant('last_refused_at');
  return {
    key,
    sourceId: BigInt(match[1]!),
    day: new Date(Date.UTC(Number(match[2]), Number(match[3]) - 1, Number(match[4]))),
    counts,
    lastAcceptedAt: instant('last_accepted_at'),
    lastRefusedAt,
    lastRefusalCode: lastRefusedAt ? (fields.get('last_refusal_code') ?? null) || null : null,
    failures: number(FAILURES_FIELD),
  };
}
