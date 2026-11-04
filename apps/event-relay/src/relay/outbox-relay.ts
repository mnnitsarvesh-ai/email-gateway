import { performance } from 'node:perf_hooks';
import {
  backoffDelay,
  BrokerUnavailableError,
  errorFields,
  type PublishItem,
  type PublishResult,
  sleep as defaultSleep,
} from '@email-gateway/common';
import { EVENT_REGISTRY } from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import type { RelayMetrics } from '../metrics/relay-metrics';
import { buildEnvelope, relayLockName } from './envelope';
import type {
  FailedRow,
  OutboxKey,
  OutboxRow,
  PoisonRow,
  RelayShard,
  RelayStore,
} from './relay-store';

/** The AMQP connection state the relay checks before touching the database (Q11 step 2). */
export interface BrokerState {
  readonly connected: boolean;
  readonly blocked: boolean;
}

/** The `ConfirmPublisher` surface the relay uses. */
export interface BatchPublisher {
  publishBatch(items: PublishItem[]): Promise<PublishResult[]>;
}

/** The `AdvisoryLocks` surface the relay uses (one dedicated lock connection per process). */
export interface ShardLocks {
  ensure(name: string): Promise<boolean>;
  isHeld(name: string): boolean;
  heldCount(prefix: string): number;
  release(name: string): Promise<void>;
}

export interface Backoff {
  baseMs: number;
  maxMs: number;
}

export interface OutboxRelayOptions {
  store: RelayStore;
  locks: ShardLocks;
  broker: BrokerState;
  publisher: BatchPublisher;
  metrics: RelayMetrics;
  logger: Logger;
  /** `RELAY_SHARDS`. */
  shards: number;
  /** `RELAY_MAX_HELD_SHARDS`: shard locks one process holds (replicas spread the rest). */
  maxHeldShards: number;
  batchSize: number;
  scanLimit: number;
  pollIntervalMs: number;
  /** Broker and database backoff (equal jitter). */
  brokerBackoff: Backoff;
  /**
   * Row backoff (equal jitter): after a mandatory return on `attempts`, after a broker nack on
   * the shard's run of consecutive passes with a nack (a nack never counts as an attempt).
   */
  rowBackoff: Backoff;
  /** `RELAY_MAX_ATTEMPTS`: rows at or above it are poison (excluded, alerted). */
  maxAttempts: number;
  maxMessageBytes: number;
  /** AMQP `appId` (for the size check; the publisher sets the property). */
  appId: string;
  /** Lock namespace (default `er`): `<prefix>:relay#<i>/<n>`. */
  lockPrefix?: string;
  /**
   * `organization_id IN (…)` scope: constructor-only (integration tests and future dedicated
   * per-tenant relays), not an environment key.
   */
  organizationIds?: readonly bigint[];
  now?: () => Date;
  random?: () => number;
  sleep?: (ms: number, signal: AbortSignal) => Promise<boolean>;
}

export type ShardOutcome =
  'not_owner' | 'broker_unavailable' | 'database_error' | 'idle' | 'published' | 'timeout';

export interface ShardReport {
  shard: number;
  outcome: ShardOutcome;
  read: number;
  published: number;
  failed: number;
  poison: number;
  /** Rows skipped because they (or an earlier row of their aggregate) are in their backoff. */
  blocked: number;
  /** Delay before the next pass of this shard. */
  delayMs: number;
}

export interface BatchPlan {
  /** Up to `batchSize` publishable rows, in id order. */
  publishable: OutboxRow[];
  /** Rows skipped: in their backoff, or behind a row of the same aggregate that is. */
  blocked: number;
}

/** How often a process that does not hold a shard re-measures that shard's lag (3.1 M2 rule). */
export const UNOWNED_LAG_EVERY_MS = 10_000;

const aggregateKey = (row: OutboxRow) => `${row.aggregateType}\u0000${row.aggregateId}`;

/**
 * Q11 step 4: walks the rows in id order; a row with `available_at > now` blocks its aggregate
 * (it and every later row of the same `(aggregate_type, aggregate_id)` are skipped in this
 * pass); takes up to `batchSize` publishable rows.
 */
export function planBatch(rows: readonly OutboxRow[], now: Date, batchSize: number): BatchPlan {
  const blockedAggregates = new Set<string>();
  const publishable: OutboxRow[] = [];
  let blocked = 0;
  for (const row of rows) {
    if (publishable.length >= batchSize) break;
    const key = aggregateKey(row);
    if (blockedAggregates.has(key)) {
      blocked += 1;
      continue;
    }
    if (row.availableAt.getTime() > now.getTime()) {
      blockedAggregates.add(key);
      blocked += 1;
      continue;
    }
    publishable.push(row);
  }
  return { publishable, blocked };
}

/**
 * The outbox relay (step 3.2 Q11, ADR-0023): publishes every `message_outbox` row to RabbitMQ
 * at least once, with publisher confirms, and marks it published only after the broker
 * confirmed it. `RELAY_SHARDS` shard loops; a loop runs its shard only while this process holds
 * `GET_LOCK('<prefix>:relay#<i>/<n>')` on the shared lock connection, at most `maxHeldShards`
 * per process. All rows of one aggregate (one message, one domain) hash to one shard, so they
 * are published by one loop in id order.
 *
 * Failure classes: broker not connected/blocked, channel death or a confirm timeout =
 * infrastructure (no row written for the unconfirmed rows, broker backoff); a broker nack = also
 * infrastructure (a full work queue with `overflow: reject-publish`, or a quorum queue without a
 * quorum): the row is deferred (`available_at`, `last_error = 'nacked'`) with a backoff that
 * grows with the shard's consecutive nacking passes, and `attempts` is unchanged, so a queue that
 * stays full for hours never turns healthy rows into poison (backpressure into MySQL, Q4); a
 * mandatory return = that row (`attempts + 1`, row backoff on `attempts`, `last_error =
 * 'unroutable'`); a contract or guard violation = poison (`attempts = maxAttempts`, never
 * published, alerted). A database error = relay backoff, no broker work. Logs carry ids and
 * codes only, never payload values.
 */
export class OutboxRelay {
  readonly lockPrefix: string;
  private readonly logger: Logger;
  private readonly now: () => Date;
  private readonly random: () => number;
  private readonly sleepFn: (ms: number, signal: AbortSignal) => Promise<boolean>;
  private readonly shardLockPrefix: string;
  private readonly failures: number[];
  /** Consecutive passes per shard in which the broker nacked at least one row. */
  private readonly nackStreaks: number[];
  private readonly unownedLag = new Map<number, { at: number; seconds: number }>();
  private acquiring: Promise<void> = Promise.resolve();
  private abort = new AbortController();
  private loops: Promise<void>[] = [];

  constructor(private readonly options: OutboxRelayOptions) {
    validate(options);
    this.lockPrefix = options.lockPrefix ?? 'er';
    this.shardLockPrefix = `${this.lockPrefix}:relay#`;
    this.logger = options.logger.child({ component: 'outbox-relay' });
    this.now = options.now ?? (() => new Date());
    this.random = options.random ?? Math.random;
    this.sleepFn = options.sleep ?? defaultSleep;
    this.failures = new Array<number>(options.shards).fill(0);
    this.nackStreaks = new Array<number>(options.shards).fill(0);
  }

  lockName(index: number): string {
    return relayLockName(this.lockPrefix, index, this.options.shards);
  }

  get running(): boolean {
    return this.loops.length > 0;
  }

  /** Starts one loop per shard (idempotent). */
  start(): void {
    if (this.loops.length > 0) return;
    this.abort = new AbortController();
    const signal = this.abort.signal;
    for (let index = 0; index < this.options.shards; index += 1) {
      this.loops.push(this.loop(index, signal));
    }
    this.logger.info(
      { shards: this.options.shards, maxHeldShards: this.options.maxHeldShards },
      'outbox relay started',
    );
  }

  /** Stops the loops (an in-flight batch finishes), then releases the shard locks. */
  async stop(): Promise<void> {
    this.abort.abort();
    const loops = this.loops;
    this.loops = [];
    await Promise.all(loops);
    for (let index = 0; index < this.options.shards; index += 1) {
      await this.options.locks.release(this.lockName(index)).catch(() => undefined);
    }
    this.options.metrics.shardsHeld.set(this.options.locks.heldCount(this.shardLockPrefix));
  }

  /** One pass over shard `index` (public for tests). Never throws. */
  async runShard(index: number): Promise<ShardReport> {
    const report: ShardReport = {
      shard: index,
      outcome: 'idle',
      read: 0,
      published: 0,
      failed: 0,
      poison: 0,
      blocked: 0,
      delayMs: this.options.pollIntervalMs,
    };
    const { broker, metrics } = this.options;
    // Step 2: before touching the database.
    if (!broker.connected || broker.blocked) {
      report.outcome = 'broker_unavailable';
      report.delayMs = this.backoff(index);
      return report;
    }
    let owner: boolean;
    try {
      owner = await this.acquire(index);
    } catch (error) {
      return this.databaseError(index, report, error, 'lock');
    } finally {
      metrics.shardsHeld.set(this.options.locks.heldCount(this.shardLockPrefix));
    }
    if (!owner) {
      report.outcome = 'not_owner';
      await this.reportUnownedLag(index);
      return report;
    }
    this.unownedLag.delete(index);

    const started = performance.now();
    let rows: OutboxRow[];
    try {
      rows = await this.options.store.readUnpublished({
        shard: this.shard(index),
        limit: this.options.scanLimit,
        maxAttempts: this.options.maxAttempts,
        ...this.scope(),
      });
    } catch (error) {
      return this.databaseError(index, report, error, 'read');
    }
    report.read = rows.length;
    const now = this.now();
    // Step 9: age of the oldest row read (0 when none).
    const oldest = rows[0];
    metrics.lag.set(
      { shard: String(index) },
      oldest ? Math.max(0, (now.getTime() - oldest.createdAt.getTime()) / 1000) : 0,
    );

    const plan = planBatch(rows, now, this.options.batchSize);
    report.blocked = plan.blocked;
    if (plan.publishable.length === 0) {
      this.failures[index] = 0;
      return report;
    }

    // Step 5: envelopes; poison rows are classified and never published.
    const poison: PoisonRow[] = [];
    const sendable: { row: OutboxRow; item: PublishItem }[] = [];
    for (const row of plan.publishable) {
      const built = buildEnvelope(row, {
        appId: this.options.appId,
        maxMessageBytes: this.options.maxMessageBytes,
      });
      if (built.ok) sendable.push({ row, item: { envelope: built.envelope } });
      else poison.push({ id: row.id, createdAt: row.createdAt, code: built.code });
    }

    let results: PublishResult[] = [];
    let brokerFailed = false;
    if (sendable.length > 0) {
      try {
        results = await this.options.publisher.publishBatch(sendable.map((s) => s.item));
      } catch (error) {
        if (!(error instanceof BrokerUnavailableError)) {
          this.logger.error({ shard: index, ...errorFields(error) }, 'relay publish failed');
        }
        metrics.failures.inc({ reason: 'broker_unavailable' });
        brokerFailed = true;
      }
    }

    // Step 6: per-row outcomes.
    const confirmed: { row: OutboxRow; exchange: string }[] = [];
    const failed: FailedRow[] = [];
    let timedOut = false;
    const nacks = results.filter((r) => r.outcome === 'nacked').length;
    const nackStreak = nacks > 0 ? (this.nackStreaks[index] ?? 0) + 1 : 0;
    results.forEach((result, i) => {
      const entry = sendable[i];
      if (!entry) return;
      const { row } = entry;
      switch (result.outcome) {
        case 'confirmed':
          confirmed.push({ row, exchange: exchangeOf(row) });
          break;
        case 'nacked':
          // Infrastructure (a full or unavailable queue): deferred, never counted as an attempt.
          failed.push({
            id: row.id,
            createdAt: row.createdAt,
            code: 'nacked',
            countsAttempt: false,
            availableAt: new Date(
              now.getTime() + backoffDelay(nackStreak, this.options.rowBackoff, this.random),
            ),
          });
          break;
        case 'returned':
          // Unroutable: specific to the row (its routing key reaches no queue).
          failed.push({
            id: row.id,
            createdAt: row.createdAt,
            code: 'unroutable',
            countsAttempt: true,
            availableAt: new Date(
              now.getTime() + backoffDelay(row.attempts + 1, this.options.rowBackoff, this.random),
            ),
          });
          break;
        case 'refused':
          poison.push({
            id: row.id,
            createdAt: row.createdAt,
            code: result.code ?? 'contract_invalid',
          });
          break;
        case 'timeout':
          timedOut = true;
          break;
      }
    });

    try {
      // Step 7: only rows the broker confirmed, only while still unpublished.
      if (confirmed.length > 0) {
        await this.options.store.markPublished(
          confirmed.map(({ row }): OutboxKey => ({ id: row.id, createdAt: row.createdAt })),
        );
      }
      if (failed.length > 0) await this.options.store.markFailed(failed);
      if (poison.length > 0) await this.options.store.markPoison(poison, this.options.maxAttempts);
    } catch (error) {
      this.countOutcomes(confirmed, failed, poison, false);
      return this.databaseError(index, report, error, 'mark');
    }
    this.countOutcomes(confirmed, failed, poison, true);
    if (results.length > 0) this.nackStreaks[index] = nackStreak;
    if (nacks > 0) {
      this.logger.warn(
        { shard: index, nacked: nacks, nackStreak },
        'broker nacked publishes (full or unavailable queue); rows deferred, attempts unchanged',
      );
    }
    metrics.batchSeconds.observe((performance.now() - started) / 1000);
    report.published = confirmed.length;
    report.failed = failed.length;
    report.poison = poison.length;

    if (brokerFailed || timedOut) {
      if (timedOut) metrics.failures.inc({ reason: 'timeout' });
      report.outcome = brokerFailed ? 'broker_unavailable' : 'timeout';
      report.delayMs = this.backoff(index);
      this.logger.warn(
        { shard: index, unconfirmed: sendable.length - confirmed.length - failed.length },
        'relay batch not confirmed; backing off',
      );
      return report;
    }
    this.failures[index] = 0;
    report.outcome = 'published';
    // Step 8: a full batch polls again at once.
    report.delayMs =
      plan.publishable.length >= this.options.batchSize ? 0 : this.options.pollIntervalMs;
    return report;
  }

  // -------------------------------------------------------------------------------------------

  private async loop(index: number, signal: AbortSignal): Promise<void> {
    while (!signal.aborted) {
      const report = await this.runShard(index);
      if (signal.aborted) break;
      if (report.delayMs > 0) await this.sleepFn(report.delayMs, signal);
    }
  }

  private shard(index: number): RelayShard {
    return { index, count: this.options.shards };
  }

  private scope(): { organizationIds?: readonly bigint[] } {
    return this.options.organizationIds === undefined
      ? {}
      : { organizationIds: this.options.organizationIds };
  }

  /** `ensure()`s the shard lock unless `maxHeldShards` other shard locks are already held here. */
  private acquire(index: number): Promise<boolean> {
    // Serialized across the shard loops: the held count must not change between the check and
    // the GET_LOCK, or concurrent loops would together exceed `maxHeldShards`.
    const attempt = this.acquiring.then(async () => {
      const { locks, maxHeldShards } = this.options;
      const name = this.lockName(index);
      if (!locks.isHeld(name) && locks.heldCount(this.shardLockPrefix) >= maxHeldShards) {
        return false;
      }
      return locks.ensure(name);
    });
    this.acquiring = attempt.then(
      () => undefined,
      () => undefined,
    );
    return attempt;
  }

  /**
   * Step 9 for a shard this process does not hold: `now − MIN(created_at)` of its publishable
   * rows, at most every `UNOWNED_LAG_EVERY_MS`, so a shard no replica holds shows a growing lag.
   */
  private async reportUnownedLag(index: number): Promise<void> {
    const nowMs = this.now().getTime();
    const cached = this.unownedLag.get(index);
    let seconds: number;
    if (cached && nowMs - cached.at < UNOWNED_LAG_EVERY_MS) {
      seconds = cached.seconds;
    } else {
      try {
        const oldest = await this.options.store.oldestUnpublished({
          shard: this.shard(index),
          maxAttempts: this.options.maxAttempts,
          ...this.scope(),
        });
        seconds = oldest ? Math.max(0, (nowMs - oldest.getTime()) / 1000) : 0;
      } catch (error) {
        this.logger.warn({ shard: index, ...errorFields(error) }, 'unowned shard lag query failed');
        this.options.metrics.failures.inc({ reason: 'database' });
        return;
      }
      this.unownedLag.set(index, { at: nowMs, seconds });
    }
    this.options.metrics.lag.set({ shard: String(index) }, seconds);
  }

  private backoff(index: number): number {
    const failures = (this.failures[index] ?? 0) + 1;
    this.failures[index] = failures;
    return backoffDelay(failures, this.options.brokerBackoff, this.random);
  }

  private databaseError(
    index: number,
    report: ShardReport,
    error: unknown,
    phase: 'lock' | 'read' | 'mark',
  ): ShardReport {
    this.options.metrics.failures.inc({ reason: 'database' });
    this.logger.warn(
      { shard: index, phase, ...errorFields(error) },
      'relay database error; backing off',
    );
    report.outcome = 'database_error';
    report.delayMs = this.backoff(index);
    return report;
  }

  /** Metrics and logs of a batch's outcomes (`marked` = the database writes succeeded). */
  private countOutcomes(
    confirmed: readonly { row: OutboxRow; exchange: string }[],
    failed: readonly FailedRow[],
    poison: readonly PoisonRow[],
    marked: boolean,
  ): void {
    const { metrics } = this.options;
    if (marked) {
      for (const { row, exchange } of confirmed) {
        metrics.published.inc({ exchange, event_type: row.eventType });
      }
    }
    for (const row of failed) metrics.failures.inc({ reason: row.code });
    for (const row of poison) {
      metrics.failures.inc({ reason: row.code });
      if (marked) {
        this.logger.warn(
          { outboxId: row.id.toString(), code: row.code },
          'poison outbox row excluded from publishing (operator action needed)',
        );
      }
    }
  }
}

const EXCHANGE_BY_TYPE = new Map<string, string>(
  Object.values(EVENT_REGISTRY).map((d) => [d.type, d.exchange]),
);

/** The registry exchange of a row's type (the publisher routes with the same lookup). */
function exchangeOf(row: OutboxRow): string {
  return EXCHANGE_BY_TYPE.get(row.eventType) ?? 'unknown';
}

function validate(options: OutboxRelayOptions): void {
  const intIn = (value: number, min: number, max: number) =>
    Number.isInteger(value) && value >= min && value <= max;
  if (!intIn(options.shards, 1, 64)) throw new Error('relay shards must be 1-64');
  if (!intIn(options.maxHeldShards, 1, 64)) throw new Error('relay maxHeldShards must be 1-64');
  if (!intIn(options.batchSize, 1, 1000)) throw new Error('relay batchSize must be 1-1000');
  if (!intIn(options.scanLimit, options.batchSize, 10_000)) {
    throw new Error('relay scanLimit must be between batchSize and 10000');
  }
  if (!intIn(options.maxAttempts, 1, 100)) throw new Error('relay maxAttempts must be 1-100');
  for (const policy of [options.brokerBackoff, options.rowBackoff]) {
    if (!(policy.baseMs > 0 && policy.maxMs >= policy.baseMs)) {
      throw new Error('relay backoff must satisfy 0 < baseMs <= maxMs');
    }
  }
  const prefix = options.lockPrefix ?? 'er';
  if (!/^[a-z0-9-]{1,32}$/i.test(prefix)) throw new Error('relay lockPrefix must be a short token');
}
