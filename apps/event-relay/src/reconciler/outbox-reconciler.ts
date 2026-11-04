import { performance } from 'node:perf_hooks';
import { errorFields, sleep as defaultSleep } from '@email-gateway/common';
import { eventTypesBoundTo, queueDefinition, type QueueName } from '@email-gateway/event-contracts';
import type { Logger } from '@email-gateway/logger';
import type { RelayMetrics } from '../metrics/relay-metrics';
import type { ConsumerProgress, ReconcilerStore, Scope, SweepRow } from './reconciler-store';

/** `outbox_unpublished_rows` is counted up to this many rows (Q12 step 1). */
export const UNPUBLISHED_COUNT_CAP = 100_000;
export const DEFAULT_RECONCILER_LOCK = 'er:reconciler';
export const DEFAULT_RECONCILE_CURSOR = 'reconcile:unconsumed';

/**
 * Ready messages of a work queue (a passive `queue.declare`; `AmqpQueueDepth` in production).
 * Rejects when the broker cannot be asked; the reconciler then defers (it never re-drives into a
 * broker it cannot see).
 */
export interface QueueDepthProbe {
  readyMessages(queue: QueueName): Promise<number>;
}

/** The `AdvisoryLocks` surface the reconciler uses. */
export interface ReconcilerLocks {
  ensure(name: string): Promise<boolean>;
  release(name: string): Promise<void>;
}

export interface OutboxReconcilerOptions {
  store: ReconcilerStore;
  locks: ReconcilerLocks;
  metrics: RelayMetrics;
  logger: Logger;
  /** `RECONCILE_QUEUES`: work queues of the topology with a ledger consumer. */
  queues: readonly QueueName[];
  intervalMs: number;
  unconsumedAfterSeconds: number;
  /** 0 = detect only. */
  maxRedrives: number;
  lookbackHours: number;
  batchSize: number;
  startPosition: 'oldest' | 'latest';
  /** `RELAY_MAX_ATTEMPTS` (poison threshold). */
  maxAttempts: number;
  /** Default `er:reconciler` (tests use their own). */
  lockName?: string;
  /** Default `reconcile:unconsumed` (tests use their own). */
  cursorName?: string;
  /** `organization_id IN (…)` scope: constructor-only (tests, dedicated per-tenant relays). */
  organizationIds?: readonly bigint[];
  /**
   * Backlog check before a re-drive (production: `AmqpQueueDepth`). Without it the queues are
   * taken as empty (unit tests).
   */
  queueDepth?: QueueDepthProbe;
  now?: () => Date;
  sleep?: (ms: number, signal: AbortSignal) => Promise<boolean>;
}

/** A tracked queue: the event types bound to it and the ledger name of its consumer. */
export interface TrackedQueue {
  queue: QueueName;
  ledgerName: string;
  eventTypes: string[];
  /**
   * Longest gap between two retry hops of one event: twice the queue's `maxDelayMs` (a hold, or a
   * delay-queue TTL that expires at most `maxDelayMs` late behind a longer one, Q8).
   */
  maxHopGapMs: number;
}

/** Why the sweep stopped before the end of its page. */
export type SweepStop = 'end' | 'not_due' | 'unpublished' | 'published_recently';

export interface ReconcileReport {
  active: boolean;
  unpublished: number;
  poison: number;
  /** Rows examined by the sweep (up to the stop). */
  swept: number;
  stoppedBy: SweepStop;
  settled: number;
  redriven: number;
  exhausted: number;
  rechecked: number;
  /** Rows whose consumer dead-lettered the event (settled: replay is their recovery path). */
  deadLettered: number;
  /**
   * Rows not re-driven now: the consumer is still retrying the event, or its queue has a backlog
   * (or cannot be checked). Watched: re-checked after the threshold.
   */
  deferred: number;
  /** Rows without a ledger row of their queue's consumer (dead letters excluded), by queue. */
  unconsumed: Record<string, number>;
  cursor: bigint;
}

/** Resolves `RECONCILE_QUEUES` against the topology. Throws for a queue without a ledger consumer. */
export function trackedQueues(queues: readonly QueueName[]): TrackedQueue[] {
  return queues.map((queue) => {
    const definition = queueDefinition(queue);
    if (definition.role !== 'work' || definition.consumer.kind !== 'ledger') {
      throw new Error('reconciled queues must be work queues with a ledger consumer');
    }
    return {
      queue,
      ledgerName: definition.consumer.ledgerName,
      eventTypes: eventTypesBoundTo(queue),
      maxHopGapMs: 2 * (definition.retry?.maxDelayMs ?? 0),
    };
  });
}

/**
 * Dead-letter reasons that a copy published by the relay cannot produce: the relay validates the
 * envelope, the schema version and the tenant against the registry before publishing, and an
 * approval it publishes always has its outbox row. Such a dead letter comes from a copy that did
 * not come from the relay (a forged or altered message with a real event id, published with a
 * leaked consumer or ops credential) or from a consumer/relay version skew. Its progress record
 * therefore never settles the outbox row: the row is reconciled like one without a record
 * (bounded re-drives, then an exhausted alert), so a forged copy cannot hide a lost event.
 */
export const UNTRUSTED_DEAD_LETTER_REASONS: ReadonlySet<string> = new Set([
  'contract_invalid',
  'unknown_event_type',
  'unsupported_schema_version',
  'tenant_mismatch',
  'approval_not_issued',
  'approval_mismatch',
]);

/** A progress record that settles a row: the consumer dead-lettered the relay's copy on purpose. */
export function settlesAsDeadLettered(progress: ConsumerProgress | undefined): boolean {
  return (
    progress?.state === 'dead_lettered' &&
    (progress.reason === null || !UNTRUSTED_DEAD_LETTER_REASONS.has(progress.reason))
  );
}

type Resolution = 'settled' | 'redriven' | 'exhausted' | 'skipped' | 'dead_lettered' | 'deferred';
type DeferReason = 'retrying' | 'queue_backlog' | 'queue_unknown';

/**
 * The reconciliation service (step 3.2 Q12, ADR-0023): one active instance
 * (`GET_LOCK('er:reconciler')`), every `intervalMs`:
 *
 * 1. outbox health gauges (unpublished count and age, poison rows);
 * 2. an unconsumed sweep over `message_outbox` by id (cursor `reconcile:unconsumed` in
 *    `stream_cursors`, rows within `lookbackHours`): a row of a tracked type, published more
 *    than `unconsumedAfterSeconds` ago, without a `message_idempotency (ledger, event_id)` row
 *    is re-driven through the outbox (`published_at = NULL`), at most `maxRedrives` times, then
 *    reported exhausted. The sweep stops at the first row that is not due, is still unpublished
 *    (the relay owns it) or was published too recently; the cursor advances through the
 *    contiguous prefix handled;
 * 3. a re-check of earlier re-drives and deferrals (`last_redriven_at`): ledger present →
 *    settled; absent → deferred again, re-driven again (bounded) or exhausted.
 *
 * "No ledger row" alone does not mean "lost" (review round 1). Before re-driving, the
 * reconciler reads the consumer's `message_consumer_progress` row: `dead_lettered` → settled
 * (the consumer gave up on purpose; replay is the recovery path, a re-drive would only make
 * another dead letter), except for the `UNTRUSTED_DEAD_LETTER_REASONS` a relay copy cannot
 * produce; `retrying` with a hop within the threshold plus the queue's longest hop
 * gap → deferred. Then the queue's ready count: a backlog (or a broker it cannot ask) →
 * deferred, so a consumer outage or a slow drain is not multiplied by re-drive copies. A
 * deferred row is watched (`last_redriven_at = NOW(3)`, `redrive_count` unchanged) and looked
 * at again by the re-check.
 *
 * Re-driven rows keep their `event_id`, so every consumer's ledger absorbs the copy. It never
 * writes business tables and never invents events.
 */
export class OutboxReconciler {
  readonly lockName: string;
  readonly cursorName: string;
  readonly tracked: TrackedQueue[];
  private readonly byType = new Map<string, TrackedQueue[]>();
  private readonly logger: Logger;
  private readonly now: () => Date;
  private readonly sleepFn: (ms: number, signal: AbortSignal) => Promise<boolean>;
  private abort = new AbortController();
  private loop: Promise<void> | undefined;
  /** The clock and the queue depths of the current run (each queue is asked once per run). */
  private runNow = new Date(0);
  private depths = new Map<QueueName, Promise<number | undefined>>();
  /** Rows the sweep of the current run resolved (the re-check never handles a row twice per run). */
  private sweptIds = new Set<bigint>();

  constructor(private readonly options: OutboxReconcilerOptions) {
    validate(options);
    this.lockName = options.lockName ?? DEFAULT_RECONCILER_LOCK;
    this.cursorName = options.cursorName ?? DEFAULT_RECONCILE_CURSOR;
    this.tracked = trackedQueues(options.queues);
    for (const queue of this.tracked) {
      for (const type of queue.eventTypes) {
        this.byType.set(type, [...(this.byType.get(type) ?? []), queue]);
      }
    }
    this.logger = options.logger.child({ component: 'outbox-reconciler' });
    this.now = options.now ?? (() => new Date());
    this.sleepFn = options.sleep ?? defaultSleep;
  }

  start(): void {
    if (this.loop) return;
    this.abort = new AbortController();
    const signal = this.abort.signal;
    this.loop = (async () => {
      while (!signal.aborted) {
        try {
          await this.runOnce();
        } catch (error) {
          this.logger.warn({ ...errorFields(error) }, 'reconciler run failed; retrying');
        }
        if (signal.aborted) break;
        await this.sleepFn(this.options.intervalMs, signal);
      }
    })();
    this.logger.info(
      { queues: this.tracked.map((q) => q.queue), intervalMs: this.options.intervalMs },
      'outbox reconciler started',
    );
  }

  async stop(): Promise<void> {
    this.abort.abort();
    await this.loop;
    this.loop = undefined;
    await this.options.locks.release(this.lockName).catch(() => undefined);
  }

  /** One run (public for tests). Throws on a database error (the loop retries next interval). */
  async runOnce(): Promise<ReconcileReport> {
    const report: ReconcileReport = {
      active: false,
      unpublished: 0,
      poison: 0,
      swept: 0,
      stoppedBy: 'end',
      settled: 0,
      redriven: 0,
      exhausted: 0,
      rechecked: 0,
      deadLettered: 0,
      deferred: 0,
      unconsumed: Object.fromEntries(this.tracked.map((q) => [q.queue, 0])),
      cursor: 0n,
    };
    if (!(await this.options.locks.ensure(this.lockName))) return report;
    report.active = true;
    const started = performance.now();
    const now = this.now();
    this.runNow = now;
    this.depths = new Map();
    this.sweptIds = new Set();
    await this.reportHealth(now, report);
    await this.sweep(now, report);
    await this.recheck(now, report);
    for (const queue of this.tracked) {
      this.options.metrics.unconsumedRows.set(
        { queue: queue.queue },
        report.unconsumed[queue.queue] ?? 0,
      );
    }
    this.options.metrics.runSeconds.observe((performance.now() - started) / 1000);
    if (report.redriven > 0 || report.exhausted > 0 || report.deferred > 0) {
      this.logger.info(
        {
          redriven: report.redriven,
          exhausted: report.exhausted,
          deferred: report.deferred,
          deadLettered: report.deadLettered,
          settled: report.settled,
          rechecked: report.rechecked,
        },
        'reconciler run',
      );
    }
    return report;
  }

  // -------------------------------------------------------------------------------------------

  private scope(): Scope {
    return this.options.organizationIds === undefined
      ? {}
      : { organizationIds: this.options.organizationIds };
  }

  /** Step 1. */
  private async reportHealth(now: Date, report: ReconcileReport): Promise<void> {
    const { metrics } = this.options;
    const health = await this.options.store.health(
      this.options.maxAttempts,
      UNPUBLISHED_COUNT_CAP,
      this.scope(),
    );
    report.unpublished = health.unpublished;
    report.poison = health.poison;
    metrics.unpublishedRows.set(health.unpublished);
    metrics.unpublishedOldestSeconds.set(
      health.oldestUnpublished
        ? Math.max(0, (now.getTime() - health.oldestUnpublished.getTime()) / 1000)
        : 0,
    );
    metrics.poisonRows.set(health.poison);
    if (health.poison > 0) {
      this.logger.warn(
        { poisonRows: health.poison, oldestPoisonId: health.oldestPoisonId?.toString() },
        'poison outbox rows need operator action (docs/runbooks/rabbitmq-messaging.md)',
      );
    }
  }

  /** Step 2. */
  private async sweep(now: Date, report: ReconcileReport): Promise<void> {
    const { store } = this.options;
    const since = new Date(now.getTime() - this.options.lookbackHours * 3_600_000);
    const dueBefore = now.getTime() - this.options.unconsumedAfterSeconds * 1000;
    const cursor = await this.cursor(since);
    report.cursor = cursor;
    const rows = await store.readAfter(cursor, since, this.options.batchSize, this.scope());

    const candidates: SweepRow[] = [];
    let advanceTo = cursor;
    let stop: SweepStop = 'end';
    for (const row of rows) {
      if (row.createdAt.getTime() > dueBefore) {
        stop = 'not_due';
        break;
      }
      const queues = this.byType.get(row.eventType);
      if (!queues || row.attempts >= this.options.maxAttempts) {
        // Untracked type or poison (reported by the health gauges): settled for this check.
        if (candidates.length === 0) advanceTo = row.id;
        else candidates.push(row);
        report.swept += 1;
        continue;
      }
      if (row.publishedAt === null) {
        stop = 'unpublished';
        break;
      }
      if (row.publishedAt.getTime() > dueBefore) {
        stop = 'published_recently';
        break;
      }
      candidates.push(row);
      report.swept += 1;
    }
    report.stoppedBy = stop;

    // Ledger lookups in one batch per consumer; every candidate is resolved, so the cursor
    // passes the whole contiguous prefix.
    const resolutions = await this.resolve(
      candidates.filter((row) => this.isTracked(row)),
      report,
    );
    for (const row of candidates) {
      if (this.isTracked(row) && resolutions.get(row.id) === undefined) break;
      advanceTo = row.id;
    }
    if (advanceTo > cursor) {
      await store.saveCursor(this.cursorName, advanceTo, now);
      report.cursor = advanceTo;
    }
  }

  /** Step 3. */
  private async recheck(now: Date, report: ReconcileReport): Promise<void> {
    const before = new Date(now.getTime() - this.options.unconsumedAfterSeconds * 1000);
    // A row the sweep just deferred carries a fresh `last_redriven_at` (database clock); with a
    // reconciler clock ahead of the database it could look due already: skip it this run.
    const rows = (
      await this.options.store.dueRechecks(before, this.options.batchSize, this.scope())
    ).filter((row) => !this.sweptIds.has(row.id));
    report.rechecked = rows.length;
    const untracked = rows.filter((row) => !this.isTracked(row));
    for (const row of untracked) await this.options.store.clearRedrive(row);
    await this.resolve(
      rows.filter((row) => this.isTracked(row)),
      report,
    );
  }

  private isTracked(row: SweepRow): boolean {
    return this.byType.has(row.eventType) && row.attempts < this.options.maxAttempts;
  }

  /** Ledger check, then settle / re-drive / exhausted per row. */
  private async resolve(
    rows: readonly SweepRow[],
    report: ReconcileReport,
  ): Promise<Map<bigint, Resolution>> {
    const resolutions = new Map<bigint, Resolution>();
    if (rows.length === 0) return resolutions;
    const { store } = this.options;
    const present = new Map<string, Set<string>>();
    const progress = new Map<string, Map<string, ConsumerProgress>>();
    for (const queue of this.tracked) {
      const ids = rows.filter((r) => queue.eventTypes.includes(r.eventType)).map((r) => r.eventId);
      const consumed = await store.ledgerPresent(queue.ledgerName, ids);
      present.set(queue.ledgerName, consumed);
      progress.set(
        queue.ledgerName,
        await store.progress(
          queue.ledgerName,
          ids.filter((id) => !consumed.has(id)),
        ),
      );
    }
    for (const row of rows) {
      const missing = (this.byType.get(row.eventType) ?? []).filter(
        (queue) => !present.get(queue.ledgerName)?.has(row.eventId),
      );
      const progressOf = (queue: TrackedQueue) => progress.get(queue.ledgerName)?.get(row.eventId);
      resolutions.set(row.id, await this.resolveRow(row, missing, progressOf, report));
      this.sweptIds.add(row.id);
    }
    return resolutions;
  }

  private async resolveRow(
    row: SweepRow,
    unhandled: readonly TrackedQueue[],
    progressOf: (queue: TrackedQueue) => ConsumerProgress | undefined,
    report: ReconcileReport,
  ): Promise<Resolution> {
    const { store, metrics, maxRedrives } = this.options;
    if (unhandled.length === 0) {
      if (row.lastRedrivenAt !== null) await store.clearRedrive(row);
      report.settled += 1;
      return 'settled';
    }
    // Dead-lettered by its consumer: settled for the reconciler (replay is the recovery path),
    // unless the reason shows the dead-lettered copy was not the relay's (forged or altered).
    const missing = unhandled.filter((queue) => !settlesAsDeadLettered(progressOf(queue)));
    if (missing.length === 0) {
      if (row.lastRedrivenAt !== null) await store.clearRedrive(row);
      for (const queue of unhandled) {
        metrics.skipped.inc({ queue: queue.queue, reason: 'dead_lettered' });
      }
      report.deadLettered += 1;
      return 'dead_lettered';
    }
    for (const queue of missing) {
      report.unconsumed[queue.queue] = (report.unconsumed[queue.queue] ?? 0) + 1;
    }
    const ids = {
      outboxId: row.id.toString(),
      eventId: row.eventId,
      eventType: row.eventType,
      queues: missing.map((q) => q.queue),
      redriveCount: row.redriveCount,
    };
    const deferReason = await this.deferReason(missing, progressOf);
    if (deferReason !== undefined) {
      if (!(await store.watch(row))) {
        this.logger.debug(ids, 'outbox row changed before its deferral');
        return 'skipped';
      }
      for (const queue of missing) metrics.skipped.inc({ queue: queue.queue, reason: deferReason });
      report.deferred += 1;
      this.logger.debug({ ...ids, reason: deferReason }, 'unconsumed outbox row deferred');
      return 'deferred';
    }
    if (row.redriveCount >= maxRedrives) {
      if (row.lastRedrivenAt !== null) await store.clearRedrive(row);
      for (const queue of missing) metrics.exhausted.inc({ queue: queue.queue });
      report.exhausted += 1;
      this.logger.warn(
        ids,
        'unconsumed outbox row exhausted its re-drives (operator action needed)',
      );
      return 'exhausted';
    }
    if (!(await store.redrive(row, maxRedrives))) {
      // Changed since it was read (no longer published or at the bound): left to the next run.
      this.logger.debug(ids, 'outbox row changed before its re-drive');
      return 'skipped';
    }
    for (const queue of missing) metrics.redriven.inc({ queue: queue.queue });
    report.redriven += 1;
    this.logger.info(ids, 'unconsumed outbox row re-driven through the relay');
    return 'redriven';
  }

  /**
   * Why a re-drive must wait: the consumer recorded a retry hop recently (within the threshold
   * plus the queue's longest hop gap), or a queue still has ready messages (a backlog the
   * consumer has not reached), or its depth cannot be read.
   */
  private async deferReason(
    missing: readonly TrackedQueue[],
    progressOf: (queue: TrackedQueue) => ConsumerProgress | undefined,
  ): Promise<DeferReason | undefined> {
    const now = this.runNow.getTime();
    const threshold = this.options.unconsumedAfterSeconds * 1000;
    const retrying = missing.some((queue) => {
      const progress = progressOf(queue);
      return (
        progress?.state === 'retrying' &&
        progress.updatedAt.getTime() >= now - threshold - queue.maxHopGapMs
      );
    });
    if (retrying) return 'retrying';
    for (const queue of missing) {
      const depth = await this.depthOf(queue.queue);
      if (depth === undefined) return 'queue_unknown';
      if (depth > 0) return 'queue_backlog';
    }
    return undefined;
  }

  /** Ready messages of `queue`, asked once per run; `undefined` when the broker cannot tell. */
  private depthOf(queue: QueueName): Promise<number | undefined> {
    const probe = this.options.queueDepth;
    if (!probe) return Promise.resolve(0);
    let depth = this.depths.get(queue);
    if (!depth) {
      depth = probe.readyMessages(queue).then(
        (n) => n,
        (error: unknown) => {
          this.logger.warn({ queue, ...errorFields(error) }, 'queue depth unavailable; deferring');
          return undefined;
        },
      );
      this.depths.set(queue, depth);
    }
    return depth;
  }

  /** The durable cursor, created at the first start (`oldest` within the lookback, or `latest`). */
  private async cursor(since: Date): Promise<bigint> {
    const { store } = this.options;
    const existing = await store.loadCursor(this.cursorName);
    if (existing !== undefined && existing !== null) return existing;
    const position =
      this.options.startPosition === 'latest'
        ? await store.latestPosition(this.scope())
        : await store.oldestPosition(since, this.scope());
    const stored = await store.initCursor(this.cursorName, position);
    this.logger.info(
      { position: stored.toString(), startPosition: this.options.startPosition },
      'reconciler cursor initialized',
    );
    return stored;
  }
}

function validate(options: OutboxReconcilerOptions): void {
  const intIn = (value: number, min: number, max: number) =>
    Number.isInteger(value) && value >= min && value <= max;
  if (options.queues.length === 0) throw new Error('reconciler needs at least one queue');
  if (!intIn(options.unconsumedAfterSeconds, 300, 518_400)) {
    throw new Error('reconciler unconsumedAfterSeconds must be at least 300');
  }
  if (!intIn(options.maxRedrives, 0, 20)) throw new Error('reconciler maxRedrives must be 0-20');
  if (!intIn(options.lookbackHours, 1, 144))
    throw new Error('reconciler lookbackHours must be 1-144');
  if (!intIn(options.batchSize, 1, 10_000)) throw new Error('reconciler batchSize must be 1-10000');
  if (!intIn(options.intervalMs, 1, 3_600_000))
    throw new Error('reconciler intervalMs is out of range');
  if (!intIn(options.maxAttempts, 1, 100)) throw new Error('reconciler maxAttempts must be 1-100');
}
