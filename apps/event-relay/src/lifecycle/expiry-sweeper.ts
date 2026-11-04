import { performance } from 'node:perf_hooks';
import { backoffDelay, errorFields, sleep as defaultSleep } from '@email-gateway/common';
import type { Logger } from '@email-gateway/logger';
import {
  EXPIRABLE_STATES,
  type MessageState,
  type TransitionOutcome,
  type TransitionRequest,
} from '@email-gateway/message-lifecycle';
import type { Backoff, ShardLocks } from '../relay/outbox-relay';
import type { LifecycleRelayMetrics } from './lifecycle-metrics';
import type { LifecycleCandidate, LifecycleStore } from './lifecycle-store';

/** Applies one expiry request in its own writer transaction (`transitionMessageWithRetry`). */
export type ExpiryTransition = (request: TransitionRequest) => Promise<TransitionOutcome>;

export interface ExpirySweeperOptions {
  store: LifecycleStore;
  transition: ExpiryTransition;
  locks: ShardLocks;
  metrics: LifecycleRelayMetrics;
  logger: Logger;
  /** `LIFECYCLE_EXPIRY_SHARDS`. */
  shards: number;
  /** `LIFECYCLE_EXPIRY_MAX_HELD_SHARDS`. */
  maxHeldShards: number;
  /** `LIFECYCLE_EXPIRY_INTERVAL_MS`: pause between two passes of a shard. */
  intervalMs: number;
  /** `LIFECYCLE_EXPIRY_BATCH_SIZE`: candidates per shard and pass (all states together). */
  batchSize: number;
  /** `LIFECYCLE_EXPIRY_LOOKBACK_DAYS`. */
  lookbackDays: number;
  /**
   * Per-state deadline in seconds (`LIFECYCLE_DEADLINE_<STATE>_HOURS` × 3600); states without an
   * entry or with 0 never expire. Integration tests pass second-scale deadlines.
   */
  deadlinesSeconds: Partial<Record<MessageState, number>>;
  /** Database backoff (`RELAY_BROKER_BACKOFF_*`, equal jitter). */
  backoff: Backoff;
  /** Lock namespace (default `er`): `<prefix>:lifecycle-expiry#<i>/<n>`. */
  lockPrefix?: string;
  organizationIds?: readonly bigint[];
  random?: () => number;
  sleep?: (ms: number, signal: AbortSignal) => Promise<boolean>;
}

export type ExpiryShardOutcome = 'not_owner' | 'database_error' | 'swept';

export interface ExpiryShardReport {
  shard: number;
  outcome: ExpiryShardOutcome;
  /** Candidates read per state. */
  found: Partial<Record<MessageState, number>>;
  expired: number;
  /** Candidates not expired (changed, duplicate, not_found). */
  skipped: number;
  delayMs: number;
}

/** The expiry shard lock name (MySQL GET_LOCK names are at most 64 characters). */
export const expiryLockName = (prefix: string, index: number, count: number): string =>
  `${prefix}:lifecycle-expiry#${index}/${count}`;

const SWEEPER_ACTOR = { role: 'sweeper', service: 'event-relay', type: 'system' } as const;

/**
 * The expiry sweeper (step 3.3 L13): `shards` loops; a loop sweeps its shard only while this
 * process holds `GET_LOCK('<prefix>:lifecycle-expiry#<i>/<n>')` on the shared lock connection, at
 * most `maxHeldShards` per process. Every `intervalMs`, for each state with a deadline, it reads
 * the overdue messages of its shard (`MOD(id, n) = i`, state changed within the lookback, at most
 * `batchSize` per pass) and moves each to `expired` in its own short transaction
 * (`expectedVersion` = the version it read, `expectedFrom` = the state it read, key
 * `expire:<id>:<version>`). A live transition in between changes the version: the service answers
 * `stale/version_mismatch` under the row lock and the candidate is skipped (`changed`), so the
 * sweeper never overwrites a newer state. A database error backs off; the loop continues.
 */
export class ExpirySweeper {
  readonly lockPrefix: string;
  private readonly logger: Logger;
  private readonly sleepFn: (ms: number, signal: AbortSignal) => Promise<boolean>;
  private readonly random: () => number;
  private readonly states: { state: MessageState; seconds: number }[];
  private readonly failures: number[];
  private readonly overdue: Map<number, Partial<Record<MessageState, number>>> = new Map();
  private acquiring: Promise<void> = Promise.resolve();
  private abort = new AbortController();
  private loops: Promise<void>[] = [];

  constructor(private readonly options: ExpirySweeperOptions) {
    validate(options);
    this.lockPrefix = options.lockPrefix ?? 'er';
    this.logger = options.logger.child({ component: 'lifecycle-expiry' });
    this.sleepFn = options.sleep ?? defaultSleep;
    this.random = options.random ?? Math.random;
    this.states = Object.entries(options.deadlinesSeconds).flatMap(([state, seconds]) =>
      seconds !== undefined && seconds > 0 ? [{ state: state as MessageState, seconds }] : [],
    );
    this.failures = new Array<number>(options.shards).fill(0);
    options.metrics.shards.set(options.shards);
  }

  lockName(index: number): string {
    return expiryLockName(this.lockPrefix, index, this.options.shards);
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
      {
        shards: this.options.shards,
        maxHeldShards: this.options.maxHeldShards,
        states: this.states.map((s) => s.state),
      },
      'lifecycle expiry sweeper started',
    );
  }

  /** Stops the loops (an in-flight candidate finishes), then releases the shard locks. */
  async stop(): Promise<void> {
    this.abort.abort();
    const loops = this.loops;
    this.loops = [];
    await Promise.all(loops);
    for (let index = 0; index < this.options.shards; index += 1) {
      await this.options.locks.release(this.lockName(index)).catch(() => undefined);
    }
    this.overdue.clear();
    this.reportGauges();
  }

  /** One pass over shard `index` (public for tests). Never throws. */
  async runShard(index: number, signal?: AbortSignal): Promise<ExpiryShardReport> {
    const report: ExpiryShardReport = {
      shard: index,
      outcome: 'swept',
      found: {},
      expired: 0,
      skipped: 0,
      delayMs: this.options.intervalMs,
    };
    let owner: boolean;
    try {
      owner = await this.acquire(index);
    } catch (error) {
      return this.databaseError(index, report, error, 'lock');
    } finally {
      this.reportGauges();
    }
    if (!owner) {
      report.outcome = 'not_owner';
      if (this.overdue.delete(index)) this.reportGauges();
      return report;
    }

    const started = performance.now();
    let remaining = this.options.batchSize;
    const candidates: LifecycleCandidate[] = [];
    try {
      for (const { state, seconds } of this.states) {
        if (remaining <= 0) {
          report.found[state] = 0;
          continue;
        }
        const rows = await this.options.store.expiryCandidates({
          state,
          olderThanSeconds: seconds,
          lookbackDays: this.options.lookbackDays,
          shard: { index, count: this.options.shards },
          limit: remaining,
          ...this.scope(),
        });
        report.found[state] = rows.length;
        remaining -= rows.length;
        candidates.push(...rows);
      }
    } catch (error) {
      return this.databaseError(index, report, error, 'read');
    }
    this.overdue.set(index, report.found);
    this.reportGauges();

    for (const candidate of candidates) {
      if (signal?.aborted) break;
      let outcome: TransitionOutcome;
      try {
        outcome = await this.options.transition(this.request(candidate));
      } catch (error) {
        this.options.metrics.passSeconds.observe((performance.now() - started) / 1000);
        return this.databaseError(index, report, error, 'expire');
      }
      this.count(candidate, outcome, report);
    }
    this.failures[index] = 0;
    this.options.metrics.passSeconds.observe((performance.now() - started) / 1000);
    if (report.expired > 0 || report.skipped > 0) {
      this.logger.info(
        { shard: index, expired: report.expired, skipped: report.skipped },
        'lifecycle expiry pass',
      );
    }
    // A full batch sweeps again at once.
    if (candidates.length >= this.options.batchSize) report.delayMs = 0;
    return report;
  }

  // -------------------------------------------------------------------------------------------

  private request(candidate: LifecycleCandidate): TransitionRequest {
    return {
      message: {
        id: candidate.id,
        receivedAt: candidate.receivedAt,
        organizationId: candidate.organizationId,
      },
      to: 'expired',
      reason: 'deadline_exceeded',
      actor: SWEEPER_ACTOR,
      transitionKey: `expire:${candidate.id.toString()}:${candidate.version}`,
      correlationId: `expire:${candidate.id.toString()}`,
      expectedVersion: candidate.version,
      expectedFrom: [candidate.state],
    };
  }

  private count(
    candidate: LifecycleCandidate,
    outcome: TransitionOutcome,
    report: ExpiryShardReport,
  ): void {
    const { metrics } = this.options;
    const ids = {
      messageId: candidate.id.toString(),
      organizationId: candidate.organizationId.toString(),
      state: candidate.state,
      version: candidate.version,
    };
    if (outcome.result === 'applied') {
      report.expired += 1;
      metrics.expired.inc({ state: candidate.state });
      this.logger.info({ ...ids, newVersion: outcome.version }, 'message expired');
      return;
    }
    report.skipped += 1;
    const reason =
      outcome.result === 'not_found'
        ? 'not_found'
        : outcome.result === 'duplicate' && outcome.why === 'transition_key'
          ? 'duplicate'
          : 'changed';
    metrics.expirySkipped.inc({ reason });
    this.logger.debug(
      { ...ids, result: outcome.result, why: 'why' in outcome ? outcome.why : undefined },
      'expiry candidate skipped',
    );
  }

  private async loop(index: number, signal: AbortSignal): Promise<void> {
    while (!signal.aborted) {
      const report = await this.runShard(index, signal);
      if (signal.aborted) break;
      if (report.delayMs > 0) await this.sleepFn(report.delayMs, signal);
    }
  }

  private scope(): { organizationIds?: readonly bigint[] } {
    return this.options.organizationIds === undefined
      ? {}
      : { organizationIds: this.options.organizationIds };
  }

  /** `ensure()`s the shard lock unless `maxHeldShards` other expiry shard locks are held here. */
  private acquire(index: number): Promise<boolean> {
    const attempt = this.acquiring.then(async () => {
      const { locks, maxHeldShards } = this.options;
      const name = this.lockName(index);
      if (!locks.isHeld(name) && locks.heldCount(this.lockNamePrefix()) >= maxHeldShards) {
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

  private lockNamePrefix(): string {
    return `${this.lockPrefix}:lifecycle-expiry#`;
  }

  private reportGauges(): void {
    const { metrics, locks } = this.options;
    metrics.shardsHeld.set(locks.heldCount(this.lockNamePrefix()));
    for (const { state } of this.states) {
      let total = 0;
      for (const found of this.overdue.values()) total += found[state] ?? 0;
      metrics.overdue.set({ state }, total);
    }
  }

  private databaseError(
    index: number,
    report: ExpiryShardReport,
    error: unknown,
    phase: 'lock' | 'read' | 'expire',
  ): ExpiryShardReport {
    this.options.metrics.errors.inc({ component: 'expiry' });
    const failures = (this.failures[index] ?? 0) + 1;
    this.failures[index] = failures;
    report.outcome = 'database_error';
    report.delayMs = backoffDelay(failures, this.options.backoff, this.random);
    this.logger.warn(
      { shard: index, phase, ...errorFields(error) },
      'lifecycle expiry database error; backing off',
    );
    return report;
  }
}

function validate(options: ExpirySweeperOptions): void {
  const intIn = (value: number, min: number, max: number) =>
    Number.isInteger(value) && value >= min && value <= max;
  if (!intIn(options.shards, 1, 64)) throw new Error('expiry shards must be 1-64');
  if (!intIn(options.maxHeldShards, 1, options.shards)) {
    throw new Error('expiry maxHeldShards must be 1-shards');
  }
  if (!intIn(options.batchSize, 1, 5000)) throw new Error('expiry batchSize must be 1-5000');
  if (!intIn(options.lookbackDays, 1, 400)) throw new Error('expiry lookbackDays must be 1-400');
  if (!intIn(options.intervalMs, 1, 3_600_000))
    throw new Error('expiry intervalMs is out of range');
  for (const [state, seconds] of Object.entries(options.deadlinesSeconds)) {
    if (!EXPIRABLE_STATES.includes(state as MessageState)) {
      throw new Error('expiry deadlines name only expirable states');
    }
    if (seconds !== undefined && !(Number.isInteger(seconds) && seconds >= 0)) {
      throw new Error('expiry deadlines must be non-negative integers (seconds)');
    }
  }
}
