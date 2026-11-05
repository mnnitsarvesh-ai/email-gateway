import { backoffDelay, sleep as defaultSleep } from '@email-gateway/common';
import type { Logger } from '@email-gateway/logger';
import { errorFields, isTransientFailure } from '../mime-ingestion/error-fields';
import { reportCompletion } from './round-service';
import type { ScanMetrics } from './scan-metrics';
import type { ScanStore } from './scan-store';

/** One cluster-wide leader (S10). */
export const SCAN_DEADLINE_LOCK = 'scan:deadline';

/** The subset of `AdvisoryLocks` the sweeper needs. */
export interface LeaderLock {
  ensure(name: string): Promise<boolean>;
  release(name: string): Promise<void>;
}

export interface DeadlineSweeperOptions {
  store: Pick<ScanStore, 'sweepCandidates' | 'sweepRound'>;
  locks: LeaderLock;
  metrics: ScanMetrics;
  logger: Logger;
  /** SCAN_SWEEP_INTERVAL_MS. */
  intervalMs: number;
  /** SCAN_SWEEP_LOOKBACK_HOURS: only rounds whose deadline passed within this window. */
  lookbackHours: number;
  /** SCAN_SWEEP_BATCH_SIZE. */
  batchSize: number;
  /** Lock name (default `scan:deadline`; integration tests use a per-run name). */
  lockName?: string;
  /** Restricts the sweep to these organizations (integration tests on the shared writer). */
  organizationIds?: readonly bigint[];
  now?: () => Date;
  sleep?: (ms: number, signal: AbortSignal) => Promise<boolean>;
  random?: () => number;
}

export interface SweepReport {
  outcome: 'not_leader' | 'database_error' | 'swept';
  found: number;
  completed: number;
  finalizedEngines: number;
  /** Rounds whose finalization failed with a non-transient error (skipped, retried next pass). */
  failed: number;
}

/**
 * The round deadline sweeper (step 4.1 S10): while this process holds
 * `GET_LOCK('scan:deadline')` (one leader per cluster), every SCAN_SWEEP_INTERVAL_MS it reads at
 * most SCAN_SWEEP_BATCH_SIZE `email_scans` rows with `status = 'running' AND deadline_at < now`
 * whose deadline passed within SCAN_SWEEP_LOOKBACK_HOURS (index `(status, deadline_at)`; bounded
 * by the round, not by the message's received_at, so rescan rounds of old messages are swept
 * too), and finalizes each
 * in its own writer transaction: message lock → scan lock → still running → a final `timeout`
 * row (`deadline_exceeded`, `engine.deadline_exceeded`) for every required engine without a
 * final → completion (E7 `scan_timeout` unless another engine failed otherwise; causation null).
 * A database error backs off; the loop continues. A round that fails with a non-transient error
 * (for example a contract violation of its `scanned.v1` payload) is counted, logged and passed
 * over, so one poisoned round (always the oldest deadline, first in every batch) never blocks
 * the others. Idempotent: a round completed meanwhile is skipped under its lock.
 */
export class DeadlineSweeper {
  readonly lockName: string;
  private readonly logger: Logger;
  private readonly now: () => Date;
  private readonly sleepFn: (ms: number, signal: AbortSignal) => Promise<boolean>;
  private readonly random: () => number;
  private abort = new AbortController();
  private loop: Promise<void> | undefined;
  private failures = 0;

  constructor(private readonly options: DeadlineSweeperOptions) {
    this.lockName = options.lockName ?? SCAN_DEADLINE_LOCK;
    this.logger = options.logger.child({ component: 'scan-deadline-sweeper' });
    this.now = options.now ?? (() => new Date());
    this.sleepFn = options.sleep ?? defaultSleep;
    this.random = options.random ?? Math.random;
  }

  get running(): boolean {
    return this.loop !== undefined;
  }

  start(): void {
    if (this.loop) return;
    this.abort = new AbortController();
    const signal = this.abort.signal;
    this.loop = this.run(signal);
    this.logger.info(
      { intervalMs: this.options.intervalMs, lock: this.lockName },
      'scan deadline sweeper started',
    );
  }

  async stop(): Promise<void> {
    this.abort.abort();
    await this.loop;
    this.loop = undefined;
    await this.options.locks.release(this.lockName).catch(() => undefined);
  }

  /** One pass (exported for tests and the loop). */
  async sweepOnce(): Promise<SweepReport> {
    const report: SweepReport = {
      outcome: 'swept',
      found: 0,
      completed: 0,
      finalizedEngines: 0,
      failed: 0,
    };
    let leader: boolean;
    try {
      leader = await this.options.locks.ensure(this.lockName);
    } catch (err) {
      this.options.metrics.sweeperErrors.inc();
      this.logger.warn(errorFields(err), 'scan deadline sweeper could not check its lock');
      return { ...report, outcome: 'database_error' };
    }
    if (!leader) return { ...report, outcome: 'not_leader' };
    const now = this.now();
    let candidates;
    try {
      candidates = await this.options.store.sweepCandidates(
        now,
        this.options.lookbackHours,
        this.options.batchSize,
        this.options.organizationIds,
      );
    } catch (err) {
      this.options.metrics.sweeperErrors.inc();
      this.logger.warn(errorFields(err), 'scan deadline sweeper could not read overdue rounds');
      return { ...report, outcome: 'database_error' };
    }
    report.found = candidates.length;
    for (const candidate of candidates) {
      const ids = {
        messageId: candidate.messageId.toString(),
        organizationId: candidate.organizationId.toString(),
        scanId: candidate.scanId.toString(),
      };
      try {
        const result = await this.options.store.sweepRound(candidate, this.now());
        for (const engine of result.finalized)
          this.options.metrics.deadlineFinalized.inc({ engine });
        for (const engine of result.finalized) {
          this.options.metrics.result(engine, 'timeout', true, null);
          this.options.metrics.failure(engine, 'deadline_exceeded');
        }
        report.finalizedEngines += result.finalized.length;
        if (result.completion.kind === 'completed') report.completed += 1;
        if (result.finalized.length > 0) {
          this.logger.warn(
            { ...ids, engines: result.finalized },
            'scan round deadline exceeded; missing engine results finalized as timeout',
          );
        }
        reportCompletion(
          result.completion,
          this.options.metrics,
          this.logger,
          result.finalized,
          ids,
          this.now(),
        );
      } catch (err) {
        this.options.metrics.sweeperErrors.inc();
        this.logger.warn(
          { ...ids, ...errorFields(err) },
          'scan deadline sweeper could not finalize a round; it is retried on the next pass',
        );
        // An outage stops the pass (backoff); a failure of this round only skips it.
        if (isTransientFailure(err)) return { ...report, outcome: 'database_error' };
        report.failed += 1;
      }
    }
    return report;
  }

  private async run(signal: AbortSignal): Promise<void> {
    while (!signal.aborted) {
      const report = await this.sweepOnce();
      let delay = this.options.intervalMs;
      if (report.outcome === 'database_error') {
        this.failures += 1;
        delay = Math.max(
          delay,
          backoffDelay(this.failures, { baseMs: 1_000, maxMs: 60_000 }, this.random),
        );
      } else {
        this.failures = 0;
        // A full batch: more rounds are overdue, continue at once (not when rounds of it failed:
        // they would be read again first, and the loop would spin on them).
        if (report.found >= this.options.batchSize && report.failed === 0) delay = 0;
      }
      if (delay > 0 && !(await this.sleepFn(delay, signal))) break;
    }
  }
}
