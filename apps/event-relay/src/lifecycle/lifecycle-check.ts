import { performance } from 'node:perf_hooks';
import { errorFields, sleep as defaultSleep } from '@email-gateway/common';
import type { PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import {
  applyDerivedDeliveryState,
  FINAL_STATES,
  isRetryableLifecycleError,
  lockLifecycle,
  MESSAGE_STATES,
  retryDelayMs,
  type DerivedStateOutcome,
  type LifecycleMetrics,
  type MessageState,
} from '@email-gateway/message-lifecycle';
import type { ReconcilerLocks } from '../reconciler/outbox-reconciler';
import type { LifecycleRelayMetrics } from './lifecycle-metrics';
import type { LifecycleCandidate, LifecycleStore } from './lifecycle-store';

export const DEFAULT_LIFECYCLE_CHECK_LOCK = 'er:lifecycle-check';
/** `lifecycle_stuck_messages` is counted up to this many messages per state (L14 step 3). */
export const STUCK_COUNT_CAP = 100_000;

/** States the check walks (L14 step 1): `approved` is counted only, the others re-derived. */
export const CHECKED_STATES = ['approved', 'delivery_pending', 'delivery_retry'] as const;
type CheckedState = (typeof CHECKED_STATES)[number];

/** Non-final states of the `lifecycle_stuck_messages` gauge. */
export const STUCK_STATES: readonly MessageState[] = MESSAGE_STATES.filter(
  (state) => !FINAL_STATES.includes(state),
);

/** Re-derives one message's delivery state in its own writer transaction. */
export type RecoverDerived = (candidate: LifecycleCandidate) => Promise<DerivedStateOutcome>;

export interface LifecycleCheckOptions {
  store: LifecycleStore;
  recover: RecoverDerived;
  locks: ReconcilerLocks;
  metrics: LifecycleRelayMetrics;
  logger: Logger;
  /** `LIFECYCLE_CHECK_INTERVAL_MS`. */
  intervalMs: number;
  /** `LIFECYCLE_CHECK_AFTER_SECONDS`. */
  afterSeconds: number;
  /** `LIFECYCLE_CHECK_BATCH_SIZE`: messages per state and run. */
  batchSize: number;
  /** `LIFECYCLE_CHECK_LOOKBACK_HOURS`. */
  lookbackHours: number;
  /** Default `er:lifecycle-check` (tests use their own). */
  lockName?: string;
  organizationIds?: readonly bigint[];
  sleep?: (ms: number, signal: AbortSignal) => Promise<boolean>;
}

export interface LifecycleCheckReport {
  active: boolean;
  /** Messages read per checked state. */
  scanned: Partial<Record<CheckedState, number>>;
  recovered: number;
  /** Re-derived, nothing to do (already consistent, or changed meanwhile). */
  consistent: number;
  failed: number;
  stuck: Partial<Record<MessageState, number>>;
}

/**
 * `RecoverDerived` on the writer: lock the message (`lockLifecycle`), then
 * `applyDerivedDeliveryState` with actor `{ role: 'recovery', service: 'event-relay' }` and key
 * `recover:<id>:<version>:<derived>` (L5.3), retried on deadlocks and conflicts (3 attempts).
 */
export function prismaRecoverDerived(
  prisma: PrismaClient,
  options: { txTimeoutMs: number; metrics?: LifecycleMetrics; maxAttempts?: number },
): RecoverDerived {
  const maxAttempts = options.maxAttempts ?? 3;
  const deps = options.metrics ? { metrics: options.metrics } : {};
  return async (candidate) => {
    const message = {
      id: candidate.id,
      receivedAt: candidate.receivedAt,
      organizationId: candidate.organizationId,
    };
    for (let attempt = 1; ; attempt += 1) {
      try {
        return await prisma.$transaction(
          async (tx) => {
            const snapshot = await lockLifecycle(tx, message);
            if (!snapshot) return { result: 'not_found' } as const;
            return applyDerivedDeliveryState(
              tx,
              message,
              {
                actor: { role: 'recovery', service: 'event-relay', type: 'system' },
                transitionKey: (derived, current) =>
                  `recover:${candidate.id.toString()}:${current.version}:${derived.state}`,
                correlationId: `recover:${candidate.id.toString()}`,
              },
              deps,
            );
          },
          { timeout: options.txTimeoutMs, maxWait: options.txTimeoutMs },
        );
      } catch (error) {
        if (attempt >= maxAttempts || !isRetryableLifecycleError(error)) throw error;
        options.metrics?.versionConflict();
        await new Promise((resolve) => setTimeout(resolve, retryDelayMs(attempt)));
      }
    }
  };
}

/**
 * The lifecycle check (step 3.3 L14): one active instance (`GET_LOCK('er:lifecycle-check')`),
 * every `intervalMs`:
 *
 * 1. for `approved`, `delivery_pending`, `delivery_retry`: messages unchanged for
 *    `afterSeconds` and changed within `lookbackHours` (state age, not message age), keyset on `(status_changed_at, id)` with an
 *    in-memory cursor per state (reset when a page returns fewer than `batchSize` rows);
 * 2. per delivery-phase message, one writer transaction re-derives the state from the recipients
 *    (`applyDerivedDeliveryState`, actor `recovery`); an applied transition is a lost derivation
 *    (`lifecycle_recovered_total{from,to}`, warn log). `approved` is only counted: the planner
 *    moves it in the approval's own transaction, and a lost approval is the step 3.2 reconciler's;
 * 3. `lifecycle_stuck_messages{state}` per non-final state (capped at 100 000).
 */
export class LifecycleCheck {
  readonly lockName: string;
  private readonly logger: Logger;
  private readonly sleepFn: (ms: number, signal: AbortSignal) => Promise<boolean>;
  private readonly cursors = new Map<CheckedState, { statusChangedAt: Date; id: bigint }>();
  private abort = new AbortController();
  private loop: Promise<void> | undefined;

  constructor(private readonly options: LifecycleCheckOptions) {
    validate(options);
    this.lockName = options.lockName ?? DEFAULT_LIFECYCLE_CHECK_LOCK;
    this.logger = options.logger.child({ component: 'lifecycle-check' });
    this.sleepFn = options.sleep ?? defaultSleep;
  }

  start(): void {
    if (this.loop) return;
    this.abort = new AbortController();
    const signal = this.abort.signal;
    this.loop = (async () => {
      while (!signal.aborted) {
        try {
          await this.runOnce(signal);
        } catch (error) {
          this.options.metrics.errors.inc({ component: 'check' });
          this.logger.warn({ ...errorFields(error) }, 'lifecycle check run failed; retrying');
        }
        if (signal.aborted) break;
        await this.sleepFn(this.options.intervalMs, signal);
      }
    })();
    this.logger.info(
      { intervalMs: this.options.intervalMs, afterSeconds: this.options.afterSeconds },
      'lifecycle check started',
    );
  }

  async stop(): Promise<void> {
    this.abort.abort();
    await this.loop;
    this.loop = undefined;
    await this.options.locks.release(this.lockName).catch(() => undefined);
  }

  /** One run (public for tests). Throws on a database error of a read (the loop retries). */
  async runOnce(signal?: AbortSignal): Promise<LifecycleCheckReport> {
    const report: LifecycleCheckReport = {
      active: false,
      scanned: {},
      recovered: 0,
      consistent: 0,
      failed: 0,
      stuck: {},
    };
    if (!(await this.options.locks.ensure(this.lockName))) return report;
    report.active = true;
    const started = performance.now();
    const { store, metrics } = this.options;

    for (const state of CHECKED_STATES) {
      const rows = await store.checkCandidates({
        state,
        olderThanSeconds: this.options.afterSeconds,
        lookbackHours: this.options.lookbackHours,
        after: this.cursors.get(state) ?? null,
        limit: this.options.batchSize,
        ...this.scope(),
      });
      report.scanned[state] = rows.length;
      const last = rows.at(-1);
      if (rows.length < this.options.batchSize || !last) this.cursors.delete(state);
      else this.cursors.set(state, { statusChangedAt: last.statusChangedAt, id: last.id });
      if (state === 'approved') continue;
      for (const row of rows) {
        if (signal?.aborted) break;
        await this.recheck(row, report);
      }
    }

    for (const state of STUCK_STATES) {
      const count = await store.countStuck({
        state,
        olderThanSeconds: this.options.afterSeconds,
        cap: STUCK_COUNT_CAP,
        ...this.scope(),
      });
      report.stuck[state] = count;
      metrics.stuck.set({ state }, count);
    }
    metrics.checkRunSeconds.observe((performance.now() - started) / 1000);
    if (report.recovered > 0 || report.failed > 0) {
      this.logger.info(
        { recovered: report.recovered, failed: report.failed, scanned: report.scanned },
        'lifecycle check run',
      );
    }
    return report;
  }

  private async recheck(row: LifecycleCandidate, report: LifecycleCheckReport): Promise<void> {
    const ids = {
      messageId: row.id.toString(),
      organizationId: row.organizationId.toString(),
      state: row.state,
      version: row.version,
    };
    let outcome: DerivedStateOutcome;
    try {
      outcome = await this.options.recover(row);
    } catch (error) {
      report.failed += 1;
      this.options.metrics.errors.inc({ component: 'check' });
      this.logger.warn({ ...ids, ...errorFields(error) }, 'lifecycle re-derivation failed');
      return;
    }
    if (outcome.result === 'transition' && outcome.outcome.result === 'applied') {
      report.recovered += 1;
      const { from, to } = outcome.outcome;
      this.options.metrics.recovered.inc({ from, to });
      this.logger.warn(
        { ...ids, from, to, reason: outcome.derived.reason, newVersion: outcome.outcome.version },
        'lost delivery-state derivation recovered (docs/runbooks/message-lifecycle.md)',
      );
      return;
    }
    report.consistent += 1;
  }

  private scope(): { organizationIds?: readonly bigint[] } {
    return this.options.organizationIds === undefined
      ? {}
      : { organizationIds: this.options.organizationIds };
  }
}

function validate(options: LifecycleCheckOptions): void {
  const intIn = (value: number, min: number, max: number) =>
    Number.isInteger(value) && value >= min && value <= max;
  if (!intIn(options.intervalMs, 1, 3_600_000)) throw new Error('check intervalMs is out of range');
  if (!intIn(options.afterSeconds, 1, 86_400))
    throw new Error('check afterSeconds is out of range');
  if (!intIn(options.batchSize, 1, 5000)) throw new Error('check batchSize must be 1-5000');
  if (!intIn(options.lookbackHours, 1, 4464)) throw new Error('check lookbackHours must be 1-4464');
}
