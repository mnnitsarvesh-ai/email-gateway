import { backoffDelay, sleep as defaultSleep } from '@email-gateway/common';
import type { Logger } from '@email-gateway/logger';
import { mapAnalysis } from '@email-gateway/sandbox';
import { errorFields, isTransientFailure } from '../../mime-ingestion/error-fields';
import type { LeaderLock } from '../deadline-sweeper';
import {
  expiredOutcome,
  finishSubmissions,
  outcomeFromAnalysis,
  SANDBOX_LINKED_BATCH,
  type SubmissionOutcome,
} from './sandbox-finalizer';
import type { SandboxMetrics } from './sandbox-metrics';
import {
  type AnalysisRow,
  DUPLICATE,
  InconsistentSandboxReadError,
  type SandboxStore,
  type SubmissionRow,
} from './sandbox-store';
import { isSandboxArtifactKey, isSandboxSampleKey, type SandboxObjects } from './sample-stager';

/** One cluster-wide leader (X16). */
export const SANDBOX_SWEEP_LOCK = 'scan:sandbox';
/** Batches per pass and step (bounded work per tick; the next pass continues). */
const MAX_BATCHES = 20;

export interface SandboxSweeperOptions {
  store: SandboxStore;
  objects: SandboxObjects;
  locks: LeaderLock;
  metrics: SandboxMetrics;
  logger: Logger;
  /** SANDBOX_SWEEP_INTERVAL_MS. */
  intervalMs: number;
  /** SANDBOX_SWEEP_BATCH. */
  batchSize: number;
  /** SANDBOX_SUBMISSION_TTL_SECONDS. */
  submissionTtlSeconds: number;
  /** Lock name (default `scan:sandbox`; integration tests use a per-run name). */
  lockName?: string;
  now?: () => Date;
  sleep?: (ms: number, signal: AbortSignal) => Promise<boolean>;
}

export const SANDBOX_SWEEP_STEPS = [
  'expire_submissions',
  'expire_analyses',
  'catch_up',
  'delete_samples',
  'purge_artifacts',
  'delete_analyses',
] as const;
export type SandboxSweepStep = (typeof SANDBOX_SWEEP_STEPS)[number];

export interface SandboxSweepReport {
  outcome: 'not_leader' | 'database_error' | 'swept';
  /** (a) pending submissions expired. */
  submissionsExpired: number;
  /** (b) analyses expired (and their linked submissions). */
  analysesExpired: number;
  linkedExpired: number;
  /** (c) submitted submissions completed from their terminal analysis. */
  caughtUp: number;
  /** (d) sample objects deleted / left for the next pass. */
  samplesDeleted: number;
  samplesLeft: number;
  /** (e) artifact keys shredded, objects deleted / left. */
  artifactKeysShredded: number;
  artifactObjectsDeleted: number;
  artifactObjectsLeft: number;
  /** (f) analysis rows deleted (with their artifact rows). */
  analysesDeleted: number;
  /** Round finals written while completing submissions. */
  finals: number;
  /** The steps in the order they ran (tests). */
  steps: SandboxSweepStep[];
}

const SWEEP_CORRELATION = 'sandbox-sweeper';

/**
 * The sandbox sweeper (step 4.6 X16): while this process holds `GET_LOCK('scan:sandbox')`, every
 * SANDBOX_SWEEP_INTERVAL_MS, in batches of SANDBOX_SWEEP_BATCH, each batch in its own writer
 * transaction (SCAN_DB_TIMEOUT_MS), in this order:
 *
 * (a) `pending` submissions older than SANDBOX_SUBMISSION_TTL_SECONDS → `expired`
 *     (`sandbox.timeout`; covers pre-4.6 rows and a stopped dispatcher);
 * (b) `pending`/`dispatched` analyses past `deadline_at` → `expired` (verdict `timeout`,
 *     `dedupe_key = NULL`) and their linked submissions → `expired`;
 * (c) `submitted` submissions whose analysis is terminal → completed from it (catch-up of the
 *     results consumer's 200-row cap);
 * (d) terminal analyses with a sample key and no `sample_deleted_at` → delete the object (a
 *     missing object counts as deleted), then set `sample_deleted_at`;
 * (e) artifacts past `expires_at` → **crypto-shredding first** (`wrapped_key = NULL`,
 *     `purged_at`, `purge_reason = 'retention'`, committed), then delete the object and set
 *     `object_deleted_at` (retried every pass until done);
 * (f) analyses past `expires_at` whose artifacts are all object-deleted (and whose sample is
 *     gone) → delete the artifact rows, then the analysis row.
 *
 * Every completion goes through the finalizer (X15), so round finals are written as submissions
 * end. An outage backs off; an object delete failure is counted (`scan_sandbox_purge_failures_total`)
 * and retried on the next pass.
 */
export class SandboxSweeper {
  readonly lockName: string;
  private readonly logger: Logger;
  private readonly now: () => Date;
  private readonly sleepFn: (ms: number, signal: AbortSignal) => Promise<boolean>;
  private abort = new AbortController();
  private loop: Promise<void> | undefined;
  private failures = 0;

  constructor(private readonly options: SandboxSweeperOptions) {
    this.lockName = options.lockName ?? SANDBOX_SWEEP_LOCK;
    this.logger = options.logger.child({ component: 'sandbox-sweeper' });
    this.now = options.now ?? (() => new Date());
    this.sleepFn = options.sleep ?? defaultSleep;
  }

  get running(): boolean {
    return this.loop !== undefined;
  }

  start(): void {
    if (this.loop) return;
    this.abort = new AbortController();
    this.loop = this.run(this.abort.signal);
    this.logger.info(
      { intervalMs: this.options.intervalMs, lock: this.lockName },
      'sandbox sweeper started',
    );
  }

  async stop(): Promise<void> {
    this.abort.abort();
    await this.loop;
    this.loop = undefined;
    await this.options.locks.release(this.lockName).catch(() => undefined);
  }

  async sweepOnce(): Promise<SandboxSweepReport> {
    const report: SandboxSweepReport = {
      outcome: 'swept',
      submissionsExpired: 0,
      analysesExpired: 0,
      linkedExpired: 0,
      caughtUp: 0,
      samplesDeleted: 0,
      samplesLeft: 0,
      artifactKeysShredded: 0,
      artifactObjectsDeleted: 0,
      artifactObjectsLeft: 0,
      analysesDeleted: 0,
      finals: 0,
      steps: [],
    };
    let leader: boolean;
    try {
      leader = await this.options.locks.ensure(this.lockName);
    } catch (err) {
      this.logger.warn(errorFields(err), 'sandbox sweeper could not check its lock');
      return { ...report, outcome: 'database_error' };
    }
    if (!leader) return { ...report, outcome: 'not_leader' };
    try {
      await this.step(report, 'expire_submissions', () => this.expireSubmissions(report));
      await this.step(report, 'expire_analyses', () => this.expireAnalyses(report));
      await this.step(report, 'catch_up', () => this.catchUp(report));
      await this.step(report, 'delete_samples', () => this.deleteSamples(report));
      await this.step(report, 'purge_artifacts', () => this.purgeArtifacts(report));
      await this.step(report, 'delete_analyses', () => this.deleteAnalyses(report));
    } catch (err) {
      if (err instanceof InconsistentSandboxReadError) this.options.metrics.inconsistent(err.read);
      this.logger.warn(errorFields(err), 'sandbox sweeper pass failed; retried');
      return { ...report, outcome: 'database_error' };
    }
    const moved =
      report.submissionsExpired +
      report.analysesExpired +
      report.caughtUp +
      report.samplesDeleted +
      report.artifactKeysShredded +
      report.artifactObjectsDeleted +
      report.analysesDeleted;
    if (moved > 0 || report.samplesLeft > 0 || report.artifactObjectsLeft > 0) {
      const { steps: _steps, outcome: _outcome, ...counts } = report;
      this.logger.info(counts, 'sandbox sweep pass');
    }
    return report;
  }

  private async step(
    report: SandboxSweepReport,
    name: SandboxSweepStep,
    fn: () => Promise<void>,
  ): Promise<void> {
    report.steps.push(name);
    await fn();
  }

  private context() {
    return { now: this.now(), correlationId: SWEEP_CORRELATION, metrics: this.options.metrics };
  }

  /** Runs `batch` until it handles fewer rows than a batch (or MAX_BATCHES). */
  private async batches(batch: () => Promise<number>): Promise<void> {
    for (let i = 0; i < MAX_BATCHES; i += 1) {
      const found = await batch();
      if (found < this.options.batchSize) return;
    }
  }

  /** (a) */
  private async expireSubmissions(report: SandboxSweepReport): Promise<void> {
    await this.batches(async () => {
      const ctx = this.context();
      const cutoff = new Date(ctx.now.getTime() - this.options.submissionTtlSeconds * 1000);
      const result = await this.options.store.transaction(async (tx) => {
        const rows = await tx.pendingSubmissionsBefore(cutoff, this.options.batchSize);
        const finished = await finishSubmissions(
          tx,
          rows.map((submission) => ({ submission, outcome: expiredOutcome() })),
          ctx,
        );
        return { found: rows.length, changed: finished.changed, finals: finished.finals.length };
      });
      if (result === DUPLICATE) return 0;
      report.submissionsExpired += result.changed;
      report.finals += result.finals;
      this.options.metrics.submission('expired', result.changed);
      return result.found;
    });
  }

  /** (b) */
  private async expireAnalyses(report: SandboxSweepReport): Promise<void> {
    const expired = mapAnalysis({ kind: 'expired' });
    await this.batches(async () => {
      const ctx = this.context();
      const result = await this.options.store.transaction(async (tx) => {
        const ids = await tx.overdueAnalyses(ctx.now, this.options.batchSize);
        let analyses = 0;
        let linked = 0;
        let finals = 0;
        for (const id of ids) {
          const analysis = await tx.lockAnalysis(id);
          if (
            !analysis ||
            (analysis.status !== 'pending' && analysis.status !== 'dispatched') ||
            analysis.deadlineAt.getTime() >= ctx.now.getTime()
          ) {
            continue;
          }
          const changed = await tx.completeAnalysis(analysis.id, ['pending', 'dispatched'], {
            status: 'expired',
            verdict: expired.verdict,
            reasonCodes: expired.reasonCodes,
            mapVersion: expired.mapVersion,
            completedAt: ctx.now,
            reuseUntil: null,
            clearDedupeKey: true,
          });
          if (!changed) continue;
          analyses += 1;
          const terminal: AnalysisRow = {
            ...analysis,
            status: 'expired',
            verdict: expired.verdict,
            reasonCodes: expired.reasonCodes,
          };
          const rows = await tx.linkedSubmitted(analysis.id, SANDBOX_LINKED_BATCH);
          const finished = await finishSubmissions(
            tx,
            rows.map((submission) => ({ submission, outcome: outcomeFromAnalysis(terminal) })),
            ctx,
          );
          linked += finished.changed;
          finals += finished.finals.length;
        }
        return { found: ids.length, analyses, linked, finals };
      });
      if (result === DUPLICATE) return 0;
      report.analysesExpired += result.analyses;
      report.linkedExpired += result.linked;
      report.finals += result.finals;
      for (let i = 0; i < result.analyses; i += 1) {
        this.options.metrics.analysis('expired');
        this.options.metrics.verdict('timeout');
      }
      this.options.metrics.submission('expired', result.linked);
      return result.found;
    });
  }

  /** (c) */
  private async catchUp(report: SandboxSweepReport): Promise<void> {
    await this.batches(async () => {
      const ctx = this.context();
      const result = await this.options.store.transaction(async (tx) => {
        const rows = await tx.submittedWithTerminalAnalysis(this.options.batchSize);
        const analyses = await tx.analysesByIds(rows.map((r) => r.analysisId!));
        const items: { submission: SubmissionRow; outcome: SubmissionOutcome }[] = [];
        for (const submission of rows) {
          const analysis = analyses.get(submission.analysisId!);
          if (!analysis) continue;
          items.push({ submission, outcome: outcomeFromAnalysis(analysis) });
        }
        const finished = await finishSubmissions(tx, items, ctx);
        const expired = items.filter((i) => i.outcome.status === 'expired').length;
        const failed = items.filter((i) => i.outcome.status === 'failed').length;
        return {
          found: rows.length,
          changed: finished.changed,
          finals: finished.finals.length,
          expired: Math.min(expired, finished.changed),
          failed: Math.min(failed, finished.changed),
        };
      });
      if (result === DUPLICATE) return 0;
      report.caughtUp += result.changed;
      report.finals += result.finals;
      this.options.metrics.submission('expired', result.expired);
      this.options.metrics.submission('failed', result.failed);
      return result.found;
    });
  }

  /** (d) */
  private async deleteSamples(report: SandboxSweepReport): Promise<void> {
    await this.batches(async () => {
      const rows = await this.options.store.samplesToDelete(this.options.batchSize);
      let progressed = 0;
      for (const row of rows) {
        if (!isSandboxSampleKey(row.key)) {
          // Never deleted outside samples/: left for an operator.
          report.samplesLeft += 1;
          continue;
        }
        try {
          await this.options.objects.delete(row.key);
        } catch (err) {
          if (!isTransientFailure(err)) throw err;
          report.samplesLeft += 1;
          this.options.metrics.purgeFailure('sample');
          this.logger.warn(
            { analysisId: row.id.toString(), ...errorFields(err) },
            'sandbox sample delete failed; retried next pass',
          );
          continue;
        }
        if (await this.options.store.markSampleDeleted(row.id, row.key, this.now())) {
          this.options.metrics.purge('sample');
          report.samplesDeleted += 1;
        }
        progressed += 1;
      }
      // Only a batch that made full progress is followed by another (a stuck object is not looped).
      return progressed === rows.length ? rows.length : 0;
    });
  }

  /** (e) */
  private async purgeArtifacts(report: SandboxSweepReport): Promise<void> {
    await this.batches(async () => {
      const now = this.now();
      const shredded = await this.options.store.transaction((tx) =>
        tx.shredExpiredArtifacts(now, this.options.batchSize),
      );
      if (shredded === DUPLICATE) return 0;
      report.artifactKeysShredded += shredded;
      this.options.metrics.purge('artifact_key', shredded);
      return shredded;
    });
    await this.batches(async () => {
      const rows = await this.options.store.artifactsToDelete(this.options.batchSize);
      let progressed = 0;
      for (const row of rows) {
        if (!isSandboxArtifactKey(row.objectKey)) {
          report.artifactObjectsLeft += 1;
          continue;
        }
        try {
          await this.options.objects.delete(row.objectKey);
        } catch (err) {
          if (!isTransientFailure(err)) throw err;
          report.artifactObjectsLeft += 1;
          this.options.metrics.purgeFailure('artifact_object');
          this.logger.warn(
            { artifactId: row.id.toString(), ...errorFields(err) },
            'sandbox artifact object delete failed; retried next pass',
          );
          continue;
        }
        if (await this.options.store.markArtifactObjectDeleted(row.id, row.objectKey, this.now())) {
          this.options.metrics.purge('artifact_object');
          report.artifactObjectsDeleted += 1;
        }
        progressed += 1;
      }
      return progressed === rows.length ? rows.length : 0;
    });
  }

  /** (f) */
  private async deleteAnalyses(report: SandboxSweepReport): Promise<void> {
    await this.batches(async () => {
      const now = this.now();
      const result = await this.options.store.transaction(async (tx) => {
        const ids = await tx.deletableAnalyses(now, this.options.batchSize);
        let deleted = 0;
        for (const id of ids) if (await tx.deleteAnalysis(id, now)) deleted += 1;
        return { found: ids.length, deleted };
      });
      if (result === DUPLICATE) return 0;
      report.analysesDeleted += result.deleted;
      this.options.metrics.purge('analysis', result.deleted);
      return result.deleted === result.found ? result.found : 0;
    });
  }

  private async run(signal: AbortSignal): Promise<void> {
    while (!signal.aborted) {
      const report = await this.sweepOnce();
      let delay = this.options.intervalMs;
      if (report.outcome === 'database_error') {
        this.failures += 1;
        delay = Math.max(delay, backoffDelay(this.failures, { baseMs: 1_000, maxMs: 60_000 }));
      } else {
        this.failures = 0;
      }
      if (!(await this.sleepFn(delay, signal))) break;
    }
  }
}
