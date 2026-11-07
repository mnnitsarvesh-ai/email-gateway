import {
  backoffDelay,
  sleep as defaultSleep,
  withTransactionDefaults,
} from '@email-gateway/common';
import type { PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import { errorFields } from '../../../mime-ingestion/error-fields';
import type { LeaderLock } from '../../deadline-sweeper';
import type { DlpMetrics } from './dlp-metrics';
import { type EvidenceObjects, isEvidenceKey } from './evidence-objects';

/** One cluster-wide leader (D16). */
export const DLP_EVIDENCE_LOCK = 'scan:dlp-evidence';
/** Rows per transaction (D16). */
export const DLP_EVIDENCE_SWEEP_BATCH = 500;
/** Batches per pass and phase (bounded work per tick; the next pass continues). */
const MAX_BATCHES = 40;

export interface DlpEvidenceSweeperOptions {
  prisma: PrismaClient;
  objects: EvidenceObjects;
  locks: LeaderLock;
  metrics: DlpMetrics;
  logger: Logger;
  /** DLP_EVIDENCE_SWEEP_INTERVAL_MS. */
  intervalMs: number;
  /** SCAN_DB_TIMEOUT_MS. */
  txTimeoutMs: number;
  /** Lock name (default `scan:dlp-evidence`; integration tests use a per-run name). */
  lockName?: string;
  /** Restricts the sweep to these organizations (integration tests on the shared writer). */
  organizationIds?: readonly bigint[];
  batchSize?: number;
  now?: () => Date;
  sleep?: (ms: number, signal: AbortSignal) => Promise<boolean>;
}

export interface DlpEvidenceSweepReport {
  outcome: 'not_leader' | 'database_error' | 'swept';
  shredded: number;
  objectsDeleted: number;
  objectsLeft: number;
  expiredUnpurged: number;
}

/**
 * The DLP evidence retention sweeper (step 4.5 D16, ADR-0038): while this process holds
 * `GET_LOCK('scan:dlp-evidence')`, every DLP_EVIDENCE_SWEEP_INTERVAL_MS it
 *
 * 1. **crypto-shreds** expired rows (`expires_at <= now`, not purged) in batches of 500, each in
 *    a writer transaction with the SCAN_DB_TIMEOUT_MS budget: `wrapped_key = NULL`,
 *    `purged_at = now`, `purge_reason = 'retention'` (the data key is gone: the object and its
 *    noncurrent versions are undecryptable from this commit on);
 * 2. **deletes the objects** of shredded rows whose `object_key` is still set (any purge reason,
 *    so a lost delete of an earlier pass or of the api's purge is retried) and clears
 *    `object_key` only after a successful delete;
 * 3. sets `dlp_evidence_expired_unpurged` to the expired rows still holding a key or an object.
 *
 * Every read is echo-checked (expiry, purge state, key prefix of the organization); the updates
 * repeat their conditions. `dlp_evidence_purged_total{reason="retention"}`.
 */
export class DlpEvidenceSweeper {
  readonly lockName: string;
  private readonly logger: Logger;
  private readonly now: () => Date;
  private readonly sleepFn: (ms: number, signal: AbortSignal) => Promise<boolean>;
  private readonly txPrisma: PrismaClient;
  private readonly batchSize: number;
  private abort = new AbortController();
  private loop: Promise<void> | undefined;
  private failures = 0;

  constructor(private readonly options: DlpEvidenceSweeperOptions) {
    this.lockName = options.lockName ?? DLP_EVIDENCE_LOCK;
    this.logger = options.logger.child({ component: 'dlp-evidence-sweeper' });
    this.now = options.now ?? (() => new Date());
    this.sleepFn = options.sleep ?? defaultSleep;
    this.txPrisma = withTransactionDefaults(options.prisma, { timeoutMs: options.txTimeoutMs });
    this.batchSize = options.batchSize ?? DLP_EVIDENCE_SWEEP_BATCH;
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
      'dlp evidence sweeper started',
    );
  }

  async stop(): Promise<void> {
    this.abort.abort();
    await this.loop;
    this.loop = undefined;
    await this.options.locks.release(this.lockName).catch(() => undefined);
  }

  private get orgFilter() {
    const ids = this.options.organizationIds;
    return ids ? { organizationId: { in: [...ids] } } : {};
  }

  async sweepOnce(): Promise<DlpEvidenceSweepReport> {
    const report: DlpEvidenceSweepReport = {
      outcome: 'swept',
      shredded: 0,
      objectsDeleted: 0,
      objectsLeft: 0,
      expiredUnpurged: 0,
    };
    let leader: boolean;
    try {
      leader = await this.options.locks.ensure(this.lockName);
    } catch (err) {
      this.options.metrics.sweeperErrors.inc();
      this.logger.warn(errorFields(err), 'dlp evidence sweeper could not check its lock');
      return { ...report, outcome: 'database_error' };
    }
    if (!leader) return { ...report, outcome: 'not_leader' };
    const now = this.now();
    try {
      for (let batch = 0; batch < MAX_BATCHES; batch += 1) {
        const found = await this.shredBatch(now, report);
        if (found < this.batchSize) break;
      }
      for (let batch = 0; batch < MAX_BATCHES; batch += 1) {
        const found = await this.deleteBatch(report);
        if (found < this.batchSize) break;
      }
      report.expiredUnpurged = await this.options.prisma.dlpEvidence.count({
        where: {
          ...this.orgFilter,
          expiresAt: { lte: now },
          OR: [{ wrappedKey: { not: null } }, { objectKey: { not: null } }],
        },
      });
      this.options.metrics.expiredUnpurged.set(report.expiredUnpurged);
    } catch (err) {
      this.options.metrics.sweeperErrors.inc();
      this.logger.warn(errorFields(err), 'dlp evidence sweeper pass failed; retried');
      return { ...report, outcome: 'database_error' };
    }
    if (report.shredded > 0 || report.objectsDeleted > 0 || report.objectsLeft > 0) {
      this.logger.info(
        {
          shredded: report.shredded,
          objectsDeleted: report.objectsDeleted,
          objectsLeft: report.objectsLeft,
        },
        'expired dlp evidence crypto-shredded and deleted',
      );
    }
    return report;
  }

  /** Phase 1: crypto-shred one batch of expired rows (one transaction). */
  private async shredBatch(now: Date, report: DlpEvidenceSweepReport): Promise<number> {
    const result = await this.txPrisma.$transaction(async (tx) => {
      const rows = await tx.dlpEvidence.findMany({
        where: { ...this.orgFilter, purgedAt: null, expiresAt: { lte: now } },
        orderBy: { expiresAt: 'asc' },
        take: this.batchSize,
        select: {
          id: true,
          receivedAt: true,
          organizationId: true,
          purgedAt: true,
          expiresAt: true,
        },
      });
      const filter = this.options.organizationIds;
      if (
        rows.some(
          (r) =>
            r.purgedAt !== null ||
            r.expiresAt.getTime() > now.getTime() ||
            (filter !== undefined && !filter.includes(r.organizationId)),
        )
      ) {
        this.options.metrics.inconsistent('evidence');
        throw new Error('inconsistent dlp evidence expiry read');
      }
      let shredded = 0;
      for (const row of rows) {
        const updated = await tx.dlpEvidence.updateMany({
          where: {
            id: row.id,
            receivedAt: row.receivedAt,
            organizationId: row.organizationId,
            purgedAt: null,
            expiresAt: { lte: now },
          },
          data: { wrappedKey: null, purgedAt: now, purgeReason: 'retention' },
        });
        shredded += updated.count;
      }
      return { found: rows.length, shredded };
    });
    if (result.shredded > 0) {
      this.options.metrics.evidencePurged.inc({ reason: 'retention' }, result.shredded);
      report.shredded += result.shredded;
    }
    return result.found;
  }

  /** Phase 2: delete the objects of shredded rows, clearing `object_key` after each delete. */
  private async deleteBatch(report: DlpEvidenceSweepReport): Promise<number> {
    const rows = await this.options.prisma.dlpEvidence.findMany({
      where: { ...this.orgFilter, wrappedKey: null, objectKey: { not: null } },
      orderBy: { id: 'asc' },
      take: this.batchSize,
      select: {
        id: true,
        receivedAt: true,
        organizationId: true,
        objectKey: true,
        wrappedKey: true,
      },
    });
    if (rows.some((r) => r.wrappedKey !== null || r.objectKey === null)) {
      this.options.metrics.inconsistent('evidence');
      throw new Error('inconsistent dlp evidence purge read');
    }
    let progressed = 0;
    for (const row of rows) {
      const key = row.objectKey!;
      if (!isEvidenceKey(key, row.organizationId)) {
        // Never delete outside the organization's evidence prefix; left for an operator.
        report.objectsLeft += 1;
        continue;
      }
      try {
        await this.options.objects.delete(key);
      } catch (err) {
        report.objectsLeft += 1;
        this.logger.warn(errorFields(err), 'dlp evidence object delete failed; retried next pass');
        continue;
      }
      await this.txPrisma.$transaction((tx) =>
        tx.dlpEvidence.updateMany({
          where: {
            id: row.id,
            receivedAt: row.receivedAt,
            organizationId: row.organizationId,
            wrappedKey: null,
            objectKey: key,
          },
          data: { objectKey: null },
        }),
      );
      report.objectsDeleted += 1;
      progressed += 1;
    }
    // Only a batch that made progress may be followed by another (a stuck object is not looped).
    return progressed === rows.length ? rows.length : 0;
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
