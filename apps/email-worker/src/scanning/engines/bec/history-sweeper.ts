import {
  backoffDelay,
  sleep as defaultSleep,
  withTransactionDefaults,
} from '@email-gateway/common';
import type { PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import { type BecPlatformSettings, resolveBecSettings } from '@email-gateway/security-contracts';
import { errorFields } from '../../../mime-ingestion/error-fields';
import type { LeaderLock } from '../../deadline-sweeper';
import type { BecMetrics } from './bec-metrics';

/** One cluster-wide leader (B12). */
export const BEC_HISTORY_LOCK = 'scan:bec-history';
/** Rows deleted per transaction (B12). */
export const BEC_HISTORY_SWEEP_BATCH = 1_000;
/** Batches per organization and pass (bounded work per tick; the next pass continues). */
const MAX_BATCHES_PER_ORGANIZATION = 50;
/** Organizations with history rows considered per pass. */
const MAX_ORGANIZATIONS = 10_000;

export interface BecHistorySweeperOptions {
  prisma: PrismaClient;
  locks: LeaderLock;
  metrics: BecMetrics;
  logger: Logger;
  /** The platform BEC settings (default retention, maximum, bounds of a tenant row). */
  platform: BecPlatformSettings;
  /** BEC_HISTORY_SWEEP_INTERVAL_MS. */
  intervalMs: number;
  /** SCAN_DB_TIMEOUT_MS. */
  txTimeoutMs: number;
  /** Lock name (default `scan:bec-history`; integration tests use a per-run name). */
  lockName?: string;
  /** Restricts the sweep to these organizations (integration tests on the shared writer). */
  organizationIds?: readonly bigint[];
  batchSize?: number;
  now?: () => Date;
  sleep?: (ms: number, signal: AbortSignal) => Promise<boolean>;
}

export interface BecHistorySweepReport {
  outcome: 'not_leader' | 'database_error' | 'swept';
  organizations: number;
  deleted: number;
}

/**
 * The communication-history retention sweeper (step 4.4 B12, ADR-0035): while this process holds
 * `GET_LOCK('scan:bec-history')`, every BEC_HISTORY_SWEEP_INTERVAL_MS it reads the organizations
 * that have `bec_contact_history` rows and, per organization, deletes the rows whose
 * `last_seen_at` is older than the tenant's retention (`history.retentionDays` of its valid `bec`
 * settings row, else BEC_HISTORY_DEFAULT_RETENTION_DAYS) in batches of 1 000, each in a writer
 * transaction with the SCAN_DB_TIMEOUT_MS budget. The rule does not depend on `history.enabled`:
 * an organization that turned history off writes no new rows, so its rows age out after the same
 * retention (B12 "disabled for more than retentionDays"). Every read is echo-checked
 * (organization, age); the delete repeats both conditions. `bec_history_rows_deleted_total`.
 */
export class BecHistorySweeper {
  readonly lockName: string;
  private readonly logger: Logger;
  private readonly now: () => Date;
  private readonly sleepFn: (ms: number, signal: AbortSignal) => Promise<boolean>;
  private readonly txPrisma: PrismaClient;
  private readonly batchSize: number;
  private abort = new AbortController();
  private loop: Promise<void> | undefined;
  private failures = 0;

  constructor(private readonly options: BecHistorySweeperOptions) {
    this.lockName = options.lockName ?? BEC_HISTORY_LOCK;
    this.logger = options.logger.child({ component: 'bec-history-sweeper' });
    this.now = options.now ?? (() => new Date());
    this.sleepFn = options.sleep ?? defaultSleep;
    this.txPrisma = withTransactionDefaults(options.prisma, { timeoutMs: options.txTimeoutMs });
    this.batchSize = options.batchSize ?? BEC_HISTORY_SWEEP_BATCH;
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
      'bec history sweeper started',
    );
  }

  async stop(): Promise<void> {
    this.abort.abort();
    await this.loop;
    this.loop = undefined;
    await this.options.locks.release(this.lockName).catch(() => undefined);
  }

  /** The retention in days of one organization (its valid `bec` row, else the default). */
  async retentionDays(organizationId: bigint): Promise<number> {
    const row = await this.options.prisma.scanEngineSetting.findUnique({
      where: { organizationId_engine: { organizationId, engine: 'bec' } },
      select: { organizationId: true, engine: true, settings: true },
    });
    if (row && (row.organizationId !== organizationId || row.engine !== 'bec')) {
      this.options.metrics.inconsistent('tenant');
      throw new Error('inconsistent bec settings read');
    }
    const resolved = resolveBecSettings(this.options.platform, row?.settings ?? null);
    return resolved.ok
      ? resolved.settings.history.retentionDays
      : this.options.platform.historyDefaultRetentionDays;
  }

  async sweepOnce(): Promise<BecHistorySweepReport> {
    const report: BecHistorySweepReport = { outcome: 'swept', organizations: 0, deleted: 0 };
    let leader: boolean;
    try {
      leader = await this.options.locks.ensure(this.lockName);
    } catch (err) {
      this.options.metrics.historySweeperErrors.inc();
      this.logger.warn(errorFields(err), 'bec history sweeper could not check its lock');
      return { ...report, outcome: 'database_error' };
    }
    if (!leader) return { ...report, outcome: 'not_leader' };
    try {
      const filter = this.options.organizationIds;
      const groups = await this.options.prisma.becContactHistory.groupBy({
        by: ['organizationId'],
        ...(filter ? { where: { organizationId: { in: [...filter] } } } : {}),
        orderBy: { organizationId: 'asc' },
        take: MAX_ORGANIZATIONS,
      });
      for (const { organizationId } of groups) {
        if (filter && !filter.includes(organizationId)) {
          this.options.metrics.inconsistent('history');
          throw new Error('inconsistent history organization read');
        }
        report.organizations += 1;
        const days = await this.retentionDays(organizationId);
        const cutoff = new Date(this.now().getTime() - days * 86_400_000);
        report.deleted += await this.sweepOrganization(organizationId, cutoff);
      }
    } catch (err) {
      this.options.metrics.historySweeperErrors.inc();
      this.logger.warn(errorFields(err), 'bec history sweeper pass failed; retried');
      return { ...report, outcome: 'database_error' };
    }
    if (report.deleted > 0) {
      this.logger.info(
        { organizations: report.organizations, deleted: report.deleted },
        'expired bec history rows deleted',
      );
    }
    return report;
  }

  private async sweepOrganization(organizationId: bigint, cutoff: Date): Promise<number> {
    let deleted = 0;
    for (let batch = 0; batch < MAX_BATCHES_PER_ORGANIZATION; batch += 1) {
      const result = await this.txPrisma.$transaction(async (tx) => {
        const rows = await tx.becContactHistory.findMany({
          where: { organizationId, lastSeenAt: { lt: cutoff } },
          orderBy: { id: 'asc' },
          take: this.batchSize,
          select: { id: true, organizationId: true, lastSeenAt: true },
        });
        if (
          rows.some(
            (r) =>
              r.organizationId !== organizationId || r.lastSeenAt.getTime() >= cutoff.getTime(),
          )
        ) {
          this.options.metrics.inconsistent('history');
          throw new Error('inconsistent history retention read');
        }
        if (rows.length === 0) return { found: 0, deleted: 0 };
        const removed = await tx.becContactHistory.deleteMany({
          where: {
            id: { in: rows.map((r) => r.id) },
            organizationId,
            lastSeenAt: { lt: cutoff },
          },
        });
        return { found: rows.length, deleted: removed.count };
      });
      deleted += result.deleted;
      if (result.deleted > 0) this.options.metrics.historyRowsDeleted.inc(result.deleted);
      if (result.found < this.batchSize) break;
    }
    return deleted;
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
