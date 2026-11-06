import {
  backoffDelay,
  sleep as defaultSleep,
  withTransactionDefaults,
} from '@email-gateway/common';
import type { PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import { errorFields } from '../../../mime-ingestion/error-fields';
import type { LeaderLock } from '../../deadline-sweeper';
import type { UrlMetrics } from './url-metrics';

/** One cluster-wide leader (U15). */
export const URL_INSPECTION_LOCK = 'scan:url-inspections';
/** Rows expired per statement. */
export const INSPECTION_SWEEP_BATCH = 500;
/** Batches per pass (bounded work per tick). */
const MAX_BATCHES = 20;

export interface InspectionSweeperOptions {
  prisma: PrismaClient;
  locks: LeaderLock;
  metrics: UrlMetrics;
  logger: Logger;
  /** URL_DYNAMIC_SWEEP_INTERVAL_MS. */
  intervalMs: number;
  /** URL_DYNAMIC_PENDING_TTL_SECONDS. */
  pendingTtlSeconds: number;
  /** SCAN_DB_TIMEOUT_MS. */
  txTimeoutMs: number;
  /** Lock name (default `scan:url-inspections`; integration tests use a per-run name). */
  lockName?: string;
  /** Restricts the sweep to these organizations (integration tests on the shared writer). */
  organizationIds?: readonly bigint[];
  batchSize?: number;
  now?: () => Date;
  sleep?: (ms: number, signal: AbortSignal) => Promise<boolean>;
}

export interface InspectionSweepReport {
  outcome: 'not_leader' | 'database_error' | 'swept';
  expired: number;
}

/**
 * The pending-inspection sweeper (U15): while this process holds
 * `GET_LOCK('scan:url-inspections')`, every URL_DYNAMIC_SWEEP_INTERVAL_MS it marks
 * `url_dynamic_inspections` rows still `pending` after URL_DYNAMIC_PENDING_TTL_SECONDS as
 * `expired` (index `(status, created_at)`), at most 500 per statement in a writer transaction
 * with the SCAN_DB_TIMEOUT_MS budget. The read is echo-checked (status and age); the update
 * repeats both conditions, so a result that arrives meanwhile is never overwritten. A dropped
 * request of the lossy `scan.url.inspect` queue ends here; the click-time decision then uses the
 * other signals only.
 */
export class InspectionSweeper {
  readonly lockName: string;
  private readonly logger: Logger;
  private readonly now: () => Date;
  private readonly sleepFn: (ms: number, signal: AbortSignal) => Promise<boolean>;
  private readonly txPrisma: PrismaClient;
  private readonly batchSize: number;
  private abort = new AbortController();
  private loop: Promise<void> | undefined;
  private failures = 0;

  constructor(private readonly options: InspectionSweeperOptions) {
    this.lockName = options.lockName ?? URL_INSPECTION_LOCK;
    this.logger = options.logger.child({ component: 'url-inspection-sweeper' });
    this.now = options.now ?? (() => new Date());
    this.sleepFn = options.sleep ?? defaultSleep;
    this.txPrisma = withTransactionDefaults(options.prisma, { timeoutMs: options.txTimeoutMs });
    this.batchSize = options.batchSize ?? INSPECTION_SWEEP_BATCH;
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
      'url inspection sweeper started',
    );
  }

  async stop(): Promise<void> {
    this.abort.abort();
    await this.loop;
    this.loop = undefined;
    await this.options.locks.release(this.lockName).catch(() => undefined);
  }

  async sweepOnce(): Promise<InspectionSweepReport> {
    let leader: boolean;
    try {
      leader = await this.options.locks.ensure(this.lockName);
    } catch (err) {
      this.logger.warn(errorFields(err), 'url inspection sweeper could not check its lock');
      return { outcome: 'database_error', expired: 0 };
    }
    if (!leader) return { outcome: 'not_leader', expired: 0 };
    const cutoff = new Date(this.now().getTime() - this.options.pendingTtlSeconds * 1000);
    const orgs = this.options.organizationIds;
    let expired = 0;
    try {
      for (let batch = 0; batch < MAX_BATCHES; batch += 1) {
        const count = await this.txPrisma.$transaction(async (tx) => {
          const rows = await tx.urlDynamicInspection.findMany({
            where: {
              status: 'pending',
              createdAt: { lt: cutoff },
              ...(orgs ? { organizationId: { in: [...orgs] } } : {}),
            },
            orderBy: { createdAt: 'asc' },
            take: this.batchSize,
            select: { id: true, receivedAt: true, status: true, createdAt: true },
          });
          if (
            rows.some((r) => r.status !== 'pending' || r.createdAt.getTime() >= cutoff.getTime())
          ) {
            this.options.metrics.inconsistent('inspection');
            throw new Error('inconsistent pending-inspection read');
          }
          if (rows.length === 0) return { found: 0, updated: 0 };
          const updated = await tx.urlDynamicInspection.updateMany({
            where: {
              OR: rows.map((r) => ({ id: r.id, receivedAt: r.receivedAt })),
              status: 'pending',
              createdAt: { lt: cutoff },
            },
            data: { status: 'expired' },
          });
          return { found: rows.length, updated: updated.count };
        });
        expired += count.updated;
        if (count.found < this.batchSize) break;
      }
    } catch (err) {
      this.logger.warn(errorFields(err), 'url inspection sweeper pass failed; retried');
      this.options.metrics.dynamic('expired', expired);
      return { outcome: 'database_error', expired };
    }
    this.options.metrics.dynamic('expired', expired);
    if (expired > 0) this.logger.info({ expired }, 'pending url inspections expired');
    return { outcome: 'swept', expired };
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
