import type { PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import type { ArchiveMetrics } from '../metrics/archive-metrics';
import { orgFilter } from '../shared/db';

/** `journal_intake_counters` rows are kept this many days (step 8.6 §3.2). */
export const INTAKE_COUNTER_RETENTION_DAYS = 400;
/** Most bounded DELETE statements per table and run. */
const MAX_BATCHES = 50;

export interface PruneReport {
  dedupeKeys: number;
  intakeCounters: number;
}

/**
 * Lifecycle maintenance of the step 8.6 transient tables (lifecycle role, inside the lifecycle
 * leader job): `archive_dedupe_keys` rows older than the merge window
 * (`ARCHIVE_DEDUPE_WINDOW_HOURS`; a record is no longer a merge candidate after it) and
 * `journal_intake_counters` days older than 400 days. Bounded `DELETE … ORDER BY … LIMIT` batches
 * over the `created_at` / `(organization_id, day)` indexes; a run stops after `MAX_BATCHES`.
 */
export class IntakeDataPruner {
  constructor(
    private readonly prisma: PrismaClient,
    private readonly options: {
      metrics: ArchiveMetrics;
      logger: Logger;
      dedupeWindowHours: number;
      batchSize: number;
      organizationIds?: readonly bigint[];
      now?: () => Date;
    },
  ) {}

  async runOnce(): Promise<PruneReport> {
    const now = this.options.now?.() ?? new Date();
    const only = this.options.organizationIds;
    const keyCutoff = new Date(now.getTime() - this.options.dedupeWindowHours * 3_600_000);
    const dayCutoff = new Date(now.getTime() - INTAKE_COUNTER_RETENTION_DAYS * 86_400_000);
    const day = dayCutoff.toISOString().slice(0, 10);
    const report: PruneReport = { dedupeKeys: 0, intakeCounters: 0 };
    const limit = this.options.batchSize;
    for (let i = 0; i < MAX_BATCHES; i += 1) {
      const n = await this.prisma.$executeRaw`
        DELETE FROM archive_dedupe_keys
        WHERE created_at < ${keyCutoff} ${orgFilter('organization_id', only)}
        ORDER BY created_at LIMIT ${limit}`;
      report.dedupeKeys += n;
      if (n < limit) break;
    }
    for (let i = 0; i < MAX_BATCHES; i += 1) {
      const n = await this.prisma.$executeRaw`
        DELETE FROM journal_intake_counters
        WHERE day < ${day} ${orgFilter('organization_id', only)}
        ORDER BY day LIMIT ${limit}`;
      report.intakeCounters += n;
      if (n < limit) break;
    }
    if (report.dedupeKeys > 0) {
      this.options.metrics.pruned.inc({ table: 'archive_dedupe_keys' }, report.dedupeKeys);
    }
    if (report.intakeCounters > 0) {
      this.options.metrics.pruned.inc({ table: 'journal_intake_counters' }, report.intakeCounters);
    }
    return report;
  }
}
