import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import type { TenantScope } from '../../auth-contracts/tenant-scope';

/**
 * The organization's journal intake tables in the order the organization purge deletes them
 * (step 8.6 §3.2, docs/runbooks/organization-deletion.md): the daily counters, the per-message
 * intake rows (`journal_intake_messages`, partitioned, no FK), then the sources. Run BEFORE the
 * provider-connection purge: `journal_intake_sources.provider_connection_id` references
 * `provider_connections` with RESTRICT. `archive_dedupe_keys` and `archive_record_sources` belong
 * to archive records and are removed by the archive-worker's disposal of the organization's
 * records (WP4), never here.
 */
export const JOURNAL_INTAKE_PURGE_ORDER = [
  'journal_intake_counters',
  'journal_intake_messages',
  'journal_intake_sources',
] as const;
export type JournalIntakePurgeTable = (typeof JOURNAL_INTAKE_PURGE_ORDER)[number];

/** Rows one purge statement deletes (short statements, no long row locks). */
export const JOURNAL_INTAKE_PURGE_BATCH = 500;

export type JournalIntakePurgeCounts = Record<JournalIntakePurgeTable, number>;

/**
 * Deletes an organization's journal intake rows for the organization purge. Writer only,
 * `systemScope` of the organization; each statement is its own autocommit `DELETE … WHERE
 * organization_id = ? ORDER BY … LIMIT n` on an index whose leading column is `organization_id`,
 * repeated until fewer than n rows go, so a crash leaves a resumable, consistent state and a
 * re-run continues where it stopped (0 everywhere once done). Never touches another
 * organization's rows. The rows hold addresses, codes and hashes only (no content, no secret).
 */
@Injectable()
export class JournalIntakeTenantDataRepository {
  constructor(private readonly prisma: PrismaService) {}

  async purgeOrganization(
    scope: TenantScope,
    batch: number = JOURNAL_INTAKE_PURGE_BATCH,
  ): Promise<JournalIntakePurgeCounts> {
    if (!Number.isSafeInteger(batch) || batch < 1) throw new Error('batch must be positive');
    const counts = Object.fromEntries(
      JOURNAL_INTAKE_PURGE_ORDER.map((t) => [t, 0]),
    ) as JournalIntakePurgeCounts;
    for (const table of JOURNAL_INTAKE_PURGE_ORDER) {
      for (;;) {
        const deleted = await this.deleteBatch(table, scope.organizationId, batch);
        counts[table] += deleted;
        if (deleted < batch) break;
      }
    }
    return counts;
  }

  /** One batch; the table name comes from the fixed purge order, never from input. */
  private deleteBatch(
    table: JournalIntakePurgeTable,
    organizationId: bigint,
    batch: number,
  ): Promise<number> {
    switch (table) {
      case 'journal_intake_counters':
        // Index (organization_id, day).
        return this.prisma.$executeRaw`DELETE FROM journal_intake_counters
          WHERE organization_id = ${organizationId} ORDER BY day, id LIMIT ${batch}`;
      case 'journal_intake_messages':
        // Index (organization_id, received_at); partitioned by received_at, no FK.
        return this.prisma.$executeRaw`DELETE FROM journal_intake_messages
          WHERE organization_id = ${organizationId}
          ORDER BY received_at, message_id LIMIT ${batch}`;
      case 'journal_intake_sources':
        // Index (organization_id, status); the counters are gone (FK CASCADE as a backstop).
        return this.prisma.$executeRaw`DELETE FROM journal_intake_sources
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
    }
  }
}
