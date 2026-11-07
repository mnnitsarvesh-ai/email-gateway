import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import { Prisma } from '@email-gateway/database';
import type { TenantScope } from '../../auth-contracts/tenant-scope';
import { DlpEvidenceStore, isEvidenceKeyOf } from '../dlp/services/dlp-evidence-store';

/**
 * The organization's DLP tables in the order the organization purge deletes them (step 4.5 D21,
 * docs/runbooks/organization-deletion.md): the evidence first (each batch crypto-shredded, its
 * objects deleted from the mail bucket, then its rows deleted), the partitioned results (no
 * foreign keys), then the configuration in foreign-key order — exceptions before the rules and
 * policies they target (`ON DELETE RESTRICT`), rules before policies, then the patterns,
 * dictionaries and the compliance row (all `organizations` RESTRICT: they must be gone before
 * the organization row).
 */
export const DLP_PURGE_ORDER = [
  'dlp_evidence',
  'dlp_scan_results',
  'dlp_exceptions',
  'dlp_policy_rules',
  'dlp_policies',
  'dlp_custom_patterns',
  'dlp_keyword_dictionaries',
  'dlp_compliance_settings',
] as const;
export type DlpPurgeTable = (typeof DLP_PURGE_ORDER)[number];

/** Rows one purge statement deletes (short statements, no long row locks). */
export const DLP_PURGE_BATCH = 500;

export interface DlpPurgeCounts extends Record<DlpPurgeTable, number> {
  /** Evidence objects deleted from the mail bucket (a missing object counts as deleted). */
  evidenceObjects: number;
}

/**
 * Deletes every DLP row and evidence object of one organization (step 4.5 D21) for the
 * organization purge (the deferred purge job of docs/runbooks/organization-deletion.md calls
 * it after its safeguards). Writer only, `systemScope` of the organization being purged; each
 * statement is its own autocommit statement over a bounded batch, so a crash leaves a
 * resumable, consistent state and a re-run continues where it stopped:
 *
 * - evidence, per batch of 500 rows ordered by id: `wrapped_key` NULL + `purged_at` +
 *   `purge_reason = organization_deleted` (crypto-shred: an object whose delete fails is
 *   undecryptable already), delete each object (only keys under `org/<org>/dlp-evidence/`; a
 *   missing object is success; another S3 error aborts the purge, which is re-run), then
 *   delete the rows;
 * - every other table: `DELETE … WHERE organization_id = ? [ORDER BY id] LIMIT n` until fewer
 *   than n rows go.
 *
 * Never touches another organization's rows or objects.
 */
@Injectable()
export class DlpTenantDataRepository {
  constructor(
    private readonly prisma: PrismaService,
    private readonly store: DlpEvidenceStore,
  ) {}

  async purgeOrganization(
    scope: TenantScope,
    batch: number = DLP_PURGE_BATCH,
  ): Promise<DlpPurgeCounts> {
    if (!Number.isSafeInteger(batch) || batch < 1) throw new Error('batch must be positive');
    const counts = {
      ...(Object.fromEntries(DLP_PURGE_ORDER.map((t) => [t, 0])) as Record<DlpPurgeTable, number>),
      evidenceObjects: 0,
    };
    const organizationId = scope.organizationId;
    for (;;) {
      const rows = await this.prisma.dlpEvidence.findMany({
        where: { organizationId },
        select: { id: true, receivedAt: true, objectKey: true, organizationId: true },
        orderBy: { id: 'asc' },
        take: batch,
      });
      if (rows.some((row) => row.organizationId !== organizationId)) {
        throw new Error('dlp purge: evidence read returned another organization');
      }
      if (rows.length === 0) break;
      const ids = rows.map((row) => row.id);
      await this.prisma.$executeRaw`UPDATE dlp_evidence
        SET wrapped_key = NULL,
            purged_at = COALESCE(purged_at, NOW(3)),
            purge_reason = COALESCE(purge_reason, 'organization_deleted')
        WHERE organization_id = ${organizationId} AND id IN (${joinIds(ids)})`;
      for (const row of rows) {
        if (row.objectKey === null || !isEvidenceKeyOf(row.objectKey, organizationId)) continue;
        await this.store.delete(organizationId, row.objectKey);
        counts.evidenceObjects += 1;
      }
      counts.dlp_evidence += await this.prisma.$executeRaw`DELETE FROM dlp_evidence
        WHERE organization_id = ${organizationId} AND id IN (${joinIds(ids)})`;
      if (rows.length < batch) break;
    }
    for (const table of DLP_PURGE_ORDER) {
      if (table === 'dlp_evidence') continue;
      for (;;) {
        const deleted = await this.deleteBatch(table, organizationId, batch);
        counts[table] += deleted;
        if (deleted < batch) break;
      }
    }
    return counts;
  }

  /** One batch; the table name comes from the fixed DLP_PURGE_ORDER list, never from input. */
  private deleteBatch(
    table: Exclude<DlpPurgeTable, 'dlp_evidence'>,
    organizationId: bigint,
    batch: number,
  ): Promise<number> {
    switch (table) {
      case 'dlp_scan_results':
        return this.prisma.$executeRaw`DELETE FROM dlp_scan_results
          WHERE organization_id = ${organizationId} LIMIT ${batch}`;
      case 'dlp_exceptions':
        return this.prisma.$executeRaw`DELETE FROM dlp_exceptions
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      case 'dlp_policy_rules':
        return this.prisma.$executeRaw`DELETE FROM dlp_policy_rules
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      case 'dlp_policies':
        return this.prisma.$executeRaw`DELETE FROM dlp_policies
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      case 'dlp_custom_patterns':
        return this.prisma.$executeRaw`DELETE FROM dlp_custom_patterns
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      case 'dlp_keyword_dictionaries':
        return this.prisma.$executeRaw`DELETE FROM dlp_keyword_dictionaries
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      case 'dlp_compliance_settings':
        return this.prisma.$executeRaw`DELETE FROM dlp_compliance_settings
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
    }
  }
}

/** `IN (…)` of bigint ids as bound parameters. */
function joinIds(ids: readonly bigint[]) {
  return Prisma.join(ids.map((id) => Prisma.sql`${id}`));
}
