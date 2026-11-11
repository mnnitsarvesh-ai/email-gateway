import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import type { TenantScope } from '../../auth-contracts/tenant-scope';

/**
 * The organization's risk scoring tables in the order the organization purge deletes them
 * (step 5.1 §3, docs/runbooks/organization-deletion.md): the partitioned scores first (no
 * foreign keys), then the profile versions (`profile_id` → `risk_scoring_profiles` is
 * RESTRICT), then the profile row (`organization_id` RESTRICT: it must be gone before the
 * organization row). `risk_scoring_profiles.active_version_id` has no foreign key, so deleting
 * the versions first is valid.
 */
export const RISK_PURGE_ORDER = [
  'message_risk_scores',
  'risk_scoring_profile_versions',
  'risk_scoring_profiles',
] as const;
export type RiskPurgeTable = (typeof RISK_PURGE_ORDER)[number];

/** Rows one purge statement deletes (short statements, no long row locks). */
export const RISK_PURGE_BATCH = 500;

export type RiskPurgeCounts = Record<RiskPurgeTable, number>;

/**
 * Deletes every risk scoring row of one organization (step 5.1 §3) for the organization purge
 * (the deferred purge job of docs/runbooks/organization-deletion.md calls it after its
 * safeguards, next to the BEC and DLP purges). Writer only, `systemScope` of the organization
 * being purged; each statement is its own autocommit `DELETE … WHERE organization_id = ?
 * [ORDER BY id] LIMIT n` until fewer than n rows go, so a crash leaves a resumable, consistent
 * state and a re-run continues where it stopped. Never touches another organization's rows.
 */
@Injectable()
export class RiskTenantDataRepository {
  constructor(private readonly prisma: PrismaService) {}

  async purgeOrganization(
    scope: TenantScope,
    batch: number = RISK_PURGE_BATCH,
  ): Promise<RiskPurgeCounts> {
    if (!Number.isSafeInteger(batch) || batch < 1) throw new Error('batch must be positive');
    const counts = Object.fromEntries(RISK_PURGE_ORDER.map((t) => [t, 0])) as RiskPurgeCounts;
    for (const table of RISK_PURGE_ORDER) {
      for (;;) {
        const deleted = await this.deleteBatch(table, scope.organizationId, batch);
        counts[table] += deleted;
        if (deleted < batch) break;
      }
    }
    return counts;
  }

  /** One batch; the table name comes from the fixed RISK_PURGE_ORDER list, never from input. */
  private deleteBatch(
    table: RiskPurgeTable,
    organizationId: bigint,
    batch: number,
  ): Promise<number> {
    switch (table) {
      case 'message_risk_scores':
        // Partitioned by received_at (no ORDER BY, like dlp_scan_results).
        return this.prisma.$executeRaw`DELETE FROM message_risk_scores
          WHERE organization_id = ${organizationId} LIMIT ${batch}`;
      case 'risk_scoring_profile_versions':
        return this.prisma.$executeRaw`DELETE FROM risk_scoring_profile_versions
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      case 'risk_scoring_profiles':
        return this.prisma.$executeRaw`DELETE FROM risk_scoring_profiles
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
    }
  }
}
