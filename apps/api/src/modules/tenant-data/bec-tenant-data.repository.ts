import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import type { TenantScope } from '../../auth-contracts/tenant-scope';

/**
 * The organization's BEC tables in the order the organization purge deletes them (step 4.4 B18,
 * docs/runbooks/organization-deletion.md): suppression rules before the feedback they name
 * (`feedback_id`, no foreign key), feedback before the results it references (`bec_result_id`,
 * no foreign key), then the profiles, trusted senders and communication history (foreign keys
 * to `organizations` `ON DELETE RESTRICT`: these rows must be gone before the organization row),
 * and the partitioned `bec_scan_results` last (no foreign keys; matched on its
 * `(organization_id, received_at)` index).
 */
export const BEC_PURGE_ORDER = [
  'bec_suppression_rules',
  'bec_feedback',
  'bec_trusted_senders',
  'bec_vendor_profiles',
  'bec_executive_profiles',
  'bec_contact_history',
  'bec_scan_results',
] as const;
export type BecPurgeTable = (typeof BEC_PURGE_ORDER)[number];

/** Rows one purge statement deletes (short statements, no long row locks). */
export const BEC_PURGE_BATCH = 5_000;

/**
 * Deletes every BEC row of one organization (step 4.4 B18) for the organization purge (the
 * deferred purge job of docs/runbooks/organization-deletion.md calls it after its safeguards:
 * `deleted` state, `purge_after` passed, no legal hold). Writer only, `systemScope` of the
 * organization being purged; each batch is its own autocommit statement
 * (`DELETE … WHERE organization_id = ? ORDER BY id LIMIT n`), so a crash leaves a resumable,
 * consistent state and a re-run continues where it stopped. Never touches another
 * organization's rows (every statement matches the scope's organization).
 */
@Injectable()
export class BecTenantDataRepository {
  constructor(private readonly prisma: PrismaService) {}

  async purgeOrganization(
    scope: TenantScope,
    batch: number = BEC_PURGE_BATCH,
  ): Promise<Record<BecPurgeTable, number>> {
    if (!Number.isSafeInteger(batch) || batch < 1) throw new Error('batch must be positive');
    const counts = Object.fromEntries(BEC_PURGE_ORDER.map((t) => [t, 0])) as Record<
      BecPurgeTable,
      number
    >;
    for (const table of BEC_PURGE_ORDER) {
      for (;;) {
        const deleted = await this.deleteBatch(table, scope.organizationId, batch);
        counts[table] += deleted;
        if (deleted < batch) break;
      }
    }
    return counts;
  }

  /** One batch; the table name comes from the fixed BEC_PURGE_ORDER list, never from input. */
  private deleteBatch(
    table: BecPurgeTable,
    organizationId: bigint,
    batch: number,
  ): Promise<number> {
    switch (table) {
      case 'bec_suppression_rules':
        return this.prisma.$executeRaw`DELETE FROM bec_suppression_rules
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      case 'bec_feedback':
        return this.prisma.$executeRaw`DELETE FROM bec_feedback
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      case 'bec_trusted_senders':
        return this.prisma.$executeRaw`DELETE FROM bec_trusted_senders
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      case 'bec_vendor_profiles':
        return this.prisma.$executeRaw`DELETE FROM bec_vendor_profiles
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      case 'bec_executive_profiles':
        return this.prisma.$executeRaw`DELETE FROM bec_executive_profiles
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      case 'bec_contact_history':
        return this.prisma.$executeRaw`DELETE FROM bec_contact_history
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      case 'bec_scan_results':
        return this.prisma.$executeRaw`DELETE FROM bec_scan_results
          WHERE organization_id = ${organizationId} LIMIT ${batch}`;
    }
  }
}
