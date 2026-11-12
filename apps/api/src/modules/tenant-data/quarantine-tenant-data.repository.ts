import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import type { TenantScope } from '../../auth-contracts/tenant-scope';

/**
 * The organization's quarantine tables in the order the organization purge deletes them (step
 * 5.3 Q17, docs/database/schema-reference.md): every table's `organization_id` is RESTRICT, and
 * `quarantine_release_logs.action_id → quarantine_actions` is RESTRICT, so grants, approval
 * requests and release logs go before the actions; digests before their runs; the entries after
 * every row that references them; the settings last.
 */
export const QUARANTINE_PURGE_ORDER = [
  'quarantine_download_grants',
  'quarantine_approval_requests',
  'quarantine_release_logs',
  'quarantine_actions',
  'quarantine_object_purges',
  'quarantine_digests',
  'quarantine_digest_runs',
  'quarantine_user_preferences',
  'quarantine_messages',
  'quarantine_settings',
] as const;
export type QuarantinePurgeTable = (typeof QUARANTINE_PURGE_ORDER)[number];

/** Rows one purge statement deletes (short statements, no long row locks). */
export const QUARANTINE_PURGE_BATCH = 500;

export type QuarantinePurgeCounts = Record<QuarantinePurgeTable, number>;

/** The organization still has an active legal hold: nothing is deleted (Q17). */
export class QuarantinePurgeRefusedError extends Error {
  override readonly name = 'QuarantinePurgeRefusedError';
  constructor(readonly activeLegalHolds: number) {
    super(`quarantine purge refused: ${activeLegalHolds} active legal hold(s)`);
  }
}

/**
 * Deletes every quarantine row of one organization (step 5.3 Q17 "Tenant purge") for the
 * organization purge (the deferred purge job of docs/runbooks/organization-deletion.md calls it
 * after its safeguards, next to the BEC, DLP, risk and policy purges). Refused while any
 * `archive_legal_holds` row of the organization is `active` (`QuarantinePurgeRefusedError`;
 * nothing deleted). Writer only, `systemScope` of the organization being purged; each statement
 * is its own autocommit `DELETE … WHERE organization_id = ? ORDER BY id LIMIT n` until fewer
 * than n rows go, so a crash leaves a resumable state and a re-run continues where it stopped.
 * The S3 objects (EML, parts, copies) follow the organization deletion runbook (deferred job).
 * Never touches another organization's rows.
 */
@Injectable()
export class QuarantineTenantDataRepository {
  constructor(private readonly prisma: PrismaService) {}

  async purgeOrganization(
    scope: TenantScope,
    batch: number = QUARANTINE_PURGE_BATCH,
  ): Promise<QuarantinePurgeCounts> {
    if (!Number.isSafeInteger(batch) || batch < 1) throw new Error('batch must be positive');
    const holds = await this.prisma.archiveLegalHold.count({
      where: { organizationId: scope.organizationId, status: 'active' },
    });
    if (holds > 0) throw new QuarantinePurgeRefusedError(holds);
    const counts = Object.fromEntries(
      QUARANTINE_PURGE_ORDER.map((t) => [t, 0]),
    ) as QuarantinePurgeCounts;
    for (const table of QUARANTINE_PURGE_ORDER) {
      for (;;) {
        const deleted = await this.deleteBatch(table, scope.organizationId, batch);
        counts[table] += deleted;
        if (deleted < batch) break;
      }
    }
    return counts;
  }

  /** One batch; the table name comes from the fixed order list, never from input. */
  private deleteBatch(
    table: QuarantinePurgeTable,
    organizationId: bigint,
    batch: number,
  ): Promise<number> {
    switch (table) {
      case 'quarantine_download_grants':
        return this.prisma.$executeRaw`DELETE FROM quarantine_download_grants
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      case 'quarantine_approval_requests':
        return this.prisma.$executeRaw`DELETE FROM quarantine_approval_requests
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      case 'quarantine_release_logs':
        return this.prisma.$executeRaw`DELETE FROM quarantine_release_logs
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      case 'quarantine_actions':
        return this.prisma.$executeRaw`DELETE FROM quarantine_actions
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      case 'quarantine_object_purges':
        return this.prisma.$executeRaw`DELETE FROM quarantine_object_purges
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      case 'quarantine_digests':
        return this.prisma.$executeRaw`DELETE FROM quarantine_digests
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      case 'quarantine_digest_runs':
        return this.prisma.$executeRaw`DELETE FROM quarantine_digest_runs
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      case 'quarantine_user_preferences':
        return this.prisma.$executeRaw`DELETE FROM quarantine_user_preferences
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      case 'quarantine_messages':
        return this.prisma.$executeRaw`DELETE FROM quarantine_messages
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      case 'quarantine_settings':
        return this.prisma.$executeRaw`DELETE FROM quarantine_settings
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
    }
  }
}
