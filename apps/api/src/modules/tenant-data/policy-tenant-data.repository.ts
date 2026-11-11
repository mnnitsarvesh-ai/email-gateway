import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import type { TenantScope } from '../../auth-contracts/tenant-scope';

/**
 * The organization's policy engine and directory tables in the order the organization purge
 * deletes them (step 5.2 P22, docs/runbooks/organization-deletion.md): the partitioned
 * evaluation rows first (no foreign keys), the retired legacy children of versions
 * (`policy_actions`, `policy_conditions`: `policy_version_id` CASCADE, `organization_id`
 * RESTRICT), the versions (`organization_id` RESTRICT), the policy exceptions, the policies,
 * the settings row, then the department members (`department_id` RESTRICT) and the
 * departments. Every table's `organization_id` is RESTRICT, so all of them must be empty before
 * the organization row goes. `email_policies.active_version_id` has no foreign key.
 */
export const POLICY_PURGE_ORDER = [
  'policy_execution_logs',
  'policy_actions',
  'policy_conditions',
  'policy_versions',
  'policy_exceptions',
  'email_policies',
  'policy_settings',
  'tenant_department_members',
  'tenant_departments',
] as const;
export type PolicyPurgeTable = (typeof POLICY_PURGE_ORDER)[number];

/** Rows one purge statement deletes (short statements, no long row locks). */
export const POLICY_PURGE_BATCH = 500;

export type PolicyPurgeCounts = Record<PolicyPurgeTable, number>;

/**
 * Deletes every policy engine and directory row of one organization (step 5.2) for the
 * organization purge (the deferred purge job of docs/runbooks/organization-deletion.md calls it
 * after its safeguards, next to the BEC, DLP and risk purges). Writer only, `systemScope` of the
 * organization being purged; each statement is its own autocommit `DELETE … WHERE
 * organization_id = ? [ORDER BY id] LIMIT n` until fewer than n rows go, so a crash leaves a
 * resumable, consistent state and a re-run continues where it stopped. Never touches another
 * organization's rows.
 */
@Injectable()
export class PolicyTenantDataRepository {
  constructor(private readonly prisma: PrismaService) {}

  async purgeOrganization(
    scope: TenantScope,
    batch: number = POLICY_PURGE_BATCH,
  ): Promise<PolicyPurgeCounts> {
    if (!Number.isSafeInteger(batch) || batch < 1) throw new Error('batch must be positive');
    const counts = Object.fromEntries(POLICY_PURGE_ORDER.map((t) => [t, 0])) as PolicyPurgeCounts;
    for (const table of POLICY_PURGE_ORDER) {
      for (;;) {
        const deleted = await this.deleteBatch(table, scope.organizationId, batch);
        counts[table] += deleted;
        if (deleted < batch) break;
      }
    }
    return counts;
  }

  /** One batch; the table name comes from the fixed POLICY_PURGE_ORDER list, never from input. */
  private deleteBatch(
    table: PolicyPurgeTable,
    organizationId: bigint,
    batch: number,
  ): Promise<number> {
    switch (table) {
      case 'policy_execution_logs':
        // Partitioned by received_at (no ORDER BY, like message_risk_scores).
        return this.prisma.$executeRaw`DELETE FROM policy_execution_logs
          WHERE organization_id = ${organizationId} LIMIT ${batch}`;
      case 'policy_actions':
        return this.prisma.$executeRaw`DELETE FROM policy_actions
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      case 'policy_conditions':
        return this.prisma.$executeRaw`DELETE FROM policy_conditions
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      case 'policy_versions':
        return this.prisma.$executeRaw`DELETE FROM policy_versions
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      case 'policy_exceptions':
        return this.prisma.$executeRaw`DELETE FROM policy_exceptions
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      case 'email_policies':
        return this.prisma.$executeRaw`DELETE FROM email_policies
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      case 'policy_settings':
        return this.prisma.$executeRaw`DELETE FROM policy_settings
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      case 'tenant_department_members':
        return this.prisma.$executeRaw`DELETE FROM tenant_department_members
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      case 'tenant_departments':
        return this.prisma.$executeRaw`DELETE FROM tenant_departments
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
    }
  }
}
