import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import type { TenantScope } from '../../auth-contracts/tenant-scope';

/**
 * The organization's API-mode tables in the order the organization purge deletes them (step
 * API-1 §3.2, docs/plan/steps/35-api-mode-protection.md; ADR-0100): the per-mailbox copies
 * (`api_message_copies`, partitioned, no FK) and the transient dedupe keys before the mailboxes,
 * the mailbox addresses (FK CASCADE as a backstop) with them, the hourly counters and the
 * mailboxes before the API-mode connections (`api_mailboxes.api_connection_id` RESTRICT). Run
 * BEFORE the provider-connection purge: `api_mode_connections.provider_connection_id` references
 * `provider_connections` with RESTRICT. Copies reference registry messages, never the reverse,
 * so the message purge is unaffected (its EMLs follow the message retention). Step API-2 §3.4
 * (docs/plan/steps/36-api-mode-remediation.md): the remediation actions go first (they reference
 * the mailboxes and the API-mode connections with RESTRICT; `organization_id` has no FK) and the
 * remediation policies with them (they reference `domains` and `organizations` with RESTRICT, so
 * this purge also runs BEFORE the domain purge). Mailbox-located quarantine entries carry no FK
 * to these tables and go with the quarantine purge. Step API-3 §3.4
 * (docs/plan/steps/37-api-mode-clawback-reporting.md): the clawback targets (CASCADE with their
 * clawback; deleted first so each statement stays short), the clawbacks and the user reports
 * (they reference the API-mode connections and the report mailboxes with RESTRICT) go before the
 * remediation actions, mailboxes and connections; the organization's API-mode settings
 * (`api_mode_org_settings`, FK to organizations RESTRICT) go before the organization. Step API-4
 * §3.3 (docs/plan/steps/38-api-mode-parity-onboarding.md): the per-domain onboarding and scope
 * rows (`api_mode_domain_settings`, FK to organizations RESTRICT, to domains CASCADE) go with the
 * settings, before the domains; detect rows of `policy_execution_logs` go with the policy purge.
 */
export const API_MODE_PURGE_ORDER = [
  'api_clawback_targets',
  'api_clawbacks',
  'api_user_reports',
  'api_remediation_actions',
  'api_remediation_policies',
  'api_mode_org_settings',
  'api_mode_domain_settings',
  'api_message_copies',
  'api_copy_dedupe_keys',
  'api_mailbox_addresses',
  'api_mailboxes',
  'api_mode_counters',
  'api_mode_connections',
] as const;
export type ApiModePurgeTable = (typeof API_MODE_PURGE_ORDER)[number];

/** Rows one purge statement deletes (short statements, no long row locks). */
export const API_MODE_PURGE_BATCH = 500;

export type ApiModePurgeCounts = Record<ApiModePurgeTable, number>;

/**
 * Deletes an organization's API-mode rows for the organization purge. Writer only, `systemScope`
 * of the organization; each statement is its own autocommit `DELETE … WHERE organization_id = ?
 * ORDER BY … LIMIT n`, repeated until fewer than n rows go, so a crash leaves a resumable,
 * consistent state and a re-run continues where it stopped (0 everywhere once done). Never
 * touches another organization's rows. The rows hold ids, hashes, addresses, verdicts and timings
 * (no content, no secret; feed cursors and client-state hashes go with their mailbox rows).
 */
@Injectable()
export class ApiModeTenantDataRepository {
  constructor(private readonly prisma: PrismaService) {}

  async purgeOrganization(
    scope: TenantScope,
    batch: number = API_MODE_PURGE_BATCH,
  ): Promise<ApiModePurgeCounts> {
    if (!Number.isSafeInteger(batch) || batch < 1) throw new Error('batch must be positive');
    const counts = Object.fromEntries(
      API_MODE_PURGE_ORDER.map((t) => [t, 0]),
    ) as ApiModePurgeCounts;
    for (const table of API_MODE_PURGE_ORDER) {
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
    table: ApiModePurgeTable,
    organizationId: bigint,
    batch: number,
  ): Promise<number> {
    switch (table) {
      case 'api_clawback_targets':
        // Index (organization_id, copy_id, copy_received_at); FK to api_clawbacks (CASCADE).
        return this.prisma.$executeRaw`DELETE FROM api_clawback_targets
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      case 'api_clawbacks':
        // Index (organization_id, created_at, id); FK to organizations (RESTRICT).
        return this.prisma.$executeRaw`DELETE FROM api_clawbacks
          WHERE organization_id = ${organizationId} ORDER BY created_at, id LIMIT ${batch}`;
      case 'api_user_reports':
        // Index (organization_id, reported_at, id); FKs to connections and mailboxes (RESTRICT).
        return this.prisma.$executeRaw`DELETE FROM api_user_reports
          WHERE organization_id = ${organizationId} ORDER BY reported_at, id LIMIT ${batch}`;
      case 'api_remediation_actions':
        // Index (organization_id, created_at, id); FKs to mailboxes and connections (RESTRICT).
        return this.prisma.$executeRaw`DELETE FROM api_remediation_actions
          WHERE organization_id = ${organizationId} ORDER BY created_at, id LIMIT ${batch}`;
      case 'api_remediation_policies':
        // Unique (organization_id, scope_key); FKs to organizations and domains (RESTRICT).
        return this.prisma.$executeRaw`DELETE FROM api_remediation_policies
          WHERE organization_id = ${organizationId} ORDER BY scope_key, id LIMIT ${batch}`;
      case 'api_mode_org_settings':
        // Primary key organization_id; FK to organizations (RESTRICT).
        return this.prisma.$executeRaw`DELETE FROM api_mode_org_settings
          WHERE organization_id = ${organizationId} ORDER BY organization_id LIMIT ${batch}`;
      case 'api_mode_domain_settings':
        // Index (organization_id); FKs to organizations (RESTRICT) and domains (CASCADE).
        return this.prisma.$executeRaw`DELETE FROM api_mode_domain_settings
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      case 'api_message_copies':
        // Index (organization_id, received_at, id); partitioned by received_at, no FK.
        return this.prisma.$executeRaw`DELETE FROM api_message_copies
          WHERE organization_id = ${organizationId} ORDER BY received_at, id LIMIT ${batch}`;
      case 'api_copy_dedupe_keys':
        // Index (organization_id).
        return this.prisma.$executeRaw`DELETE FROM api_copy_dedupe_keys
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      case 'api_mailbox_addresses':
        // Unique (organization_id, address).
        return this.prisma.$executeRaw`DELETE FROM api_mailbox_addresses
          WHERE organization_id = ${organizationId} ORDER BY address LIMIT ${batch}`;
      case 'api_mailboxes':
        // Index (organization_id, status).
        return this.prisma.$executeRaw`DELETE FROM api_mailboxes
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
      case 'api_mode_counters':
        // Index (organization_id, hour).
        return this.prisma.$executeRaw`DELETE FROM api_mode_counters
          WHERE organization_id = ${organizationId} ORDER BY hour, id LIMIT ${batch}`;
      case 'api_mode_connections':
        // Index (organization_id); mailboxes and counters are gone (RESTRICT / CASCADE).
        return this.prisma.$executeRaw`DELETE FROM api_mode_connections
          WHERE organization_id = ${organizationId} ORDER BY id LIMIT ${batch}`;
    }
  }
}
