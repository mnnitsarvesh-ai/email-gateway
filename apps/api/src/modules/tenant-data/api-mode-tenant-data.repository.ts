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
 * so the message purge is unaffected (its EMLs follow the message retention).
 */
export const API_MODE_PURGE_ORDER = [
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
