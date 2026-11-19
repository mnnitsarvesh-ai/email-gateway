import { randomUUID } from 'node:crypto';
import type { PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import type { CheckRunner } from '../checks/checks';
import { loadConnection } from '../checks/context';
import { orgFilter } from '../shared/db';
import { errorFields } from '../shared/errors';
import type { TenantBinder } from './tenant-binding';

/** A link whose check failed is not picked again before this. */
export const DOMAIN_CHECK_RETRY_MS = 60_000;

/**
 * D4 (tasks role): newly linked domains (`provider_verification = 'unknown'`) of connections
 * with an active mail-flow grant are checked at the provider (`PUT …/domains` "triggers a
 * provider domain check"), then the tenant is bound on proof of control and I10 is evaluated
 * (`TenantBinder`). Claims per connection with `FOR UPDATE SKIP
 * LOCKED`; `provider_checked_at` doubles as the attempt time, so a failing provider is retried
 * after a minute, not in a tight loop.
 */
export class DomainCheckTask {
  constructor(
    private readonly writer: PrismaClient,
    private readonly options: {
      checks: CheckRunner;
      binder: TenantBinder;
      logger: Logger;
      now: () => Date;
      organizationIds?: readonly bigint[];
    },
  ) {}

  async runOnce(limit: number, signal: AbortSignal): Promise<number> {
    const now = this.options.now();
    const retryBefore = new Date(now.getTime() - DOMAIN_CHECK_RETRY_MS);
    const connectionIds = await this.writer.$transaction(async (tx) => {
      const rows = await tx.$queryRaw<Array<{ id: bigint; connection_id: bigint }>>`
        SELECT d.id, d.connection_id
          FROM provider_connection_domains d
          JOIN provider_connections c ON c.id = d.connection_id AND c.organization_id = d.organization_id
         WHERE d.provider_verification = 'unknown'
           AND (d.provider_checked_at IS NULL OR d.provider_checked_at < ${retryBefore})
           AND c.status IN ('configuring', 'active')
           AND EXISTS (SELECT 1 FROM provider_connection_grants g
                        WHERE g.connection_id = c.id AND g.status = 'active')
           ${orgFilter('d.organization_id', this.options.organizationIds)}
         ORDER BY d.id
         LIMIT ${limit * 20}
         FOR UPDATE OF d SKIP LOCKED`;
      if (rows.length === 0) return [];
      // Only the links of the connections processed in this pass are stamped: links of further
      // connections stay eligible for the next pass instead of waiting out the retry delay.
      const selected = [...new Set(rows.map((r) => BigInt(r.connection_id)))].slice(0, limit);
      const chosen = new Set(selected);
      const linkIds = rows
        .filter((r) => chosen.has(BigInt(r.connection_id)))
        .map((r) => BigInt(r.id));
      await tx.providerConnectionDomain.updateMany({
        where: { id: { in: linkIds } },
        data: { providerCheckedAt: now },
      });
      return selected;
    });
    for (const connectionId of connectionIds) {
      if (signal.aborted) break;
      try {
        const connection = await loadConnection(this.writer, connectionId);
        if (!connection) continue;
        await this.options.checks.checkProviderDomains(connection, signal);
        // Tenant binding on proof of control, then I10 (TenantBinder).
        await this.options.binder.settle(connectionId, signal, randomUUID());
      } catch (error) {
        this.options.logger.warn(
          { connectionId: connectionId.toString(), ...errorFields(error) },
          'provider domain check failed; retried',
        );
      }
    }
    return connectionIds.length;
  }
}
