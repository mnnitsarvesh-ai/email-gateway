import { Prisma, type PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import { isApiSide, loadOrgApiModeState } from '../domain/api-mode-state';
import { grantActive, loadConnectionContext } from '../domain/connections';
import { DELETED_MAILBOX_RETENTION_DAYS } from '../inventory/inventory-runner';
import type { ProviderRuntime } from '../runtime/provider-runtime';
import { errorFields } from '../shared/errors';

/** `api_mode_counters` are kept this long (§3.2, retention.md). */
export const COUNTER_RETENTION_DAYS = 400;
const DAY_MS = 86_400_000;
const BATCH = 5_000;

export interface MaintenanceReport {
  dedupeKeys: number;
  expiredClaims: number;
  counters: number;
  deletedMailboxes: number;
  feedsStopped: number;
  feedsActivated: number;
}

export interface MaintenanceDeps {
  prisma: PrismaClient;
  /** For best-effort Graph subscription deletion of disabled feeds; null without provider roles. */
  runtime: ProviderRuntime | null;
  logger: Logger;
  now: () => Date;
  config: { dedupeWindowHours: number };
  organizationIds?: readonly bigint[];
}

/**
 * Maintenance of the health leader (design D11.4): prunes `api_copy_dedupe_keys` older than
 * `API_MODE_DEDUPE_WINDOW_HOURS` and expired in-flight feed claims, `api_mode_counters` older than
 * 400 days and mailboxes `deleted` for more than 30 days (their addresses cascade); stops the feeds
 * of connections whose feeds were disabled (Graph subscriptions deleted best effort, cursors
 * cleared) and starts `pending` feeds for in-scope mailboxes of connections with feeds enabled and
 * an active grant (a domain switched to api/hybrid, a grant restored). Batched deletes.
 */
export class Maintenance {
  constructor(private readonly deps: MaintenanceDeps) {}

  private orgFilter(column = 'organization_id'): Prisma.Sql {
    return this.deps.organizationIds
      ? Prisma.sql`AND ${Prisma.raw(column)} IN (${Prisma.join(this.deps.organizationIds)})`
      : Prisma.empty;
  }

  async runOnce(): Promise<MaintenanceReport> {
    const now = this.deps.now();
    const report: MaintenanceReport = {
      dedupeKeys: 0,
      expiredClaims: 0,
      counters: 0,
      deletedMailboxes: 0,
      feedsStopped: 0,
      feedsActivated: 0,
    };
    const prisma = this.deps.prisma;
    const dedupeCutoff = new Date(now.getTime() - this.deps.config.dedupeWindowHours * 3_600_000);
    report.dedupeKeys = await this.drain(
      () => prisma.$executeRaw`
        DELETE FROM api_copy_dedupe_keys WHERE created_at < ${dedupeCutoff} ${this.orgFilter()}
        LIMIT ${BATCH}`,
    );
    report.expiredClaims = await this.drain(
      () => prisma.$executeRaw`
        DELETE FROM api_copy_dedupe_keys
        WHERE copy_id IS NULL AND claim_expires_at < ${now} ${this.orgFilter()}
        LIMIT ${BATCH}`,
    );
    const counterCutoff = new Date(now.getTime() - COUNTER_RETENTION_DAYS * DAY_MS);
    report.counters = await this.drain(
      () => prisma.$executeRaw`
        DELETE FROM api_mode_counters WHERE hour < ${counterCutoff} ${this.orgFilter()}
        LIMIT ${BATCH}`,
    );
    const deletedCutoff = new Date(now.getTime() - DELETED_MAILBOX_RETENTION_DAYS * DAY_MS);
    report.deletedMailboxes = await this.drain(
      () => prisma.$executeRaw`
        DELETE FROM api_mailboxes
        WHERE status = 'deleted' AND deleted_at < ${deletedCutoff} ${this.orgFilter()}
        LIMIT 1000`,
    );
    const feeds = await this.feedSweeps(now);
    report.feedsStopped = feeds.stopped;
    report.feedsActivated = feeds.activated;
    return report;
  }

  private async drain(statement: () => Promise<number>): Promise<number> {
    let total = 0;
    for (let i = 0; i < 100; i++) {
      const n = await statement();
      total += n;
      if (n < BATCH) break;
    }
    return total;
  }

  private async feedSweeps(now: Date): Promise<{ stopped: number; activated: number }> {
    const prisma = this.deps.prisma;
    let stopped = 0;
    let activated = 0;
    const connections = await prisma.apiModeConnection.findMany({
      where: this.deps.organizationIds
        ? { organizationId: { in: [...this.deps.organizationIds] } }
        : {},
      select: { id: true },
      orderBy: { id: 'asc' },
    });
    for (const { id } of connections) {
      try {
        const ctx = await loadConnectionContext(prisma, id);
        if (!ctx) continue;
        if (!ctx.feedsEnabled) {
          const subscribed = await prisma.apiMailbox.findMany({
            where: { apiConnectionId: ctx.id, subscriptionId: { not: null } },
            select: { id: true, subscriptionId: true },
            take: 1000,
          });
          const graph =
            subscribed.length > 0 && grantActive(ctx) && this.deps.runtime
              ? this.deps.runtime.clientsFor(ctx).graph
              : null;
          for (const m of subscribed) {
            if (graph && m.subscriptionId) {
              await graph
                .deleteSubscription(m.subscriptionId, AbortSignal.timeout(30_000))
                .catch(() => undefined);
            }
          }
          stopped += await prisma.$executeRaw`
            UPDATE api_mailboxes
            SET feed_status = 'off', feed_cursor = NULL, feed_started_at = NULL,
                subscription_id = NULL, subscription_expires_at = NULL, client_state_hash = NULL,
                sync_requested_at = NULL, next_sync_at = NULL, lease_until = NULL,
                consecutive_failures = 0, updated_at = ${now}
            WHERE api_connection_id = ${ctx.id} AND organization_id = ${ctx.organizationId}
              AND (feed_status <> 'off' OR subscription_id IS NOT NULL OR feed_cursor IS NOT NULL)
              AND (lease_until IS NULL OR lease_until < ${now})`;
          continue;
        }
        if (!grantActive(ctx)) continue;
        const state = await loadOrgApiModeState(prisma, ctx.organizationId);
        const apiDomainIds = state?.domains
          .filter((d) => isApiSide(d.effectiveMode))
          .map((d) => d.id);
        if (!apiDomainIds || apiDomainIds.length === 0) continue;
        activated += await prisma.$executeRaw`
          UPDATE api_mailboxes
          SET feed_status = 'pending', next_sync_at = ${now}, consecutive_failures = 0,
              last_error_code = NULL, updated_at = ${now}
          WHERE api_connection_id = ${ctx.id} AND organization_id = ${ctx.organizationId}
            AND status = 'active' AND provider_user_id IS NOT NULL
            AND feed_status IN ('off', 'revoked')
            AND domain_id IN (${Prisma.join(apiDomainIds)})`;
      } catch (error) {
        this.deps.logger.warn(
          { apiConnectionId: id.toString(), ...errorFields(error) },
          'api-mode feed sweep failed for a connection; retried next run',
        );
      }
    }
    return { stopped, activated };
  }
}
