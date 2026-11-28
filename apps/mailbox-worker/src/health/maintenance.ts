import { Prisma, type PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import { scopeExcludedSql } from '../domain/scope';
import { isApiSide, loadOrgApiModeState } from '../domain/api-mode-state';
import { grantActive, loadConnectionContext } from '../domain/connections';
import { DELETED_MAILBOX_RETENTION_DAYS } from '../inventory/inventory-runner';
import { expireMailboxEntries } from '../remediation/quarantine-entries';
import type { ProviderRuntime } from '../runtime/provider-runtime';
import { errorFields } from '../shared/errors';

/** `api_mode_counters` are kept this long (§3.2, retention.md). */
export const COUNTER_RETENTION_DAYS = 400;
const DAY_MS = 86_400_000;
const BATCH = 5_000;
/** Mailbox entries expired per maintenance run (one short transaction each). */
const ENTRY_EXPIRY_BATCH = 500;
/** Terminal remediation actions pruned per statement. */
const ACTION_PRUNE_BATCH = 1_000;
/** Terminal clawbacks pruned per statement (their targets cascade, so keep it small). */
const CLAWBACK_PRUNE_BATCH = 100;

export interface MaintenanceReport {
  dedupeKeys: number;
  expiredClaims: number;
  counters: number;
  deletedMailboxes: number;
  feedsStopped: number;
  feedsActivated: number;
  /** Step API-2 R11.4: mailbox-located quarantine entries expired. */
  mailboxEntriesExpired: number;
  /** Step API-2 §3.1: terminal `api_remediation_actions` rows pruned. */
  remediationActions: number;
  /** Step API-3 §3.4: terminal clawbacks (their targets cascade) and reports pruned. */
  clawbacks: number;
  reports: number;
}

export interface MaintenanceDeps {
  prisma: PrismaClient;
  /** For best-effort Graph subscription deletion of disabled feeds; null without provider roles. */
  runtime: ProviderRuntime | null;
  logger: Logger;
  now: () => Date;
  config: {
    dedupeWindowHours: number;
    remediationRetentionDays: number;
    /** `API_MODE_CLAWBACK_RETENTION_DAYS` (§3.4). */
    clawbackRetentionDays: number;
    /** `API_MODE_REPORT_RETENTION_DAYS` (§3.4). */
    reportRetentionDays: number;
  };
  organizationIds?: readonly bigint[];
}

/**
 * Maintenance of the health leader (design D11.4): prunes `api_copy_dedupe_keys` older than
 * `API_MODE_DEDUPE_WINDOW_HOURS` and expired in-flight feed claims, `api_mode_counters` older than
 * 400 days and mailboxes `deleted` for more than 30 days (their addresses cascade); stops the feeds
 * of connections whose feeds were disabled (Graph subscriptions deleted best effort, cursors
 * cleared) and starts `pending` feeds for in-scope mailboxes of connections with feeds enabled and
 * an active grant (a domain switched to api/hybrid, a grant restored). Batched deletes.
 *
 * Step API-2: expires due mailbox-located quarantine entries (R11.4; no mailbox change, no
 * lifecycle edge) and prunes terminal remediation actions older than
 * `API_MODE_REMEDIATION_RETENTION_DAYS` whose quarantine entry is terminal or gone (§3.1).
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
      mailboxEntriesExpired: 0,
      remediationActions: 0,
      clawbacks: 0,
      reports: 0,
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
    report.mailboxEntriesExpired = await expireMailboxEntries(prisma, {
      now,
      batch: ENTRY_EXPIRY_BATCH,
      ...(this.deps.organizationIds ? { organizationIds: this.deps.organizationIds } : {}),
    });
    const actionCutoff = new Date(
      now.getTime() - this.deps.config.remediationRetentionDays * DAY_MS,
    );
    for (let i = 0; i < 100; i++) {
      const n = await prisma.$executeRaw`
        DELETE a FROM api_remediation_actions a
        JOIN (
          SELECT x.id FROM api_remediation_actions x
          LEFT JOIN quarantine_messages q ON q.id = x.quarantine_entry_id
          WHERE x.status IN ('succeeded', 'failed', 'skipped', 'simulated', 'cancelled')
            AND COALESCE(x.completed_at, x.updated_at) < ${actionCutoff}
            AND (q.id IS NULL OR q.status NOT IN ('held', 'pending_approval', 'releasing'))
            ${this.orgFilter('x.organization_id')}
          ORDER BY x.id
          LIMIT ${ACTION_PRUNE_BATCH}
        ) d ON d.id = a.id`;
      report.remediationActions += n;
      if (n < ACTION_PRUNE_BATCH) break;
    }
    // Step API-3 §3.4: terminal clawbacks (targets cascade) and terminal reports.
    const clawbackCutoff = new Date(
      now.getTime() - this.deps.config.clawbackRetentionDays * DAY_MS,
    );
    report.clawbacks = await this.drain(
      () => prisma.$executeRaw`
        DELETE FROM api_clawbacks
        WHERE status IN ('completed', 'completed_with_errors', 'no_match', 'too_broad', 'denied',
                         'expired', 'cancelled', 'failed')
          AND restore_status NOT IN ('requested', 'running')
          AND COALESCE(completed_at, updated_at) < ${clawbackCutoff} ${this.orgFilter()}
        LIMIT ${CLAWBACK_PRUNE_BATCH}`,
      CLAWBACK_PRUNE_BATCH,
    );
    const reportCutoff = new Date(now.getTime() - this.deps.config.reportRetentionDays * DAY_MS);
    report.reports = await this.drain(
      () => prisma.$executeRaw`
        DELETE FROM api_user_reports
        WHERE status IN ('resolved', 'rejected') AND updated_at < ${reportCutoff}
          ${this.orgFilter()}
        LIMIT ${BATCH}`,
    );
    return report;
  }

  private async drain(statement: () => Promise<number>, batch = BATCH): Promise<number> {
    let total = 0;
    for (let i = 0; i < 100; i++) {
      const n = await statement();
      total += n;
      if (n < batch) break;
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
            AND domain_id IN (${Prisma.join(apiDomainIds)})
            AND NOT ${scopeExcludedSql('api_mailboxes')}`;
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
