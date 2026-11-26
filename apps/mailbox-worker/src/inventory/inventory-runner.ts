import { uuidv7 } from '@email-gateway/common';
import { Prisma, type PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import { MailboxApiError } from '@email-gateway/mailbox-api';
import { isApiSide, loadOrgApiModeState, type OrgApiModeState } from '../domain/api-mode-state';
import {
  applyGrantRevocation,
  connectionUsable,
  grantActive,
  loadConnectionContext,
  type ConnectionContext,
} from '../domain/connections';
import { classifyFailure } from '../feeds/schedule';
import type { MailboxMetrics } from '../metrics/mailbox-metrics';
import type { MailboxClients, ProviderRuntime } from '../runtime/provider-runtime';
import type { CounterStore } from '../runtime/redis-stores';
import { big, TX_OPTIONS } from '../shared/db';
import { errorFields } from '../shared/errors';
import { fromGoogleUser, fromGraphUser, inScope, type DirectoryUser } from './directory';

/** Lease of a claimed inventory run (the next due time while it runs). */
export const INVENTORY_LEASE_MS = 30 * 60_000;
/** Retry of a failed inventory. */
export const INVENTORY_RETRY_MS = 15 * 60_000;
/** Pages of one listing (999 / 500 users per page). */
const MAX_PAGES = 2_000;
/** Deleted mailboxes stay visible this long before the health maintenance purges them. */
export const DELETED_MAILBOX_RETENTION_DAYS = 30;

export interface InventoryConfig {
  intervalHours: number;
  maxMailboxes: number;
}

export interface InventoryDeps {
  prisma: PrismaClient;
  runtime: ProviderRuntime;
  counters: CounterStore;
  metrics: MailboxMetrics | null;
  logger: Logger;
  now: () => Date;
  config: InventoryConfig;
  organizationIds?: readonly bigint[];
}

export interface InventoryReport {
  result: 'ok' | 'unavailable' | 'deferred' | 'throttled' | 'limit' | 'failed';
  users?: number;
  created?: number;
  adopted?: number;
  disabled?: number;
  deleted?: number;
  addressConflicts?: number;
}

class InventoryLimitError extends Error {
  readonly code = 'inventory_limit';
}

/**
 * The inventory role (design D11.1): per API connection every `API_MODE_INVENTORY_INTERVAL_HOURS`
 * or on request (`inventory_requested_at`), with the active mailbox-access grant (else D4:
 * `inventory_status = unavailable`): Graph / Directory users whose primary or alias address is in
 * a domain linked to the 8.2 connection are upserted by `(api_connection_id, provider_user_id)` or
 * adopt a `discovered` mailbox by address; their address rows are replaced (an address owned by
 * another mailbox of the organization is skipped and counted); disabled / suspended users become
 * `disabled`, users no longer listed `deleted`; more than `API_MODE_MAX_MAILBOXES_PER_CONNECTION`
 * fails `inventory_limit` without changes; `mailboxes_total` = active mailboxes on api/hybrid
 * domains. With feeds enabled, new in-scope mailboxes become `pending`.
 */
export class InventoryRunner {
  constructor(private readonly deps: InventoryDeps) {}

  /** One tick: runs at most one due connection; true when one ran (more may be due). */
  async tick(): Promise<boolean> {
    const id = await this.claim();
    if (id === null) return false;
    await this.run(id).catch((error: unknown) => {
      this.deps.logger.warn({ ...errorFields(error) }, 'mailbox inventory bookkeeping failed');
    });
    return true;
  }

  private async claim(): Promise<bigint | null> {
    const now = this.deps.now();
    const orgFilter = this.deps.organizationIds
      ? Prisma.sql`AND organization_id IN (${Prisma.join(this.deps.organizationIds)})`
      : Prisma.empty;
    return this.deps.prisma.$transaction(async (tx) => {
      const rows = await tx.$queryRaw<Array<{ id: bigint | number }>>`
        SELECT id FROM api_mode_connections
        WHERE (inventory_requested_at IS NOT NULL OR next_inventory_at IS NULL
               OR next_inventory_at <= ${now})
          ${orgFilter}
        ORDER BY (inventory_requested_at IS NULL), next_inventory_at, id
        LIMIT 1
        FOR UPDATE SKIP LOCKED`;
      if (!rows[0]) return null;
      const id = big(rows[0].id);
      await tx.$executeRaw`
        UPDATE api_mode_connections
        SET next_inventory_at = ${new Date(now.getTime() + INVENTORY_LEASE_MS)},
            inventory_requested_at = NULL, updated_at = ${now}
        WHERE id = ${id}`;
      return id;
    }, TX_OPTIONS);
  }

  /** The inventory of one connection (also called directly by tests). */
  async run(apiConnectionId: bigint): Promise<InventoryReport> {
    const now = this.deps.now();
    const ctx = await loadConnectionContext(this.deps.prisma, apiConnectionId);
    if (!ctx) return { result: 'failed' };
    const next = new Date(now.getTime() + this.deps.config.intervalHours * 3_600_000);
    const done = (report: InventoryReport) => {
      this.deps.metrics?.inventoryRuns.inc({ provider: ctx.provider, result: report.result });
      return report;
    };
    if (!grantActive(ctx)) {
      await applyGrantRevocation(this.deps.prisma, ctx, now);
      await this.schedule(ctx, next, {});
      return done({ result: 'unavailable' });
    }
    if (!connectionUsable(ctx)) {
      await this.schedule(ctx, next, { lastErrorCode: 'connection_inactive' });
      return done({ result: 'deferred' });
    }
    const state = await loadOrgApiModeState(this.deps.prisma, ctx.organizationId);
    if (!state) return done({ result: 'failed' });
    const clients = this.deps.runtime.clientsFor(ctx);
    try {
      const report = await this.inventory(ctx, state, clients);
      await this.deps.counters.add(ctx.id, {
        provider_requests: clients.tally.requests,
        provider_errors: clients.tally.errors,
      });
      return done(report);
    } catch (error) {
      await this.deps.counters.add(ctx.id, {
        provider_requests: clients.tally.requests,
        provider_errors: clients.tally.errors,
      });
      if (error instanceof InventoryLimitError) {
        await this.schedule(ctx, next, {
          inventoryStatus: 'failed',
          lastErrorCode: 'inventory_limit',
        });
        this.deps.logger.warn(
          { apiConnectionId: ctx.publicId, max: this.deps.config.maxMailboxes },
          'mailbox inventory above the per-connection limit; nothing changed',
        );
        return done({ result: 'limit' });
      }
      const failure = classifyFailure(error);
      if (failure.kind === 'throttled') {
        await this.schedule(ctx, new Date(now.getTime() + failure.retryAfterMs), {});
        return done({ result: 'throttled' });
      }
      const code = failure.kind === 'failure' ? failure.code : 'inventory_failed';
      await this.schedule(ctx, new Date(now.getTime() + INVENTORY_RETRY_MS), {
        inventoryStatus: 'failed',
        lastErrorCode: code.slice(0, 64),
      });
      this.deps.logger.warn(
        { apiConnectionId: ctx.publicId, code, ...errorFields(error) },
        'mailbox inventory failed; retried later',
      );
      return done({ result: 'failed' });
    }
  }

  private async schedule(
    ctx: ConnectionContext,
    next: Date,
    patch: { inventoryStatus?: 'failed'; lastErrorCode?: string },
  ): Promise<void> {
    await this.deps.prisma.apiModeConnection.updateMany({
      where: { id: ctx.id, organizationId: ctx.organizationId },
      data: {
        nextInventoryAt: next,
        ...(patch.inventoryStatus ? { inventoryStatus: patch.inventoryStatus } : {}),
        ...(patch.lastErrorCode ? { lastErrorCode: patch.lastErrorCode } : {}),
      },
    });
  }

  /** Lists the provider users (every page) as normalized, in-scope directory users. */
  private async listUsers(
    ctx: ConnectionContext,
    clients: MailboxClients,
    linked: ReadonlySet<string>,
    signal: AbortSignal,
  ): Promise<DirectoryUser[]> {
    const users: DirectoryUser[] = [];
    const keep = (user: DirectoryUser | null) => {
      if (user && inScope(user, linked)) users.push(user);
      if (users.length > this.deps.config.maxMailboxes) throw new InventoryLimitError();
    };
    if (ctx.provider === 'microsoft_365') {
      if (!clients.graph) throw new MailboxApiError('grant_missing', { retryable: false });
      let link: string | undefined;
      for (let page = 0; page < MAX_PAGES; page++) {
        const answer = await clients.graph.listUsers(link, signal);
        answer.users.forEach((u) => keep(fromGraphUser(u)));
        if (!answer.nextLink) return users;
        link = answer.nextLink;
      }
    } else {
      // The Directory token impersonates the grant's delegated administrator.
      if (!clients.directory) throw new MailboxApiError('grant_missing', { retryable: false });
      let token: string | undefined;
      for (let page = 0; page < MAX_PAGES; page++) {
        const answer = await clients.directory.listUsers(token, signal);
        answer.users.forEach((u) => keep(fromGoogleUser(u)));
        if (!answer.nextPageToken) return users;
        token = answer.nextPageToken;
      }
    }
    throw new MailboxApiError('unexpected_response', { retryable: true });
  }

  private async inventory(
    ctx: ConnectionContext,
    state: OrgApiModeState,
    clients: MailboxClients,
  ): Promise<InventoryReport> {
    const now = this.deps.now();
    const linkedIds = new Set(ctx.linkedDomainIds.map(String));
    const linked = new Set(
      state.domains.filter((d) => linkedIds.has(d.id.toString())).map((d) => d.name),
    );
    const users = await this.listUsers(ctx, clients, linked, AbortSignal.timeout(600_000));
    const report: Required<InventoryReport> = {
      result: 'ok',
      users: users.length,
      created: 0,
      adopted: 0,
      disabled: 0,
      deleted: 0,
      addressConflicts: 0,
    };
    const seen = new Set<string>();
    for (const user of users) {
      if (seen.has(user.providerUserId)) continue;
      seen.add(user.providerUserId);
      const outcome = await this.upsert(ctx, state, user, now);
      if (outcome.created) report.created += 1;
      if (outcome.adopted) report.adopted += 1;
      if (!user.enabled) report.disabled += 1;
      report.addressConflicts += outcome.conflicts;
    }
    report.deleted = await this.markDeleted(ctx, seen, now, clients);
    const apiDomainIds = state.domains.filter((d) => isApiSide(d.effectiveMode)).map((d) => d.id);
    const total =
      apiDomainIds.length === 0
        ? 0
        : await this.deps.prisma.apiMailbox.count({
            where: {
              apiConnectionId: ctx.id,
              organizationId: ctx.organizationId,
              status: 'active',
              domainId: { in: apiDomainIds },
            },
          });
    if (ctx.feedsEnabled && apiDomainIds.length > 0) {
      await this.deps.prisma.$executeRaw`
        UPDATE api_mailboxes
        SET feed_status = 'pending', next_sync_at = ${now}, consecutive_failures = 0,
            last_error_code = NULL, updated_at = ${now}
        WHERE api_connection_id = ${ctx.id} AND organization_id = ${ctx.organizationId}
          AND status = 'active' AND provider_user_id IS NOT NULL
          AND feed_status IN ('off', 'revoked')
          AND domain_id IN (${Prisma.join(apiDomainIds)})`;
    }
    await this.deps.prisma.apiModeConnection.updateMany({
      where: { id: ctx.id, organizationId: ctx.organizationId },
      data: {
        inventoryStatus: 'ok',
        inventorySyncedAt: now,
        nextInventoryAt: new Date(now.getTime() + this.deps.config.intervalHours * 3_600_000),
        mailboxesTotal: total,
        lastErrorCode: null,
      },
    });
    this.deps.logger.info(
      {
        apiConnectionId: ctx.publicId,
        users: report.users,
        created: report.created,
        adopted: report.adopted,
        disabled: report.disabled,
        deleted: report.deleted,
        addressConflicts: report.addressConflicts,
        mailboxesTotal: total,
      },
      'mailbox inventory synced',
    );
    return report;
  }

  /** One user: upsert (or adopt a discovered mailbox), then its address rows. */
  private async upsert(
    ctx: ConnectionContext,
    state: OrgApiModeState,
    user: DirectoryUser,
    now: Date,
  ): Promise<{ created: boolean; adopted: boolean; conflicts: number }> {
    const prisma = this.deps.prisma;
    const domainId = state.domains.find((d) => d.name === user.primary.split('@')[1])?.id ?? null;
    const status = user.enabled ? ('active' as const) : ('disabled' as const);
    let created = false;
    let adopted = false;
    let mailbox = await prisma.apiMailbox.findUnique({
      where: {
        apiConnectionId_providerUserId: {
          apiConnectionId: ctx.id,
          providerUserId: user.providerUserId,
        },
      },
      select: { id: true, organizationId: true },
    });
    if (mailbox && mailbox.organizationId !== ctx.organizationId) mailbox = null;
    if (!mailbox) {
      const discovered = await prisma.apiMailbox.findFirst({
        where: {
          organizationId: ctx.organizationId,
          apiConnectionId: ctx.id,
          providerUserId: null,
          addresses: { some: { address: { in: [user.primary, ...user.aliases] } } },
        },
        select: { id: true, organizationId: true },
        orderBy: { id: 'asc' },
      });
      if (discovered) {
        mailbox = discovered;
        adopted = true;
      }
    }
    if (mailbox) {
      await prisma.apiMailbox.update({
        where: { id: mailbox.id },
        data: {
          providerUserId: user.providerUserId,
          primaryAddress: user.primary,
          domainId,
          status,
          deletedAt: null,
        },
      });
    } else {
      const row = await prisma.apiMailbox.create({
        data: {
          publicId: uuidv7(now.getTime()),
          organizationId: ctx.organizationId,
          apiConnectionId: ctx.id,
          providerUserId: user.providerUserId,
          primaryAddress: user.primary,
          domainId,
          status,
        },
        select: { id: true, organizationId: true },
      });
      mailbox = row;
      created = true;
    }
    const conflicts = await this.replaceAddresses(ctx.organizationId, mailbox.id, user, now);
    return { created, adopted, conflicts };
  }

  /** Replaces the mailbox's address rows with primary + aliases; foreign-owned ones are skipped. */
  private async replaceAddresses(
    organizationId: bigint,
    mailboxId: bigint,
    user: DirectoryUser,
    now: Date,
  ): Promise<number> {
    const prisma = this.deps.prisma;
    const wanted = new Map<string, 'primary' | 'alias'>([[user.primary, 'primary']]);
    for (const alias of user.aliases) if (!wanted.has(alias)) wanted.set(alias, 'alias');
    await prisma.apiMailboxAddress.deleteMany({
      where: { mailboxId, organizationId, address: { notIn: [...wanted.keys()] } },
    });
    let conflicts = 0;
    for (const [address, kind] of wanted) {
      const inserted = await prisma.$executeRaw`
        INSERT IGNORE INTO api_mailbox_addresses (organization_id, mailbox_id, address, kind, created_at)
        VALUES (${organizationId}, ${mailboxId}, ${address}, ${kind}, ${now})`;
      if (inserted === 1) continue;
      const owner = await prisma.apiMailboxAddress.findUnique({
        where: { organizationId_address: { organizationId, address } },
        select: { id: true, mailboxId: true, kind: true },
      });
      if (!owner) continue;
      if (owner.mailboxId !== mailboxId) {
        conflicts += 1;
        continue;
      }
      if (owner.kind !== kind) {
        await prisma.apiMailboxAddress.update({ where: { id: owner.id }, data: { kind } });
      }
    }
    return conflicts;
  }

  /** Mailboxes of the connection no longer listed → `deleted` (feeds off, subscription deleted). */
  private async markDeleted(
    ctx: ConnectionContext,
    seen: ReadonlySet<string>,
    now: Date,
    clients: MailboxClients,
  ): Promise<number> {
    const present = await this.deps.prisma.apiMailbox.findMany({
      where: {
        apiConnectionId: ctx.id,
        organizationId: ctx.organizationId,
        providerUserId: { not: null },
        status: { not: 'deleted' },
      },
      select: { id: true, providerUserId: true, subscriptionId: true },
    });
    const gone = present.filter((m) => m.providerUserId !== null && !seen.has(m.providerUserId));
    for (const mailbox of gone) {
      if (mailbox.subscriptionId && clients.graph) {
        await clients.graph
          .deleteSubscription(mailbox.subscriptionId, AbortSignal.timeout(30_000))
          .catch(() => undefined);
      }
      await this.deps.prisma.apiMailbox.update({
        where: { id: mailbox.id },
        data: {
          status: 'deleted',
          deletedAt: now,
          feedStatus: 'off',
          feedCursor: null,
          subscriptionId: null,
          subscriptionExpiresAt: null,
          clientStateHash: null,
          syncRequestedAt: null,
          nextSyncAt: null,
        },
      });
    }
    return gone.length;
  }
}
