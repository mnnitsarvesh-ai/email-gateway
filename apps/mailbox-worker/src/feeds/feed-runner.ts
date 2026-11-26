import {
  Prisma,
  type ApiMailboxFeedStatus,
  type ApiMailboxStatus,
  type PrismaClient,
} from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import {
  classifyRecipientDirection,
  clientStateHash,
  copyMessageIdHash,
  deriveClientState,
  emlObjectKeyForCopy,
  extractCopyHeaders,
  ingestKeyForCopy,
  MailboxApiError,
  toMailboxApiError,
  type GmailClient,
  type GraphMailClient,
  type MailboxApiFamily,
  type MailboxContentStream,
  type ThrottleGate,
} from '@email-gateway/mailbox-api';
import { isApiSide, loadOrgApiModeState, type OrgApiModeState } from '../domain/api-mode-state';
import {
  applyGrantRevocation,
  connectionUsable,
  grantActive,
  loadConnectionContext,
  type ConnectionContext,
} from '../domain/connections';
import type { MailboxMetrics } from '../metrics/mailbox-metrics';
import type { MailboxClients, ProviderRuntime } from '../runtime/provider-runtime';
import type { CounterDelta, CounterStore } from '../runtime/redis-stores';
import { big, TX_OPTIONS } from '../shared/db';
import { errorFields } from '../shared/errors';
import { mapLimit } from '../shared/loops';
import type { EmlSink } from './eml-sink';
import { claimForFeed } from './feed-claims';
import { MailboxCopyRepository } from './mailbox-copy.repository';
import {
  backoffMs,
  BUDGET_RETRY_MS,
  classifyFailure,
  pollIntervalMs,
  statusAfterFailure,
} from './schedule';

/** Lease of a claimed mailbox (D10.2). */
export const FEED_LEASE_MS = 120_000;
/** Delta/history pages per sync run; more pending work asks for an immediate next run. */
export const MAX_PAGES_PER_SYNC = 20;
/** Pages of an initialization round (no backfill: items are discarded) before it gives up. */
export const MAX_INIT_PAGES = 2_000;

export interface FeedConfig {
  batch: number;
  concurrency: number;
  concurrencyPerConnection: number;
  feedPollSeconds: number;
  safetyPollSeconds: number;
  maxMessageBytes: number;
  headerMaxBytes: number;
  subscriptionMinutes: number;
  renewBeforeMinutes: number;
  /** `API_MODE_GRAPH_NOTIFICATION_URL`; notifications only when set (with the secret). */
  notificationUrl: string | null;
  notificationSecret: string | null;
}

export interface FeedDeps {
  prisma: PrismaClient;
  runtime: ProviderRuntime;
  throttle: ThrottleGate;
  sink: EmlSink;
  counters: CounterStore;
  metrics: MailboxMetrics | null;
  logger: Logger;
  now: () => Date;
  config: FeedConfig;
  organizationIds?: readonly bigint[];
  /** TEST SEAM: delta/history pages per sync run (default `MAX_PAGES_PER_SYNC`). */
  maxPagesPerSync?: number;
}

/** A claimed feed mailbox (the row as the sync reads it). */
export interface FeedMailbox {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  apiConnectionId: bigint;
  providerUserId: string | null;
  primaryAddress: string;
  domainId: bigint | null;
  status: ApiMailboxStatus;
  feedStatus: ApiMailboxFeedStatus;
  feedCursor: string | null;
  feedStartedAt: Date | null;
  subscriptionId: string | null;
  subscriptionExpiresAt: Date | null;
  clientStateVersion: number;
  consecutiveFailures: number;
}

export type SyncResult =
  'ok' | 'initialized' | 'reset' | 'throttled' | 'deferred' | 'error' | 'revoked' | 'off';

interface SyncRun {
  mailbox: FeedMailbox;
  ctx: ConnectionContext;
  state: OrgApiModeState;
  clients: MailboxClients;
  signal: AbortSignal;
  counters: CounterDelta;
  /** More pages remain (the next tick continues at once). */
  more: boolean;
}

export const MAILBOX_SELECT = {
  id: true,
  publicId: true,
  organizationId: true,
  apiConnectionId: true,
  providerUserId: true,
  primaryAddress: true,
  domainId: true,
  status: true,
  feedStatus: true,
  feedCursor: true,
  feedStartedAt: true,
  subscriptionId: true,
  subscriptionExpiresAt: true,
  clientStateVersion: true,
  consecutiveFailures: true,
} as const;

const familyOf = (ctx: ConnectionContext): MailboxApiFamily =>
  ctx.provider === 'microsoft_365' ? 'graph' : 'gmail';

/**
 * The feeds role (design D10): every `API_MODE_FEED_TICK_MS` claim due mailboxes (`FOR UPDATE
 * SKIP LOCKED`, lease 120 s, ≤ `API_MODE_FETCH_CONCURRENCY` overall and
 * `…_PER_CONNECTION` per connection) and sync each: re-check the connection (active, bound), the
 * mailbox-access grant (else D4 revocation), `feeds_enabled`, the mailbox's domain mode and the
 * throttle pause; then the Graph Inbox delta (D10.3, initialized without backfill, the next link
 * stored after every page, `cursor_expired` re-initializes and records a gap) with change
 * notifications (D10.4), or the Gmail history (D10.5). New items are deduplicated metadata first
 * (D10.3 a), fetched ≤ `API_MODE_MAX_MESSAGE_BYTES` into the mail bucket and committed through
 * `MailboxCopyRepository` (registry message + pending copy + `received.v1`). Failures back off per
 * D10.6; a throttle ends the mailbox `throttled` until the pause elapses. Logs: mailbox and
 * connection public ids and codes only.
 */
export class FeedRunner {
  readonly repository: MailboxCopyRepository;

  constructor(private readonly deps: FeedDeps) {
    this.repository = new MailboxCopyRepository(deps.prisma);
  }

  /** One tick: claims and syncs due mailboxes; true when the claim was full (more work). */
  async tick(): Promise<boolean> {
    const claimed = await this.claim();
    if (claimed.length === 0) return false;
    const contexts = new Map<bigint, Promise<ConnectionContext | null>>();
    const states = new Map<bigint, Promise<OrgApiModeState | null>>();
    const byConnection = new Map<bigint, FeedMailbox[]>();
    for (const mailbox of claimed) {
      const list = byConnection.get(mailbox.apiConnectionId) ?? [];
      list.push(mailbox);
      byConnection.set(mailbox.apiConnectionId, list);
    }
    const perConnection = this.deps.config.concurrencyPerConnection;
    await mapLimit([...byConnection.values()], this.deps.config.concurrency, (group) =>
      mapLimit(group, perConnection, async (mailbox) => {
        let ctx = contexts.get(mailbox.apiConnectionId);
        if (!ctx) {
          ctx = loadConnectionContext(this.deps.prisma, mailbox.apiConnectionId);
          contexts.set(mailbox.apiConnectionId, ctx);
        }
        let state = states.get(mailbox.organizationId);
        if (!state) {
          state = loadOrgApiModeState(this.deps.prisma, mailbox.organizationId);
          states.set(mailbox.organizationId, state);
        }
        await this.syncMailbox(mailbox, await ctx, await state).catch((error: unknown) => {
          this.deps.logger.warn(
            { mailboxId: mailbox.publicId, ...errorFields(error) },
            'mailbox feed sync bookkeeping failed; the lease expires and the mailbox is retried',
          );
        });
      }),
    );
    return claimed.length >= Math.min(this.deps.config.batch, this.deps.config.concurrency);
  }

  /**
   * D10.2 claim: due mailboxes (`sync_requested_at` set or `next_sync_at ≤ now`, lease expired) in
   * a feed state, oldest request first, capped per connection; the lease and the consumed
   * `sync_requested_at` are written in the same transaction.
   */
  async claim(): Promise<FeedMailbox[]> {
    const now = this.deps.now();
    const { batch, concurrency, concurrencyPerConnection } = this.deps.config;
    const limit = Math.max(1, Math.min(batch, concurrency));
    const orgFilter = this.deps.organizationIds
      ? Prisma.sql`AND organization_id IN (${Prisma.join(this.deps.organizationIds)})`
      : Prisma.empty;
    return this.deps.prisma.$transaction(async (tx) => {
      const rows = await tx.$queryRaw<
        Array<{ id: bigint | number; api_connection_id: bigint | number }>
      >`
        SELECT id, api_connection_id FROM api_mailboxes
        WHERE feed_status IN ('pending', 'active', 'error', 'throttled')
          AND (sync_requested_at IS NOT NULL OR next_sync_at <= ${now})
          AND (lease_until IS NULL OR lease_until < ${now})
          ${orgFilter}
        ORDER BY (sync_requested_at IS NULL), COALESCE(sync_requested_at, next_sync_at), id
        LIMIT ${limit * 4}
        FOR UPDATE SKIP LOCKED`;
      const perConnection = new Map<bigint, number>();
      const chosen: bigint[] = [];
      for (const row of rows) {
        const connection = big(row.api_connection_id);
        const used = perConnection.get(connection) ?? 0;
        if (used >= concurrencyPerConnection) continue;
        perConnection.set(connection, used + 1);
        chosen.push(big(row.id));
        if (chosen.length >= limit) break;
      }
      if (chosen.length === 0) return [];
      await tx.$executeRaw`
        UPDATE api_mailboxes
        SET lease_until = ${new Date(now.getTime() + FEED_LEASE_MS)}, sync_requested_at = NULL,
            updated_at = ${now}
        WHERE id IN (${Prisma.join(chosen)})`;
      return tx.apiMailbox.findMany({
        where: { id: { in: chosen } },
        select: MAILBOX_SELECT,
        orderBy: { id: 'asc' },
      });
    }, TX_OPTIONS);
  }

  /** One mailbox: the re-checks of D10.2, then the provider sync and its bookkeeping. */
  async syncMailbox(
    mailbox: FeedMailbox,
    ctx: ConnectionContext | null,
    state: OrgApiModeState | null,
  ): Promise<SyncResult> {
    const now = this.deps.now();
    const provider = ctx?.provider ?? 'unknown';
    const done = (result: SyncResult) => {
      this.deps.metrics?.feedSyncs.inc({ provider, result });
      return result;
    };
    if (!ctx || ctx.organizationId !== mailbox.organizationId || !state) {
      await this.turnOff(mailbox, null, 'connection_missing');
      return done('off');
    }
    if (!grantActive(ctx)) {
      await applyGrantRevocation(this.deps.prisma, ctx, now);
      this.deps.logger.info(
        { apiConnectionId: ctx.publicId, grantStatus: ctx.grant?.status ?? 'missing' },
        'mailbox access not active; feeds of the connection stopped',
      );
      return done('revoked');
    }
    if (!connectionUsable(ctx)) {
      await this.defer(mailbox, now, this.pollMs(mailbox), 'connection_inactive');
      return done('deferred');
    }
    const domain = state.domains.find((d) => d.id === mailbox.domainId);
    if (
      !ctx.feedsEnabled ||
      mailbox.status !== 'active' ||
      mailbox.providerUserId === null ||
      !domain ||
      !isApiSide(domain.effectiveMode)
    ) {
      const clients = this.deps.runtime.clientsFor(ctx);
      await this.turnOff(
        mailbox,
        clients.graph,
        !ctx.feedsEnabled ? 'feeds_disabled' : 'mailbox_out_of_scope',
      );
      return done('off');
    }
    const family = familyOf(ctx);
    const pausedMs = Math.max(
      ctx.throttledUntil ? ctx.throttledUntil.getTime() - now.getTime() : 0,
      await this.deps.throttle.remainingMs(ctx.publicId, family),
    );
    if (pausedMs > 0) {
      await this.markThrottled(mailbox, now, pausedMs);
      return done('throttled');
    }
    const run: SyncRun = {
      mailbox,
      ctx,
      state,
      clients: this.deps.runtime.clientsFor(ctx),
      signal: AbortSignal.timeout(FEED_LEASE_MS - 10_000),
      counters: {},
      more: false,
    };
    let result: SyncResult;
    try {
      result = await this.runSync(run);
    } catch (error) {
      result = await this.handleFailure(run, error);
    } finally {
      run.counters.provider_requests = run.clients.tally.requests;
      run.counters.provider_errors = run.clients.tally.errors;
      await this.deps.counters.add(ctx.id, run.counters);
    }
    return done(result);
  }

  private async runSync(run: SyncRun): Promise<SyncResult> {
    let result: SyncResult;
    try {
      result =
        run.ctx.provider === 'microsoft_365'
          ? await this.graphSync(run)
          : await this.gmailSync(run);
    } catch (error) {
      if (classifyFailure(error).kind !== 'cursor_expired') throw error;
      // D10.3/D10.5: the stored cursor is gone; re-initialize at "now" (no backfill), record a gap.
      await this.resetCursor(run);
      result =
        run.ctx.provider === 'microsoft_365'
          ? await this.graphInit(run)
          : await this.gmailInit(run);
      result = 'reset';
    }
    if (run.ctx.provider === 'microsoft_365') await this.ensureSubscription(run);
    await this.markSynced(run);
    return result;
  }

  // ---------------------------------------------------------------- Graph (D10.3, D10.4)

  private graph(run: SyncRun): GraphMailClient {
    if (!run.clients.graph) throw new MailboxApiError('grant_missing', { retryable: false });
    return run.clients.graph;
  }

  /** Pages the delta to its delta link, discarding the items (no backfill, N6). */
  private async graphInit(run: SyncRun): Promise<SyncResult> {
    const graph = this.graph(run);
    let link: string | undefined;
    for (let page = 0; page < MAX_INIT_PAGES; page++) {
      const answer = await graph.inboxDelta(run.mailbox.providerUserId!, link, run.signal);
      if (answer.deltaLink) {
        await this.storeCursor(run, answer.deltaLink, true);
        return 'initialized';
      }
      link = answer.nextLink ?? undefined;
    }
    throw new MailboxApiError('unexpected_response', { retryable: true });
  }

  private async graphSync(run: SyncRun): Promise<SyncResult> {
    if (!run.mailbox.feedCursor) return this.graphInit(run);
    const graph = this.graph(run);
    let link = run.mailbox.feedCursor;
    for (let page = 0; ; page++) {
      if (page >= (this.deps.maxPagesPerSync ?? MAX_PAGES_PER_SYNC)) {
        run.more = true;
        break;
      }
      const answer = await graph.inboxDelta(run.mailbox.providerUserId!, link, run.signal);
      for (const item of answer.messages) {
        if (item.isDraft) continue;
        if (
          run.mailbox.feedStartedAt &&
          item.receivedDateTime &&
          item.receivedDateTime.getTime() < run.mailbox.feedStartedAt.getTime()
        ) {
          continue;
        }
        await this.ingest(run, {
          providerMessageId: item.id,
          internetMessageId: item.internetMessageId,
          deliveredAt: item.receivedDateTime,
          sizeEstimate: null,
          fetch: (maxBytes, signal) =>
            graph.messageMime(run.mailbox.providerUserId!, item.id, maxBytes, signal),
        });
      }
      link = (answer.deltaLink ?? answer.nextLink)!;
      await this.storeCursor(run, link, false);
      if (answer.deltaLink) break;
    }
    return 'ok';
  }

  /**
   * D10.4: with `feed_mode = notify`, a configured notification URL and Microsoft 365, the mailbox
   * keeps a subscription (created after initialization with a new client-state version; renewed
   * `API_MODE_SUBSCRIPTION_RENEW_BEFORE_MINUTES` before expiry; re-created when Graph lost it).
   * Otherwise an existing subscription is deleted (best effort). Throttling propagates; other
   * subscription failures leave the feed polling (`last_error_code = subscription_failed`).
   */
  private async ensureSubscription(run: SyncRun): Promise<void> {
    const { mailbox, ctx } = run;
    const graph = this.graph(run);
    const cfg = this.deps.config;
    const wanted =
      ctx.feedMode === 'notify' && cfg.notificationUrl !== null && cfg.notificationSecret !== null;
    if (!wanted) {
      if (mailbox.subscriptionId) await this.dropSubscription(mailbox, graph, run.signal);
      return;
    }
    const now = this.deps.now();
    const renewAt = mailbox.subscriptionExpiresAt
      ? mailbox.subscriptionExpiresAt.getTime() - cfg.renewBeforeMinutes * 60_000
      : 0;
    const expiry = new Date(now.getTime() + cfg.subscriptionMinutes * 60_000);
    try {
      if (mailbox.subscriptionId && renewAt > now.getTime()) return;
      if (mailbox.subscriptionId) {
        try {
          const renewed = await graph.renewSubscription(mailbox.subscriptionId, expiry, run.signal);
          await this.deps.prisma.apiMailbox.update({
            where: { id: mailbox.id },
            data: { subscriptionExpiresAt: renewed.expirationDateTime },
          });
          mailbox.subscriptionExpiresAt = renewed.expirationDateTime;
          return;
        } catch (error) {
          if (toMailboxApiError(error).code !== 'not_found') throw error;
          mailbox.subscriptionId = null;
        }
      }
      const version = mailbox.clientStateVersion + 1;
      const clientState = deriveClientState(cfg.notificationSecret!, mailbox.publicId, version);
      const created = await graph.createSubscription(
        {
          userId: mailbox.providerUserId!,
          notificationUrl: cfg.notificationUrl!,
          lifecycleNotificationUrl: `${cfg.notificationUrl!.replace(/\/+$/, '')}/lifecycle`,
          expirationDateTime: expiry,
          clientState,
        },
        run.signal,
      );
      await this.deps.prisma.apiMailbox.update({
        where: { id: mailbox.id },
        data: {
          subscriptionId: created.id,
          subscriptionExpiresAt: created.expirationDateTime,
          clientStateHash: clientStateHash(clientState),
          clientStateVersion: version,
        },
      });
      mailbox.subscriptionId = created.id;
      mailbox.subscriptionExpiresAt = created.expirationDateTime;
      mailbox.clientStateVersion = version;
    } catch (error) {
      if (classifyFailure(error).kind === 'throttled') throw error;
      this.deps.logger.warn(
        { mailboxId: mailbox.publicId, apiConnectionId: ctx.publicId, ...errorFields(error) },
        'graph subscription not created or renewed; the feed keeps polling',
      );
      await this.deps.prisma.apiMailbox.update({
        where: { id: mailbox.id },
        data: { lastErrorCode: 'subscription_failed' },
      });
    }
  }

  /** Deletes a subscription at Graph (best effort) and clears it. */
  private async dropSubscription(
    mailbox: FeedMailbox,
    graph: GraphMailClient | null,
    signal: AbortSignal,
  ): Promise<void> {
    if (mailbox.subscriptionId && graph) {
      await graph.deleteSubscription(mailbox.subscriptionId, signal).catch((error: unknown) => {
        this.deps.logger.info(
          { mailboxId: mailbox.publicId, ...errorFields(error) },
          'graph subscription delete failed (best effort; it expires at the provider)',
        );
      });
    }
    await this.deps.prisma.apiMailbox.update({
      where: { id: mailbox.id },
      data: { subscriptionId: null, subscriptionExpiresAt: null, clientStateHash: null },
    });
    mailbox.subscriptionId = null;
    mailbox.subscriptionExpiresAt = null;
  }

  // ---------------------------------------------------------------- Gmail (D10.5)

  private gmail(run: SyncRun): GmailClient {
    if (!run.clients.gmail) throw new MailboxApiError('grant_missing', { retryable: false });
    return run.clients.gmail;
  }

  /** The profile's history id is the cursor of a new feed (no backfill). */
  private async gmailInit(run: SyncRun): Promise<SyncResult> {
    const profile = await this.gmail(run).profile(run.mailbox.primaryAddress, run.signal);
    await this.storeCursor(run, profile.historyId, true);
    return 'initialized';
  }

  private async gmailSync(run: SyncRun): Promise<SyncResult> {
    if (!run.mailbox.feedCursor) return this.gmailInit(run);
    const gmail = this.gmail(run);
    const user = run.mailbox.primaryAddress;
    const start = run.mailbox.feedCursor;
    const maxPages = this.deps.maxPagesPerSync ?? MAX_PAGES_PER_SYNC;
    let pageToken: string | undefined;
    let latest = start;
    let stored = start;
    for (let page = 0; ; page++) {
      if (page >= maxPages) {
        // The processed pages' highest record id is already stored: the next run resumes after it
        // (a fresh start id; page tokens are bound to the original one).
        run.more = true;
        return 'ok';
      }
      const answer = await gmail.history(user, start, pageToken, run.signal);
      for (const added of answer.added) {
        if (!added.inInbox) continue;
        const ingestKey = this.ingestKeyOf(run, added.id);
        if (await this.repository.findCommitted(run.mailbox.organizationId, ingestKey)) {
          this.deps.metrics?.copy('gmail', 'already_ingested');
          continue;
        }
        const meta = await gmail.messageMetadata(user, added.id, run.signal);
        if (!meta.labelIds.includes('INBOX')) continue;
        if (
          run.mailbox.feedStartedAt &&
          meta.internalDate &&
          meta.internalDate.getTime() < run.mailbox.feedStartedAt.getTime()
        ) {
          continue;
        }
        await this.ingest(run, {
          providerMessageId: added.id,
          internetMessageId: meta.messageId,
          deliveredAt: meta.internalDate,
          sizeEstimate: meta.sizeEstimate,
          fetch: (maxBytes, signal) => gmail.messageRaw(user, added.id, maxBytes, signal),
        });
      }
      latest = answer.historyId;
      if (!answer.nextPageToken) break;
      pageToken = answer.nextPageToken;
      // Gmail pages share the start id, so the run keeps paging with it; the stored cursor moves to
      // the highest record id this page processed (records are after the start id, so it only
      // grows). A crash or the page cap resumes after it and replays at most one page.
      if (answer.lastRecordId !== null && BigInt(answer.lastRecordId) > BigInt(stored)) {
        stored = answer.lastRecordId;
        await this.storeCursor(run, stored, false);
      }
    }
    // After the last page the cursor is the mailbox's current history id.
    await this.storeCursor(run, latest, false);
    return 'ok';
  }

  // ---------------------------------------------------------------- one item (D10.3 a–c)

  private ingestKeyOf(run: SyncRun, providerMessageId: string): string {
    return ingestKeyForCopy({
      connectionPublicId: run.ctx.publicId,
      mailboxPublicId: run.mailbox.publicId,
      providerMessageId,
    });
  }

  private async ingest(
    run: SyncRun,
    item: {
      providerMessageId: string;
      internetMessageId: string | null;
      deliveredAt: Date | null;
      sizeEstimate: number | null;
      fetch: (maxBytes: number, signal: AbortSignal) => Promise<MailboxContentStream>;
    },
  ): Promise<void> {
    const { mailbox, ctx } = run;
    const source = ctx.provider === 'microsoft_365' ? ('graph' as const) : ('gmail' as const);
    const basis = source === 'graph' ? ('graph_received' as const) : ('gmail_internal' as const);
    const organizationId = mailbox.organizationId;
    const ingestKey = this.ingestKeyOf(run, item.providerMessageId);
    if (await this.repository.findCommitted(organizationId, ingestKey)) {
      this.deps.metrics?.copy(source, 'already_ingested');
      return;
    }
    const hash = copyMessageIdHash(organizationId, item.internetMessageId);
    let claimId: bigint | null = null;
    if (hash !== null) {
      const claim = await claimForFeed(this.deps.prisma, {
        organizationId,
        mailboxId: mailbox.id,
        hash,
        source,
        providerMessageId: item.providerMessageId,
        now: this.deps.now(),
      });
      if (claim.kind === 'duplicate') {
        run.counters.duplicates = (run.counters.duplicates ?? 0) + 1;
        this.deps.metrics?.copy(source, 'duplicate');
        return;
      }
      if (claim.kind === 'already') {
        this.deps.metrics?.copy(source, 'already_ingested');
        return;
      }
      claimId = claim.claimId;
    }
    const max = this.deps.config.maxMessageBytes;
    const receivedAt = this.deps.now();
    const tooLarge = async () => {
      await this.repository.commitTooLarge({
        organizationId,
        apiConnectionId: ctx.id,
        mailbox: { id: mailbox.id },
        source,
        providerMessageId: item.providerMessageId,
        ingestKey,
        receivedAt,
        providerDeliveredAt: item.deliveredAt,
        deliveredBasis: basis,
        messageIdHash: hash,
        dedupeClaimId: claimId,
      });
      run.counters.too_large = (run.counters.too_large ?? 0) + 1;
      this.deps.metrics?.copy(source, 'too_large');
    };
    if (item.sizeEstimate !== null && item.sizeEstimate > max) return tooLarge();
    const ref = {
      connectionPublicId: ctx.publicId,
      mailboxPublicId: mailbox.publicId,
      providerMessageId: item.providerMessageId,
      organizationId,
    };
    const key = emlObjectKeyForCopy(ref, receivedAt);
    let stored;
    try {
      const content = await item.fetch(max, run.signal);
      if (content.contentLength !== undefined && content.contentLength > max) {
        return tooLarge();
      }
      stored = await this.deps.sink.put(key, content.body, {
        maxBytes: max,
        headerMaxBytes: this.deps.config.headerMaxBytes,
        signal: run.signal,
      });
    } catch (error) {
      if (toMailboxApiError(error).code === 'response_too_large') return tooLarge();
      throw error;
    }
    const headers = extractCopyHeaders(stored.head, { maxBytes: this.deps.config.headerMaxBytes });
    const direction = classifyRecipientDirection(
      headers.from,
      mailbox.primaryAddress,
      run.state.domains.map((d) => d.name),
    );
    const result = await this.repository.commit({
      organizationId,
      apiConnection: { id: ctx.id, publicId: ctx.publicId, provider: ctx.provider },
      mailbox: {
        id: mailbox.id,
        publicId: mailbox.publicId,
        primaryAddress: mailbox.primaryAddress,
        domainId: mailbox.domainId,
      },
      source,
      providerMessageId: item.providerMessageId,
      ingestKey,
      receivedAt,
      providerDeliveredAt: item.deliveredAt,
      deliveredBasis: basis,
      direction,
      internetMessageId: headers.messageId ?? item.internetMessageId,
      headerFrom: headers.from,
      subject: headers.subject,
      envelopeFrom: headers.from ?? '',
      sizeBytes: stored.sizeBytes,
      emlObjectKey: key,
      emlSha256: stored.sha256,
      messageIdHash: hash,
      dedupeClaimId: claimId,
    });
    if (result.status === 'duplicate') {
      this.deps.metrics?.copy(source, 'already_ingested');
      return;
    }
    run.counters.feed_copies = (run.counters.feed_copies ?? 0) + 1;
    run.counters.fetch_bytes = (run.counters.fetch_bytes ?? 0) + stored.sizeBytes;
    this.deps.metrics?.copy(source, 'ingested');
    this.deps.metrics?.fetchBytes.inc({ provider: ctx.provider }, stored.sizeBytes);
  }

  // ---------------------------------------------------------------- bookkeeping

  private pollMs(mailbox: Pick<FeedMailbox, 'subscriptionId'>): number {
    return pollIntervalMs(mailbox.subscriptionId !== null, {
      feedPollSeconds: this.deps.config.feedPollSeconds,
      safetyPollSeconds: this.deps.config.safetyPollSeconds,
    });
  }

  /** Stores the next link / history id after a page (a crash replays at most one page). */
  private async storeCursor(run: SyncRun, cursor: string, started: boolean): Promise<void> {
    const now = this.deps.now();
    await this.deps.prisma.apiMailbox.update({
      where: { id: run.mailbox.id },
      data: {
        feedCursor: cursor,
        ...(started ? { feedStartedAt: now, feedStatus: 'active' as const } : {}),
      },
    });
    run.mailbox.feedCursor = cursor;
    if (started) run.mailbox.feedStartedAt = now;
  }

  private async resetCursor(run: SyncRun): Promise<void> {
    const now = this.deps.now();
    await this.deps.prisma.apiMailbox.update({
      where: { id: run.mailbox.id },
      data: { feedCursor: null, lastGapAt: now },
    });
    run.mailbox.feedCursor = null;
    run.counters.cursor_resets = (run.counters.cursor_resets ?? 0) + 1;
    this.deps.metrics?.cursorResets.inc({ provider: run.ctx.provider });
    this.deps.logger.warn(
      { mailboxId: run.mailbox.publicId, apiConnectionId: run.ctx.publicId },
      'mailbox feed cursor expired; re-initialized without backfill (coverage gap recorded)',
    );
  }

  private async markSynced(run: SyncRun): Promise<void> {
    const now = this.deps.now();
    await this.deps.prisma.$executeRaw`
      UPDATE api_mailboxes
      SET feed_status = 'active', consecutive_failures = 0, last_sync_at = ${now},
          last_error_code = IF(last_error_code = 'subscription_failed', last_error_code, NULL),
          next_sync_at = ${new Date(now.getTime() + this.pollMs(run.mailbox))},
          sync_requested_at = IF(${run.more}, COALESCE(sync_requested_at, ${now}), sync_requested_at),
          lease_until = NULL, updated_at = ${now}
      WHERE id = ${run.mailbox.id} AND organization_id = ${run.mailbox.organizationId}`;
  }

  private async handleFailure(run: SyncRun, error: unknown): Promise<SyncResult> {
    const now = this.deps.now();
    const failure = classifyFailure(error);
    if (failure.kind === 'throttled') {
      await this.markThrottled(run.mailbox, now, failure.retryAfterMs);
      return 'throttled';
    }
    if (failure.kind === 'budget') {
      await this.defer(run.mailbox, now, BUDGET_RETRY_MS, null);
      return 'deferred';
    }
    const code = failure.kind === 'failure' ? failure.code : 'cursor_expired';
    const failures = run.mailbox.consecutiveFailures + 1;
    const status = statusAfterFailure(failures, run.mailbox.feedCursor !== null);
    await this.deps.prisma.$executeRaw`
      UPDATE api_mailboxes
      SET feed_status = ${status}, consecutive_failures = ${Math.min(failures, 65_535)},
          last_error_code = ${code.slice(0, 64)},
          next_sync_at = ${new Date(now.getTime() + backoffMs(failures))},
          lease_until = NULL, updated_at = ${now}
      WHERE id = ${run.mailbox.id} AND organization_id = ${run.mailbox.organizationId}`;
    this.deps.logger.warn(
      {
        mailboxId: run.mailbox.publicId,
        apiConnectionId: run.ctx.publicId,
        code,
        failures,
        ...errorFields(error),
      },
      'mailbox feed sync failed; backing off',
    );
    return 'error';
  }

  /** D10.6: the mailbox waits for the connection family's pause (`next_sync_at = until`). */
  private async markThrottled(mailbox: FeedMailbox, now: Date, waitMs: number): Promise<void> {
    await this.deps.prisma.$executeRaw`
      UPDATE api_mailboxes
      SET feed_status = 'throttled', next_sync_at = ${new Date(now.getTime() + waitMs)},
          last_error_code = 'throttled', lease_until = NULL, updated_at = ${now}
      WHERE id = ${mailbox.id} AND organization_id = ${mailbox.organizationId}`;
  }

  private async defer(
    mailbox: FeedMailbox,
    now: Date,
    waitMs: number,
    code: string | null,
  ): Promise<void> {
    await this.deps.prisma.$executeRaw`
      UPDATE api_mailboxes
      SET next_sync_at = ${new Date(now.getTime() + waitMs)},
          last_error_code = COALESCE(${code}, last_error_code), lease_until = NULL,
          updated_at = ${now}
      WHERE id = ${mailbox.id} AND organization_id = ${mailbox.organizationId}`;
  }

  /** Feeds off for this mailbox (disabled, out of scope): subscription deleted, cursor cleared. */
  private async turnOff(
    mailbox: FeedMailbox,
    graph: GraphMailClient | null,
    code: string,
  ): Promise<void> {
    if (mailbox.subscriptionId) {
      await this.dropSubscription(mailbox, graph, AbortSignal.timeout(30_000));
    }
    const now = this.deps.now();
    await this.deps.prisma.$executeRaw`
      UPDATE api_mailboxes
      SET feed_status = 'off', feed_cursor = NULL, feed_started_at = NULL, next_sync_at = NULL,
          sync_requested_at = NULL, consecutive_failures = 0, last_error_code = ${code},
          lease_until = NULL, updated_at = ${now}
      WHERE id = ${mailbox.id} AND organization_id = ${mailbox.organizationId}`;
  }
}
