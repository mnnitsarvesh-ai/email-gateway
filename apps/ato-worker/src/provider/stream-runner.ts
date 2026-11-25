import { createHash } from 'node:crypto';
import {
  normalizeProviderEvent,
  ProviderAdapterError,
  providerEventSchema,
  providerPageKey,
  sha256Hex,
  type AtoStore,
  type ProviderEvent,
  type ProviderIngestPage,
  type ProviderStream,
} from '@email-gateway/ato-detection';
import {
  Prisma,
  type AtoAccount,
  type AtoProviderIntegration,
  type AtoProviderStream,
} from '@email-gateway/database';
import {
  completedCoverage,
  ConnectionAccessError,
  decodeCursor,
  domainOf,
  identityHash,
  initialCursor,
  isReplayed,
  STREAM_ROLES,
  type AtoProviderKind,
  type IdpAdapter,
} from '@email-gateway/idp-adapters';
import type { Logger } from '@email-gateway/logger';
import { enrichOutside, runLedgered, type DetectDeps } from '../detect/context';
import { authObservation } from '../detect/login.handler';
import type { AfterCommit, DetectionPipeline } from '../detect/pipeline';
import type { IpEnrichment } from '../enrichment/enricher';
import type { AtoMetrics } from '../metrics/ato-metrics';
import type { IdpMetrics } from '../metrics/idp-metrics';
import { atoEnabled, type OrgContext } from '../reads/org-context';
import { big, LEDGERS, orgFilter, type Tx } from '../shared/db';
import { errorCode, errorFields } from '../shared/errors';
import { mapLimit } from '../shared/loops';
import { bindingSettingsOf, directoryDomainsOf, type IdpRegistry } from './idp-runtime';
import {
  deferDelayMs,
  IDP_PAGE_TX_ATTEMPTS,
  IDP_WRITE_ATTEMPTS,
  isTransientDbFailure,
  withTransientRetry,
  type FailureOrigin,
  type RetrySleep,
} from './transient';

/** Budget of one provider page fetch (never inside a database transaction). */
export const IDP_INGEST_TIMEOUT_MS = 60_000;
/** Stream backoff cap after failures (D7.1). */
export const IDP_MAX_STREAM_BACKOFF_MS = 3_600_000;
/** Lease of a claimed stream (a crashed poll is retried after it). */
export const IDP_STREAM_LEASE_MS = 5 * 60_000;
/** A stream not yet probed (no directory domains) is retried after this delay. */
export const IDP_NOT_PROBED_DELAY_MS = 30_000;
/** Consecutive failures of a stream after which the integration is probed at once (D6). */
export const IDP_PROBE_AFTER_FAILURES = 3;
/** Event ids already processed are remembered this long (longer than any overlap window). */
export const IDP_EVENT_SEEN_TTL_SECONDS = 6 * 3600;
/** Claimed streams polled in parallel by one runner pass. */
export const IDP_POLL_CONCURRENCY = 4;

/** The snapshot-sweep primary stream per provider (D8.3): its first full sweep is historical. */
export const SNAPSHOT_PRIMARY: Readonly<Record<AtoProviderKind, ProviderStream>> = {
  microsoft_entra: 'mailbox_audit',
  google_workspace: 'forwarding_changes',
};

/** Retry delay of a stream or probe of an organization whose ATO feature is (still) off. */
export const IDP_FEATURE_OFF_RETRY_MS = 60_000;
const THROTTLE_CODES = new Set(['throttled', 'quota_exhausted', 'rate_budget']);
const CONNECTION_CODES = new Set([
  'connection_not_found',
  'connection_inactive',
  'grant_missing',
  'consent_missing',
  'scope_not_granted',
  'credentials_invalid',
]);

/** The subset of ioredis the event dedupe uses. */
export interface SeenRedis {
  mget(...keys: string[]): Promise<Array<string | null>>;
  set(key: string, value: string, mode: 'EX', seconds: number): Promise<unknown>;
}

export interface IdpStreamRunnerConfig {
  claimBatch: number;
  maxPagesPerPoll: number;
  maxConsecutiveFailures: number;
  /** 8.4's `ATO_PROVIDER_POLL_INTERVAL_SECONDS`: the default when settings omit it. */
  defaultPollIntervalSeconds: number;
  historicalSignalAgeHours: number;
  concurrency?: number;
}

/** Rows of one claimed stream and its integration. */
interface Claimed {
  stream: AtoProviderStream;
  integration: AtoProviderIntegration;
}

/** What a processed page changed (counters of the stream row and its companions). */
interface PageEffect {
  emitted: number;
  maxOccurredAt: Date | null;
}

/** Companion streams of a primary for a provider (D3). */
export function companionsOf(kind: AtoProviderKind, primary: ProviderStream): ProviderStream[] {
  return (
    Object.entries(STREAM_ROLES[kind]) as [ProviderStream, { role: string; primary?: string }][]
  )
    .filter(([, d]) => d.role === 'companion' && d.primary === primary)
    .map(([s]) => s);
}

/** Whether a page's resulting cursor shows a completed snapshot sweep (sweep state, no continuation). */
export function sweepCompleted(cursor: string, version: string): boolean {
  const decoded = decodeCursor(cursor, version);
  if (!decoded.ok) return false;
  const sw = decoded.cursor.sw;
  const page = decoded.cursor.page;
  return Boolean(sw?.at) && !sw?.next && !(typeof page === 'string' && page.startsWith('u:'));
}

/**
 * The step 8.5 stream runner (`provider` role; D7, D8; ADR-0083). Claims due
 * `ato_provider_streams` rows (`enabled`, `role = 'primary'`, `status IN ('active','backfilling')`,
 * `next_poll_at <= now`, integration `active`) with `FOR UPDATE SKIP LOCKED`, ≤
 * `ATO_IDP_CLAIM_BATCH` per pass; companion rows are never polled (their events come with the
 * primary's pages). Per stream: ≤ `ATO_PROVIDER_MAX_PAGES_PER_POLL` pages, each in 8.4's page
 * transaction (`processOnce` key `providerPageKey(integrationId, stream, cursorBefore)`): identity
 * mapping, detection, then the stream row's cursor, cursor seq, watermark and counters (CAS on the
 * cursor, so an api backfill or reset in between wins). Events of identities outside the
 * integration's provider-verified linked domains are dropped (`foreign_domain`, inv. 4); events
 * already processed (overlap re-reads) are skipped through a Redis seen-set written after commit;
 * events older than `ATO_IDP_HISTORICAL_SIGNAL_AGE_HOURS`, and the first full mailbox sweep of a
 * binding, run in historical mode (PX3). Successful `idp_sign_in` auth events are aggregated per
 * (account, IP, device hash, hour) (§4.1 volume). Throttling sets `throttled_until`; failures back
 * off exponentially per stream (cap 1 h) and the integration's 8.4 counters aggregate its streams.
 */
export class IdpStreamRunner {
  constructor(
    private readonly deps: DetectDeps & {
      pipelineRef: DetectionPipeline;
      registry: IdpRegistry;
      store: AtoStore;
      metrics: AtoMetrics | null;
      idpMetrics: IdpMetrics | null;
      seen: SeenRedis;
      logger: Logger;
      config: IdpStreamRunnerConfig;
      /** Test seam: the wait between transient retries (default: a timer). */
      retrySleep?: RetrySleep;
    },
  ) {}

  /**
   * Consecutive deferrals per stream id after transient database errors (step AI-4 D14); reset
   * by a successful poll. In-process only: a restart starts again at the shortest deferral.
   */
  private readonly deferrals = new Map<string, number>();

  /** One pass; true when more streams may be due. */
  async runOnce(): Promise<boolean> {
    const claimed = await this.claim();
    // Streams of one integration touch the same accounts and identities: they are polled one
    // after the other (no self-deadlock); integrations are polled in parallel.
    const groups = new Map<string, Claimed[]>();
    for (const c of claimed) {
      const key = c.integration.id.toString();
      groups.set(key, [...(groups.get(key) ?? []), c]);
    }
    await mapLimit(
      [...groups.values()],
      this.deps.config.concurrency ?? IDP_POLL_CONCURRENCY,
      async (group) => {
        for (const c of group) {
          await this.poll(c).catch((error: unknown) => {
            this.deps.logger.warn(
              { streamId: c.stream.id.toString(), ...errorFields(error) },
              'ato idp stream poll failed',
            );
          });
        }
      },
    );
    return claimed.length === this.deps.config.claimBatch;
  }

  /** A bounded retry of one idempotent write or read of the loop (transient errors only). */
  private write<T>(fn: () => Promise<T>): Promise<T> {
    return withTransientRetry(fn, {
      attempts: IDP_WRITE_ATTEMPTS,
      ...(this.deps.retrySleep ? { sleep: this.deps.retrySleep } : {}),
      onRetry: () => this.deps.idpMetrics?.transientDbError('stream', 'retried'),
    });
  }

  private async claim(): Promise<Claimed[]> {
    const now = this.deps.now();
    const lease = new Date(now.getTime() + IDP_STREAM_LEASE_MS);
    const ids = await this.write(() => this.claimIds(now, lease));
    if (ids.length === 0) return [];
    try {
      return await this.write(() => this.loadClaimed(ids));
    } catch (error) {
      // The claim committed but its rows could not be read: hand the streams back after a short
      // deferral instead of leaving them leased for IDP_STREAM_LEASE_MS (best effort).
      if (isTransientDbFailure(error)) {
        await this.deps.prisma.atoProviderStream
          .updateMany({
            where: { id: { in: ids } },
            data: { nextPollAt: new Date(this.deps.now().getTime() + deferDelayMs(1)) },
          })
          .catch(() => undefined);
        this.deps.idpMetrics?.transientDbError('stream', 'deferred');
      }
      throw error;
    }
  }

  private claimIds(now: Date, lease: Date): Promise<bigint[]> {
    return this.deps.db.transaction(async (tx) => {
      const rows = await tx.$queryRaw<Array<{ id: bigint | number }>>`
        SELECT s.id FROM ato_provider_streams s
        JOIN ato_provider_integrations i
          ON i.id = s.integration_id AND i.organization_id = s.organization_id
        WHERE s.status IN ('active', 'backfilling') AND s.next_poll_at <= ${now}
          AND s.enabled = 1 AND s.role = 'primary' AND i.status = 'active'
          ${orgFilter('s.organization_id', this.deps.organizationIds)}
        ORDER BY s.next_poll_at, s.id
        LIMIT ${this.deps.config.claimBatch}
        FOR UPDATE OF s SKIP LOCKED`;
      if (rows.length === 0) return [];
      const claimed = rows.map((r) => big(r.id));
      await tx.atoProviderStream.updateMany({
        where: { id: { in: claimed } },
        data: { nextPollAt: lease, lastAttemptAt: now },
      });
      return claimed;
    });
  }

  private async loadClaimed(ids: bigint[]): Promise<Claimed[]> {
    const streams = await this.deps.prisma.atoProviderStream.findMany({
      where: { id: { in: ids } },
      orderBy: { id: 'asc' },
    });
    const integrations = await this.deps.prisma.atoProviderIntegration.findMany({
      where: { id: { in: [...new Set(streams.map((s) => s.integrationId))] } },
    });
    const byId = new Map(integrations.map((i) => [i.id, i]));
    const out: Claimed[] = [];
    for (const stream of streams) {
      const integration = byId.get(stream.integrationId);
      if (!integration || integration.organizationId !== stream.organizationId) continue;
      out.push({ stream, integration });
    }
    return out;
  }

  private pollIntervalMs(integration: AtoProviderIntegration): number {
    try {
      const kind = integration.provider as AtoProviderKind;
      return bindingSettingsOf(kind, integration.settings).pollIntervalSeconds * 1000;
    } catch {
      return this.deps.config.defaultPollIntervalSeconds * 1000;
    }
  }

  /**
   * One claimed stream. A transient database error anywhere in the poll (organization context,
   * page transaction after its retries, the success or failure write) defers the stream by
   * 5–60 s without touching its failure counters (step AI-4 D14); provider errors back off as
   * before (D7.1).
   */
  private async poll(c: Claimed): Promise<void> {
    const phase: { origin: FailureOrigin } = { origin: 'database' };
    try {
      await this.pollStream(c, phase);
    } catch (error) {
      if (!isTransientDbFailure(error, phase.origin)) throw error;
      await this.defer(c, error);
    }
  }

  /** Re-schedules a stream after a transient database error (counters untouched). */
  private async defer(c: Claimed, error: unknown): Promise<void> {
    const { stream } = c;
    const key = stream.id.toString();
    const k = (this.deferrals.get(key) ?? 0) + 1;
    this.deferrals.set(key, k);
    const delayMs = deferDelayMs(k);
    this.deps.idpMetrics?.transientDbError('stream', 'deferred');
    this.deps.logger.warn(
      { streamId: key, stream: stream.stream, deferMs: delayMs, ...errorFields(error) },
      'ato idp stream poll deferred after a transient database error',
    );
    await this.write(() =>
      this.deps.prisma.atoProviderStream.updateMany({
        where: { id: stream.id, organizationId: stream.organizationId },
        data: { nextPollAt: new Date(this.deps.now().getTime() + delayMs) },
      }),
    );
  }

  private async pollStream(c: Claimed, phase: { origin: FailureOrigin }): Promise<void> {
    const { stream, integration } = c;
    const kind = integration.provider as AtoProviderKind;
    const org = await this.deps.orgs.get(integration.organizationId);
    if (!atoEnabled(org)) {
      // ATO is off (or was off when the organization context was cached): retry within a minute
      // instead of after the whole lease (WP6); nothing is read while the feature is off.
      await this.deps.prisma.atoProviderStream.updateMany({
        where: { id: stream.id, organizationId: stream.organizationId },
        data: { nextPollAt: new Date(this.deps.now().getTime() + IDP_FEATURE_OFF_RETRY_MS) },
      });
      return;
    }
    const domains = new Set(directoryDomainsOf(integration.directoryDomains));
    if (domains.size === 0 || integration.healthCheckedAt === null) {
      // Not probed yet (D4: a probe runs first): no linked domain is known, so nothing could pass
      // the domain guard. Retry shortly.
      await this.deps.prisma.atoProviderStream.updateMany({
        where: { id: stream.id, organizationId: stream.organizationId },
        data: {
          nextPollAt: new Date(this.deps.now().getTime() + IDP_NOT_PROBED_DELAY_MS),
          lastErrorCode: 'not_probed',
        },
      });
      return;
    }
    const started = performance.now();
    let adapter: IdpAdapter;
    try {
      adapter = this.deps.registry.adapterFor(integration) as IdpAdapter;
    } catch (error) {
      await this.failure(c, errorCode(error, 'adapter_unavailable'), undefined);
      return;
    }
    const name = stream.stream;
    let cursor: string | null = stream.cursor;
    if (stream.status === 'backfilling' && stream.backfillFrom && cursor === null) {
      // D8.1: the backfill window starts at backfill_from; seq continues (monotonic cursors).
      cursor = initialCursor(adapter.version, stream.backfillFrom, Number(stream.cursorSeq));
    }
    let initialDone = stream.backfillCompletedAt !== null;
    let retryAfterMs: number | undefined;
    let hasMore = false;
    let pages = 0;
    let sweepDone = false;
    try {
      for (; pages < this.deps.config.maxPagesPerPoll; pages++) {
        phase.origin = 'adapter';
        const page = await this.ingest(adapter, name, cursor);
        phase.origin = 'database';
        if (page.retryAfterMs !== undefined) retryAfterMs = page.retryAfterMs;
        hasMore = page.hasMore;
        if (page.cursor === cursor) {
          // No progress (nothing settled yet, or throttled before any record): nothing to commit.
          if (page.events.length > 0) {
            this.deps.idpMetrics?.events(
              { provider: kind, stream: name, result: 'invalid' },
              page.events.length,
            );
          }
          hasMore = false;
          break;
        }
        const initialSnapshot = SNAPSHOT_PRIMARY[kind] === name && !initialDone;
        const moved = await this.withPageRetry(() =>
          this.processPage(org, c, adapter, cursor, page, domains, initialSnapshot),
        );
        if (!moved) {
          hasMore = false;
          break; // the cursor was changed by the api in between (backfill/reset): stop this poll
        }
        cursor = page.cursor;
        if (retryAfterMs !== undefined || !page.hasMore) break;
      }
      // The sweep state persists in the cursor: a completed first sweep stays visible later.
      sweepDone =
        SNAPSHOT_PRIMARY[kind] === name &&
        cursor !== null &&
        sweepCompleted(cursor, adapter.version);
      await this.success(c, adapter, { retryAfterMs, hasMore, pages, sweepDone, initialDone });
      initialDone = true;
    } catch (error) {
      // A database outage is not a provider failure: deferred by poll() (D14).
      if (isTransientDbFailure(error, phase.origin)) throw error;
      const retryAfter =
        error instanceof ProviderAdapterError || error instanceof ConnectionAccessError
          ? error.retryAfterMs
          : undefined;
      this.deps.logger.warn(
        {
          integrationId: integration.id.toString(),
          provider: kind,
          stream: name,
          ...errorFields(error),
        },
        'ato idp ingestion failed',
      );
      await this.failure(c, errorCode(error, 'provider_error'), retryAfter);
    } finally {
      this.deps.metrics?.providerPollSeconds.observe(
        { provider: kind },
        (performance.now() - started) / 1000,
      );
    }
  }

  private async ingest(
    adapter: IdpAdapter,
    stream: ProviderStream,
    cursor: string | null,
  ): Promise<ProviderIngestPage> {
    try {
      const page = await adapter.ingest(stream, cursor, AbortSignal.timeout(IDP_INGEST_TIMEOUT_MS));
      this.deps.metrics?.providerOperations.inc({
        provider: adapter.kind,
        operation: 'ingest',
        outcome: page.retryAfterMs !== undefined ? 'throttled' : 'ok',
      });
      return page;
    } catch (error) {
      this.deps.metrics?.providerOperations.inc({
        provider: adapter.kind,
        operation: 'ingest',
        outcome:
          (error instanceof ProviderAdapterError || error instanceof ConnectionAccessError) &&
          (error instanceof ConnectionAccessError
            ? error.code === 'throttled' || error.code === 'provider_unavailable'
            : error.retryable)
            ? 'retryable'
            : 'failed',
      });
      throw error;
    }
  }

  /**
   * Streams of one integration run in parallel and touch the same accounts and identities, so a
   * page transaction of another replica or role (or the adapter's mailbox upserts) can win a
   * deadlock (MySQL 1213) or a lock wait (1205); under load the pool can time out (`P2024`) or
   * the server be briefly unreachable (`P1001`, `P1017`). The page is atomic (ledger, effects and
   * cursor commit together), so it is retried on lock conflicts and transient infrastructure
   * errors, at most IDP_PAGE_TX_ATTEMPTS times with jittered back-off 200 ms × 2^(n−1) ≤ 5 s
   * (step AI-4 D14).
   */
  private withPageRetry<T>(fn: () => Promise<T>): Promise<T> {
    return withTransientRetry(fn, {
      attempts: IDP_PAGE_TX_ATTEMPTS,
      ...(this.deps.retrySleep ? { sleep: this.deps.retrySleep } : {}),
      onRetry: () => this.deps.idpMetrics?.transientDbError('stream', 'retried'),
    });
  }

  /** The Redis key remembering that an event of an integration was processed. */
  private seenKey(organizationId: bigint, integrationId: bigint, event: ProviderEvent): string {
    const digest = createHash('sha256')
      .update(`${event.stream}|${event.eventId}`, 'utf8')
      .digest('hex')
      .slice(0, 32);
    return `ato:idp:ev:${organizationId.toString()}:${integrationId.toString()}:${digest}`;
  }

  /**
   * One page in one ledger transaction. Returns false when the stream's cursor changed under the
   * poll (CAS miss: the transaction is rolled back, nothing of the page is kept).
   */
  private async processPage(
    org: OrgContext,
    c: Claimed,
    adapter: IdpAdapter,
    cursorBefore: string | null,
    page: ProviderIngestPage,
    domains: ReadonlySet<string>,
    initialSnapshot: boolean,
  ): Promise<boolean> {
    const { stream, integration } = c;
    const kind = integration.provider as AtoProviderKind;
    const primary = stream.stream;
    const group = new Set<ProviderStream>([primary, ...companionsOf(kind, primary)]);
    const settings = bindingSettingsOf(kind, integration.settings);
    const now = this.deps.now();
    const historicalBefore = now.getTime() - this.deps.config.historicalSignalAgeHours * 3_600_000;

    // Validation, stream and domain filters (inv. 4: foreign identities are dropped, counted).
    const valid: ProviderEvent[] = [];
    for (const raw of page.events) {
      const parsed = providerEventSchema.safeParse(raw);
      if (!parsed.success || parsed.data.provider !== kind || !group.has(parsed.data.stream)) {
        this.deps.idpMetrics?.events({ provider: kind, stream: primary, result: 'invalid' }, 1);
        continue;
      }
      const event = parsed.data;
      if (!settings.streams[event.stream].enabled) {
        this.deps.idpMetrics?.events(
          { provider: kind, stream: event.stream, result: 'stream_disabled' },
          1,
        );
        continue;
      }
      const address = event.identity.primaryEmail ?? event.identity.userPrincipalName ?? '';
      const domain = domainOf(address);
      // Entra guests (`…#EXT#@tenant`) carry the tenant's domain but are not its mailboxes.
      if (domain === null || !domains.has(domain) || /#ext#/i.test(address)) {
        this.deps.idpMetrics?.events(
          { provider: kind, stream: event.stream, result: 'foreign_domain' },
          1,
        );
        continue;
      }
      // A backfill re-reading history an earlier ingestion of this stream already processed
      // (review fix): skipped durably, not only within the seen-set's 6 hours.
      if (isReplayed(stream, event)) {
        this.deps.idpMetrics?.events(
          { provider: kind, stream: event.stream, result: 'replayed' },
          1,
        );
        continue;
      }
      valid.push(event);
    }
    // Overlap re-reads: skip events already processed (remembered after the commit).
    const keys = valid.map((e) => this.seenKey(integration.organizationId, integration.id, e));
    const seen = keys.length > 0 ? await this.deps.seen.mget(...keys) : [];
    const fresh: { event: ProviderEvent; key: string }[] = [];
    valid.forEach((event, i) => {
      if (seen[i] === null || seen[i] === undefined) fresh.push({ event, key: keys[i]! });
    });
    const enriched = await enrichOutside(
      this.deps,
      org.id,
      fresh.map((f) => (f.event.stream === 'sign_ins' ? (f.event.ip ?? null) : null)),
    );
    const decoded = decodeCursor(page.cursor, adapter.version);
    const seq = decoded.ok ? BigInt(decoded.cursor.seq) : stream.cursorSeq + 1n;
    const watermark = decoded.ok && decoded.cursor.wm ? new Date(decoded.cursor.wm) : null;
    const throttledUntil =
      page.retryAfterMs !== undefined ? new Date(now.getTime() + page.retryAfterMs) : null;
    let moved = true;
    const counts = new Map<ProviderStream, PageEffect>();
    const result = await runLedgered(
      this.deps,
      {
        consumer: LEDGERS.provider,
        eventId: providerPageKey(
          integration.id,
          primary,
          cursorBefore ?? `start#${stream.cursorSeq.toString()}`,
        ),
        source: 'provider',
        occurredAt: fresh[0] ? new Date(fresh[0].event.occurredAt) : now,
      },
      async (tx, after) => {
        for (const { event } of fresh) {
          const historical =
            Date.parse(event.occurredAt) < historicalBefore ||
            (initialSnapshot && event.eventId.startsWith('snap:'));
          const processed = await this.processEvent(
            tx,
            after,
            org,
            integration,
            event,
            enriched,
            historical,
          );
          if (!processed) continue;
          const effect = counts.get(event.stream) ?? { emitted: 0, maxOccurredAt: null };
          effect.emitted += 1;
          const at = new Date(event.occurredAt);
          if (!effect.maxOccurredAt || at > effect.maxOccurredAt) effect.maxOccurredAt = at;
          counts.set(event.stream, effect);
        }
        // The cursor moves with the page (same transaction as its effects), CAS on the cursor.
        const self = counts.get(primary);
        const updated = await tx.$executeRaw`
          UPDATE ato_provider_streams
          SET \`cursor\` = ${page.cursor}, cursor_seq = ${seq},
              watermark_at = COALESCE(${watermark}, watermark_at),
              pages_total = pages_total + 1,
              events_total = events_total + ${self?.emitted ?? 0},
              last_event_at = GREATEST(COALESCE(last_event_at, ${self?.maxOccurredAt ?? null}),
                                       COALESCE(${self?.maxOccurredAt ?? null}, last_event_at)),
              throttled_until = ${throttledUntil},
              row_version = row_version + 1, updated_at = ${now}
          WHERE id = ${stream.id} AND organization_id = ${stream.organizationId}
            AND \`cursor\` <=> ${stream.cursor}`;
        if (updated !== 1) {
          moved = false;
          throw new CursorMovedError();
        }
        for (const [name, effect] of counts) {
          if (name === primary) continue;
          await tx.$executeRaw`
            UPDATE ato_provider_streams
            SET events_total = events_total + ${effect.emitted},
                last_event_at = GREATEST(COALESCE(last_event_at, ${effect.maxOccurredAt}),
                                         ${effect.maxOccurredAt}),
                updated_at = ${now}
            WHERE integration_id = ${integration.id} AND organization_id = ${integration.organizationId}
              AND stream = ${name}`;
        }
        after.push(async () => {
          for (const { key } of fresh) {
            await this.deps.seen.set(key, '1', 'EX', IDP_EVENT_SEEN_TTL_SECONDS);
          }
        });
      },
    ).catch((error: unknown) => {
      if (error instanceof CursorMovedError) return 'skipped' as const;
      throw error;
    });
    if (!moved || result === 'skipped') return false;
    if (result === 'duplicate') {
      // The page key was committed before but the cursor was set back (api reset): move on.
      this.deps.logger.warn(
        { integrationId: integration.id.toString(), stream: primary },
        'ato idp page already processed; cursor advanced without effects',
      );
      const updated = await this.deps.prisma.atoProviderStream.updateMany({
        where: { id: stream.id, organizationId: stream.organizationId, cursor: stream.cursor },
        data: {
          cursor: page.cursor,
          cursorSeq: seq,
          ...(watermark ? { watermarkAt: watermark } : {}),
        },
      });
      if (updated.count !== 1) return false;
    }
    this.deps.metrics?.events.inc(
      { source: 'provider', result: result === 'duplicate' ? 'duplicate' : 'processed' },
      Math.max(1, fresh.length),
    );
    // The next page's CAS compares with this cursor.
    stream.cursor = page.cursor;
    stream.cursorSeq = seq;
    if (watermark) stream.watermarkAt = watermark;
    return true;
  }

  /** One event: identity mapping, then 8.4's pipeline (historical per PX3). */
  private async processEvent(
    tx: Tx,
    after: AfterCommit[],
    org: OrgContext,
    integration: AtoProviderIntegration,
    event: ProviderEvent,
    enriched: Map<string, IpEnrichment>,
    historical: boolean,
  ): Promise<boolean> {
    const account = await this.mapIdentity(tx, org.id, integration, event);
    if (!account || !account.address) {
      this.deps.metrics?.events.inc({ source: 'provider', result: 'unattributed' });
      return false;
    }
    if (event.mailbox) {
      // Mailbox items written by the adapter before the identity was mapped get the account now.
      await tx.$executeRaw`
        UPDATE ato_provider_mailbox_items SET account_id = ${account.id}
        WHERE integration_id = ${integration.id} AND organization_id = ${org.id}
          AND identity_external_id_hash = ${identityHash(event.provider, event.identity.externalId)}
          AND account_id IS NULL`;
    }
    const occurredAt = new Date(event.occurredAt);
    const signIn = event.stream === 'sign_ins';
    const en = signIn && event.ip ? (enriched.get(event.ip) ?? null) : null;
    const base = normalizeProviderEvent(event);
    const device = base.type === 'auth' ? base.device : null;
    const success = signIn && event.outcome === 'success';
    const hour = new Date(Math.floor(occurredAt.getTime() / 3_600_000) * 3_600_000);
    await this.deps.pipelineRef.run(
      tx,
      {
        org,
        subject: { kind: 'mailbox', address: account.address },
        historical,
        observation: ({ baseline }) => {
          const observed = normalizeProviderEvent(event, {
            knownDomains: baseline.externalDomains,
          });
          if (observed.type !== 'auth') return observed;
          return {
            ...authObservation({
              key: observed.key,
              source: 'idp_sign_in',
              channel: 'idp',
              outcome: observed.outcome,
              failureCode: observed.failureCode,
              occurredAt,
              enriched: en,
              device: observed.device,
              breachListed: null,
            }),
          };
        },
        authEvent: signIn
          ? {
              source: 'idp_sign_in',
              channel: 'idp',
              outcome:
                event.outcome === 'success'
                  ? 'success'
                  : event.outcome === 'interrupted'
                    ? 'mfa_required'
                    : 'failure',
              failureCode: event.failureCode ?? null,
              // §4.1 volume: successful IdP sign-ins are aggregated per (account, IP, device hash,
              // hour) like 8.4's SMTP successes; failures are individual rows.
              occurredAt: success ? hour : occurredAt,
              ...(success ? { lastOccurredAt: occurredAt, aggregate: true } : {}),
              ip: en?.ip ?? null,
              ipPrefix: en?.ipPrefix ?? null,
              geo: en?.geo ?? null,
              reputation: en?.reputation ?? null,
              // PX1: the adapter's structured device (hash and `<browser> · <os>` label).
              device,
              mechanism: null,
              sourceRef: `prov:${event.stream}`.slice(0, 64),
              dedupeKey: success
                ? sha256Hex(
                    `prov-success|${account.id.toString()}|${en?.ip ?? event.ip ?? '-'}|${device?.hash ?? '-'}|${hour.toISOString()}`,
                  )
                : sha256Hex(`prov|${event.provider}|${event.stream}|${event.eventId}`),
            }
          : null,
        activity: signIn
          ? () =>
              success
                ? {
                    at: occurredAt,
                    authSuccess: 1,
                    ipPrefix: en?.ipPrefix
                      ? { p: en.ipPrefix, cc: en.geo.country, asn: en.geo.asn }
                      : null,
                  }
                : { at: occurredAt, authFailure: 1 }
          : null,
        success: success ? { geo: en?.geo ?? null, trusted: en?.trustedNetwork ?? false } : null,
      },
      after,
    );
    return true;
  }

  /**
   * `ato_account_identities` (8.4 D15, extended by 8.5): the mapped identity, else the primary
   * e-mail's mailbox account; the identity records its integration and primary e-mail domain.
   */
  private async mapIdentity(
    tx: Tx,
    organizationId: bigint,
    integration: AtoProviderIntegration,
    event: ProviderEvent,
  ): Promise<AtoAccount | null> {
    const hash = sha256Hex(event.identity.externalId);
    const now = this.deps.now();
    const address = (event.identity.primaryEmail ?? event.identity.userPrincipalName ?? '')
      .trim()
      .toLowerCase();
    const domain = domainOf(address);
    const mapped = await tx.atoAccountIdentity.findUnique({
      where: {
        organizationId_provider_externalIdHash: {
          organizationId,
          provider: event.provider,
          externalIdHash: hash,
        },
      },
    });
    if (mapped) {
      if (mapped.organizationId !== organizationId) return null;
      const stale =
        mapped.integrationId !== integration.id ||
        (domain !== null && mapped.primaryEmailDomain !== domain) ||
        now.getTime() - mapped.lastSeenAt.getTime() > 60_000;
      if (stale) {
        await tx.atoAccountIdentity.update({
          where: { id: mapped.id },
          data: {
            lastSeenAt: now,
            integrationId: integration.id,
            ...(domain !== null ? { primaryEmailDomain: domain } : {}),
          },
        });
      }
      const account = await tx.atoAccount.findUnique({ where: { id: mapped.accountId } });
      return account && account.organizationId === organizationId ? account : null;
    }
    if (!address.includes('@')) return null;
    const account = await this.deps.store.ensureAccount(tx, {
      organizationId,
      subject: { kind: 'mailbox', address },
      at: now,
    });
    try {
      await tx.atoAccountIdentity.create({
        data: {
          organizationId,
          accountId: account.id,
          provider: event.provider,
          externalId: event.identity.externalId.slice(0, 128),
          externalIdHash: hash,
          userPrincipalName: event.identity.userPrincipalName?.slice(0, 320) ?? null,
          firstSeenAt: now,
          lastSeenAt: now,
          integrationId: integration.id,
          primaryEmailDomain: domain,
          directoryStatus: 'active',
          directoryStatusAt: now,
        },
      });
    } catch (error) {
      if (!(error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002')) {
        throw error;
      }
    }
    return account;
  }

  /** After a poll without exception (D7.1). */
  private async success(
    c: Claimed,
    adapter: IdpAdapter,
    r: {
      retryAfterMs?: number;
      hasMore: boolean;
      pages: number;
      sweepDone: boolean;
      initialDone: boolean;
    },
  ): Promise<void> {
    const { stream, integration } = c;
    const kind = integration.provider as AtoProviderKind;
    const name = stream.stream;
    const now = this.deps.now();
    const interval = this.pollIntervalMs(integration);
    const nextPoll =
      r.retryAfterMs !== undefined
        ? now.getTime() + Math.max(1000, r.retryAfterMs)
        : r.hasMore
          ? now.getTime() // pages left after ATO_PROVIDER_MAX_PAGES_PER_POLL: next pass
          : now.getTime() + interval;
    // Backfill ends when a poll caught up (the adapter's last window reached now − settle, D8.1);
    // a snapshot primary's initial ingestion also needs its first full sweep (its snapshot events
    // run historical until then).
    const caughtUp = r.retryAfterMs === undefined && !r.hasMore;
    const backfillComplete = stream.status !== 'backfilling' || caughtUp;
    const initialComplete =
      !r.initialDone && backfillComplete && (SNAPSHOT_PRIMARY[kind] !== name || r.sweepDone);
    await this.write(() =>
      this.deps.prisma.atoProviderStream.updateMany({
        where: { id: stream.id, organizationId: stream.organizationId },
        data: {
          nextPollAt: new Date(nextPoll),
          consecutiveFailures: 0,
          lastErrorCode: null,
          lastSuccessAt: now,
          throttledUntil:
            r.retryAfterMs !== undefined ? new Date(now.getTime() + r.retryAfterMs) : null,
          ...(stream.status === 'backfilling' && backfillComplete
            ? {
                status: 'active',
                // The backfilled range joins what it replayed; the replay window is done.
                coveredFrom: completedCoverage(stream),
                replayFrom: null,
                replayUntil: null,
              }
            : {}),
          ...(initialComplete ? { backfillCompletedAt: now } : {}),
        },
      }),
    );
    this.deferrals.delete(stream.id.toString());
    // Companions mirror their primary's watermark and success (D3).
    const companions = companionsOf(kind, name);
    if (companions.length > 0) {
      await this.write(() =>
        this.deps.prisma.atoProviderStream.updateMany({
          where: {
            integrationId: integration.id,
            organizationId: integration.organizationId,
            stream: { in: companions },
          },
          data: {
            lastSuccessAt: now,
            consecutiveFailures: 0,
            lastErrorCode: null,
            ...(stream.watermarkAt ? { watermarkAt: stream.watermarkAt } : {}),
          },
        }),
      );
    }
    await this.write(() => this.aggregate(integration, now, { success: true }));
  }

  /** Backoff after a failed poll (D7.1); throttling is not a failure. */
  private async failure(c: Claimed, code: string, retryAfterMs: number | undefined): Promise<void> {
    const { stream, integration } = c;
    const now = this.deps.now();
    if (THROTTLE_CODES.has(code)) {
      const wait = Math.max(1000, retryAfterMs ?? 60_000);
      await this.write(() =>
        this.deps.prisma.atoProviderStream.updateMany({
          where: { id: stream.id, organizationId: stream.organizationId },
          data: {
            nextPollAt: new Date(now.getTime() + wait),
            throttledUntil: new Date(now.getTime() + wait),
            lastErrorCode: code.slice(0, 64),
          },
        }),
      );
      return;
    }
    const failures = stream.consecutiveFailures + 1;
    const backoff = Math.min(
      IDP_MAX_STREAM_BACKOFF_MS,
      this.pollIntervalMs(integration) * 2 ** Math.min(failures, 12),
    );
    await this.write(() =>
      this.deps.prisma.atoProviderStream.updateMany({
        where: { id: stream.id, organizationId: stream.organizationId },
        data: {
          consecutiveFailures: failures,
          lastErrorCode: code.slice(0, 64),
          nextPollAt: new Date(now.getTime() + Math.max(backoff, retryAfterMs ?? 0)),
        },
      }),
    );
    stream.consecutiveFailures = failures;
    // D6: probe at once after 3 consecutive failures of a stream or a connection/token failure.
    if (failures >= IDP_PROBE_AFTER_FAILURES || CONNECTION_CODES.has(code)) {
      await this.write(() =>
        this.deps.prisma.atoProviderIntegration.updateMany({
          where: { id: integration.id, organizationId: integration.organizationId },
          data: { nextHealthAt: now },
        }),
      );
    }
    await this.write(() => this.aggregate(integration, now, { success: false, code }));
  }

  /** The integration's 8.4 failure counters aggregate its primary streams (D7.1). */
  private async aggregate(
    integration: AtoProviderIntegration,
    now: Date,
    outcome: { success: boolean; code?: string },
  ): Promise<void> {
    const worst = await this.deps.prisma.atoProviderStream.findFirst({
      where: {
        integrationId: integration.id,
        organizationId: integration.organizationId,
        role: 'primary',
        enabled: true,
      },
      orderBy: { consecutiveFailures: 'desc' },
      select: { consecutiveFailures: true, lastErrorCode: true },
    });
    const failures = worst?.consecutiveFailures ?? 0;
    await this.deps.prisma.atoProviderIntegration.updateMany({
      where: { id: integration.id, organizationId: integration.organizationId },
      data: {
        consecutiveFailures: failures,
        lastErrorCode: failures > 0 ? (worst?.lastErrorCode ?? outcome.code ?? null) : null,
        ...(outcome.success ? { lastSuccessAt: now } : {}),
      },
    });
    if (failures >= this.deps.config.maxConsecutiveFailures) {
      // 8.4: `error` after ATO_PROVIDER_MAX_CONSECUTIVE_FAILURES; a passing probe recovers it.
      await this.deps.prisma.atoProviderIntegration.updateMany({
        where: { id: integration.id, organizationId: integration.organizationId, status: 'active' },
        data: { status: 'error' },
      });
    }
  }
}

/** Attempts of a page transaction that lost a deadlock, a lock wait or a transient error (D14). */
export const IDP_PAGE_DEADLOCK_RETRIES = IDP_PAGE_TX_ATTEMPTS;

/** The stream's cursor changed during the poll (an api backfill or reset): roll the page back. */
class CursorMovedError extends Error {
  constructor() {
    super('cursor_moved');
    this.name = 'CursorMovedError';
  }
}
