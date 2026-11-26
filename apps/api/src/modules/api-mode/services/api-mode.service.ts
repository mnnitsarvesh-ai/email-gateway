import { Inject, Injectable } from '@nestjs/common';
import { coveragePercent, type LagBucket, lagPercentileSeconds } from '@email-gateway/mailbox-api';
import { z } from 'zod';
import { API_CONFIG } from '../../../api-config.token';
import { AuditService } from '../../../audit/audit.service';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { CursorCodec } from '../../../http/cursor/cursor-codec';
import {
  parseIdempotencyKey,
  principalKey,
  requestFingerprint,
} from '../../../http/idempotency/idempotency-key';
import {
  type IdempotentResult,
  IdempotencyService,
} from '../../../http/idempotency/idempotency.service';
import { decideKeysetPage } from '../../../http/listing/scan-budget';
import { rangeWindow, resolveRange } from '../../../http/listing/range';
import { ApiModeStatusService } from '../../../tenancy/api-mode-status.service';
import { maskAddress } from '../../messages/domain/sensitive-masking';
import {
  decimalKey,
  decodeListCursor,
  encodeListCursor,
  listBinding,
  timeIdKeyOf,
  timeIdKeys,
} from '../../messages/domain/v1-list';
import {
  API_MODE_AUDIT,
  API_MODE_CURSOR_RESOURCES,
  API_MODE_OPERATIONS,
  API_MODE_RESOURCES,
  API_MODE_TX_TIMEOUT_MS,
  type ApiModeConfig,
  CONNECTION_COUNTER_DAYS,
  DETECTION_REASON_CODES,
  DETECTIONS_DEFAULT_DAYS,
  DETECTIONS_MAX_DAYS,
  MAILBOX_RECENT_COPIES,
} from '../api-mode.constants';
import {
  connectionConflict,
  connectionNotFound,
  detectionNotFound,
  mailboxAccessRequired,
  mailboxNotFound,
  notificationsUnavailable,
} from '../api-mode.errors';
import { computeApiModeWizard, type ApiModeWizardInput } from '../domain/wizard';
import {
  type ApiModeConnectionDetailView,
  type ApiModeConnectionListView,
  type ApiModeConnectionView,
  type ApiModeOverviewView,
  type DetectionDetailView,
  type DetectionListQuery,
  type DetectionPage,
  type DetectionView,
  type InventorySyncView,
  type MailboxDetailView,
  type MailboxListQuery,
  type MailboxPage,
  type MailboxResyncView,
  type MailboxView,
  UpdateSettingsBodySchema,
} from '../dto/api-mode.schemas';
import {
  type ConnectionFacts,
  type CopyRow,
  type CounterRow,
  ApiModeRepository,
  type MailboxRow,
} from '../repositories/api-mode.repository';
import { parseBody, parsePublicId } from './protection-mode.service';

const HOUR_MS = 3_600_000;
const DAY_MS = 86_400_000;

const iso = (d: Date | null): string | null => (d === null ? null : d.toISOString());
const utcDay = (d: Date): Date => new Date(Math.floor(d.getTime() / DAY_MS) * DAY_MS);

const principalUserId = (p: Principal): bigint | null => (p.kind === 'user' ? p.userId : null);

/** The stored `api-mode-health/1` checks (lenient: unknown codes are kept, bad rows dropped). */
const healthDocument = z.object({
  checks: z.array(
    z.object({
      code: z.string().max(64),
      status: z.enum(['pass', 'warn', 'fail']),
      evidence: z.string().max(512).optional(),
    }),
  ),
});

function healthChecksOf(
  value: unknown,
): Array<{ code: string; status: 'pass' | 'warn' | 'fail'; evidence: string | null }> {
  const parsed = healthDocument.safeParse(value);
  if (!parsed.success) return [];
  return parsed.data.checks.map((c) => ({
    code: c.code,
    status: c.status,
    evidence: c.evidence ?? null,
  }));
}

/** Lag and throttling aggregated from hourly counter rows. */
interface CounterSums {
  buckets: Record<LagBucket, number>;
  lagMaxMs: number;
  throttled: number;
  copies: number;
}

function sumCounters(rows: readonly CounterRow[]): CounterSums {
  const out: CounterSums = {
    buckets: { le_60s: 0, le_300s: 0, le_900s: 0, le_3600s: 0, gt_3600s: 0 },
    lagMaxMs: 0,
    throttled: 0,
    copies: 0,
  };
  for (const r of rows) {
    out.buckets.le_60s += r.lagLe60s;
    out.buckets.le_300s += r.lagLe300s;
    out.buckets.le_900s += r.lagLe900s;
    out.buckets.le_3600s += r.lagLe3600s;
    out.buckets.gt_3600s += r.lagGt3600s;
    out.lagMaxMs = Math.max(out.lagMaxMs, r.lagMaxMs);
    out.throttled += r.throttled429 + r.throttled503;
    out.copies += r.journalCopies + r.feedCopies;
  }
  return out;
}

const p = (s: CounterSums, q: number): number | null =>
  lagPercentileSeconds(s.buckets, q, s.lagMaxMs);

/** Lag (p50/p95 of the last hour and day) and throttling of a set of counter rows. */
function windowStats(rows: readonly CounterRow[], now: Date) {
  const h1 = sumCounters(rows.filter((r) => r.hour.getTime() >= now.getTime() - HOUR_MS));
  const h24 = sumCounters(rows.filter((r) => r.hour.getTime() >= now.getTime() - DAY_MS));
  const today = sumCounters(rows.filter((r) => r.hour.getTime() >= utcDay(now).getTime()));
  return {
    lag: {
      p50Seconds1h: p(h1, 0.5),
      p95Seconds1h: p(h1, 0.95),
      p50Seconds24h: p(h24, 0.5),
      p95Seconds24h: p(h24, 0.95),
    },
    throttling: { events1h: h1.throttled, events24h: h24.throttled },
    copiesToday: today.copies,
  };
}

/** Coverage of one connection: total only with an `ok` inventory (D11.2). */
function coverageOf(
  facts: ConnectionFacts,
  counts: { covered: number; gap: number } | undefined,
): { covered: number; gap: number; total: number | null; percent: number | null } {
  const c = counts ?? { covered: 0, gap: 0 };
  const known = facts.api !== null && facts.api.inventoryStatus === 'ok';
  return {
    covered: c.covered,
    gap: c.gap,
    total: known ? (facts.api!.mailboxesTotal ?? null) : null,
    percent: known ? round1(coveragePercent(c)) : null,
  };
}

const round1 = (v: number | null): number | null => (v === null ? null : Math.round(v * 10) / 10);

/** The best provider journal source of a connection: verified and live first. */
function bestJournalSource(facts: ConnectionFacts) {
  const live = facts.journalSources.filter((s) => s.status !== 'disabled');
  return (
    live.find((s) => s.verifiedAt !== null && s.healthStatus !== 'failing') ??
    live.find((s) => s.verifiedAt !== null) ??
    live[0] ??
    null
  );
}

/**
 * API-mode reads and writes (step API-1 D10.1, D11, D12 #4-#14; ADR-0100): the overview and the
 * per-connection views (an 8.2 connection without an API-mode row shows the defaults; the row is
 * created lazily by the first write or by the mailbox-worker), the feeds settings with CAS, the
 * inventory and mailbox resync requests, and the mailbox and detection lists with signed
 * tenant-bound v1 cursors. Views never carry a feed cursor, a subscription id or a client-state
 * hash; copy subjects are withheld and senders masked (ADR-0062).
 */
@Injectable()
export class ApiModeService {
  constructor(
    @Inject(API_CONFIG) private readonly config: ApiModeConfig,
    private readonly repository: ApiModeRepository,
    private readonly status: ApiModeStatusService,
    private readonly idempotency: IdempotencyService,
    private readonly audit: AuditService,
    private readonly codec: CursorCodec,
  ) {}

  now(): Date {
    return new Date();
  }

  // ---- views ------------------------------------------------------------------------------------

  connectionView(facts: ConnectionFacts): ApiModeConnectionView {
    const a = facts.api;
    return {
      id: facts.publicId,
      apiConnectionId: a?.publicId ?? null,
      displayName: facts.displayName,
      provider: facts.provider,
      status: facts.status,
      bound: facts.activeTenantKey !== null && facts.externalTenantId !== null,
      feedsEnabled: a?.feedsEnabled ?? false,
      feedMode: a?.feedMode ?? 'poll',
      feedsEnabledAt: iso(a?.feedsEnabledAt ?? null),
      inventoryStatus: a?.inventoryStatus ?? 'never',
      inventorySyncedAt: iso(a?.inventorySyncedAt ?? null),
      inventoryRequestedAt: iso(a?.inventoryRequestedAt ?? null),
      mailboxesTotal: a?.mailboxesTotal ?? null,
      health: { status: a?.healthStatus ?? 'unknown', changedAt: iso(a?.healthChangedAt ?? null) },
      throttledUntil: iso(a?.throttledUntil ?? null),
      lastErrorCode: a?.lastErrorCode ?? null,
      grant:
        facts.grant === null
          ? null
          : {
              profile: facts.grant.profile,
              status: facts.grant.status,
              authMethod: facts.grant.authMethod,
            },
      journalSources: facts.journalSources.map((s) => ({
        id: s.publicId,
        displayName: s.displayName,
        kind: s.kind,
        status: s.status,
        health: s.healthStatus,
        verified: s.verifiedAt !== null,
      })),
      // An absent row is created at version 1 by the first write (CAS against 1 succeeds).
      rowVersion: a?.rowVersion ?? 1,
    };
  }

  /** `GET /api-mode/overview` (D12 #4). */
  async overview(scope: TenantScope): Promise<ApiModeOverviewView> {
    const now = this.now();
    const [status, connections] = await Promise.all([
      this.status.status(scope.organizationId),
      this.repository.connections(scope),
    ]);
    const apiIds = connections.flatMap((c) => (c.api === null ? [] : [c.api.id]));
    const from = new Date(Math.min(now.getTime() - DAY_MS, utcDay(now).getTime()));
    const [coverage, counters] = await Promise.all([
      this.repository.coverage(scope, apiIds),
      this.repository.counters(scope, apiIds, from),
    ]);
    const byHealth = { unknown: 0, healthy: 0, degraded: 0, failing: 0 };
    const items = connections.map((c) => {
      const health = c.api?.healthStatus ?? 'unknown';
      byHealth[health] += 1;
      const stats = windowStats(
        counters.filter((r) => c.api !== null && r.apiConnectionId === c.api.id),
        now,
      );
      return {
        id: c.publicId,
        displayName: c.displayName,
        provider: c.provider,
        health,
        failingChecks: healthChecksOf(c.api?.healthChecks ?? null)
          .filter((h) => h.status !== 'pass')
          .map((h) => h.code),
        coverage: coverageOf(c, c.api === null ? undefined : coverage.get(c.api.id)),
        feedsEnabled: c.api?.feedsEnabled ?? false,
        feedMode: c.api?.feedMode ?? ('poll' as const),
        grantStatus: c.grant?.status ?? null,
        inventoryStatus: c.api?.inventoryStatus ?? ('never' as const),
        ...stats,
        throttledUntil: iso(c.api?.throttledUntil ?? null),
      };
    });
    const covered = items.reduce((n, i) => n + i.coverage.covered, 0);
    const gap = items.reduce((n, i) => n + i.coverage.gap, 0);
    const withApi = items.filter((_, i) => connections[i]!.api !== null);
    const totalKnown = withApi.length > 0 && withApi.every((i) => i.coverage.total !== null);
    return {
      generatedAt: now.toISOString(),
      entitled: status.entitled,
      active: status.active,
      organizationMode: status.organizationMode,
      domainsByEffectiveMode: status.domainsByEffectiveMode,
      coverage: {
        covered,
        gap,
        total: totalKnown ? withApi.reduce((n, i) => n + (i.coverage.total ?? 0), 0) : null,
        percent: totalKnown ? round1(coveragePercent({ covered, gap })) : null,
      },
      connectionsByHealth: byHealth,
      ...windowStats(counters, now),
      connections: items,
    };
  }

  /** `GET /api-mode/connections` (D12 #5). */
  async connections(scope: TenantScope): Promise<ApiModeConnectionListView> {
    const rows = await this.repository.connections(scope);
    return { data: rows.map((c) => this.connectionView(c)) };
  }

  private async load(scope: TenantScope, rawId: unknown): Promise<ConnectionFacts> {
    const facts = await this.repository.connection(scope, parsePublicId(rawId, 'connectionId'));
    if (facts === null) throw connectionNotFound();
    return facts;
  }

  /** `GET /api-mode/connections/{connectionId}` (D12 #6): + wizard, checks, 7-day counters. */
  async connection(scope: TenantScope, rawId: unknown): Promise<ApiModeConnectionDetailView> {
    const facts = await this.load(scope, rawId);
    const now = this.now();
    const domains = await this.repository.apiModeDomains(scope);
    const apiIds = facts.api === null ? [] : [facts.api.id];
    const [coverage, counters, feeds] = await Promise.all([
      this.repository.coverage(scope, apiIds),
      this.repository.counters(
        scope,
        apiIds,
        new Date(utcDay(now).getTime() - (CONNECTION_COUNTER_DAYS - 1) * DAY_MS),
      ),
      facts.api === null
        ? Promise.resolve({ inScope: 0, active: 0 })
        : this.repository.feedCounts(
            scope,
            facts.api.id,
            domains.map((d) => d.id),
          ),
    ]);
    const journal = bestJournalSource(facts);
    const input: ApiModeWizardInput = {
      apiModeDomains: domains.filter((d) => d.connectionId === facts.id).length,
      connection: {
        status: facts.status,
        bound: facts.activeTenantKey !== null && facts.externalTenantId !== null,
      },
      journal:
        journal === null
          ? null
          : {
              status: journal.status,
              verified: journal.verifiedAt !== null,
              health: journal.healthStatus,
            },
      grant: facts.grant?.status ?? null,
      feeds: {
        enabled: facts.api?.feedsEnabled ?? false,
        inScopeMailboxes: feeds.inScope,
        activeMailboxes: feeds.active,
      },
      health: facts.api?.healthStatus ?? 'unknown',
    };
    const days = new Map<string, CounterRow[]>();
    for (const r of counters) {
      const day = utcDay(r.hour).toISOString().slice(0, 10);
      days.set(day, [...(days.get(day) ?? []), r]);
    }
    const sum = (rows: CounterRow[], k: keyof CounterRow): number =>
      rows.reduce((n, r) => n + Number(r[k] as number), 0);
    return {
      ...this.connectionView(facts),
      coverage: coverageOf(facts, facts.api === null ? undefined : coverage.get(facts.api.id)),
      wizard: computeApiModeWizard(input),
      healthChecks: healthChecksOf(facts.api?.healthChecks ?? null),
      counters: [...days.entries()]
        .sort(([a], [b]) => (a < b ? 1 : -1))
        .map(([day, rows]) => ({
          day,
          journalCopies: sum(rows, 'journalCopies'),
          feedCopies: sum(rows, 'feedCopies'),
          duplicates: sum(rows, 'duplicates'),
          skippedInternal: sum(rows, 'skippedInternal'),
          tooLarge: sum(rows, 'tooLarge'),
          providerRequests: sum(rows, 'providerRequests'),
          throttled429: sum(rows, 'throttled429'),
          throttled503: sum(rows, 'throttled503'),
          providerErrors: sum(rows, 'providerErrors'),
          cursorResets: sum(rows, 'cursorResets'),
          lagCount: sum(rows, 'lagCount'),
          lagP95Seconds: p(sumCounters(rows), 0.95),
        })),
    };
  }

  // ---- writes -----------------------------------------------------------------------------------

  /**
   * `PUT /api-mode/connections/{connectionId}/settings` (keyed, CAS; D10.1): feeds need the
   * active mailbox-access grant (`409 api_mode_mailbox_access_required`); `notify` needs
   * Microsoft 365 and a platform notification URL (`422 api_mode_notifications_unavailable`).
   * Enabling marks the in-scope mailboxes `pending`. Disabling only flips the switch: the
   * mailbox-worker deletes the subscriptions and stops the feeds at its next claim.
   */
  async updateSettings(
    principal: Principal,
    scope: TenantScope,
    input: { id: unknown; idempotencyKey: unknown; body: unknown },
    sourceIp: string | null,
  ): Promise<IdempotentResult<ApiModeConnectionView>> {
    const publicId = parsePublicId(input.id, 'connectionId');
    const key = parseIdempotencyKey(input.idempotencyKey);
    const body = parseBody(UpdateSettingsBodySchema, input.body);
    const operation = API_MODE_OPERATIONS.settingsUpdate;
    return this.idempotency.execute<ApiModeConnectionView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId: publicId,
        fingerprint: requestFingerprint({ operation, resourceId: publicId, body }),
      },
      async (tx) => {
        const facts = await this.repository.lockConnection(
          tx,
          scope,
          publicId,
          principalUserId(principal),
        );
        if (facts === null || facts.api === null) throw connectionNotFound();
        const api = facts.api;
        if (api.rowVersion !== body.expectedRowVersion) throw connectionConflict(api.rowVersion);
        const feedMode = body.feedMode ?? api.feedMode;
        if (feedMode === 'notify' && facts.provider !== 'microsoft_365') {
          throw notificationsUnavailable('provider');
        }
        if (feedMode === 'notify' && this.config.API_MODE_GRAPH_NOTIFICATION_URL === undefined) {
          throw notificationsUnavailable('platform');
        }
        if (body.feedsEnabled && facts.grant?.status !== 'active') throw mailboxAccessRequired();
        const changed = [
          ...(body.feedsEnabled !== api.feedsEnabled ? ['feedsEnabled'] : []),
          ...(feedMode !== api.feedMode ? ['feedMode'] : []),
        ];
        if (changed.length === 0) return { statusCode: 200, body: this.connectionView(facts) };
        const now = this.now();
        const enabling = body.feedsEnabled && !api.feedsEnabled;
        const ok = await this.repository.updateApiConnection(tx, scope, api.id, api.rowVersion, {
          feedsEnabled: body.feedsEnabled,
          feedMode,
          ...(enabling && { feedsEnabledAt: now }),
          ...(!body.feedsEnabled && { feedsEnabledAt: null }),
        });
        if (!ok) throw connectionConflict(api.rowVersion);
        let queued = 0;
        if (enabling) {
          const domains = await this.repository.apiModeDomains(scope, tx);
          queued = await this.repository.markFeedsPending(
            tx,
            scope,
            api.id,
            domains.map((d) => d.id),
            now,
          );
        }
        await this.audit.record(
          {
            organizationId: scope.organizationId,
            actor: this.audit.actorFrom(principal),
            action: API_MODE_AUDIT.settingsUpdated,
            resourceType: API_MODE_RESOURCES.connection,
            resourceId: api.publicId,
            sourceIp,
            metadata: {
              connectionId: facts.publicId,
              apiConnectionId: api.publicId,
              changedPaths: changed,
              feedsEnabled: body.feedsEnabled,
              feedMode,
              mailboxesQueued: queued,
              rowVersion: api.rowVersion + 1,
            },
          },
          tx,
        );
        const after = await this.repository.connection(scope, publicId, tx);
        return { statusCode: 200, body: this.connectionView(after ?? facts) };
      },
      { timeoutMs: API_MODE_TX_TIMEOUT_MS },
    );
  }

  /** `POST /api-mode/connections/{connectionId}/inventory-sync` (keyed; 202; D11.1). */
  async inventorySync(
    principal: Principal,
    scope: TenantScope,
    input: { id: unknown; idempotencyKey: unknown },
    sourceIp: string | null,
  ): Promise<IdempotentResult<InventorySyncView>> {
    const publicId = parsePublicId(input.id, 'connectionId');
    const key = parseIdempotencyKey(input.idempotencyKey);
    const operation = API_MODE_OPERATIONS.inventorySync;
    return this.idempotency.execute<InventorySyncView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId: publicId,
        fingerprint: requestFingerprint({ operation, resourceId: publicId, body: {} }),
      },
      async (tx) => {
        const facts = await this.repository.lockConnection(
          tx,
          scope,
          publicId,
          principalUserId(principal),
        );
        if (facts === null || facts.api === null) throw connectionNotFound();
        if (facts.grant?.status !== 'active') throw mailboxAccessRequired();
        const now = this.now();
        await this.repository.requestInventory(tx, scope, facts.api.id, now);
        await this.audit.record(
          {
            organizationId: scope.organizationId,
            actor: this.audit.actorFrom(principal),
            action: API_MODE_AUDIT.inventorySyncRequested,
            resourceType: API_MODE_RESOURCES.connection,
            resourceId: facts.api.publicId,
            sourceIp,
            metadata: { connectionId: facts.publicId, apiConnectionId: facts.api.publicId },
          },
          tx,
        );
        return {
          statusCode: 202,
          body: {
            connectionId: facts.publicId,
            inventoryRequestedAt: now.toISOString(),
            nextInventoryAt: now.toISOString(),
          },
        };
      },
      { timeoutMs: API_MODE_TX_TIMEOUT_MS },
    );
  }

  /** `POST /api-mode/mailboxes/{mailboxId}/resync` (keyed; 202; D12 #12). */
  async resync(
    principal: Principal,
    scope: TenantScope,
    input: { id: unknown; idempotencyKey: unknown },
    sourceIp: string | null,
  ): Promise<IdempotentResult<MailboxResyncView>> {
    const publicId = parsePublicId(input.id, 'mailboxId');
    const key = parseIdempotencyKey(input.idempotencyKey);
    const operation = API_MODE_OPERATIONS.mailboxResync;
    return this.idempotency.execute<MailboxResyncView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId: publicId,
        fingerprint: requestFingerprint({ operation, resourceId: publicId, body: {} }),
      },
      async (tx) => {
        const mailbox = await this.repository.lockMailbox(tx, scope, publicId);
        if (mailbox === null) throw mailboxNotFound();
        if (!mailbox.grantActive) throw mailboxAccessRequired();
        const now = this.now();
        await this.repository.requestResync(tx, scope, mailbox.id, now);
        await this.audit.record(
          {
            organizationId: scope.organizationId,
            actor: this.audit.actorFrom(principal),
            action: API_MODE_AUDIT.mailboxResyncRequested,
            resourceType: API_MODE_RESOURCES.mailbox,
            resourceId: mailbox.publicId,
            sourceIp,
            metadata: {
              mailboxId: mailbox.publicId,
              connectionId: mailbox.connectionPublicId,
              feedStatus: mailbox.feedStatus,
            },
          },
          tx,
        );
        return {
          statusCode: 202,
          body: { mailboxId: mailbox.publicId, syncRequestedAt: now.toISOString() },
        };
      },
      { timeoutMs: API_MODE_TX_TIMEOUT_MS },
    );
  }

  // ---- mailboxes and detections ---------------------------------------------------------------

  mailboxView(row: MailboxRow): MailboxView {
    return {
      id: row.publicId,
      connectionId: row.connectionPublicId,
      address: row.primaryAddress,
      domain: row.domain === null ? null : { id: row.domain.publicId, name: row.domain.name },
      status: row.status,
      coverage: row.coverageState,
      coverageChangedAt: iso(row.coverageChangedAt),
      feedStatus: row.feedStatus,
      journalLastSeenAt: iso(row.journalLastSeenAt),
      lastSyncAt: iso(row.lastSyncAt),
      lastErrorCode: row.lastErrorCode,
    };
  }

  /** A copy as the API item: subject withheld, sender masked (ADR-0062). */
  detectionView(row: CopyRow): DetectionView {
    return {
      id: row.publicId,
      mailboxId: row.mailboxPublicId,
      mailboxAddress: row.mailboxAddress,
      connectionId: row.connectionPublicId,
      source: row.source,
      seenJournal: row.seenJournal,
      seenApi: row.seenApi,
      status: row.status,
      verdict: row.verdict,
      riskScore: row.riskScore,
      verdictAuthority: row.verdictAuthority,
      receivedAt: row.receivedAt.toISOString(),
      providerDeliveredAt: iso(row.providerDeliveredAt),
      verdictAt: iso(row.verdictAt),
      lagMs: row.lagMs,
      subject: null,
      subjectMasked: row.subject !== null && row.subject !== '',
      headerFrom:
        row.headerFrom === null || row.headerFrom === '' ? null : maskAddress(row.headerFrom),
    };
  }

  /** `GET /api-mode/mailboxes` (v1 cursor list, newest first). */
  async mailboxes(
    principal: Principal,
    scope: TenantScope,
    query: MailboxListQuery,
  ): Promise<MailboxPage> {
    const binding = listBinding({
      resource: API_MODE_CURSOR_RESOURCES.mailboxes,
      principal,
      filters: query.filters,
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 1);
    const f = query.filters;
    const first = <T>(v: { values?: T[] } | undefined): T | undefined => v?.values?.[0];
    const q = first(f.q);
    const fetched = await this.repository.mailboxes(
      scope,
      {
        ...(first(f.connectionId) !== undefined && {
          connectionPublicId: String(first(f.connectionId)).toLowerCase(),
        }),
        ...(f.coverage?.values && { coverage: [...f.coverage.values] }),
        ...(f.feedStatus?.values && { feedStatus: [...f.feedStatus.values] }),
        ...(f.status?.values && { status: [...f.status.values] }),
        ...(first(f.domainId) !== undefined && {
          domainPublicId: String(first(f.domainId)).toLowerCase(),
        }),
        ...(q !== undefined && { q: q.trim().toLowerCase() }),
      },
      { take: query.limit + 1, ...(decoded && { beforeId: decimalKey(decoded.keys[0]) }) },
    );
    const decision = decideKeysetPage({ fetched, limit: query.limit, keyOf: (r) => r.id });
    return {
      data: fetched.slice(0, decision.rows).map((r) => this.mailboxView(r)),
      nextCursor:
        decision.next === null
          ? null
          : encodeListCursor(this.codec, binding, [decision.next.toString()]),
    };
  }

  /** `GET /api-mode/mailboxes/{mailboxId}`: + aliases and the last 20 copies. */
  async mailbox(scope: TenantScope, rawId: unknown): Promise<MailboxDetailView> {
    const row = await this.repository.mailbox(scope, parsePublicId(rawId, 'mailboxId'));
    if (row === null) throw mailboxNotFound();
    const copies = await this.repository.recentCopies(scope, row.id, MAILBOX_RECENT_COPIES);
    return {
      ...this.mailboxView(row),
      aliases: row.aliases,
      feedStartedAt: iso(row.feedStartedAt),
      notifications: { subscribed: row.subscribed, expiresAt: iso(row.subscriptionExpiresAt) },
      lastChangeAt: iso(row.lastChangeAt),
      lastGapAt: iso(row.lastGapAt),
      consecutiveFailures: row.consecutiveFailures,
      recentDetections: copies.map((c) => this.detectionView(c)),
    };
  }

  /** `GET /api-mode/detections` (v1 cursor list; `[from, to)` ≤ 31 days; newest first). */
  async detections(
    principal: Principal,
    scope: TenantScope,
    query: DetectionListQuery,
  ): Promise<DetectionPage> {
    const binding = listBinding({
      resource: API_MODE_CURSOR_RESOURCES.detections,
      principal,
      filters: query.filters,
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 2);
    const range = resolveRange(query, {
      defaultMs: DETECTIONS_DEFAULT_DAYS * DAY_MS,
      maxDays: DETECTIONS_MAX_DAYS,
      now: this.now(),
      cursorWindow: decoded?.window,
    });
    const before = timeIdKeyOf(decoded);
    const f = query.filters;
    const one = <T>(v: { values?: T[] } | undefined): T | undefined => v?.values?.[0];
    const fetched = await this.repository.detections(
      scope,
      {
        ...(f.verdict?.values && { verdict: [...f.verdict.values] }),
        ...(f.status?.values && { status: [...f.status.values] }),
        ...(f.source?.values && { source: [...f.source.values] }),
        ...(one(f.mailboxId) !== undefined && {
          mailboxPublicId: String(one(f.mailboxId)).toLowerCase(),
        }),
        ...(one(f.connectionId) !== undefined && {
          connectionPublicId: String(one(f.connectionId)).toLowerCase(),
        }),
        ...(one(f.minRiskScore) !== undefined && { minRiskScore: Number(one(f.minRiskScore)) }),
      },
      range,
      { take: query.limit + 1, ...(before && { before }) },
    );
    const decision = decideKeysetPage({
      fetched,
      limit: query.limit,
      keyOf: (r) => ({ at: r.receivedAt, id: r.id }),
    });
    return {
      data: fetched.slice(0, decision.rows).map((r) => this.detectionView(r)),
      nextCursor:
        decision.next === null
          ? null
          : encodeListCursor(this.codec, binding, timeIdKeys(decision.next), rangeWindow(range)),
    };
  }

  /** `GET /api-mode/detections/{detectionId}`: + up to 10 risk reason codes. */
  async detection(scope: TenantScope, rawId: unknown): Promise<DetectionDetailView> {
    const row = await this.repository.detection(scope, parsePublicId(rawId, 'detectionId'));
    if (row === null) throw detectionNotFound();
    const codes = await this.repository.reasonCodes(scope, row.messageId, row.receivedAt);
    return {
      ...this.detectionView(row),
      direction: row.direction,
      deliveredBasis: row.deliveredBasis,
      reasonCodes: codes.slice(0, DETECTION_REASON_CODES),
    };
  }
}
