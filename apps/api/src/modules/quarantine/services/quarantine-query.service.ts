import { Inject, Injectable } from '@nestjs/common';
import {
  allowedActionsFor,
  APPROVAL_REASONS,
  BULK_ACTIONS,
  checkSearchRange,
  checkSelfService,
  decodeSearchCursor,
  encodeSearchCursor,
  ENTRY_ACTIONS,
  type Page,
  QUARANTINE_APPROVAL_KINDS,
  QUARANTINE_APPROVAL_STATUSES,
  QUARANTINE_ENTRY_KINDS,
  QUARANTINE_ERROR_CODES,
  QUARANTINE_ORIGINS,
  QUARANTINE_PERMISSIONS,
  QUARANTINE_PRIMARY_ENGINES,
  QUARANTINE_REASONS,
  QUARANTINE_RELEASE_MODES,
  QUARANTINE_RELEASE_STATUSES,
  QUARANTINE_RISK_LEVELS,
  QUARANTINE_SEARCH_DEFAULT_PAGE_SIZE,
  QUARANTINE_STATES,
  type QuarantineApprovalView,
  type QuarantineEntryDetail,
  type QuarantineEntrySummary,
  type QuarantineSettings,
  riskLevelRank,
  searchFilterHash,
} from '@email-gateway/quarantine';
import { API_CONFIG } from '../../../api-config.token';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import type { ClientContext } from '../../auth/services/session.service';
import {
  approvalView,
  contentAvailable,
  entryDetail,
  entrySummary,
  type EntryRow,
  releaseView,
} from '../domain/entry';
import type {
  ApprovalListQuery,
  CatalogResponse,
  EntrySearchQuery,
  HistoryResponse,
  ReleaseDetail,
  SelfSearchQuery,
  SummaryQuery,
  SummaryResponse,
} from '../dto/quarantine.schemas';
import {
  type QuarantineConfig,
  QUARANTINE_AUDIT,
  QUARANTINE_RESOURCE,
} from '../quarantine.constants';
import {
  approvalNotFound,
  cursorInvalid,
  entryNotFound,
  releaseNotFound,
  searchRangeInvalid,
} from '../quarantine.errors';
import {
  type EntrySearch,
  type Keyset,
  QuarantineReadRepository,
} from '../repositories/quarantine-read.repository';
import { QuarantineWriteRepository } from '../repositories/quarantine-write.repository';
import { QuarantineContext, permissionsOf } from './quarantine-context';
import { actorOf } from './quarantine-entry-ops';
import { QuarantineMetrics } from './quarantine-metrics';
import { QuarantineWriter } from './quarantine-writer';

type Config = Pick<
  QuarantineConfig,
  | 'QUARANTINE_SEARCH_MAX_RANGE_DAYS'
  | 'QUARANTINE_SEARCH_MAX_PAGE_SIZE'
  | 'QUARANTINE_BULK_MAX_ITEMS'
  | 'QUARANTINE_BULK_MAX_ITEMS_PER_MINUTE'
  | 'QUARANTINE_PREVIEW_MAX_TEXT_CHARS'
  | 'QUARANTINE_DOWNLOAD_TOKEN_TTL_SECONDS'
  | 'QUARANTINE_DOWNLOAD_MAX_BYTES'
>;

/** The levels at or above `min` (Q9 `minRiskLevel`). */
export const levelsFrom = (min: (typeof QUARANTINE_RISK_LEVELS)[number]): string[] =>
  QUARANTINE_RISK_LEVELS.filter((l) => riskLevelRank(l) >= riskLevelRank(min));

/**
 * The quarantine reads (step 5.3 Q9, Q10, Q14, Q26): keyset search on the replica with a bounded
 * range and a filter-bound cursor, one `quarantine.searched` audit row per search (filter hash
 * and count, never the filter values); entry detail with `allowedActions` and a `view` action +
 * `quarantine.entry_viewed` audit row; history, releases, approvals, the bounded summary and the
 * catalog. Subjects are shown only to `quarantine:preview` holders and on self routes.
 */
@Injectable()
export class QuarantineQueryService {
  constructor(
    @Inject(API_CONFIG) private readonly config: Config,
    private readonly reads: QuarantineReadRepository,
    private readonly writes: QuarantineWriteRepository,
    private readonly context: QuarantineContext,
    private readonly writer: QuarantineWriter,
    private readonly metrics: QuarantineMetrics,
  ) {}

  // ------------------------------------------------------------------ search

  async search(
    principal: Principal,
    scope: TenantScope,
    query: EntrySearchQuery,
    client: ClientContext,
  ): Promise<Page<QuarantineEntrySummary>> {
    const filter: Omit<EntrySearch, 'from' | 'to' | 'after' | 'take'> = {
      ...(query.state !== undefined && { states: query.state }),
      ...(query.kind !== undefined && { kind: query.kind }),
      ...(query.direction !== undefined && { direction: query.direction }),
      ...(query.reason !== undefined && { reasons: query.reason }),
      ...(query.riskLevel !== undefined && { riskLevels: query.riskLevel }),
      ...(query.minRiskLevel !== undefined && { riskLevels: levelsFrom(query.minRiskLevel) }),
      ...(query.primaryEngine !== undefined && { primaryEngines: query.primaryEngine }),
      ...(query.policyId !== undefined && { policyId: query.policyId }),
      ...(query.ruleId !== undefined && { ruleId: query.ruleId }),
      ...(query.sender !== undefined && { sender: query.sender }),
      ...(query.headerFrom !== undefined && { headerFrom: query.headerFrom }),
      ...(query.senderDomain !== undefined && { senderDomain: query.senderDomain }),
      ...(query.recipient !== undefined && { recipient: query.recipient }),
      ...(query.hasAttachments !== undefined && { hasAttachments: query.hasAttachments }),
      ...(query.hasHardBlock !== undefined && { hasHardBlock: query.hasHardBlock }),
    };
    let messageId: bigint | undefined;
    if (query.messageId !== undefined) {
      const id = await this.reads.messageIdByPublicId(scope, query.messageId);
      // Unknown or another tenant's message: an empty page (never confirms existence).
      messageId = id ?? 0n;
    }
    return this.runSearch(principal, scope, client, {
      query,
      filter: { ...filter, ...(messageId !== undefined && { messageId }) },
      showSubject: principal.permissions.has(QUARANTINE_PERMISSIONS.preview),
      self: false,
    });
  }

  async selfSearch(
    principal: Principal,
    scope: TenantScope,
    query: SelfSearchQuery,
    client: ClientContext,
  ): Promise<Page<QuarantineEntrySummary>> {
    const caller = await this.context.selfCaller(principal, scope);
    const settings = await this.context.settings(scope);
    if (!settings.endUser.enabled) return { items: [], nextCursor: null };
    return this.runSearch(principal, scope, client, {
      query,
      filter: {
        ...(query.state !== undefined && { states: query.state }),
        ...(query.reason !== undefined && { reasons: query.reason }),
        recipient: caller.address,
      },
      showSubject: true,
      self: true,
    });
  }

  private async runSearch(
    principal: Principal,
    scope: TenantScope,
    client: ClientContext,
    s: {
      query: { from: string; to: string; cursor?: string; limit?: number } & Record<
        string,
        unknown
      >;
      filter: Omit<EntrySearch, 'from' | 'to' | 'after' | 'take'>;
      showSubject: boolean;
      self: boolean;
    },
  ): Promise<Page<QuarantineEntrySummary>> {
    const from = new Date(s.query.from);
    const to = new Date(s.query.to);
    const maxDays = this.config.QUARANTINE_SEARCH_MAX_RANGE_DAYS;
    if (!checkSearchRange(from, to, maxDays)) throw searchRangeInvalid(maxDays);
    const limit = Math.min(
      s.query.limit ?? QUARANTINE_SEARCH_DEFAULT_PAGE_SIZE,
      this.config.QUARANTINE_SEARCH_MAX_PAGE_SIZE,
    );
    const hash = searchFilterHash({ ...s.query, self: s.self });
    let after: Keyset | undefined;
    if (s.query.cursor !== undefined) {
      const cursor = decodeSearchCursor(s.query.cursor, hash);
      if (cursor === null) throw cursorInvalid();
      after = { t: new Date(cursor.t), id: BigInt(cursor.id) };
    }
    const rows = await this.reads.search(scope, {
      ...s.filter,
      from,
      to,
      ...(after !== undefined && { after }),
      take: limit + 1,
    });
    const page = rows.slice(0, limit);
    const items = await this.summaries(scope, page, s.showSubject);
    const last = page[page.length - 1];
    const nextCursor =
      rows.length > limit && last !== undefined
        ? encodeSearchCursor({
            t: last.quarantinedAt.toISOString(),
            id: last.id.toString(),
            f: hash,
          })
        : null;
    await this.writer.record(undefined, {
      principal,
      scope,
      client,
      action: QUARANTINE_AUDIT.searched,
      resourceType: QUARANTINE_RESOURCE.search,
      resourceId: null,
      metadata: { filterHash: hash, resultCount: items.length, self: s.self },
    });
    this.metrics.request('search', 'ok');
    return { items, nextCursor };
  }

  private async summaries(
    scope: TenantScope,
    rows: readonly EntryRow[],
    showSubject: boolean,
  ): Promise<QuarantineEntrySummary[]> {
    const [messages, approvals, subjects] = await Promise.all([
      this.reads.messagePublicIds(
        scope,
        rows.map((r) => r.messageId),
      ),
      this.reads.approvalPublicIds(
        scope,
        rows.flatMap((r) => (r.approvalRequestId === null ? [] : [r.approvalRequestId])),
      ),
      showSubject
        ? this.reads.subjects(
            scope,
            rows.map((r) => ({ messageId: r.messageId, receivedAt: r.messageReceivedAt })),
          )
        : Promise.resolve(new Map<bigint, string | null>()),
    ]);
    return rows.flatMap((r) => {
      const messagePublicId = messages.get(r.messageId);
      if (messagePublicId === undefined) return [];
      return [
        entrySummary(r, {
          messagePublicId,
          approvalPublicId:
            r.approvalRequestId === null ? null : (approvals.get(r.approvalRequestId) ?? null),
          subject: showSubject ? (subjects.get(r.messageId) ?? null) : null,
        }),
      ];
    });
  }

  // ------------------------------------------------------------------ detail, history

  async detail(
    principal: Principal,
    scope: TenantScope,
    entryId: string,
    client: ClientContext,
  ): Promise<QuarantineEntryDetail> {
    const entry = await this.reads.entry(scope, entryId);
    if (entry === null) throw entryNotFound();
    const settings = await this.context.settings(scope);
    return this.detailOf(principal, scope, entry, settings, client, {
      isSelf: false,
      showSubject: principal.permissions.has(QUARANTINE_PERMISSIONS.preview),
    });
  }

  async selfDetail(
    principal: Principal,
    scope: TenantScope,
    entryId: string,
    client: ClientContext,
  ): Promise<QuarantineEntryDetail> {
    const caller = await this.context.selfCaller(principal, scope);
    const settings = await this.context.settings(scope);
    const entry = await this.reads.entry(scope, entryId, caller.address);
    const check = checkSelfService({
      action: 'view',
      settings,
      caller: {
        type: 'user',
        verifiedEmail: caller.address,
        permissions: permissionsOf(principal),
      },
      ...(entry !== null && {
        entry: {
          recipientAddress: entry.recipientAddress,
          state: entry.state,
          reason: entry.reason,
          riskLevel: entry.riskLevel,
          hasHardBlock: entry.hasHardBlock,
        },
      }),
    });
    if (entry === null || !check.allowed) throw entryNotFound();
    return this.detailOf(principal, scope, entry, settings, client, {
      isSelf: true,
      showSubject: true,
    });
  }

  private async detailOf(
    principal: Principal,
    scope: TenantScope,
    entry: EntryRow,
    settings: QuarantineSettings,
    client: ClientContext,
    o: { isSelf: boolean; showSubject: boolean },
  ): Promise<QuarantineEntryDetail> {
    const [messages, approvals, subjects, releases] = await Promise.all([
      this.reads.messagePublicIds(scope, [entry.messageId]),
      this.reads.approvalPublicIds(
        scope,
        entry.approvalRequestId === null ? [] : [entry.approvalRequestId],
      ),
      o.showSubject
        ? this.reads.subjects(scope, [
            { messageId: entry.messageId, receivedAt: entry.messageReceivedAt },
          ])
        : Promise.resolve(new Map<bigint, string | null>()),
      o.isSelf ? Promise.resolve([]) : this.reads.releasesOfEntry(scope, entry.id),
    ]);
    const messagePublicId = messages.get(entry.messageId);
    if (messagePublicId === undefined) throw entryNotFound();
    const allowed = allowedActionsFor({
      entry: {
        state: entry.state,
        kind: entry.kind,
        reason: entry.reason,
        riskLevel: entry.riskLevel,
        hasHardBlock: entry.hasHardBlock,
        contentAvailable: contentAvailable(entry),
      },
      permissions: permissionsOf(principal),
      settings,
      isSelf: o.isSelf,
    });
    const detail = entryDetail(
      entry,
      {
        messagePublicId,
        approvalPublicId:
          entry.approvalRequestId === null
            ? null
            : (approvals.get(entry.approvalRequestId) ?? null),
        subject: subjects.get(entry.messageId) ?? null,
      },
      releases,
      allowed,
    );
    // The view is recorded (action + audit) in one writer transaction after the replica read.
    await this.writer.run(async (tx) => {
      await this.writes.insertAction(tx, {
        organizationId: scope.organizationId,
        quarantineMessageId: entry.id,
        action: 'view',
        ...actorOf(principal),
        reason: null,
        result: null,
        details: { self: o.isSelf },
        idempotencyKey: null,
      });
      await this.writer.record(tx, {
        principal,
        scope,
        client,
        action: QUARANTINE_AUDIT.entryViewed,
        resourceType: QUARANTINE_RESOURCE.entry,
        resourceId: entry.publicId,
        metadata: { entryId: entry.publicId, self: o.isSelf },
      });
    });
    this.metrics.request('view', 'ok');
    return detail;
  }

  async history(scope: TenantScope, entryId: string): Promise<HistoryResponse> {
    const entry = await this.reads.entry(scope, entryId);
    if (entry === null) throw entryNotFound();
    const [actions, releases] = await Promise.all([
      this.reads.actions(scope, entry.id),
      this.reads.releasesOfEntry(scope, entry.id),
    ]);
    this.metrics.request('history', 'ok');
    return {
      actions: actions.map((a) => ({
        action: a.action,
        actor: { type: a.actorType, id: a.actorId },
        result: a.result,
        reason: a.actorType === 'system' ? null : a.reason,
        at: a.createdAt.toISOString(),
      })),
      releases: releases.map(releaseView),
    };
  }

  async release(scope: TenantScope, releaseId: string): Promise<ReleaseDetail> {
    const rows = await this.reads.release(scope, releaseId);
    const first = rows[0];
    if (first === undefined) throw releaseNotFound();
    return { ...releaseView(first), entryIds: rows.map((r) => r.entryPublicId) };
  }

  // ------------------------------------------------------------------ approvals

  async approvals(
    scope: TenantScope,
    query: ApprovalListQuery,
  ): Promise<Page<QuarantineApprovalView>> {
    const limit = Math.min(
      query.limit ?? QUARANTINE_SEARCH_DEFAULT_PAGE_SIZE,
      this.config.QUARANTINE_SEARCH_MAX_PAGE_SIZE,
    );
    const { cursor: _c, limit: _l, ...filters } = query;
    const hash = searchFilterHash({ ...filters, list: 'approvals' });
    let after: Keyset | undefined;
    if (query.cursor !== undefined) {
      const cursor = decodeSearchCursor(query.cursor, hash);
      if (cursor === null) throw cursorInvalid();
      after = { t: new Date(cursor.t), id: BigInt(cursor.id) };
    }
    const rows = await this.reads.approvals(scope, {
      ...(query.status !== undefined && { statuses: query.status }),
      ...(query.kind !== undefined && { kinds: query.kind }),
      ...(query.from !== undefined && { from: new Date(query.from) }),
      ...(query.to !== undefined && { to: new Date(query.to) }),
      ...(after !== undefined && { after }),
      take: limit + 1,
    });
    const page = rows.slice(0, limit);
    const last = page[page.length - 1];
    return {
      items: page.map(approvalView),
      nextCursor:
        rows.length > limit && last !== undefined
          ? encodeSearchCursor({ t: last.createdAt.toISOString(), id: last.id.toString(), f: hash })
          : null,
    };
  }

  async approval(scope: TenantScope, approvalId: string): Promise<QuarantineApprovalView> {
    const row = await this.reads.approval(scope, approvalId);
    if (row === null) throw approvalNotFound();
    return approvalView(row);
  }

  // ------------------------------------------------------------------ summary, catalog

  async summary(scope: TenantScope, query: SummaryQuery): Promise<SummaryResponse> {
    const from = new Date(query.from);
    const to = new Date(query.to);
    const maxDays = this.config.QUARANTINE_SEARCH_MAX_RANGE_DAYS;
    if (!checkSearchRange(from, to, maxDays)) throw searchRangeInvalid(maxDays);
    const [counts, pending] = await Promise.all([
      this.reads.countsByState(scope, from, to),
      this.reads.pendingApprovals(scope),
    ]);
    return {
      from: from.toISOString(),
      to: to.toISOString(),
      counts: Object.fromEntries(
        QUARANTINE_STATES.map((s) => [s, counts.get(s) ?? 0]),
      ) as SummaryResponse['counts'],
      pendingApprovals: pending,
    };
  }

  async catalog(scope: TenantScope): Promise<CatalogResponse> {
    const settings = await this.context.settings(scope);
    return {
      states: [...QUARANTINE_STATES],
      kinds: [...QUARANTINE_ENTRY_KINDS],
      origins: [...QUARANTINE_ORIGINS],
      reasons: [...QUARANTINE_REASONS],
      primaryEngines: [...QUARANTINE_PRIMARY_ENGINES],
      riskLevels: [...QUARANTINE_RISK_LEVELS],
      releaseModes: [...QUARANTINE_RELEASE_MODES],
      releaseStatuses: [...QUARANTINE_RELEASE_STATUSES],
      approvalKinds: [...QUARANTINE_APPROVAL_KINDS],
      approvalStatuses: [...QUARANTINE_APPROVAL_STATUSES],
      approvalReasons: [...APPROVAL_REASONS],
      entryActions: [...ENTRY_ACTIONS],
      bulkActions: [...BULK_ACTIONS],
      errorCodes: { ...QUARANTINE_ERROR_CODES },
      limits: {
        searchMaxRangeDays: this.config.QUARANTINE_SEARCH_MAX_RANGE_DAYS,
        searchMaxPageSize: this.config.QUARANTINE_SEARCH_MAX_PAGE_SIZE,
        searchDefaultPageSize: QUARANTINE_SEARCH_DEFAULT_PAGE_SIZE,
        bulkMaxItems: this.config.QUARANTINE_BULK_MAX_ITEMS,
        bulkMaxItemsPerMinute: this.config.QUARANTINE_BULK_MAX_ITEMS_PER_MINUTE,
        previewMaxTextChars: this.config.QUARANTINE_PREVIEW_MAX_TEXT_CHARS,
        downloadTokenTtlSeconds: this.config.QUARANTINE_DOWNLOAD_TOKEN_TTL_SECONDS,
        downloadMaxBytes: this.config.QUARANTINE_DOWNLOAD_MAX_BYTES,
        reasonMaxChars: 512,
      },
      selfService: {
        enabled: settings.endUser.enabled,
        preview: settings.endUser.preview,
        selfRelease: settings.endUser.selfRelease,
        selfReleaseReasons: [...settings.endUser.selfReleaseReasons],
        selfReleaseMaxLevel: settings.endUser.selfReleaseMaxLevel,
        requestRelease: settings.endUser.requestRelease,
        digestAllowOptOut: settings.digest.allowOptOut,
      },
      downloadEnabled: settings.download.enabled,
    };
  }
}
