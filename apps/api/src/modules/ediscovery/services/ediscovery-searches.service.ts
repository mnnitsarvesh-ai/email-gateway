import { Inject, Injectable } from '@nestjs/common';
import {
  canonicalSha256,
  holdBound,
  REVEAL_GATED_FILTERS,
  searchFilterHash,
  searchFilterNames,
} from '@email-gateway/archive';
import { uuidv7 } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
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
import { OrganizationFeaturesService } from '../../../tenancy/organization-features.service';
import {
  ARCHIVE_PERMISSIONS as P,
  ARCHIVE_TX_TIMEOUT_MS,
  type ArchiveConfig,
} from '../../archive/archive.constants';
import {
  archiveFilterForbidden,
  archiveSearchRangeInvalid,
  caseClosed,
  caseNotFound,
  legalHoldNotFound,
  reviewLimit,
  searchLimit,
  searchNotCompleted,
  searchNotFound,
} from '../../archive/archive.errors';
import { messageViewOfRecord } from '../../archive/domain/archive-views';
import { ArchiveRecordsRepository } from '../../archive/repositories/archive-records.repository';
import { parsePublicId, requireArchiving, userIdOf } from '../../archive/services/archive-common';
import {
  decimalKey,
  decodeListCursor,
  encodeListCursor,
  listBinding,
} from '../../messages/domain/v1-list';
import { searchView } from '../domain/ediscovery-views';
import type {
  CreateSearchBody,
  HitListQuery,
  HitPage,
  ReviewBody,
  ReviewResultView,
  SearchListQuery,
  SearchPage,
  SearchView,
} from '../dto/ediscovery.schemas';
import {
  EDISCOVERY_AUDIT,
  EDISCOVERY_CURSOR_RESOURCES,
  EDISCOVERY_OPERATIONS,
  EDISCOVERY_RESOURCE,
} from '../ediscovery.constants';
import {
  type CaseRow,
  EdiscoveryRepository,
  type SearchRow,
} from '../repositories/ediscovery.repository';
import { EdiscoveryCasesService } from './ediscovery-cases.service';

const DAY_MS = 86_400_000;

/** Query parameter / criteria name of a refused reveal-gated criterion. */
const GATED_NAME: Record<string, string> = {
  recipients: 'criteria.recipients',
  subject: 'criteria.subject',
  custodians: 'criteria.custodians',
};

/**
 * Case searches, hits and review (step 8.1 §4.4 #33–#37; A17, A18, ADR-0069). A search is
 * queued (`202`) for the archive-worker's `ediscovery` role, which runs it through the tenant
 * alias to completion, verifies every hit against MySQL and reports completeness. Creation
 * checks the open case, the `archiving` entitlement, reveal-gated criteria (`message:reveal`),
 * the hold of a `holdId`, the range (≤ ARCHIVE_CASE_SEARCH_MAX_RANGE_DAYS) and at most
 * ARCHIVE_CASE_MAX_ACTIVE_SEARCHES queued/running searches per case (`429
 * ediscovery_search_limit`). Hits are masked like archive search results; their first page is
 * audited. Review tags at most ARCHIVE_REVIEW_MAX_ITEMS hits per request (users only).
 */
@Injectable()
export class EdiscoverySearchesService {
  constructor(
    @Inject(API_CONFIG)
    private readonly config: Pick<
      ArchiveConfig,
      | 'ARCHIVE_CASE_SEARCH_MAX_RANGE_DAYS'
      | 'ARCHIVE_CASE_MAX_ACTIVE_SEARCHES'
      | 'ARCHIVE_REVIEW_MAX_ITEMS'
    >,
    private readonly repo: EdiscoveryRepository,
    private readonly records: ArchiveRecordsRepository,
    private readonly cases: EdiscoveryCasesService,
    private readonly features: OrganizationFeaturesService,
    private readonly idempotency: IdempotencyService,
    private readonly audit: AuditService,
    private readonly codec: CursorCodec,
  ) {}

  now(): Date {
    return new Date();
  }

  /** `POST /ediscovery/cases/{caseId}/searches` (#33): `202 queued`. */
  async create(
    principal: Principal,
    scope: TenantScope,
    rawCaseId: unknown,
    idempotencyKey: unknown,
    body: CreateSearchBody,
    sourceIp: string | null,
  ): Promise<IdempotentResult<SearchView>> {
    const caseId = parsePublicId(rawCaseId, 'caseId');
    const key = parseIdempotencyKey(idempotencyKey);
    const criteria = body.criteria;
    const reveal = principal.permissions.has(P.reveal);
    // Permission gates first (A17): a reveal-gated criterion needs `message:reveal`.
    if (!reveal) {
      for (const name of REVEAL_GATED_FILTERS) {
        // `custodians: "case"` names the case's own list, which the caller already sees and which
        // only a holder of `message:reveal` can write (`requireCustodianWriter`).
        if (name === 'custodians' && criteria.custodians === 'case') continue;
        if (criteria[name] !== undefined) throw archiveFilterForbidden(GATED_NAME[name]!);
      }
    }
    const from = holdBound(criteria.from, false);
    const to = holdBound(criteria.to, true);
    const maxDays = this.config.ARCHIVE_CASE_SEARCH_MAX_RANGE_DAYS;
    if (
      !Number.isFinite(from) ||
      !Number.isFinite(to) ||
      from > to ||
      to - from > maxDays * DAY_MS
    ) {
      throw archiveSearchRangeInvalid(maxDays);
    }
    const operation = EDISCOVERY_OPERATIONS.searchCreate;
    return this.idempotency.execute<SearchView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId: caseId,
        fingerprint: requestFingerprint({ operation, resourceId: caseId, body }),
      },
      async (tx) => {
        const c = await this.repo.lockCase(tx, scope, caseId);
        if (c === null) throw caseNotFound();
        await requireArchiving(this.features, scope, tx);
        if (c.status !== 'open') throw caseClosed();
        if (criteria.holdId !== undefined) {
          const hold = await this.repo.findHold(scope, criteria.holdId.toLowerCase(), tx);
          if (hold === null) throw legalHoldNotFound();
        }
        const max = this.config.ARCHIVE_CASE_MAX_ACTIVE_SEARCHES;
        if ((await this.repo.countActiveSearches(tx, scope, c.id)) >= max) throw searchLimit(max);
        const row = await this.repo.createSearch(tx, scope, {
          publicId: uuidv7(),
          caseId: c.id,
          criteria: criteria,
          criteriaSha256: canonicalSha256(criteria),
          requestedByUserId: userIdOf(principal),
        });
        await this.record(
          principal,
          scope,
          EDISCOVERY_AUDIT.searchRequested,
          row.publicId,
          sourceIp,
          {
            caseId: c.publicId,
            filterNames: searchFilterNames(criteria),
            filterHash: searchFilterHash(criteria),
          },
          tx,
        );
        return { statusCode: 202, body: searchView(row, c.publicId, reveal) };
      },
      { timeoutMs: ARCHIVE_TX_TIMEOUT_MS },
    );
  }

  async list(
    principal: Principal,
    scope: TenantScope,
    rawCaseId: unknown,
    query: SearchListQuery,
  ): Promise<SearchPage> {
    const c = await this.cases.caseOf(scope, rawCaseId);
    const binding = listBinding({
      resource: EDISCOVERY_CURSOR_RESOURCES.searches,
      principal,
      filters: { ...query.filters, caseId: { values: [c.publicId] } },
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 1);
    const rows = await this.repo.listSearches(scope, c.id, {
      take: query.limit + 1,
      beforeId: decoded ? decimalKey(decoded.keys[0]) : undefined,
      statuses: query.filters.status?.values,
    });
    const decision = decideKeysetPage({ fetched: rows, limit: query.limit, keyOf: (r) => r.id });
    const reveal = principal.permissions.has(P.reveal);
    return {
      data: rows.slice(0, decision.rows).map((r) => searchView(r, c.publicId, reveal)),
      nextCursor:
        decision.next === null
          ? null
          : encodeListCursor(this.codec, binding, [decision.next.toString()]),
    };
  }

  /** The case and search of a path (replica); `404` for unknown or foreign ids. */
  private async searchOf(
    scope: TenantScope,
    rawCaseId: unknown,
    rawSearchId: unknown,
  ): Promise<{ c: CaseRow; search: SearchRow }> {
    const c = await this.cases.caseOf(scope, rawCaseId);
    const search = await this.repo.findSearch(scope, c.id, parsePublicId(rawSearchId, 'searchId'));
    if (search === null) throw searchNotFound();
    return { c, search };
  }

  async get(
    principal: Principal,
    scope: TenantScope,
    rawCaseId: unknown,
    rawSearchId: unknown,
  ): Promise<SearchView> {
    const { c, search } = await this.searchOf(scope, rawCaseId, rawSearchId);
    return searchView(search, c.publicId, principal.permissions.has(P.reveal));
  }

  /** `GET …/searches/{searchId}/hits` (#36): masked hits; the first page is audited. */
  async hits(
    principal: Principal,
    scope: TenantScope,
    rawCaseId: unknown,
    rawSearchId: unknown,
    query: HitListQuery,
    sourceIp: string | null,
  ): Promise<HitPage> {
    const { c, search } = await this.searchOf(scope, rawCaseId, rawSearchId);
    const binding = listBinding({
      resource: EDISCOVERY_CURSOR_RESOURCES.hits,
      principal,
      filters: { ...query.filters, searchId: { values: [search.publicId] } },
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 1);
    const rows = await this.repo.listHits(scope, search.id, {
      take: query.limit + 1,
      beforeId: decoded ? decimalKey(decoded.keys[0]) : undefined,
      tags: query.filters.reviewTag?.values,
    });
    const decision = decideKeysetPage({ fetched: rows, limit: query.limit, keyOf: (r) => r.id });
    const page = rows.slice(0, decision.rows);
    const records = await this.records.recordsByKeys(
      scope,
      page.map((h) => ({ messageId: h.messageId, receivedAt: h.messageReceivedAt })),
    );
    const byKey = new Map(
      records
        .filter((r) => r.deletedAt === null)
        .map((r) => [`${r.messageId.toString()}:${r.receivedAt.getTime()}`, r]),
    );
    if (query.cursor === undefined) {
      await this.audit.record({
        organizationId: scope.organizationId,
        actor: this.audit.actorFrom(principal),
        action: EDISCOVERY_AUDIT.hitsViewed,
        resourceType: EDISCOVERY_RESOURCE.search,
        resourceId: search.publicId,
        sourceIp,
        metadata: {
          caseId: c.publicId,
          searchId: search.publicId,
          resultCount: page.length,
          tags: query.filters.reviewTag?.values ?? [],
        },
      });
    }
    return {
      data: page.map((h) => {
        const record = byKey.get(`${h.messageId.toString()}:${h.messageReceivedAt.getTime()}`);
        return {
          messageId: h.messagePublicId,
          receivedAt: h.messageReceivedAt.toISOString(),
          reviewTag: h.reviewTag,
          reviewedBy: h.reviewedByPublicId,
          reviewedAt: h.reviewedAt?.toISOString() ?? null,
          message: record === undefined ? null : messageViewOfRecord(record),
        };
      }),
      nextCursor:
        decision.next === null
          ? null
          : encodeListCursor(this.codec, binding, [decision.next.toString()]),
    };
  }

  /** `POST …/searches/{searchId}/review` (#37). */
  async review(
    principal: Principal,
    scope: TenantScope,
    rawCaseId: unknown,
    rawSearchId: unknown,
    idempotencyKey: unknown,
    body: ReviewBody,
    sourceIp: string | null,
  ): Promise<IdempotentResult<ReviewResultView>> {
    const caseId = parsePublicId(rawCaseId, 'caseId');
    const searchId = parsePublicId(rawSearchId, 'searchId');
    const key = parseIdempotencyKey(idempotencyKey);
    const max = this.config.ARCHIVE_REVIEW_MAX_ITEMS;
    if (body.messageIds.length > max) throw reviewLimit(max);
    const ids = body.messageIds.map((i) => i.toLowerCase());
    const operation = EDISCOVERY_OPERATIONS.review;
    return this.idempotency.execute<ReviewResultView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId: searchId,
        fingerprint: requestFingerprint({ operation, resourceId: searchId, body }),
      },
      async (tx) => {
        const c = await this.repo.lockCase(tx, scope, caseId);
        if (c === null) throw caseNotFound();
        const search = await this.repo.findSearch(scope, c.id, searchId, tx);
        if (search === null) throw searchNotFound();
        await requireArchiving(this.features, scope, tx);
        if (c.status !== 'open') throw caseClosed();
        if (search.status !== 'completed') throw searchNotCompleted(search.status);
        const updated = await this.repo.reviewHits(tx, scope, search.id, ids, {
          tag: body.tag,
          userId: userIdOf(principal),
          now: this.now(),
        });
        await this.record(
          principal,
          scope,
          EDISCOVERY_AUDIT.reviewTagged,
          search.publicId,
          sourceIp,
          {
            caseId: c.publicId,
            tag: body.tag,
            requested: ids.length,
            updated,
            messageIds: ids,
          },
          tx,
        );
        return {
          statusCode: 200,
          body: {
            searchId: search.publicId,
            tag: body.tag,
            updated,
            notFound: ids.length - updated,
          },
        };
      },
      { timeoutMs: ARCHIVE_TX_TIMEOUT_MS },
    );
  }

  private record(
    principal: Principal,
    scope: TenantScope,
    action: string,
    searchPublicId: string,
    sourceIp: string | null,
    metadata: Record<string, unknown>,
    tx: Prisma.TransactionClient,
  ): Promise<void> {
    return this.audit.record(
      {
        organizationId: scope.organizationId,
        actor: this.audit.actorFrom(principal),
        action,
        resourceType: EDISCOVERY_RESOURCE.search,
        resourceId: searchPublicId,
        sourceIp,
        metadata: { searchId: searchPublicId, ...metadata },
      },
      tx,
    );
  }
}
