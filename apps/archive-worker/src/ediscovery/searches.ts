import {
  type ArchiveSearchCriteria,
  archiveSearchCriteriaSchema,
  ArchiveSearchQueryError,
  buildArchiveSearchQuery,
  holdBound,
  holdToSearchCriteria,
  isUuid,
  parseSearchAfter,
  type SearchAfter,
  tenantAliasName,
} from '@email-gateway/archive';
import type { OpenSearchService } from '@email-gateway/common';
import { Prisma, type PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import type { ArchiveMetrics } from '../metrics/archive-metrics';
import { big, orgFilter, systemAudit } from '../shared/db';
import { errorCode, errorFields } from '../shared/errors';

const DAY_MS = 86_400_000;
/** Hits per OpenSearch page of a case search. */
export const CASE_SEARCH_PAGE = 1_000;
/** The organization's index queue must hold no operation older than this at completion (A18). */
export const INDEX_LAG_TOLERANCE_MS = 60_000;

export type IncompleteReason = 'index_lag' | 'unverified_days' | 'mismatched_days';

export class CaseSearchError extends Error {
  constructor(readonly code: string) {
    super(`case search failed: ${code}`);
    this.name = 'CaseSearchError';
  }
}

interface ClaimedSearch {
  id: bigint;
  publicId: string;
  caseId: bigint;
  casePublicId: string;
  organizationId: bigint;
  criteria: unknown;
}

export interface CaseSearchOutcome {
  status: 'completed' | 'failed';
  hitCount: number;
  truncated: boolean;
  indexComplete: boolean | null;
  incompleteReason: IncompleteReason | null;
  errorCode: string | null;
}

/**
 * Completeness of a finished case search (A18): `index_complete = true` only when the
 * organization's index queue holds no operation older than 60 s **and** every UTC day of the
 * range has an `ok` row in `archive_index_checks`; otherwise `false` with the reason (`index_lag`
 * first, then `mismatched_days`, then `unverified_days`). Days before the organization's first
 * record and after today hold no record in MySQL, so they cannot hide a hit and are not required.
 */
export async function searchCompleteness(
  db: PrismaClient | Prisma.TransactionClient,
  input: { organizationId: bigint; from: Date; to: Date; now: Date },
): Promise<{ complete: boolean; reason: IncompleteReason | null }> {
  const [oldest] = await db.$queryRaw<Array<{ at: Date | null }>>`
    SELECT MIN(created_at) AS at FROM archive_index_queue WHERE organization_id = ${input.organizationId}`;
  if (
    oldest?.at instanceof Date &&
    input.now.getTime() - oldest.at.getTime() > INDEX_LAG_TOLERANCE_MS
  ) {
    return { complete: false, reason: 'index_lag' };
  }
  const [first] = await db.$queryRaw<Array<{ at: Date | null }>>`
    SELECT MIN(received_at) AS at FROM email_archives WHERE organization_id = ${input.organizationId}`;
  if (!(first?.at instanceof Date)) return { complete: true, reason: null };
  const startDay = Date.parse(`${first.at.toISOString().slice(0, 10)}T00:00:00.000Z`);
  const todayStart = Date.parse(`${input.now.toISOString().slice(0, 10)}T00:00:00.000Z`);
  const from = Math.max(
    Date.parse(`${input.from.toISOString().slice(0, 10)}T00:00:00.000Z`),
    startDay,
  );
  const to = Math.min(
    Date.parse(`${input.to.toISOString().slice(0, 10)}T00:00:00.000Z`),
    todayStart,
  );
  if (from > to) return { complete: true, reason: null };
  const expected = Math.round((to - from) / DAY_MS) + 1;
  const rows = await db.$queryRaw<Array<{ state: string; n: bigint | number }>>`
    SELECT state, COUNT(*) AS n FROM archive_index_checks
    WHERE organization_id = ${input.organizationId}
      AND day >= ${new Date(from).toISOString().slice(0, 10)}
      AND day <= ${new Date(to).toISOString().slice(0, 10)}
    GROUP BY state`;
  const count = (state: string) => Number(rows.find((r) => r.state === state)?.n ?? 0);
  if (count('mismatch') + count('repairing') > 0)
    return { complete: false, reason: 'mismatched_days' };
  if (count('ok') < expected) return { complete: false, reason: 'unverified_days' };
  return { complete: true, reason: null };
}

/**
 * eDiscovery case searches (A18, `ediscovery` role): claims one `queued` search (→ `running`;
 * a `running` search older than twice the deadline is taken over), runs it through the tenant
 * alias (+ the mandatory tenant filter, routing) with `search_after` to completion — at most
 * `ARCHIVE_CASE_SEARCH_MAX_HITS` verified hits (then `truncated`) within
 * `ARCHIVE_CASE_SEARCH_DEADLINE_MS` — verifies every hit in MySQL batches (same organization,
 * `active`/`expiry_review`), writes `ediscovery_search_hits`, computes the completeness flags and
 * commits `completed` with the system audit row `ediscovery.search_completed` (or `failed` and
 * `ediscovery.search_failed`; partial hits are removed).
 */
export class CaseSearchRunner {
  private readonly now: () => Date;

  constructor(
    private readonly prisma: PrismaClient,
    private readonly options: {
      search: OpenSearchService;
      metrics: ArchiveMetrics;
      logger: Logger;
      indexPrefix: string;
      maxHits: number;
      deadlineMs: number;
      timeoutMs: number;
      organizationIds?: readonly bigint[];
      now?: () => Date;
    },
  ) {
    this.now = options.now ?? (() => new Date());
  }

  /** One search per pass; true when one ran (another may be queued). */
  async runOnce(): Promise<boolean> {
    const claimed = await this.claim();
    if (claimed === null) return false;
    await this.run(claimed);
    return true;
  }

  private async claim(): Promise<ClaimedSearch | null> {
    const now = this.now();
    const stale = new Date(now.getTime() - 2 * this.options.deadlineMs);
    return this.prisma.$transaction(async (tx) => {
      const [row] = await tx.$queryRaw<
        Array<{
          id: bigint | number;
          public_id: string;
          case_id: bigint | number;
          organization_id: bigint | number;
          criteria: unknown;
        }>
      >`
        SELECT id, public_id, case_id, organization_id, criteria FROM ediscovery_searches
        WHERE (status = 'queued' OR (status = 'running' AND started_at < ${stale}))
          ${orgFilter('organization_id', this.options.organizationIds)}
        ORDER BY created_at, id LIMIT 1 FOR UPDATE SKIP LOCKED`;
      if (row === undefined) return null;
      await tx.$executeRaw`
        UPDATE ediscovery_searches SET status = 'running', started_at = ${now}, hit_count = 0,
          truncated = 0, index_complete = NULL, incomplete_reason = NULL, error_code = NULL,
          updated_at = NOW(3)
        WHERE id = ${big(row.id)}`;
      const kase = await tx.ediscoveryCase.findUnique({
        where: { id: big(row.case_id) },
        select: { publicId: true, organizationId: true },
      });
      return {
        id: big(row.id),
        publicId: row.public_id,
        caseId: big(row.case_id),
        casePublicId: kase?.organizationId === big(row.organization_id) ? kase.publicId : '',
        organizationId: big(row.organization_id),
        criteria:
          typeof row.criteria === 'string' ? (JSON.parse(row.criteria) as unknown) : row.criteria,
      };
    });
  }

  async run(s: ClaimedSearch): Promise<CaseSearchOutcome> {
    const started = this.now().getTime();
    try {
      if (s.casePublicId === '') throw new CaseSearchError('case_not_found');
      // A takeover restarts from nothing.
      await this.prisma.ediscoverySearchHit.deleteMany({ where: { searchId: s.id } });
      const parsed = archiveSearchCriteriaSchema.safeParse(s.criteria);
      if (!parsed.success) throw new CaseSearchError('criteria_invalid');
      const criteria = parsed.data;
      const caseCustodians = criteria.custodians === 'case' ? await this.custodians(s) : null;
      const hold = criteria.holdId === undefined ? null : await this.hold(s, criteria.holdId);
      const alias = tenantAliasName(this.options.indexPrefix, s.organizationId);
      let searchAfter: SearchAfter | null = null;
      let hitCount = 0;
      let truncated = false;
      for (;;) {
        if (this.now().getTime() - started > this.options.deadlineMs) {
          throw new CaseSearchError('search_deadline_exceeded');
        }
        let body: Record<string, unknown>;
        try {
          body = buildArchiveSearchQuery({
            organizationId: s.organizationId,
            criteria,
            sort: '-receivedAt',
            limit: CASE_SEARCH_PAGE,
            searchAfter,
            permissions: { reveal: true, holds: true },
            hold,
            caseCustodians,
            timeoutMs: this.options.timeoutMs,
          });
        } catch (error) {
          if (error instanceof ArchiveSearchQueryError) throw new CaseSearchError(error.code);
          throw error;
        }
        const res = await this.options.search.search<{ message_id?: string; received_at?: string }>(
          alias,
          body,
          { routing: s.organizationId.toString() },
        );
        if (res.timedOut) throw new CaseSearchError('search_timed_out');
        const page = res.hits.slice(0, CASE_SEARCH_PAGE);
        const verified = await this.verifyAndStore(s, page, this.options.maxHits - hitCount);
        hitCount += verified.stored;
        if (
          verified.capped ||
          (hitCount >= this.options.maxHits && res.hits.length > page.length)
        ) {
          truncated = true;
          break;
        }
        if (res.hits.length <= CASE_SEARCH_PAGE) break;
        const last = page[page.length - 1];
        searchAfter = last ? parseSearchAfter(last.sort) : null;
        if (searchAfter === null) throw new CaseSearchError('cursor_invalid');
      }
      const completeness = await searchCompleteness(this.prisma, {
        organizationId: s.organizationId,
        from: new Date(holdBound(criteria.from, false)),
        to: new Date(holdBound(criteria.to, true)),
        now: this.now(),
      });
      const outcome: CaseSearchOutcome = {
        status: 'completed',
        hitCount,
        truncated,
        indexComplete: completeness.complete,
        incompleteReason: completeness.reason,
        errorCode: null,
      };
      await this.prisma.$transaction(async (tx) => {
        await tx.$executeRaw`
          UPDATE ediscovery_searches SET status = 'completed', hit_count = ${hitCount},
            truncated = ${truncated ? 1 : 0}, index_complete = ${completeness.complete ? 1 : 0},
            incomplete_reason = ${completeness.reason}, completed_at = ${this.now()},
            updated_at = NOW(3)
          WHERE id = ${s.id} AND status = 'running'`;
        await systemAudit(tx, {
          organizationId: s.organizationId,
          action: 'ediscovery.search_completed',
          resourceType: 'ediscovery_search',
          resourceId: s.publicId,
          correlationId: `ediscovery-search:${s.publicId}`,
          metadata: {
            caseId: s.casePublicId,
            hitCount,
            truncated,
            indexComplete: completeness.complete,
            incompleteReason: completeness.reason,
            durationMs: this.now().getTime() - started,
          },
        });
      });
      this.options.metrics.ediscoverySearches.inc({
        result: truncated ? 'truncated' : 'completed',
      });
      return outcome;
    } catch (error) {
      const code =
        error instanceof CaseSearchError ? error.code : errorCode(error, 'search_failed');
      this.options.logger.warn(
        { searchId: s.publicId, ...errorFields(error), failureCode: code },
        'eDiscovery case search failed',
      );
      await this.prisma.ediscoverySearchHit.deleteMany({ where: { searchId: s.id } });
      await this.prisma.$transaction(async (tx) => {
        await tx.$executeRaw`
          UPDATE ediscovery_searches SET status = 'failed', error_code = ${code.slice(0, 64)},
            hit_count = 0, completed_at = ${this.now()}, updated_at = NOW(3)
          WHERE id = ${s.id} AND status = 'running'`;
        await systemAudit(tx, {
          organizationId: s.organizationId,
          action: 'ediscovery.search_failed',
          resourceType: 'ediscovery_search',
          resourceId: s.publicId,
          correlationId: `ediscovery-search:${s.publicId}`,
          metadata: { caseId: s.casePublicId || null, errorCode: code.slice(0, 64) },
        });
      });
      this.options.metrics.ediscoverySearches.inc({ result: 'failed' });
      return {
        status: 'failed',
        hitCount: 0,
        truncated: false,
        indexComplete: null,
        incompleteReason: null,
        errorCode: code,
      };
    }
  }

  private async custodians(s: ClaimedSearch): Promise<string[]> {
    const rows = await this.prisma.ediscoveryCustodian.findMany({
      where: { caseId: s.caseId, organizationId: s.organizationId },
      select: { organizationId: true, address: true },
      take: 10_000,
    });
    return rows.filter((r) => r.organizationId === s.organizationId).map((r) => r.address);
  }

  private async hold(s: ClaimedSearch, holdId: string) {
    if (!isUuid(holdId)) throw new CaseSearchError('hold_unresolved');
    const row = await this.prisma.archiveLegalHold.findUnique({
      where: { publicId: holdId },
      select: { organizationId: true, criteria: true, criteriaVersion: true },
    });
    if (row === null || row.organizationId !== s.organizationId) {
      throw new CaseSearchError('hold_unresolved');
    }
    return holdToSearchCriteria(row.criteria, row.criteriaVersion);
  }

  /** Verifies a page of hits against MySQL (same organization, live) and stores the survivors. */
  private async verifyAndStore(
    s: ClaimedSearch,
    hits: ReadonlyArray<{ _id: string; _source?: { message_id?: string; received_at?: string } }>,
    room: number,
  ): Promise<{ stored: number; capped: boolean }> {
    const candidates = hits
      .map((h) => ({
        id: h._source?.message_id ?? h._id,
        at: Date.parse(h._source?.received_at ?? ''),
      }))
      .filter((h) => isUuid(h.id) && Number.isFinite(h.at));
    if (candidates.length === 0) return { stored: 0, capped: false };
    const rows = await this.prisma.$queryRaw<
      Array<{ message_id: bigint | number; received_at: Date; message_public_id: string }>
    >`
      SELECT message_id, received_at, message_public_id FROM email_archives
      WHERE organization_id = ${s.organizationId}
        AND received_at IN (${Prisma.join([...new Set(candidates.map((c) => c.at))].map((t) => new Date(t)))})
        AND message_public_id IN (${Prisma.join(candidates.map((c) => c.id))})
        AND status IN ('active', 'expiry_review')`;
    const live = new Map(rows.map((r) => [r.message_public_id, r]));
    const ordered = candidates.map((c) => live.get(c.id)).filter((r) => r !== undefined);
    const capped = ordered.length > room;
    const take = ordered.slice(0, Math.max(0, room));
    if (take.length > 0) {
      await this.prisma.ediscoverySearchHit.createMany({
        data: take.map((r) => ({
          searchId: s.id,
          organizationId: s.organizationId,
          messageId: big(r.message_id),
          messageReceivedAt: r.received_at,
          messagePublicId: r.message_public_id,
        })),
        skipDuplicates: true,
      });
    }
    return { stored: take.length, capped };
  }
}

export type { ArchiveSearchCriteria };
