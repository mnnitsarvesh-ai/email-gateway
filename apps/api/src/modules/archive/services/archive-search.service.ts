import { BadRequestException, Inject, Injectable, Logger } from '@nestjs/common';
import {
  type ArchiveSearchFilters,
  ArchiveSearchQueryError,
  buildArchiveSearchQuery,
  holdToSearchCriteria,
  parseSearchAfter,
  type SearchAfter,
  searchAfterOfHit,
  searchFilterHash,
  searchFilterNames,
} from '@email-gateway/archive';
import { AuditService } from '../../../audit/audit.service';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { API_CONFIG } from '../../../api-config.token';
import { CursorCodec, cursorInvalid } from '../../../http/cursor/cursor-codec';
import {
  decodeListCursor,
  encodeListCursor,
  listBinding,
  sha256Hex,
} from '../../messages/domain/v1-list';
import {
  ARCHIVE_AUDIT,
  ARCHIVE_CURSOR_RESOURCES,
  ARCHIVE_PERMISSIONS as P,
  ARCHIVE_RESOURCE,
  type ArchiveConfig,
} from '../archive.constants';
import {
  archiveFilterForbidden,
  archiveSearchRangeInvalid,
  legalHoldNotFound,
} from '../archive.errors';
import { messageViewOfSource } from '../domain/archive-views';
import type { ArchiveMessagePage, ArchiveSearchQuery } from '../dto/archive.schemas';
import { ArchiveRecordsRepository } from '../repositories/archive-records.repository';
import { secondsBetween } from './archive-common';
import { ArchiveMetrics } from './archive-metrics';
import { ArchiveSearchClient } from './archive-search.client';

const DAY_MS = 86_400_000;
const SHA256 = /^[0-9a-fA-F]{64}$/;

/** Query parameter name of a library filter (refusals name what the caller sent). */
const PARAMETER_OF: Record<string, string> = {
  recipients: 'recipient',
  subject: 'subject',
  custodians: 'custodian',
  holdId: 'holdId',
};

/** Filters whose values identify people or messages: audited as SHA-256 only (6.1 D11). */
const IDENTIFYING = [
  'senders',
  'recipients',
  'custodians',
  'subject',
  'internetMessageId',
  'attachmentName',
  'attachmentSha256',
  'senderDomains',
  'recipientDomains',
] as const;

export interface ArchiveSearchResult {
  page: ArchiveMessagePage;
  /** `X-EG-Index-Lag-Seconds`: age of the organization's oldest queued index op. */
  lagSeconds: number;
}

/**
 * `GET /archive/messages` (step 8.1 §4.4 #15; A17, ADR-0068): metadata search through the
 * tenant alias with the query of `buildArchiveSearchQuery` (organization term, bounded range,
 * allow-listed filters, `search_after` paging, no totals). Filters that would confirm a masked
 * value (`recipient`, `subject`, `custodian`) need `message:reveal` and `holdId` needs
 * `archive:legal_hold` or `ediscovery:manage`: refused with `403 archive_filter_forbidden`
 * before any query. Results are masked for every caller. The signed v1 cursor (`archive_messages`)
 * wraps the `search_after` position and is bound to the filters, the range, the sort and the
 * organization. The first page is audited (`archive.searched`: filter names, filter hash,
 * hashes of identifying values, result count; never values).
 */
@Injectable()
export class ArchiveSearchService {
  private readonly logger = new Logger(ArchiveSearchService.name);

  constructor(
    @Inject(API_CONFIG)
    private readonly config: Pick<
      ArchiveConfig,
      'ARCHIVE_SEARCH_MAX_RANGE_DAYS' | 'ARCHIVE_SEARCH_TIMEOUT_MS'
    >,
    private readonly client: ArchiveSearchClient,
    private readonly records: ArchiveRecordsRepository,
    private readonly audit: AuditService,
    private readonly codec: CursorCodec,
    private readonly metrics: ArchiveMetrics,
  ) {}

  now(): Date {
    return new Date();
  }

  async search(
    principal: Principal,
    scope: TenantScope,
    query: ArchiveSearchQuery,
    sourceIp: string | null,
  ): Promise<ArchiveSearchResult> {
    if (query.from === undefined || query.to === undefined) {
      throw new BadRequestException([
        ...(query.from === undefined ? ['from: Required'] : []),
        ...(query.to === undefined ? ['to: Required'] : []),
      ]);
    }
    const maxDays = this.config.ARCHIVE_SEARCH_MAX_RANGE_DAYS;
    if (
      query.from.getTime() > query.to.getTime() ||
      query.to.getTime() - query.from.getTime() > maxDays * DAY_MS
    ) {
      this.metrics.searches.inc({ result: 'invalid' });
      throw archiveSearchRangeInvalid(maxDays);
    }
    const criteria = this.criteriaOf(query);
    const permissions = {
      reveal: principal.permissions.has(P.reveal),
      holds: principal.permissions.has(P.legalHold) || principal.permissions.has(P.ediscovery),
    };
    // Permission gates first: a forbidden filter never reaches a cursor check or a query.
    for (const name of ['recipients', 'subject', 'custodians'] as const) {
      if (criteria[name] !== undefined && !permissions.reveal) {
        this.metrics.searches.inc({ result: 'forbidden_filter' });
        throw archiveFilterForbidden(PARAMETER_OF[name]!);
      }
    }
    if (criteria.holdId !== undefined && !permissions.holds) {
      this.metrics.searches.inc({ result: 'forbidden_filter' });
      throw archiveFilterForbidden('holdId');
    }
    const binding = listBinding({
      resource: ARCHIVE_CURSOR_RESOURCES.messages,
      principal,
      filters: { ...query.filters, range: { gte: query.from, lte: query.to } },
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 2);
    let searchAfter: SearchAfter | null = null;
    if (decoded) {
      const ms = Number(decoded.keys[0]);
      searchAfter = parseSearchAfter([ms, decoded.keys[1]]);
      if (searchAfter === null) throw cursorInvalid();
    }
    let hold = null;
    if (criteria.holdId !== undefined) {
      const holds = await this.records.activeHolds(scope);
      const found = holds.find((h) => h.publicId === criteria.holdId);
      if (found === undefined) throw legalHoldNotFound();
      hold = holdToSearchCriteria(found.criteria, found.criteriaVersion);
    }
    let body: Record<string, unknown>;
    try {
      body = buildArchiveSearchQuery({
        organizationId: scope.organizationId,
        criteria,
        sort: query.sort === 'receivedAt' ? 'receivedAt' : '-receivedAt',
        limit: query.limit,
        searchAfter,
        permissions,
        hold,
        timeoutMs: this.config.ARCHIVE_SEARCH_TIMEOUT_MS,
      });
    } catch (error) {
      if (error instanceof ArchiveSearchQueryError) {
        if (error.code === 'archive_filter_forbidden') {
          throw archiveFilterForbidden(PARAMETER_OF[error.filter ?? ''] ?? error.filter ?? '-');
        }
        if (error.code === 'cursor_invalid') throw cursorInvalid();
        throw archiveSearchRangeInvalid(maxDays);
      }
      throw error;
    }
    const started = process.hrtime.bigint();
    let hits;
    try {
      hits = (await this.client.search(scope.organizationId, body)).hits;
    } catch (error) {
      this.metrics.searches.inc({ result: 'unavailable' });
      throw error;
    } finally {
      this.metrics.searchDuration.observe(Number(process.hrtime.bigint() - started) / 1e9);
    }
    // Defence in depth: the alias filters by tenant, the query too; a foreign doc is never served.
    const own = hits.filter((h) => {
      const ok = h._source?.org_id === scope.organizationId.toString();
      if (!ok) this.logger.error({ message: 'archive search returned a foreign document' });
      return ok;
    });
    const page = own.slice(0, query.limit);
    const data = page
      .map((h) => (h._source ? messageViewOfSource(h._source) : null))
      .filter((v): v is NonNullable<typeof v> => v !== null);
    const last = page.at(-1);
    const next = hits.length > query.limit && last ? searchAfterOfHit(last) : null;
    if (query.cursor === undefined) {
      await this.audit.record({
        organizationId: scope.organizationId,
        actor: this.audit.actorFrom(principal),
        action: ARCHIVE_AUDIT.searched,
        resourceType: ARCHIVE_RESOURCE.message,
        resourceId: '-',
        sourceIp,
        metadata: {
          filterNames: searchFilterNames(criteria),
          filterHash: searchFilterHash(criteria),
          valueHashes: this.valueHashes(criteria),
          resultCount: data.length,
          sort: query.sort,
        },
      });
    }
    this.metrics.searches.inc({ result: 'ok' });
    const oldest = await this.records.oldestIndexOpAt(scope);
    return {
      page: {
        data,
        nextCursor:
          next === null ? null : encodeListCursor(this.codec, binding, [String(next[0]), next[1]]),
      },
      lagSeconds: secondsBetween(oldest, this.now()),
    };
  }

  /** The `archive-search/1`-shaped filters of the query (plus `legalHold`). */
  private criteriaOf(query: ArchiveSearchQuery): ArchiveSearchFilters {
    const f = query.filters;
    const first = <T>(v: { values?: T[] } | undefined): T | undefined => v?.values?.[0];
    const sha = f.attachmentSha256?.values;
    if (sha !== undefined && sha.some((v) => !SHA256.test(v))) {
      throw new BadRequestException(['attachmentSha256: must be SHA-256 values (64 hex)']);
    }
    const risk = f.riskScore;
    const eq = risk?.values?.[0];
    const criteria: ArchiveSearchFilters = {
      from: query.from!.toISOString(),
      to: query.to!.toISOString(),
      ...(f.direction?.values && { directions: [...f.direction.values] }),
      ...(f.category?.values && { categories: [...f.category.values] }),
      ...(f.source?.values && { sources: [...f.source.values] }),
      ...(f.status?.values && { statuses: [...f.status.values] }),
      ...(first(f.sender) !== undefined && { senders: [first(f.sender)!] }),
      ...(first(f.senderDomain) !== undefined && { senderDomains: [first(f.senderDomain)!] }),
      ...(first(f.recipient) !== undefined && { recipients: [first(f.recipient)!] }),
      ...(first(f.recipientDomain) !== undefined && {
        recipientDomains: [first(f.recipientDomain)!],
      }),
      ...(first(f.custodian) !== undefined && { custodians: [first(f.custodian)!] }),
      ...(first(f.subject) !== undefined && { subject: first(f.subject)! }),
      ...(first(f.internetMessageId) !== undefined && {
        internetMessageId: first(f.internetMessageId)!,
      }),
      ...(first(f.hasAttachments) !== undefined && { hasAttachments: first(f.hasAttachments)! }),
      ...(first(f.attachmentName) !== undefined && { attachmentName: first(f.attachmentName)! }),
      ...(sha && { attachmentSha256: sha.map((v) => v.toLowerCase()) }),
      ...(f.verdict?.values && { verdicts: [...f.verdict.values] }),
      ...(f.finalAction?.values && { finalActions: [...f.finalAction.values] }),
      ...((risk?.gte ?? risk?.gt ?? eq) !== undefined && {
        riskScoreGte: risk?.gte ?? (risk?.gt !== undefined ? risk.gt + 1 : eq),
      }),
      ...((risk?.lte ?? risk?.lt ?? eq) !== undefined && {
        riskScoreLte: risk?.lte ?? (risk?.lt !== undefined ? risk.lt - 1 : eq),
      }),
      ...(first(f.malicious) !== undefined && { malicious: first(f.malicious)! }),
      ...(first(f.legalHold) !== undefined && { legalHold: first(f.legalHold)! }),
      ...(first(f.holdId) !== undefined && { holdId: first(f.holdId)!.toLowerCase() }),
    };
    return criteria;
  }

  /** SHA-256 of each identifying value (audit metadata never holds the value, D11). */
  private valueHashes(criteria: ArchiveSearchFilters): Record<string, string[]> {
    const out: Record<string, string[]> = {};
    for (const name of IDENTIFYING) {
      const value = criteria[name];
      if (value === undefined) continue;
      const values = Array.isArray(value) ? value : [value];
      out[name] = values.map((v) => sha256Hex(String(v).trim().toLowerCase()));
    }
    return out;
  }
}
