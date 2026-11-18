import { createHash } from 'node:crypto';
import { canonicalJson } from '../documents/canonical';
import type { ArchiveSearchCriteria } from '../documents/search';
import { type HoldSearchCriteria, holdBound } from '../holds/matcher';
import { isUuid, type NumericId } from '../ids';
import { messageIdKey } from './document';
import { organizationTerm } from './names';

/**
 * The only builder of archive search queries (§4.3, A17, ADR-0068). Every query:
 *
 * - filters on the organization term **and** a bounded `received_at` range (in addition to the
 *   tenant alias the caller searches through);
 * - refuses reveal-gated filters (`recipients`, `subject`, `custodians`) without
 *   `permissions.reveal`, and `holdId` without `permissions.holds`, with a typed error raised
 *   before any query is sent;
 * - sorts by `received_at` then `message_id`, pages with `search_after`, asks for `limit + 1`
 *   hits (the extra one tells whether a next page exists), never counts totals and returns only
 *   the listed `_source` fields.
 */

export type ArchiveSearchQueryErrorCode =
  | 'archive_filter_forbidden'
  | 'archive_search_range_invalid'
  | 'hold_unresolved'
  | 'case_custodians_unresolved'
  | 'cursor_invalid';

export class ArchiveSearchQueryError extends Error {
  constructor(
    readonly code: ArchiveSearchQueryErrorCode,
    /** The filter concerned (a name, never a value). */
    readonly filter: string | null = null,
  ) {
    super(filter ? `${code} (${filter})` : code);
    this.name = 'ArchiveSearchQueryError';
  }
}

/** Filters: `archive-search/1` plus `legalHold` of `GET /archive/messages`. */
export type ArchiveSearchFilters = ArchiveSearchCriteria & { legalHold?: boolean };

/** Fields the search responses read (`_source.includes`). */
export const ARCHIVE_SEARCH_SOURCE_FIELDS = Object.freeze([
  'org_id',
  'message_id',
  'received_at',
  'captured_at',
  'direction',
  'category',
  'sources',
  'status',
  'envelope_from',
  'header_from',
  'recipients',
  'subject',
  'message_id_key',
  'size_bytes',
  'attachment_count',
  'attachment_names',
  'verdict',
  'final_action',
  'risk_score',
  'malicious',
  'retain_until',
  'legal_hold',
  'lock_mode',
] as const);

/** Filters that would confirm a masked value (ADR-0062 decision 6). */
export const REVEAL_GATED_FILTERS = Object.freeze(['recipients', 'subject', 'custodians'] as const);

export type SearchAfter = [number, string];

export interface ArchiveSearchQueryInput {
  organizationId: NumericId;
  criteria: ArchiveSearchFilters;
  sort?: 'receivedAt' | '-receivedAt';
  /** 1 … 1 000 (the api allows 1 … 100; case searches page larger). */
  limit: number;
  searchAfter?: SearchAfter | null;
  permissions: { reveal: boolean; holds: boolean };
  /** The hold named by `holdId`, resolved by the caller inside the organization. */
  hold?: HoldSearchCriteria | null;
  /** The case's custodians when `custodians = 'case'`. */
  caseCustodians?: readonly string[] | null;
  /** OpenSearch `timeout` (ms). */
  timeoutMs?: number;
}

type Clause = Record<string, unknown>;

const lower = (values: readonly string[]) => [
  ...new Set(values.map((v) => v.trim().toLowerCase())),
];

function bound(value: string, end: boolean): number {
  const t = holdBound(value, end);
  if (!Number.isFinite(t)) throw new ArchiveSearchQueryError('archive_search_range_invalid');
  return t;
}

function partyClause(addresses: readonly string[]): Clause {
  const list = lower(addresses);
  return {
    bool: {
      should: [
        { terms: { envelope_from: list } },
        { terms: { header_from: list } },
        { terms: { recipients: list } },
      ],
      minimum_should_match: 1,
    },
  };
}

/** Validates a `search_after` value: `[receivedAtMs, messagePublicId]`. */
export function parseSearchAfter(value: unknown): SearchAfter | null {
  if (!Array.isArray(value) || value.length !== 2) return null;
  const [ms, id] = value as unknown[];
  if (typeof ms !== 'number' || !Number.isSafeInteger(ms) || ms < 0) return null;
  if (!isUuid(id)) return null;
  return [ms, id];
}

/** Compact cursor value `<receivedAtMs>.<messageId>` (wrapped by the api's signed v1 cursor). */
export function encodeSearchAfter(value: SearchAfter): string {
  const parsed = parseSearchAfter(value);
  if (parsed === null) throw new ArchiveSearchQueryError('cursor_invalid');
  return `${parsed[0]}.${parsed[1]}`;
}

export function decodeSearchAfter(value: string): SearchAfter {
  const m = typeof value === 'string' ? /^(0|[1-9][0-9]{0,15})\.(.+)$/.exec(value) : null;
  const parsed = m ? parseSearchAfter([Number(m[1]), m[2]]) : null;
  if (parsed === null) throw new ArchiveSearchQueryError('cursor_invalid');
  return parsed;
}

/** The `search_after` of a hit (its `sort` values), null when malformed. */
export function searchAfterOfHit(hit: { sort?: unknown }): SearchAfter | null {
  return parseSearchAfter(hit.sort);
}

/** SHA-256 of the canonical filters (cursor binding and the `archive.searched` audit). */
export function searchFilterHash(criteria: ArchiveSearchFilters): string {
  return createHash('sha256').update(canonicalJson(criteria), 'utf8').digest('hex');
}

/** Names of the filters present (audit metadata: names only, never values). */
export function searchFilterNames(criteria: ArchiveSearchFilters): string[] {
  return Object.keys(criteria)
    .filter((k) => (criteria as Record<string, unknown>)[k] !== undefined)
    .sort();
}

export function buildArchiveSearchQuery(input: ArchiveSearchQueryInput): Record<string, unknown> {
  const c = input.criteria;
  const org = organizationTerm(input.organizationId);
  if (!Number.isInteger(input.limit) || input.limit < 1 || input.limit > 1_000) {
    throw new RangeError('limit must be 1 … 1 000');
  }
  // Permission gates first: nothing is built for a forbidden filter.
  if (!input.permissions.reveal) {
    for (const f of REVEAL_GATED_FILTERS) {
      if (c[f] !== undefined) throw new ArchiveSearchQueryError('archive_filter_forbidden', f);
    }
  }
  if (c.holdId !== undefined && !input.permissions.holds) {
    throw new ArchiveSearchQueryError('archive_filter_forbidden', 'holdId');
  }
  const from = bound(c.from, false);
  const to = bound(c.to, true);
  if (from > to) throw new ArchiveSearchQueryError('archive_search_range_invalid');

  const filter: Clause[] = [
    { term: { org_id: org } },
    {
      range: {
        received_at: {
          gte: new Date(from).toISOString(),
          lte: new Date(to).toISOString(),
          format: 'strict_date_optional_time',
        },
      },
    },
  ];
  const terms = (field: string, values: readonly string[] | undefined, normalize = false) => {
    if (values !== undefined)
      filter.push({ terms: { [field]: normalize ? lower(values) : [...values] } });
  };
  terms('direction', c.directions);
  terms('category', c.categories);
  terms('sources', c.sources);
  terms('status', c.statuses);
  if (c.senders !== undefined) {
    const list = lower(c.senders);
    filter.push({
      bool: {
        should: [{ terms: { envelope_from: list } }, { terms: { header_from: list } }],
        minimum_should_match: 1,
      },
    });
  }
  terms('sender_domain', c.senderDomains, true);
  terms('recipients', c.recipients, true);
  terms('recipient_domains', c.recipientDomains, true);
  if (c.custodians !== undefined) {
    const list = c.custodians === 'case' ? input.caseCustodians : c.custodians;
    if (list === undefined || list === null) {
      throw new ArchiveSearchQueryError('case_custodians_unresolved', 'custodians');
    }
    // A case without custodians matches nothing (never everything).
    filter.push(
      list.length === 0 ? { bool: { must_not: [{ match_all: {} }] } } : partyClause(list),
    );
  }
  if (c.subject !== undefined) {
    filter.push({ match_phrase: { subject: { query: c.subject } } });
  }
  if (c.internetMessageId !== undefined) {
    filter.push({ term: { message_id_key: messageIdKey(c.internetMessageId) ?? '' } });
  }
  if (c.hasAttachments !== undefined) {
    filter.push(
      c.hasAttachments
        ? { range: { attachment_count: { gte: 1 } } }
        : { term: { attachment_count: 0 } },
    );
  }
  if (c.attachmentName !== undefined) {
    filter.push({ match_phrase: { attachment_names: { query: c.attachmentName } } });
  }
  terms('attachment_sha256', c.attachmentSha256, true);
  terms('verdict', c.verdicts);
  terms('final_action', c.finalActions);
  if (c.riskScoreGte !== undefined || c.riskScoreLte !== undefined) {
    filter.push({
      range: {
        risk_score: {
          ...(c.riskScoreGte !== undefined ? { gte: c.riskScoreGte } : {}),
          ...(c.riskScoreLte !== undefined ? { lte: c.riskScoreLte } : {}),
        },
      },
    });
  }
  if (c.malicious !== undefined) filter.push({ term: { malicious: c.malicious } });
  if (c.legalHold !== undefined) filter.push({ term: { legal_hold: c.legalHold } });
  if (c.holdId !== undefined) {
    const hold = input.hold;
    if (hold === undefined || hold === null) {
      throw new ArchiveSearchQueryError('hold_unresolved', 'holdId');
    }
    if (!hold.matchAll) {
      if (hold.custodians.length > 0) filter.push(partyClause(hold.custodians));
      if (hold.from !== null || hold.to !== null) {
        filter.push({
          range: {
            received_at: {
              ...(hold.from ? { gte: hold.from.toISOString() } : {}),
              ...(hold.to ? { lte: hold.to.toISOString() } : {}),
              format: 'strict_date_optional_time',
            },
          },
        });
      }
      if (hold.directions.length > 0) filter.push({ terms: { direction: hold.directions } });
    }
  }

  const order = input.sort === 'receivedAt' ? 'asc' : 'desc';
  const body: Record<string, unknown> = {
    size: input.limit + 1,
    track_total_hits: false,
    query: { bool: { filter } },
    sort: [{ received_at: { order } }, { message_id: { order } }],
    _source: { includes: [...ARCHIVE_SEARCH_SOURCE_FIELDS] },
  };
  if (input.searchAfter !== undefined && input.searchAfter !== null) {
    const after = parseSearchAfter(input.searchAfter);
    if (after === null) throw new ArchiveSearchQueryError('cursor_invalid');
    body.search_after = after;
  }
  if (input.timeoutMs !== undefined) body.timeout = `${Math.max(1, Math.floor(input.timeoutMs))}ms`;
  return body;
}

/** Count query of one UTC day of an organization (index reconciliation, A15). */
export function buildDayCountQuery(
  organizationId: NumericId,
  day: string,
): Record<string, unknown> {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(day))
    throw new ArchiveSearchQueryError('archive_search_range_invalid');
  const from = bound(day, false);
  const to = bound(day, true);
  return {
    query: {
      bool: {
        filter: [
          { term: { org_id: organizationTerm(organizationId) } },
          {
            range: {
              received_at: {
                gte: new Date(from).toISOString(),
                lte: new Date(to).toISOString(),
                format: 'strict_date_optional_time',
              },
            },
          },
        ],
      },
    },
  };
}

/** `_delete_by_query` body of an organization purge (send with `routing` = the organization). */
export function buildOrganizationPurgeQuery(organizationId: NumericId): Record<string, unknown> {
  return { query: { bool: { filter: [{ term: { org_id: organizationTerm(organizationId) } }] } } };
}
