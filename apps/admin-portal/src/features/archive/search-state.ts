import { z } from 'zod';
import type { QueryParams, RequestBody } from '@/lib/api/types';
import {
  ARCHIVE_CATEGORIES,
  ARCHIVE_DIRECTIONS,
  ARCHIVE_FINAL_ACTIONS,
  ARCHIVE_RECORD_STATUSES,
  ARCHIVE_SEARCH_MAX_RANGE_DAYS,
  ARCHIVE_SOURCES,
  ARCHIVE_VERDICTS,
} from './model';

/**
 * Search state of the archive (`/archive`, step 8.1 A17 / §4.4 #15) and its two mappings: to the
 * query of `GET /archive/messages` and to the `archive-search/1` criteria of an eDiscovery case
 * search (A18). The range is whole UTC days (presets or a custom `from`/`to` day, `to`
 * inclusive). Every key falls back silently when its value is invalid (7.1 `useUrlState`). Pure:
 * `now` is passed in, so every mapping is unit-tested.
 *
 * Filters that would confirm a masked value (`recipient`, `subject`, `custodian`) need
 * `message:reveal`; `holdId` needs `archive:legal_hold` or `ediscovery:manage` (A17). The page
 * drops them for other callers (and says so) instead of sending a request the api refuses.
 */

export const ARCHIVE_RANGE_PRESETS = ['24h', '7d', '30d', '90d', '365d'] as const;
export type ArchiveRangePreset = (typeof ARCHIVE_RANGE_PRESETS)[number];
export const ARCHIVE_RANGE_KINDS = [...ARCHIVE_RANGE_PRESETS, 'custom'] as const;
export const RANGE_LABEL: Readonly<Record<(typeof ARCHIVE_RANGE_KINDS)[number], string>> = {
  '24h': 'Last 24 hours',
  '7d': 'Last 7 days',
  '30d': 'Last 30 days',
  '90d': 'Last 90 days',
  '365d': 'Last 365 days',
  custom: 'Custom days',
};
const PRESET_MS: Readonly<Record<ArchiveRangePreset, number>> = {
  '24h': 86_400_000,
  '7d': 7 * 86_400_000,
  '30d': 30 * 86_400_000,
  '90d': 90 * 86_400_000,
  '365d': 365 * 86_400_000,
};
export const ARCHIVE_SORTS = ['-receivedAt', 'receivedAt'] as const;
const DAY_MS = 86_400_000;
const HOUR_MS = 3_600_000;

const DAY = /^\d{4}-\d{2}-\d{2}$/;
export const isDay = (value: string | undefined): value is string =>
  typeof value === 'string' && DAY.test(value) && !Number.isNaN(Date.parse(`${value}T00:00:00Z`));

const EMAIL = /^[^\s@<>()",;]+@[^\s@<>()",;]+\.[^\s@<>()",;]+$/;
const DOMAIN = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$/i;
const SHA256 = /^[0-9a-f]{64}$/i;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function enumList<T extends readonly [string, ...string[]]>(values: T) {
  return z
    .array(z.enum(values))
    .max(values.length)
    .transform((list) => [...new Set(list)])
    .default([])
    .catch([]);
}
const optionalText = (max: number, pattern?: RegExp) =>
  z
    .string()
    .trim()
    .min(1)
    .max(max)
    .refine((v) => !pattern || pattern.test(v))
    .optional()
    .catch(undefined);
const bool = z.enum(['true', 'false']).optional().catch(undefined);
const riskBound = z.coerce.number().int().min(0).max(1000).optional().catch(undefined);
const day = z.string().refine(isDay).optional().catch(undefined);

/** `?` keys of `/archive`. */
export const ARCHIVE_URL_SHAPE = {
  range: z.enum(ARCHIVE_RANGE_KINDS).default('7d').catch('7d'),
  from: day,
  to: day,
  direction: enumList(ARCHIVE_DIRECTIONS),
  category: enumList(ARCHIVE_CATEGORIES),
  source: enumList(ARCHIVE_SOURCES),
  status: enumList(ARCHIVE_RECORD_STATUSES),
  verdict: enumList(ARCHIVE_VERDICTS),
  finalAction: enumList(ARCHIVE_FINAL_ACTIONS),
  sender: optionalText(320, EMAIL),
  senderDomain: optionalText(253, DOMAIN),
  recipient: optionalText(320, EMAIL),
  recipientDomain: optionalText(253, DOMAIN),
  subject: optionalText(256),
  custodian: optionalText(320, EMAIL),
  internetMessageId: optionalText(998),
  attachmentName: optionalText(256),
  attachmentSha256: optionalText(64, SHA256),
  hasAttachments: bool,
  malicious: bool,
  legalHold: bool,
  holdId: z.string().regex(UUID).optional().catch(undefined),
  riskMin: riskBound,
  riskMax: riskBound,
  sort: z.enum(ARCHIVE_SORTS).default('-receivedAt').catch('-receivedAt'),
};

export type ArchiveSearchState = {
  [K in keyof typeof ARCHIVE_URL_SHAPE]: z.output<(typeof ARCHIVE_URL_SHAPE)[K]>;
};
export type ArchiveSearchPatch = Partial<{
  [K in keyof ArchiveSearchState]: ArchiveSearchState[K] | undefined;
}>;

export const DEFAULT_ARCHIVE_STATE: ArchiveSearchState = Object.fromEntries(
  Object.entries(ARCHIVE_URL_SHAPE).map(([key, schema]) => [key, schema.parse(undefined)]),
) as ArchiveSearchState;

/** Text filters with their labels and validation messages (the filter form). */
export const TEXT_FILTERS = [
  { id: 'sender', label: 'Sender address', kind: 'email', reveal: false },
  { id: 'senderDomain', label: 'Sender domain', kind: 'domain', reveal: false },
  { id: 'recipient', label: 'Recipient address', kind: 'email', reveal: true },
  { id: 'recipientDomain', label: 'Recipient domain', kind: 'domain', reveal: false },
  { id: 'custodian', label: 'Custodian (sender or recipient)', kind: 'email', reveal: true },
  { id: 'subject', label: 'Subject phrase', kind: 'text', reveal: true },
  { id: 'internetMessageId', label: 'Message-ID', kind: 'text', reveal: false },
  { id: 'attachmentName', label: 'Attachment name', kind: 'text', reveal: false },
  { id: 'attachmentSha256', label: 'Attachment SHA-256', kind: 'sha256', reveal: false },
] as const;
export type TextFilterId = (typeof TEXT_FILTERS)[number]['id'];
export const REVEAL_FILTERS: readonly TextFilterId[] = TEXT_FILTERS.filter((f) => f.reveal).map(
  (f) => f.id,
);

/** Validates one text filter value (`null` = valid). */
export function textFilterError(kind: string, value: string): string | null {
  const v = value.trim();
  if (!v) return null;
  if (kind === 'email' && !EMAIL.test(v)) return 'Enter a complete email address';
  if (kind === 'domain' && !DOMAIN.test(v)) return 'Enter a domain such as example.com';
  if (kind === 'sha256' && !SHA256.test(v)) return 'Enter 64 hexadecimal characters';
  return null;
}

export interface ArchiveFilterCapabilities {
  /** `message:reveal`: recipient, subject and custodian filters. */
  readonly reveal: boolean;
  /** `archive:legal_hold` or `ediscovery:manage`: the `holdId` filter. */
  readonly holds: boolean;
}

/** Drops filters the caller may not use; names the dropped ones (shown as a notice). */
export function permittedArchiveState(
  state: ArchiveSearchState,
  can: ArchiveFilterCapabilities,
): { state: ArchiveSearchState; ignored: string[] } {
  const next = { ...state };
  const ignored: string[] = [];
  if (!can.reveal) {
    for (const id of REVEAL_FILTERS) {
      if (next[id] !== undefined) {
        ignored.push(id);
        next[id] = undefined;
      }
    }
  }
  if (!can.holds && next.holdId !== undefined) {
    ignored.push('holdId');
    next.holdId = undefined;
  }
  return { state: next, ignored };
}

/** The UTC window of a state: `[from 00:00, to + 1 day 00:00)` or the preset ending this hour. */
export function rangeOf(
  state: Pick<ArchiveSearchState, 'range' | 'from' | 'to'>,
  now: number,
  maxDays = ARCHIVE_SEARCH_MAX_RANGE_DAYS,
): { from: string; to: string } {
  if (state.range === 'custom' && customRangeError(state.from, state.to, maxDays) === null) {
    return {
      from: `${state.from}T00:00:00.000Z`,
      to: new Date(Date.parse(`${state.to}T00:00:00.000Z`) + DAY_MS).toISOString(),
    };
  }
  const preset: ArchiveRangePreset = state.range === 'custom' ? '7d' : state.range;
  const to = Math.ceil(now / HOUR_MS) * HOUR_MS;
  return {
    from: new Date(to - PRESET_MS[preset]).toISOString(),
    to: new Date(to).toISOString(),
  };
}

/** Validation of a custom day range (`null` = valid). */
export function customRangeError(
  from: string | undefined,
  to: string | undefined,
  maxDays = ARCHIVE_SEARCH_MAX_RANGE_DAYS,
): string | null {
  if (!isDay(from) || !isDay(to)) return 'Choose both days';
  const start = Date.parse(`${from}T00:00:00Z`);
  const end = Date.parse(`${to}T00:00:00Z`) + DAY_MS;
  if (end <= start) return 'The last day must not be before the first day';
  if (end - start > maxDays * DAY_MS) return `Choose at most ${maxDays} days`;
  return null;
}

/** `riskMin` > `riskMax` (`null` = valid). */
export function riskError(state: Pick<ArchiveSearchState, 'riskMin' | 'riskMax'>): string | null {
  return state.riskMin !== undefined && state.riskMax !== undefined && state.riskMin > state.riskMax
    ? 'The minimum risk score must not exceed the maximum'
    : null;
}

export type ArchiveSearchQuery = QueryParams<'ArchiveMessagesController_list_v1'>;

/** The query of `GET /archive/messages` (without `limit` and `cursor`). */
export function archiveSearchQuery(state: ArchiveSearchState, now: number): ArchiveSearchQuery {
  const range = rangeOf(state, now);
  const query: Record<string, string> = { from: range.from, to: range.to, sort: state.sort };
  const list = (key: string, values: readonly string[]) => {
    if (values.length > 0) query[key] = values.join(',');
  };
  list('direction', state.direction);
  list('category', state.category);
  list('source', state.source);
  list('status', state.status);
  list('verdict', state.verdict);
  list('finalAction', state.finalAction);
  for (const filter of TEXT_FILTERS) {
    const value = state[filter.id];
    if (value) query[filter.id] = value;
  }
  if (state.hasAttachments) query.hasAttachments = state.hasAttachments;
  if (state.malicious) query.malicious = state.malicious;
  if (state.legalHold) query.legalHold = state.legalHold;
  if (state.holdId) query.holdId = state.holdId;
  if (riskError(state) === null) {
    if (state.riskMin !== undefined) query['riskScore.gte'] = String(state.riskMin);
    if (state.riskMax !== undefined) query['riskScore.lte'] = String(state.riskMax);
  }
  return query as ArchiveSearchQuery;
}

/** Whether any filter other than range and sort is set. */
export function hasArchiveFilters(state: ArchiveSearchState): boolean {
  return Object.entries(state).some(([key, value]) => {
    if (key === 'range' || key === 'from' || key === 'to' || key === 'sort') return false;
    return Array.isArray(value) ? value.length > 0 : value !== undefined;
  });
}

/** Patch clearing every filter (range and sort kept). */
export const CLEARED_ARCHIVE_FILTERS: ArchiveSearchPatch = Object.fromEntries(
  Object.keys(ARCHIVE_URL_SHAPE)
    .filter((key) => !['range', 'from', 'to', 'sort'].includes(key))
    .map((key) => [key, undefined]),
);

export type CaseSearchCriteria = RequestBody<'EdiscoverySearchesController_create_v1'>['criteria'];

/**
 * The `archive-search/1` criteria of a case search (A18) from the same filter state. Days are
 * sent as dates (whole UTC days, `to` inclusive); `custodians: 'case'` searches the case's
 * custodians (WP4 D11: allowed without `message:reveal`).
 */
export function caseSearchCriteria(
  state: ArchiveSearchState,
  options: { useCaseCustodians: boolean; now: number },
): CaseSearchCriteria {
  const range =
    state.range === 'custom' && isDay(state.from) && isDay(state.to)
      ? { from: state.from, to: state.to }
      : (() => {
          const r = rangeOf(state, options.now);
          return { from: r.from.slice(0, 10), to: r.to.slice(0, 10) };
        })();
  const criteria: CaseSearchCriteria = { from: range.from, to: range.to };
  if (state.direction.length > 0) criteria.directions = [...state.direction];
  if (state.category.length > 0) criteria.categories = [...state.category];
  if (state.source.length > 0) criteria.sources = [...state.source];
  if (state.status.length > 0) criteria.statuses = [...state.status];
  if (state.verdict.length > 0) criteria.verdicts = [...state.verdict];
  if (state.finalAction.length > 0) criteria.finalActions = [...state.finalAction];
  if (state.sender) criteria.senders = [state.sender];
  if (state.senderDomain) criteria.senderDomains = [state.senderDomain];
  if (state.recipient) criteria.recipients = [state.recipient];
  if (state.recipientDomain) criteria.recipientDomains = [state.recipientDomain];
  if (options.useCaseCustodians) criteria.custodians = 'case';
  else if (state.custodian) criteria.custodians = [state.custodian];
  if (state.subject) criteria.subject = state.subject;
  if (state.internetMessageId) criteria.internetMessageId = state.internetMessageId;
  if (state.attachmentName) criteria.attachmentName = state.attachmentName;
  if (state.attachmentSha256) criteria.attachmentSha256 = [state.attachmentSha256.toLowerCase()];
  if (state.hasAttachments) criteria.hasAttachments = state.hasAttachments === 'true';
  if (state.malicious) criteria.malicious = state.malicious === 'true';
  if (state.holdId) criteria.holdId = state.holdId;
  if (riskError(state) === null) {
    if (state.riskMin !== undefined) criteria.riskScoreGte = state.riskMin;
    if (state.riskMax !== undefined) criteria.riskScoreLte = state.riskMax;
  }
  return criteria;
}
