import { z } from 'zod';
import type { QueryParams } from '@/lib/api/types';
import {
  DATE_TIME_RANGE_KINDS,
  isMinuteIso,
  isValidCustomRange,
  resolveDateTimeRange,
  type DateTimeRangeValue,
} from '@/lib/date-time-range';
import { SEARCH_FIELD_IDS, VALIDATORS, type SearchFieldId } from './search-fields';

/**
 * URL state of the Email Explorer and its single mapping to `GET /messages` (step 7.2 §2 E10,
 * §3.6). Every key falls back silently when its value is invalid (7.1 `useUrlState` + zod
 * `catch`). Pure: `explorerQuery(state, now)` is unit-tested for every filter.
 */

/** Enumerations of `GET /messages` (docs/api/openapi.json, MessagesController_list_v1). */
export const MESSAGE_DIRECTIONS = ['inbound', 'outbound', 'internal'] as const;
export const MESSAGE_STATUSES = [
  'received',
  'persisted',
  'scanning',
  'scanned',
  'scan_failed',
  'policy_evaluated',
  'approved',
  'quarantined',
  'held_for_review',
  'rejected',
  'delivery_pending',
  'delivery_retry',
  'delivered',
  'archived',
  'expired',
] as const;
export const MESSAGE_VERDICTS = [
  'clean',
  'spam',
  'bulk',
  'phishing',
  'malware',
  'bec',
  'dlp_violation',
  'suspicious',
  'unknown',
] as const;
export const MESSAGE_ACTIONS = [
  'deliver',
  'tag',
  'quarantine',
  'discard',
  'reject',
  'require_approval',
  'partial',
] as const;
export const DELIVERY_STATUSES = [
  'pending',
  'in_progress',
  'queued',
  'delivered',
  'deferred',
  'bounced',
  'failed',
  'suppressed',
  'expired',
  'unknown',
] as const;
export const QUARANTINE_STATUSES = [
  'held',
  'pending_approval',
  'releasing',
  'released',
  'rejected',
  'deleted',
  'expired',
  'superseded',
] as const;
export const MESSAGE_SORTS = ['-receivedAt', 'receivedAt'] as const;

/** Comma lists of `status`, `verdict`, `action` hold at most 5 values (API guide, Messages). */
export const MAX_LIST_VALUES = 5;
export const MAX_VERDICTS = MAX_LIST_VALUES;

/** Score bands offered as presets (labelled by numbers: risk levels are per profile version). */
export const RISK_BANDS = [
  { min: 0, max: 299 },
  { min: 300, max: 599 },
  { min: 600, max: 799 },
  { min: 800, max: 1000 },
] as const;

function enumList<T extends readonly [string, ...string[]]>(values: T, max: number) {
  return z
    .array(z.enum(values))
    .max(max)
    .transform((list) => [...new Set(list)])
    .default([])
    .catch([]);
}

const riskBound = z.coerce.number().int().min(0).max(1000).optional().catch(undefined);

/** A search value: valid for its field's validator, normalized; otherwise dropped. */
function searchValue(field: SearchFieldId) {
  return z
    .string()
    .transform((raw, ctx) => {
      const result = VALIDATORS[field](raw);
      if (!result.ok) {
        ctx.addIssue({ code: 'custom', message: result.message });
        return z.NEVER;
      }
      return result.value;
    })
    .optional()
    .catch(undefined);
}

const minuteIso = z.string().refine(isMinuteIso).optional().catch(undefined);

/** `?` keys of `/messages` (§3.6). */
export const EXPLORER_URL_SHAPE = {
  range: z.enum(DATE_TIME_RANGE_KINDS).default('24h').catch('24h'),
  from: minuteIso,
  to: minuteIso,
  direction: enumList(MESSAGE_DIRECTIONS, MESSAGE_DIRECTIONS.length),
  status: enumList(MESSAGE_STATUSES, MAX_LIST_VALUES),
  verdict: enumList(MESSAGE_VERDICTS, MAX_LIST_VALUES),
  action: enumList(MESSAGE_ACTIONS, MAX_LIST_VALUES),
  domainId: z.uuid().optional().catch(undefined),
  riskMin: riskBound,
  riskMax: riskBound,
  attachments: z.enum(['true', 'false']).optional().catch(undefined),
  /** Accepted alias of `attachments` (the 7.1 attachment page links `?hasAttachments=true`). */
  hasAttachments: z.enum(['true', 'false']).optional().catch(undefined),
  deliveryStatus: z.enum(DELIVERY_STATUSES).optional().catch(undefined),
  quarantineStatus: z.enum(QUARANTINE_STATUSES).optional().catch(undefined),
  sender: searchValue('sender'),
  headerFrom: searchValue('headerFrom'),
  recipient: searchValue('recipient'),
  subject: searchValue('subject'),
  subjectPrefix: searchValue('subjectPrefix'),
  messageId: searchValue('messageId'),
  senderDomain: searchValue('senderDomain'),
  recipientDomain: searchValue('recipientDomain'),
  sort: z.enum(MESSAGE_SORTS).default('-receivedAt').catch('-receivedAt'),
  view: z.uuid().optional().catch(undefined),
};

export type ExplorerState = {
  [K in keyof typeof EXPLORER_URL_SHAPE]: z.output<(typeof EXPLORER_URL_SHAPE)[K]>;
};
export type ExplorerPatch = Partial<{ [K in keyof ExplorerState]: ExplorerState[K] | undefined }>;

/** The default state (the explorer without any `?` key). */
export const DEFAULT_EXPLORER_STATE: ExplorerState = Object.fromEntries(
  Object.entries(EXPLORER_URL_SHAPE).map(([key, schema]) => [key, schema.parse(undefined)]),
) as ExplorerState;

/** The range of a state: a valid custom window, else the preset (an invalid custom → 24 h). */
export function rangeValueOf(
  state: Pick<ExplorerState, 'range' | 'from' | 'to'>,
): DateTimeRangeValue {
  if (state.range === 'custom') {
    return isValidCustomRange(state.from, state.to) && state.from && state.to
      ? { kind: 'custom', from: state.from, to: state.to }
      : { kind: '24h' };
  }
  return { kind: state.range };
}

/** URL patch of a range (`from`/`to` only with `custom`). */
export function rangePatch(value: DateTimeRangeValue): ExplorerPatch {
  return value.kind === 'custom'
    ? { range: 'custom', from: value.from, to: value.to }
    : { range: value.kind, from: undefined, to: undefined };
}

/** `GET /messages` parameter of each search field (`messageId` → `internetMessageId`). */
export const SEARCH_PARAMETER: Readonly<Record<SearchFieldId, string>> = {
  sender: 'sender',
  headerFrom: 'headerFrom',
  recipient: 'recipient',
  subject: 'subject',
  subjectPrefix: 'subjectPrefix',
  messageId: 'internetMessageId',
  senderDomain: 'senderDomain',
  recipientDomain: 'recipientDomain',
};

export type MessageListFilters = Omit<
  QueryParams<'MessagesController_list_v1'>,
  'from' | 'to' | 'sort' | 'limit' | 'cursor'
>;

/**
 * The filters of a state as `GET /messages` parameters (without range, sort, limit and cursor):
 * also the `filters` of a saved view's definition.
 */
export function explorerFilters(state: ExplorerState): MessageListFilters {
  const filters: Record<string, string> = {};
  if (state.direction.length > 0) filters.direction = state.direction.join(',');
  if (state.status.length > 0) filters.status = state.status.join(',');
  if (state.verdict.length > 0) filters.verdict = state.verdict.join(',');
  if (state.action.length > 0) filters.action = state.action.join(',');
  if (state.domainId) filters.domainId = state.domainId;
  if (state.riskMin !== undefined) filters['riskScore.gte'] = String(state.riskMin);
  if (state.riskMax !== undefined) filters['riskScore.lte'] = String(state.riskMax);
  const attachments = state.attachments ?? state.hasAttachments;
  if (attachments) filters.hasAttachments = attachments;
  if (state.deliveryStatus) filters.deliveryStatus = state.deliveryStatus;
  if (state.quarantineStatus) filters.quarantineStatus = state.quarantineStatus;
  for (const field of SEARCH_FIELD_IDS) {
    const value = state[field];
    if (value) filters[SEARCH_PARAMETER[field]] = value;
  }
  return filters;
}

/**
 * The single mapping of the explorer's URL state to `GET /messages` query parameters (§3.6):
 * the range resolved at `now` (presets end at the next whole minute; custom bounds as given),
 * the sort and every filter. `limit` and `cursor` are added by the cursor list.
 */
export function explorerQuery(
  state: ExplorerState,
  now: number,
): QueryParams<'MessagesController_list_v1'> {
  const window = resolveDateTimeRange(rangeValueOf(state), now);
  return { from: window.from, to: window.to, sort: state.sort, ...explorerFilters(state) };
}

/** Filters besides range, sort and view (filtered-empty state, "Clear filters"). */
export function hasExplorerFilters(state: ExplorerState): boolean {
  return Object.keys(explorerFilters(state)).length > 0;
}

export const CLEARED_EXPLORER_FILTERS: ExplorerPatch = {
  direction: [],
  status: [],
  verdict: [],
  action: [],
  domainId: undefined,
  riskMin: undefined,
  riskMax: undefined,
  attachments: undefined,
  hasAttachments: undefined,
  deliveryStatus: undefined,
  quarantineStatus: undefined,
  sender: undefined,
  headerFrom: undefined,
  recipient: undefined,
  subject: undefined,
  subjectPrefix: undefined,
  messageId: undefined,
  senderDomain: undefined,
  recipientDomain: undefined,
};

/**
 * Filter keys of the state that need a permission beyond `message:read` (§2 E2): the exact
 * recipient and the subject searches need `message:reveal` (they would confirm a masked value,
 * ADR-0062), the state filters their modules' read permissions.
 */
export const FILTER_PERMISSIONS: Readonly<
  Partial<Record<keyof ExplorerState, { readonly permission: string; readonly label: string }>>
> = {
  recipient: { permission: 'message:reveal', label: 'Recipient' },
  subject: { permission: 'message:reveal', label: 'Subject' },
  subjectPrefix: { permission: 'message:reveal', label: 'Subject starts with' },
  deliveryStatus: { permission: 'delivery:read', label: 'Delivery status' },
  quarantineStatus: { permission: 'quarantine:read', label: 'Quarantine status' },
};

/**
 * Drops the filters the user may not use (a shared link or an old view may carry them), so the
 * list never sends a request the api would refuse with `403 message_filter_forbidden`.
 */
export function permittedState(
  state: ExplorerState,
  has: (permission: string) => boolean,
): { state: ExplorerState; ignored: string[] } {
  const ignored: string[] = [];
  const next = { ...state };
  for (const [key, rule] of Object.entries(FILTER_PERMISSIONS)) {
    if (!rule || has(rule.permission)) continue;
    const field = key as keyof ExplorerState;
    if (next[field] !== undefined) {
      ignored.push(rule.label);
      (next as Record<string, unknown>)[field] = undefined;
    }
  }
  return { state: next, ignored };
}

/** Validation of the risk bounds shown inline (the api would return an empty list). */
export function riskBoundsError(state: Pick<ExplorerState, 'riskMin' | 'riskMax'>): string | null {
  if (state.riskMin !== undefined && state.riskMax !== undefined && state.riskMin > state.riskMax) {
    return 'The lowest risk score is above the highest.';
  }
  return null;
}
