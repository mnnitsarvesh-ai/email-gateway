import type { ParsedFilter } from '../../../http/listing/list-query';
import type { MessageListFilters } from '../dto/message-data.schemas';
import { normalizeSubjectKey, normalizeSubjectPrefix } from './search-keys';

/**
 * Query plan of `GET /messages` (step 7.2 §2 E1, §3.2, ADR-0061; supersedes the four plans of
 * step 6.1 D5 / ADR-0051 decision 8), a pure function of which filters are present:
 *
 * - The **driver** is the first present filter in `DRIVER_PRIORITY` (most selective first); a
 *   `verdict` drives only with exactly one value. Its index is read in keyset order
 *   `(received_at, id)` after an equality on its key (`subjectPrefix`: a capped range).
 * - Every other present filter is a **residual**. Without residuals the driver's page is exact
 *   (`LIMIT limit + 1`, no budget). With residuals the step 6.1 two-step budget (D6) runs over
 *   the driver's index (`budgeted`). Without any driver but with residuals the driver is `scan`
 *   (the 6.1 scan-bounded plan over `(organization_id, received_at, id)`); without any filter it
 *   is `none` (the 6.1 index plan).
 * - `subjectPrefix` is never budgeted: its probe refuses more than
 *   `API_MESSAGES_SEARCH_MAX_MATCHES` matches, and its page sorts at most that many rows with the
 *   residuals applied.
 */
export const DRIVER_PRIORITY = [
  'internetMessageId',
  'sender',
  'headerFrom',
  'recipient',
  'subject',
  'senderDomain',
  'recipientDomain',
  'subjectPrefix',
  'quarantineStatus',
  'deliveryStatus',
  'verdict',
] as const;
export type FilterDriver = (typeof DRIVER_PRIORITY)[number];

/** `none`: no filter (6.1 index plan); `scan`: residual filters only (6.1 scan plan). */
export type MessageListDriver = FilterDriver | 'none' | 'scan';

/** Every driver, for metrics and tests. */
export const MESSAGE_LIST_DRIVERS: readonly MessageListDriver[] = [
  ...DRIVER_PRIORITY,
  'none',
  'scan',
];

/**
 * Where a driver's index lives: `messages` (an `email_messages` index), `recipient` (the 6.1
 * recipient address index, keyset `(received_at, recipient row id)`), `foreign` (an index of
 * another table grouped by `(time, message_id)`), `prefix` (the capped subject-key range).
 */
export type DriverKind = 'messages' | 'recipient' | 'foreign' | 'prefix';

export const DRIVER_KIND: Readonly<Record<MessageListDriver, DriverKind>> = Object.freeze({
  internetMessageId: 'messages',
  sender: 'messages',
  headerFrom: 'messages',
  recipient: 'recipient',
  subject: 'messages',
  senderDomain: 'messages',
  recipientDomain: 'foreign',
  subjectPrefix: 'prefix',
  quarantineStatus: 'foreign',
  deliveryStatus: 'foreign',
  verdict: 'messages',
  none: 'messages',
  scan: 'messages',
});

/** Names of the `GET /messages` filters (keys of the parsed query's `filters`). */
export type MessageListFilterName = Extract<keyof MessageListFilters, string>;

export interface MessageListPlan {
  driver: MessageListDriver;
  /** The present filters other than the driver's, sorted. */
  residuals: MessageListFilterName[];
  /** True when the scan budget bounds the page (residuals over a non-prefix driver). */
  budgeted: boolean;
}

/** The filters that identify a person, a message or content (D11): audited when present. */
export const IDENTIFYING_FILTERS = [
  'sender',
  'headerFrom',
  'recipient',
  'internetMessageId',
  'subject',
  'subjectPrefix',
] as const;
export type IdentifyingFilter = (typeof IDENTIFYING_FILTERS)[number];

/**
 * Filter-level permissions (§2 E2), checked before any read: a subject search is a content
 * oracle and an exact recipient search confirms a masked recipient address (both need
 * `message:reveal`, ADR-0062: a role that cannot see a value cannot probe it); the delivery and
 * quarantine state filters probe other modules' data (their read permissions). `recipientDomain`
 * stays open: the masked address keeps its domain in clear.
 */
export const FILTER_PERMISSIONS = Object.freeze({
  recipient: 'message:reveal',
  subject: 'message:reveal',
  subjectPrefix: 'message:reveal',
  deliveryStatus: 'delivery:read',
  quarantineStatus: 'quarantine:read',
} as const satisfies Partial<Record<MessageListFilterName, string>>);
export type GatedFilter = keyof typeof FILTER_PERMISSIONS;

const present = (filter: ParsedFilter<unknown> | undefined): boolean =>
  filter !== undefined &&
  Object.values(filter).some(
    (value) => value !== undefined && (!Array.isArray(value) || value.length > 0),
  );

/** Names of the filters with a value, sorted. */
export function presentFilters(filters: MessageListFilters): MessageListFilterName[] {
  return Object.entries(filters as Record<string, ParsedFilter<unknown> | undefined>)
    .filter(([, filter]) => present(filter))
    .map(([name]) => name as MessageListFilterName)
    .sort();
}

const drives = (name: FilterDriver, filters: MessageListFilters): boolean =>
  name !== 'verdict' || filters.verdict?.values?.length === 1;

export function selectMessagePlan(filters: MessageListFilters): MessageListPlan {
  const names = presentFilters(filters);
  const driver = DRIVER_PRIORITY.find(
    (name) => (names as string[]).includes(name) && drives(name, filters),
  );
  if (driver === undefined) {
    return names.length === 0
      ? { driver: 'none', residuals: [], budgeted: false }
      : { driver: 'scan', residuals: names, budgeted: true };
  }
  const residuals = names.filter((name) => name !== driver);
  return { driver, residuals, budgeted: residuals.length > 0 && driver !== 'subjectPrefix' };
}

/** The identifying filters of a request (audited when non-empty, first page only). */
export function identifyingFilters(filters: MessageListFilters): IdentifyingFilter[] {
  const names = new Set<string>(presentFilters(filters));
  return IDENTIFYING_FILTERS.filter((name) => names.has(name));
}

/**
 * The value an identifying filter's audit hash covers: the normalized subject key / prefix for
 * the subject filters (§2 E1: "SHA-256 of the normalized value"), the parsed value otherwise
 * (addresses lower-cased by the query schema, header From and Message-ID as given).
 */
export function identifyingValue(name: IdentifyingFilter, filters: MessageListFilters): string {
  const value = String(filters[name]?.values?.[0] ?? '');
  if (name === 'subject') return normalizeSubjectKey(value);
  if (name === 'subjectPrefix') return normalizeSubjectPrefix(value);
  return value;
}

/**
 * The first present filter whose permission the caller lacks (stable order of
 * `FILTER_PERMISSIONS`), or null. `403 message_filter_forbidden` names it.
 */
export function forbiddenFilter(
  filters: MessageListFilters,
  permissions: ReadonlySet<string>,
): { filter: GatedFilter; permission: string } | null {
  const names = new Set<string>(presentFilters(filters));
  for (const [filter, permission] of Object.entries(FILTER_PERMISSIONS) as [
    GatedFilter,
    string,
  ][]) {
    if (names.has(filter) && !permissions.has(permission)) return { filter, permission };
  }
  return null;
}

/**
 * The pseudo filter that binds the driver into the v1 cursor's filter hash (§2 E1 "Cursor
 * binding"): a cursor issued under one plan is `400 cursor_invalid` under another. `@` keeps it
 * apart from every real filter name (`/^[a-z]/`).
 */
export const DRIVER_BINDING_KEY = '@driver';

export const driverBinding = (
  driver: MessageListDriver,
): Record<typeof DRIVER_BINDING_KEY, ParsedFilter<string>> => ({
  [DRIVER_BINDING_KEY]: { values: [driver] },
});
