import type { ParsedFilter } from '../../../http/listing/list-query';
import type { MessageListFilters } from '../dto/message-data.schemas';

/**
 * Query plan of `GET /messages` (step 6.1 D5), chosen only by which filters are present:
 *
 * 1. `index`: no filter besides the range and the sort: keyset `(received_at, id)` over
 *    `(organization_id, received_at, id)` (MessagesRepository.listRecent).
 * 2. `verdict`: exactly one `verdict` value and nothing else: keyset over
 *    `email_messages_org_verdict_received_idx (organization_id, final_verdict, received_at, id)`.
 * 3. `recipient`: only `recipient` (exact address): keyset `(received_at, recipient id)` over
 *    `email_recipients (organization_id, address(100), received_at)`, then the messages by
 *    `(id, received_at)`; duplicates of one message on a page are collapsed.
 * 4. `scan`: every other filter or combination (several verdicts, the verdict or recipient
 *    filter combined with anything): the scan-bounded keyset of D5/D6 over the index of plan 1.
 */
export type MessageListPlan = 'index' | 'verdict' | 'recipient' | 'scan';

/** The filters that identify a person or a message (D11): their presence audits the search. */
export const IDENTIFYING_FILTERS = [
  'sender',
  'headerFrom',
  'recipient',
  'internetMessageId',
] as const;
export type IdentifyingFilter = (typeof IDENTIFYING_FILTERS)[number];

const present = (filter: ParsedFilter<unknown> | undefined): boolean =>
  filter !== undefined &&
  Object.values(filter).some(
    (value) => value !== undefined && (!Array.isArray(value) || value.length > 0),
  );

/** Names of the filters with a value, sorted. */
export function presentFilters(filters: MessageListFilters): string[] {
  return Object.entries(filters as Record<string, ParsedFilter<unknown> | undefined>)
    .filter(([, filter]) => present(filter))
    .map(([name]) => name)
    .sort();
}

export function selectMessagePlan(filters: MessageListFilters): MessageListPlan {
  const names = presentFilters(filters);
  if (names.length === 0) return 'index';
  if (names.length === 1 && names[0] === 'verdict' && filters.verdict?.values?.length === 1) {
    return 'verdict';
  }
  if (names.length === 1 && names[0] === 'recipient') return 'recipient';
  return 'scan';
}

/** The identifying filters of a request (audited when non-empty, first page only). */
export function identifyingFilters(filters: MessageListFilters): IdentifyingFilter[] {
  const names = new Set(presentFilters(filters));
  return IDENTIFYING_FILTERS.filter((name) => names.has(name));
}
