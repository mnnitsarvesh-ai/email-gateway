import { z } from 'zod';
import type { QueryParams } from '@/lib/api/types';
import { RANGE_PRESETS, resolvePreset } from '@/lib/range';

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
export const MESSAGE_SORTS = ['-receivedAt', 'receivedAt'] as const;
/** The api accepts at most 5 values in a comma list of this list (API guide, Messages). */
export const MAX_VERDICTS = 5;

const riskBound = z.coerce.number().int().min(0).max(1000).optional().catch(undefined);
const address = z.string().trim().min(1).max(320).optional().catch(undefined);

/** URL state of the explorer (filters, range and sort live in the URL: design P8). */
export const EXPLORER_URL_SHAPE = {
  range: z.enum(RANGE_PRESETS).default('24h').catch('24h'),
  direction: z.enum(MESSAGE_DIRECTIONS).optional().catch(undefined),
  status: z.enum(MESSAGE_STATUSES).optional().catch(undefined),
  verdict: z.array(z.enum(MESSAGE_VERDICTS)).max(MAX_VERDICTS).default([]).catch([]),
  action: z.enum(MESSAGE_ACTIONS).optional().catch(undefined),
  sender: address,
  recipient: address,
  attachments: z.enum(['true', 'false']).optional().catch(undefined),
  riskMin: riskBound,
  riskMax: riskBound,
  sort: z.enum(MESSAGE_SORTS).default('-receivedAt').catch('-receivedAt'),
};

export type ExplorerState = {
  [K in keyof typeof EXPLORER_URL_SHAPE]: z.output<(typeof EXPLORER_URL_SHAPE)[K]>;
};

/** The filters besides range and sort (drives "Clear filters" and the filtered-empty state). */
export function hasExplorerFilters(state: ExplorerState): boolean {
  return Boolean(
    state.direction ||
    state.status ||
    state.verdict.length > 0 ||
    state.action ||
    state.sender ||
    state.recipient ||
    state.attachments ||
    state.riskMin !== undefined ||
    state.riskMax !== undefined,
  );
}

export const CLEARED_EXPLORER_FILTERS: Partial<ExplorerState> = {
  direction: undefined,
  status: undefined,
  verdict: [],
  action: undefined,
  sender: undefined,
  recipient: undefined,
  attachments: undefined,
  riskMin: undefined,
  riskMax: undefined,
};

/** Query parameters of `GET /messages` for a URL state (without limit and cursor). */
export function explorerQuery(
  state: ExplorerState,
  now = Date.now(),
): QueryParams<'MessagesController_list_v1'> {
  const window = resolvePreset(state.range, now);
  const query: QueryParams<'MessagesController_list_v1'> = {
    from: window.from,
    to: window.to,
    sort: state.sort,
  };
  if (state.direction) query.direction = state.direction;
  if (state.status) query.status = state.status;
  if (state.verdict.length > 0) query.verdict = state.verdict.join(',');
  if (state.action) query.action = state.action;
  if (state.sender) query.sender = state.sender;
  if (state.recipient) query.recipient = state.recipient;
  if (state.attachments) query.hasAttachments = state.attachments;
  if (state.riskMin !== undefined) query['riskScore.gte'] = String(state.riskMin);
  if (state.riskMax !== undefined) query['riskScore.lte'] = String(state.riskMax);
  return query;
}
