import { z } from 'zod';
import type { RequestBody, SuccessBody } from '@/lib/api/types';
import { MESSAGES_MAX_RANGE_DAYS } from '@/lib/date-time-range';
import {
  EXPLORER_URL_SHAPE,
  FILTER_PERMISSIONS,
  explorerFilters,
  rangeValueOf,
  type ExplorerPatch,
  type ExplorerState,
} from './explorer-state';

/**
 * Saved explorer views (step 7.2 §2 E4, §3.3; ADR-0061): the strict request schemas of the forms
 * (validated against the OpenAPI request schemas by the contract helper in tests), the
 * definition built from the explorer state, and applying a definition back to the URL state and
 * column set (an outdated view applies what it can and lists the rest).
 */
export type SavedView = SuccessBody<'SavedViewsController_get_v1'>;
export type SavedViewDefinition = SavedView['definition'];

export const SAVED_VIEW_KIND = 'message_explorer' as const;
/** Page size of the views list: one page holds every view (`SAVED_VIEWS_MAX_PER_USER` ≤ 200). */
export const SAVED_VIEWS_PAGE_SIZE = '100';

/** A view name: trimmed, 1–80 characters, no control characters (the api's rule). */
export const viewNameSchema = z
  .string()
  .trim()
  .min(1, 'Enter a name.')
  .max(80, 'Use at most 80 characters.')
  // eslint-disable-next-line no-control-regex -- the api refuses control characters
  .refine((value) => !/[\u0000-\u001f\u007f-\u009f]/.test(value), 'Remove control characters.');

const isoDateTime = z.iso.datetime({ offset: true });
const COLUMN_ID = /^[a-zA-Z][a-zA-Z0-9]{0,31}$/;

export const savedViewDefinitionSchema = z
  .object({
    version: z.literal(1),
    filters: z
      .record(z.string(), z.string().min(1).max(998))
      .refine((filters) => Object.keys(filters).length <= 24, 'At most 24 filters.'),
    sort: z.enum(['-receivedAt', 'receivedAt']),
    range: z.discriminatedUnion('kind', [
      z
        .object({ kind: z.literal('relative'), preset: z.enum(['1h', '24h', '7d', '30d']) })
        .strict(),
      z.object({ kind: z.literal('absolute'), from: isoDateTime, to: isoDateTime }).strict(),
    ]),
    columns: z.array(z.string().regex(COLUMN_ID)).max(24).nullable(),
  })
  .strict();

/** `POST /saved-views` body (strict, mirrors the request schema). */
export const createSavedViewSchema = z
  .object({
    kind: z.literal(SAVED_VIEW_KIND),
    name: viewNameSchema,
    definition: savedViewDefinitionSchema,
  })
  .strict();

/** `PUT /saved-views/{viewId}` body (strict). */
export const updateSavedViewSchema = z
  .object({
    name: viewNameSchema,
    definition: savedViewDefinitionSchema,
    expectedRowVersion: z.number().int().min(1),
  })
  .strict();

/** The name dialogs' form (name only). */
export const viewNameFormSchema = z.object({ name: viewNameSchema }).strict();

export function createViewBody(
  name: string,
  definition: SavedViewDefinition,
): RequestBody<'SavedViewsController_create_v1'> {
  return createSavedViewSchema.parse({ kind: SAVED_VIEW_KIND, name, definition });
}

export function updateViewBody(
  view: Pick<SavedView, 'rowVersion'>,
  name: string,
  definition: SavedViewDefinition,
): RequestBody<'SavedViewsController_update_v1'> {
  return updateSavedViewSchema.parse({ name, definition, expectedRowVersion: view.rowVersion });
}

/** The definition of the current explorer state and column set (`null` = default columns). */
export function definitionFromState(
  state: ExplorerState,
  columns: readonly string[] | null,
): SavedViewDefinition {
  const range = rangeValueOf(state);
  return {
    version: 1,
    filters: { ...explorerFilters(state) },
    sort: state.sort,
    range:
      range.kind === 'custom'
        ? { kind: 'absolute', from: range.from, to: range.to }
        : { kind: 'relative', preset: range.kind },
    columns: columns ? [...columns] : null,
  };
}

/** Stable comparison key of a definition (filter order and column order ignored). */
export function definitionKey(definition: SavedViewDefinition): string {
  const filters = Object.keys(definition.filters)
    .sort()
    .map((key) => [key, definition.filters[key]]);
  return JSON.stringify([
    filters,
    definition.sort,
    definition.range,
    definition.columns ? [...definition.columns].sort() : null,
  ]);
}

/**
 * `GET /messages` parameter → explorer URL key. Parameters the explorer does not offer
 * (`riskScore`, `riskScore.gt`, `riskScore.lt`) are not applied.
 */
const PARAMETER_TO_KEY: Readonly<Record<string, keyof ExplorerState>> = {
  direction: 'direction',
  status: 'status',
  verdict: 'verdict',
  action: 'action',
  domainId: 'domainId',
  'riskScore.gte': 'riskMin',
  'riskScore.lte': 'riskMax',
  hasAttachments: 'attachments',
  deliveryStatus: 'deliveryStatus',
  quarantineStatus: 'quarantineStatus',
  sender: 'sender',
  headerFrom: 'headerFrom',
  recipient: 'recipient',
  subject: 'subject',
  subjectPrefix: 'subjectPrefix',
  internetMessageId: 'messageId',
  senderDomain: 'senderDomain',
  recipientDomain: 'recipientDomain',
};

const ARRAY_KEYS = new Set<keyof ExplorerState>(['direction', 'status', 'verdict', 'action']);

export interface AppliedView {
  /** URL patch: every filter key (cleared unless the view sets it), range, sort and `view`. */
  readonly patch: ExplorerPatch;
  /** Column ids to show (`null`: the default set). */
  readonly columns: readonly string[] | null;
  /** Human descriptions of the settings that no longer apply (outdated view). */
  readonly skipped: string[];
}

/**
 * Applies a saved definition: each filter is parsed with the URL schema (an invalid or
 * unsupported value is skipped), filters needing a permission the user lacks are skipped, an
 * absolute range longer than the api allows falls back to 24 h, unknown columns are dropped.
 */
export function applyDefinition(
  view: Pick<SavedView, 'id' | 'definition'>,
  has: (permission: string) => boolean,
  knownColumns: readonly string[],
  now: number,
): AppliedView {
  const skipped: string[] = [];
  const patch: Record<string, unknown> = {};
  for (const key of Object.values(PARAMETER_TO_KEY)) {
    patch[key] = ARRAY_KEYS.has(key) ? [] : undefined;
  }
  patch.hasAttachments = undefined;
  const definition = view.definition;
  for (const [parameter, raw] of Object.entries(definition.filters ?? {})) {
    const key = PARAMETER_TO_KEY[parameter];
    if (!key) {
      skipped.push(`the filter ${parameter} (not offered by the explorer)`);
      continue;
    }
    const rule = FILTER_PERMISSIONS[key];
    if (rule && !has(rule.permission)) {
      skipped.push(`the filter ${rule.label} (needs ${rule.permission})`);
      continue;
    }
    const schema = EXPLORER_URL_SHAPE[key];
    const input = ARRAY_KEYS.has(key) ? String(raw).split(',').filter(Boolean) : String(raw);
    const parsed = schema.safeParse(input);
    const value = parsed.success ? parsed.data : undefined;
    const empty = value === undefined || (Array.isArray(value) && value.length === 0);
    if (empty || (Array.isArray(value) && Array.isArray(input) && value.length < input.length)) {
      skipped.push(`the filter ${parameter} (its value is no longer valid)`);
      if (empty) continue;
    }
    patch[key] = value;
  }
  const range = definition.range;
  if (range.kind === 'relative') {
    Object.assign(patch, { range: range.preset, from: undefined, to: undefined });
  } else {
    const from = Date.parse(range.from);
    const to = Date.parse(range.to);
    const valid =
      Number.isFinite(from) &&
      Number.isFinite(to) &&
      to > from &&
      to - from <= MESSAGES_MAX_RANGE_DAYS * 86_400_000 &&
      from <= now;
    if (valid) {
      Object.assign(patch, {
        range: 'custom',
        from: new Date(from - (from % 60_000)).toISOString(),
        to: new Date(to - (to % 60_000)).toISOString(),
      });
    } else {
      skipped.push('its time range (replaced by the last 24 hours)');
      Object.assign(patch, { range: '24h', from: undefined, to: undefined });
    }
  }
  patch.sort = definition.sort;
  patch.view = view.id;
  let columns: string[] | null = null;
  if (definition.columns) {
    columns = definition.columns.filter((id) => knownColumns.includes(id));
    const unknown = definition.columns.filter((id) => !knownColumns.includes(id));
    if (unknown.length > 0) skipped.push(`the columns ${unknown.join(', ')}`);
  }
  return { patch: patch, columns, skipped };
}
