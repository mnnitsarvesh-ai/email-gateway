import { z } from 'zod';
import { defineListQuery } from '../../http/listing/list-query';
import { MessageListQuerySchema } from '../messages/dto/message-data.schemas';

/**
 * Saved explorer views (step 7.2 §2 E4, §3.3, ADR-0061 decision 7): request and response shapes
 * of `/saved-views`. A view is the caller's own, per organization and kind (`message_explorer`
 * only); its `definition` is strict and validated by the service with the real `GET /messages`
 * query schema and the filter-level permissions.
 */

export const SAVED_VIEW_KINDS = ['message_explorer'] as const;
export type SavedViewKind = (typeof SAVED_VIEW_KINDS)[number];

/** v1 cursor resource (keyset `id` desc). */
export const SAVED_VIEWS_RESOURCE = 'saved_views';

/** Bounds of a definition (§3.3). */
export const SAVED_VIEW_LIMITS = Object.freeze({
  nameMaxLength: 80,
  maxFilters: 24,
  filterValueMaxLength: 998,
  maxColumns: 24,
  definitionMaxBytes: 8192,
});

/** Range presets of the explorer (§2 E10). */
export const SAVED_VIEW_PRESETS = ['1h', '24h', '7d', '30d'] as const;

/** `GET /messages` parameters that are not filters (never stored in `definition.filters`). */
export const NON_FILTER_PARAMETERS = ['limit', 'cursor', 'sort', 'from', 'to'] as const;

const isoInstant = z.iso.datetime({ offset: true });

const RangeSchema = z.discriminatedUnion('kind', [
  z.strictObject({
    kind: z.literal('relative'),
    preset: z.enum(SAVED_VIEW_PRESETS),
  }),
  z.strictObject({
    kind: z.literal('absolute'),
    from: isoInstant,
    to: isoInstant,
  }),
]);

const COLUMN_ID = /^[a-zA-Z][a-zA-Z0-9]{0,31}$/;
/** A `GET /messages` parameter name (`riskScore.gte` included); the query schema checks it. */
const FILTER_KEY = /^[a-z][A-Za-z0-9]{0,39}(?:\.[a-z]{2,3})?$/;

/** The structural definition (§3.3); the service adds the semantic checks. */
export const SavedViewDefinitionSchema = z.strictObject({
  version: z.literal(1),
  filters: z
    .record(
      z.string().regex(FILTER_KEY, 'must be a GET /messages parameter name'),
      z.string().min(1).max(SAVED_VIEW_LIMITS.filterValueMaxLength),
    )
    .refine((filters) => Object.keys(filters).length <= SAVED_VIEW_LIMITS.maxFilters, {
      message: `may hold at most ${SAVED_VIEW_LIMITS.maxFilters} filters`,
    })
    .describe(
      '`GET /messages` query parameters (except `limit`, `cursor`, `sort`, `from`, `to`) and ' +
        'their values as strings, e.g. `{ "verdict": "phishing,malware", "senderDomain": ' +
        '"example.com" }`',
    ),
  sort: z.enum(['-receivedAt', 'receivedAt']),
  range: RangeSchema.describe(
    '`{ kind: "relative", preset }` (1h, 24h, 7d, 30d) or `{ kind: "absolute", from, to }` ' +
      '(ISO 8601, at most API_MESSAGES_MAX_RANGE_DAYS days)',
  ),
  columns: z
    .array(z.string().regex(COLUMN_ID, 'must be a column id'))
    .max(SAVED_VIEW_LIMITS.maxColumns)
    .refine((columns) => new Set(columns).size === columns.length, {
      message: 'must not repeat a column',
    })
    .nullable()
    .describe('Visible explorer columns in order, or null for the default set'),
});
export type SavedViewDefinition = z.output<typeof SavedViewDefinitionSchema>;

const NameSchema = z
  .string()
  .trim()
  .min(1)
  .max(SAVED_VIEW_LIMITS.nameMaxLength)
  .regex(/^[^\p{Cc}]*$/u, 'must not contain control characters');

export const CreateSavedViewBodySchema = z.strictObject({
  kind: z.enum(SAVED_VIEW_KINDS),
  name: NameSchema,
  definition: SavedViewDefinitionSchema,
});
export type CreateSavedViewBody = z.output<typeof CreateSavedViewBodySchema>;

export const UpdateSavedViewBodySchema = z.strictObject({
  name: NameSchema,
  definition: SavedViewDefinitionSchema,
  expectedRowVersion: z.number().int().min(1).describe('`rowVersion` of the view you edited'),
});
export type UpdateSavedViewBody = z.output<typeof UpdateSavedViewBodySchema>;

export const SavedViewIdSchema = z.uuid();

/** `GET /saved-views`: `kind` (required), `limit`, `cursor`, `sort=-createdAt`. */
export const SavedViewListQuerySchema = defineListQuery({
  filters: { kind: { type: 'enum', values: SAVED_VIEW_KINDS } },
  sorts: ['-createdAt'],
  defaultSort: '-createdAt',
}).superRefine((query, ctx) => {
  if (query.filters.kind?.values?.[0] === undefined) {
    ctx.addIssue({ code: 'custom', path: ['kind'], message: 'Required' });
  }
});
export type SavedViewListQuery = z.output<typeof SavedViewListQuerySchema>;

export const SAVED_VIEW_LIST_PARAMETERS: Record<string, string> = {
  kind: '`message_explorer` (required; the only kind)',
  limit: 'Page size, 1-100 (default 25)',
  cursor: '`nextCursor` of the previous page',
  sort: '`-createdAt` (the only order: newest first)',
};

const IsoDate = z.iso.datetime();

export const SavedViewSchema = z.object({
  id: z.uuid().describe('Saved view public id'),
  kind: z.enum(SAVED_VIEW_KINDS),
  name: z.string(),
  definition: SavedViewDefinitionSchema,
  rowVersion: z.number().int().min(1).describe('Optimistic concurrency token of PUT'),
  createdAt: IsoDate,
  updatedAt: IsoDate,
});
export type SavedView = z.output<typeof SavedViewSchema>;

export const SavedViewPageSchema = z.object({
  data: z.array(SavedViewSchema),
  nextCursor: z.string().nullable(),
});
export type SavedViewPage = z.output<typeof SavedViewPageSchema>;

/** A violation of the definition rules (paths under `definition`, never values). */
export interface DefinitionIssue {
  path: string;
  message: string;
}

const DAY_MS = 86_400_000;

/**
 * The semantic checks of a structurally valid definition (§3.3): the filters and sort parse with
 * the real `GET /messages` query schema (unknown parameter or bad value → issues under
 * `definition.filters`), no non-filter parameter among the filters, an absolute range that is
 * ordered and at most `maxRangeDays`, and the serialized JSON within 8 192 bytes.
 */
export function definitionIssues(
  definition: SavedViewDefinition,
  maxRangeDays: number,
): DefinitionIssue[] {
  const issues: DefinitionIssue[] = [];
  for (const key of Object.keys(definition.filters)) {
    if ((NON_FILTER_PARAMETERS as readonly string[]).includes(key)) {
      issues.push({ path: `definition.filters.${key}`, message: 'is not a filter' });
    }
  }
  if (issues.length === 0) {
    const parsed = MessageListQuerySchema.safeParse({
      ...definition.filters,
      sort: definition.sort,
    });
    if (!parsed.success) {
      for (const issue of parsed.error.issues) {
        const [head, ...rest] = issue.path.map(String);
        const path =
          head === undefined
            ? 'definition.filters'
            : head === 'sort'
              ? 'definition.sort'
              : ['definition.filters', head, ...rest].join('.');
        issues.push({ path, message: issue.message });
      }
    }
  }
  if (definition.range.kind === 'absolute') {
    const from = Date.parse(definition.range.from);
    const to = Date.parse(definition.range.to);
    if (from >= to) issues.push({ path: 'definition.range.from', message: 'must be before to' });
    else if (to - from > maxRangeDays * DAY_MS) {
      issues.push({
        path: 'definition.range.to',
        message: `the range may cover at most ${maxRangeDays} days`,
      });
    }
  }
  const bytes = Buffer.byteLength(JSON.stringify(definition), 'utf8');
  if (bytes > SAVED_VIEW_LIMITS.definitionMaxBytes) {
    issues.push({
      path: 'definition',
      message: `must be at most ${SAVED_VIEW_LIMITS.definitionMaxBytes} bytes as JSON`,
    });
  }
  return issues;
}

const EXAMPLE_DEFINITION: SavedViewDefinition = {
  version: 1,
  filters: { verdict: 'phishing,malware', direction: 'inbound', senderDomain: 'example.com' },
  sort: '-receivedAt',
  range: { kind: 'relative', preset: '7d' },
  columns: ['receivedAt', 'from', 'subject', 'verdict', 'riskScore'],
};

const EXAMPLE_VIEW: SavedView = {
  id: '01930c2e-7d1a-7000-8000-0000000005a1',
  kind: 'message_explorer',
  name: 'Inbound phishing, last 7 days',
  definition: EXAMPLE_DEFINITION,
  rowVersion: 1,
  createdAt: '2026-11-14T09:12:44.512Z',
  updatedAt: '2026-11-14T09:12:44.512Z',
};

/** Explicit OpenAPI examples (6.1 D14: every new route). */
export const SAVED_VIEW_EXAMPLES = {
  view: EXAMPLE_VIEW,
  page: { data: [EXAMPLE_VIEW], nextCursor: null } satisfies SavedViewPage,
  create: {
    kind: 'message_explorer',
    name: 'Inbound phishing, last 7 days',
    definition: EXAMPLE_DEFINITION,
  } satisfies CreateSavedViewBody,
  update: {
    name: 'Inbound phishing and malware, last 7 days',
    definition: { ...EXAMPLE_DEFINITION, columns: null },
    expectedRowVersion: 1,
  } satisfies UpdateSavedViewBody,
};
