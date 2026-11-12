import {
  APPROVAL_REASONS,
  BULK_ACTIONS,
  ENTRY_ACTIONS,
  pageSchema,
  QUARANTINE_APPROVAL_KINDS,
  QUARANTINE_APPROVAL_STATUSES,
  QUARANTINE_DIRECTIONS,
  QUARANTINE_DOWNLOAD_OBJECTS,
  QUARANTINE_ENTRY_KINDS,
  QUARANTINE_ERROR_CODES,
  QUARANTINE_ORIGINS,
  QUARANTINE_PRIMARY_ENGINES,
  QUARANTINE_REASONS,
  QUARANTINE_RELEASE_MODES,
  QUARANTINE_RELEASE_STATUSES,
  QUARANTINE_RISK_LEVELS,
  QUARANTINE_STATES,
  quarantineApprovalViewSchema,
  quarantineEntryDetailSchema,
  quarantineEntrySummarySchema,
  quarantineReleaseViewSchema,
  quarantineSettingsSchema,
  effectiveQuarantineTenantSettingsSchema,
  SELF_RELEASE_MAX_LEVELS,
  SELF_RELEASE_REASONS,
  BULK_ITEM_STATUSES,
} from '@email-gateway/quarantine';
import { quarantinePreviewSchema } from '@email-gateway/mail-safety';
import { z } from 'zod';

/**
 * Request and response shapes of the quarantine routes (step 5.3 Q26). The entry, release and
 * approval DTOs come from `@email-gateway/quarantine` (frontend-ready, shared with the portal);
 * this file adds the query strings, bodies and the route-specific envelopes.
 */

export const EntryIdSchema = z.uuid();
export const ApprovalIdSchema = z.uuid();
export const ReleaseIdSchema = z.uuid();

const IsoDate = z.iso.datetime({ offset: true });
const Reason = z
  .string()
  .trim()
  .min(1)
  .max(512)
  .describe('Why the caller acts (stored in quarantine_actions.reason; never in audit metadata)');

/** Comma-separated or repeated query values (`state=held,pending_approval` or `state=held&state=…`). */
const list = <T extends readonly [string, ...string[]]>(values: T) =>
  z
    .union([z.string(), z.array(z.string())])
    .transform((v) =>
      (Array.isArray(v) ? v : [v])
        .flatMap((s) => s.split(','))
        .map((s) => s.trim())
        .filter(Boolean),
    )
    .pipe(z.array(z.enum(values)).min(1).max(values.length))
    .optional();

const booleanQuery = z
  .enum(['true', 'false'])
  .transform((v) => v === 'true')
  .optional();

const lowerAddress = z
  .string()
  .trim()
  .min(3)
  .max(320)
  .regex(/^[^\s@]+@[^\s@]+$/, 'must be an email address')
  .transform((v) => v.toLowerCase());

const Limit = z.coerce.number().int().min(1).optional();

/** `GET /quarantine/entries` (Q9). `from`/`to` bound `quarantined_at` and are required. */
export const EntrySearchQuerySchema = z
  .strictObject({
    from: IsoDate.describe('Inclusive lower bound of quarantinedAt (required)'),
    to: IsoDate.describe(
      'Exclusive upper bound of quarantinedAt (required; to - from ≤ the max range)',
    ),
    state: list(QUARANTINE_STATES),
    kind: z.enum(QUARANTINE_ENTRY_KINDS).optional(),
    direction: z.enum(QUARANTINE_DIRECTIONS).optional(),
    reason: list(QUARANTINE_REASONS),
    riskLevel: list(QUARANTINE_RISK_LEVELS),
    minRiskLevel: z.enum(QUARANTINE_RISK_LEVELS).optional(),
    primaryEngine: list(QUARANTINE_PRIMARY_ENGINES),
    policyId: z.uuid().optional().describe('Decisive policy public id'),
    ruleId: z.string().trim().min(1).max(48).optional(),
    sender: lowerAddress
      .optional()
      .describe('Exact envelope sender (index `(organization_id, envelope_from, quarantined_at)`)'),
    headerFrom: lowerAddress
      .optional()
      .describe('Exact header From address (no dedicated index: filtered within the range)'),
    senderDomain: z
      .string()
      .trim()
      .min(1)
      .max(253)
      .regex(/^[A-Za-z0-9.-]+$/, 'must be a domain name')
      .transform((v) => v.toLowerCase())
      .optional()
      .describe('Envelope sender domain (filtered within the range)'),
    recipient: lowerAddress.optional().describe('Exact recipient address'),
    hasAttachments: booleanQuery,
    hasHardBlock: booleanQuery,
    messageId: z.uuid().optional().describe('Message public id'),
    cursor: z.string().min(1).max(512).optional(),
    limit: Limit.describe('Page size (default 50, at most QUARANTINE_SEARCH_MAX_PAGE_SIZE)'),
  })
  .refine((q) => !(q.riskLevel !== undefined && q.minRiskLevel !== undefined), {
    message: 'use either riskLevel or minRiskLevel',
    path: ['minRiskLevel'],
  });
export type EntrySearchQuery = z.output<typeof EntrySearchQuerySchema>;

/** `GET /quarantine/me/entries` (Q15: the search subset of the end user). */
export const SelfSearchQuerySchema = z.strictObject({
  from: IsoDate,
  to: IsoDate,
  state: list(QUARANTINE_STATES),
  reason: list(QUARANTINE_REASONS),
  cursor: z.string().min(1).max(512).optional(),
  limit: Limit,
});
export type SelfSearchQuery = z.output<typeof SelfSearchQuerySchema>;

export const SummaryQuerySchema = z.strictObject({ from: IsoDate, to: IsoDate });
export type SummaryQuery = z.output<typeof SummaryQuerySchema>;

export const ApprovalListQuerySchema = z.strictObject({
  status: list(QUARANTINE_APPROVAL_STATUSES),
  kind: list(QUARANTINE_APPROVAL_KINDS),
  from: IsoDate.optional().describe('Inclusive lower bound of requestedAt'),
  to: IsoDate.optional().describe('Exclusive upper bound of requestedAt'),
  cursor: z.string().min(1).max(512).optional(),
  limit: Limit,
});
export type ApprovalListQuery = z.output<typeof ApprovalListQuerySchema>;

// ---- Bodies -----------------------------------------------------------------------------------

export const ReleaseBodySchema = z.strictObject({
  reason: Reason,
  expectedRowVersion: z.number().int().min(1).max(4_294_967_295).optional(),
});
export type ReleaseBody = z.output<typeof ReleaseBodySchema>;

export const ReasonBodySchema = z.strictObject({ reason: Reason });
export type ReasonBody = z.output<typeof ReasonBodySchema>;

export const RejectBodySchema = z.strictObject({
  reason: Reason,
  notifySender: z
    .boolean()
    .optional()
    .describe(
      'Outbound/internal entries only (never inbound: no backscatter); default notices.senderOnReject',
    ),
  expectedRowVersion: z.number().int().min(1).max(4_294_967_295).optional(),
});
export type RejectBody = z.output<typeof RejectBodySchema>;

export const DeleteBodySchema = z.strictObject({
  reason: Reason,
  expectedRowVersion: z.number().int().min(1).max(4_294_967_295).optional(),
});
export type DeleteBody = z.output<typeof DeleteBodySchema>;

export const ManualQuarantineBodySchema = z.strictObject({
  messageId: z.uuid().describe('Message public id'),
  rcptSeqs: z
    .array(z.number().int().min(0).max(65_535))
    .min(1)
    .max(1000)
    .refine((v) => new Set(v).size === v.length, 'Duplicate rcptSeq')
    .optional()
    .describe('Recipients to quarantine (default: every eligible recipient)'),
  reason: Reason,
});
export type ManualQuarantineBody = z.output<typeof ManualQuarantineBodySchema>;

export const DownloadGrantBodySchema = z
  .strictObject({
    object: z.enum(QUARANTINE_DOWNLOAD_OBJECTS),
    partIndex: z.number().int().min(0).max(65_535).optional(),
    password: z.string().min(1).max(1024).describe('The caller’s password (re-authorization)'),
    totpCode: z
      .string()
      .regex(/^[0-9]{6}$/)
      .optional()
      .describe('Required when the caller has MFA enrolled'),
  })
  .refine((b) => (b.object === 'attachment') === (b.partIndex !== undefined), {
    message: 'partIndex is required for an attachment and refused for the EML',
    path: ['partIndex'],
  });
export type DownloadGrantBody = z.output<typeof DownloadGrantBodySchema>;

export const SettingsUpdateBodySchema = z.strictObject({
  settings: z.unknown().describe('The quarantine settings document (Q24; every key optional)'),
  expectedRowVersion: z
    .number()
    .int()
    .min(0)
    .max(4_294_967_295)
    .describe('rowVersion of GET /quarantine/settings (0 when no row exists yet)'),
});
export type SettingsUpdateBody = z.output<typeof SettingsUpdateBodySchema>;

export const PreferencesBodySchema = z.strictObject({ digestOptOut: z.boolean() });
export type PreferencesBody = z.output<typeof PreferencesBodySchema>;

export const BulkBodySchema = z.strictObject({
  action: z.enum(BULK_ACTIONS),
  ids: z.array(z.uuid()).describe('Entry ids (approval request ids for approve/deny)'),
  reason: Reason,
  notifySender: z.boolean().optional(),
});

// ---- Responses --------------------------------------------------------------------------------

export const EntryPageSchema = pageSchema(quarantineEntrySummarySchema, 500);
export const ApprovalPageSchema = pageSchema(quarantineApprovalViewSchema, 500);
export const EntryDetailSchema = quarantineEntryDetailSchema;
export const ApprovalViewSchema = quarantineApprovalViewSchema;
export const PreviewSchema = quarantinePreviewSchema;

export const HistoryResponseSchema = z.strictObject({
  actions: z
    .array(
      z.strictObject({
        action: z.string().max(32),
        actor: z.strictObject({
          type: z.enum(['system', 'user', 'api_key']),
          id: z.string().max(64).nullable(),
        }),
        result: z.string().max(64).nullable(),
        reason: z.string().max(512).nullable().describe('Operator-typed reason (operator actions)'),
        at: z.iso.datetime(),
      }),
    )
    .max(500),
  releases: z.array(quarantineReleaseViewSchema).max(100),
});
export type HistoryResponse = z.output<typeof HistoryResponseSchema>;

export const ReleaseDetailSchema = quarantineReleaseViewSchema.extend({
  entryIds: z.array(z.uuid()).min(1).max(1000),
});
export type ReleaseDetail = z.output<typeof ReleaseDetailSchema>;

export const ReleaseOutcomeSchema = z.discriminatedUnion('outcome', [
  z.strictObject({
    outcome: z.literal('queued'),
    entryId: z.uuid(),
    state: z.literal('releasing'),
    releaseId: z.uuid().describe('GET /quarantine/releases/{releaseId}'),
    rowVersion: z.number().int(),
  }),
  z.strictObject({
    outcome: z.literal('approval_requested'),
    entryId: z.uuid(),
    state: z.literal('pending_approval'),
    approvalRequestId: z.uuid(),
    approvalReasons: z.array(z.enum(APPROVAL_REASONS)),
    rowVersion: z.number().int(),
  }),
]);
export type ReleaseOutcome = z.output<typeof ReleaseOutcomeSchema>;

export const EntryStateResponseSchema = z.strictObject({
  entryId: z.uuid(),
  state: z.enum(QUARANTINE_STATES),
  rowVersion: z.number().int(),
  messageTransition: z
    .enum(['E16', 'E17', 'E18', 'E29'])
    .nullable()
    .describe('The lifecycle edge applied to the message, if any'),
  purge: z
    .enum(['pending', 'retained'])
    .nullable()
    .describe('Object disposal scheduled for the message (Q17), if any'),
});
export type EntryStateResponse = z.output<typeof EntryStateResponseSchema>;

export const ManualQuarantineResponseSchema = z.strictObject({
  messageId: z.uuid(),
  entries: z.array(
    z.strictObject({ id: z.uuid(), rcptSeq: z.number().int(), state: z.enum(QUARANTINE_STATES) }),
  ),
  messageTransition: z.enum(['E16', 'E29']).nullable(),
});
export type ManualQuarantineResponse = z.output<typeof ManualQuarantineResponseSchema>;

export const ApprovalDecisionResponseSchema = z.strictObject({
  approvalRequestId: z.uuid(),
  status: z.enum(QUARANTINE_APPROVAL_STATUSES),
  entryId: z.uuid(),
  entryState: z.enum(QUARANTINE_STATES),
  releaseId: z.uuid().nullable(),
  messageTransition: z.enum(['E17', 'E18']).nullable(),
});
export type ApprovalDecisionResponse = z.output<typeof ApprovalDecisionResponseSchema>;

export const DownloadGrantResponseSchema = z.strictObject({
  token: z.string().describe('Single-use; GET /quarantine/downloads/{token} within expiresAt'),
  expiresAt: z.iso.datetime(),
  filename: z.string().max(160),
  sizeBytes: z.number().int().min(0),
  sha256: z.string().regex(/^[0-9a-f]{64}$/),
});
export type DownloadGrantResponse = z.output<typeof DownloadGrantResponseSchema>;

export const BulkResponseSchema = z.strictObject({
  action: z.enum(BULK_ACTIONS),
  results: z.array(
    z.strictObject({
      id: z.uuid(),
      status: z.enum(BULK_ITEM_STATUSES),
      code: z.string().max(64).optional(),
      releaseId: z.uuid().optional(),
      approvalRequestId: z.uuid().optional(),
    }),
  ),
  counts: z.record(z.enum(BULK_ITEM_STATUSES), z.number().int()),
});

export const SummaryResponseSchema = z.strictObject({
  from: z.iso.datetime(),
  to: z.iso.datetime(),
  counts: z.record(z.enum(QUARANTINE_STATES), z.number().int().min(0)),
  pendingApprovals: z.number().int().min(0),
});
export type SummaryResponse = z.output<typeof SummaryResponseSchema>;

export const SettingsResponseSchema = z.strictObject({
  effective: effectiveQuarantineTenantSettingsSchema.extend({
    hold: z.strictObject({ days: z.number().int() }),
    digestSchedule: z.strictObject({
      enabled: z.boolean(),
      schedule: z.string(),
      timeZone: z.string(),
    }),
  }),
  raw: quarantineSettingsSchema.nullable().describe('The stored document (null: defaults)'),
  invalidStored: z.boolean().describe('The stored document is invalid; defaults apply'),
  bounds: z.strictObject({
    maxHoldDays: z.number().int(),
    maxReviewDays: z.number().int(),
    requestTtlHours: z.strictObject({ min: z.number().int(), max: z.number().int() }),
    digestMaxEntries: z.strictObject({ min: z.number().int(), max: z.number().int() }),
    alertMinIntervalMinutes: z.strictObject({ min: z.number().int(), max: z.number().int() }),
  }),
  rowVersion: z.number().int().min(0),
});
export type SettingsResponse = z.output<typeof SettingsResponseSchema>;

export const PreferencesResponseSchema = z.strictObject({
  digestOptOut: z.boolean(),
  allowOptOut: z.boolean(),
});
export type PreferencesResponse = z.output<typeof PreferencesResponseSchema>;

export const CatalogResponseSchema = z.strictObject({
  states: z.array(z.enum(QUARANTINE_STATES)),
  kinds: z.array(z.enum(QUARANTINE_ENTRY_KINDS)),
  origins: z.array(z.enum(QUARANTINE_ORIGINS)),
  reasons: z.array(z.enum(QUARANTINE_REASONS)),
  primaryEngines: z.array(z.enum(QUARANTINE_PRIMARY_ENGINES)),
  riskLevels: z.array(z.enum(QUARANTINE_RISK_LEVELS)),
  releaseModes: z.array(z.enum(QUARANTINE_RELEASE_MODES)),
  releaseStatuses: z.array(z.enum(QUARANTINE_RELEASE_STATUSES)),
  approvalKinds: z.array(z.enum(QUARANTINE_APPROVAL_KINDS)),
  approvalStatuses: z.array(z.enum(QUARANTINE_APPROVAL_STATUSES)),
  approvalReasons: z.array(z.enum(APPROVAL_REASONS)),
  entryActions: z.array(z.enum(ENTRY_ACTIONS)),
  bulkActions: z.array(z.enum(BULK_ACTIONS)),
  errorCodes: z.record(z.string(), z.number().int()),
  limits: z.strictObject({
    searchMaxRangeDays: z.number().int(),
    searchMaxPageSize: z.number().int(),
    searchDefaultPageSize: z.number().int(),
    bulkMaxItems: z.number().int(),
    bulkMaxItemsPerMinute: z.number().int(),
    previewMaxTextChars: z.number().int(),
    downloadTokenTtlSeconds: z.number().int(),
    downloadMaxBytes: z.number().int(),
    reasonMaxChars: z.number().int(),
  }),
  selfService: z.strictObject({
    enabled: z.boolean(),
    preview: z.boolean(),
    selfRelease: z.boolean(),
    selfReleaseReasons: z.array(z.enum(SELF_RELEASE_REASONS)),
    selfReleaseMaxLevel: z.enum(SELF_RELEASE_MAX_LEVELS),
    requestRelease: z.boolean(),
    digestAllowOptOut: z.boolean(),
  }),
  downloadEnabled: z.boolean(),
});
export type CatalogResponse = z.output<typeof CatalogResponseSchema>;

/** Every code of Q26 (documentation of the coded error bodies). */
export const QUARANTINE_CODES = Object.keys(QUARANTINE_ERROR_CODES);
