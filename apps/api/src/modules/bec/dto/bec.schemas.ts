import {
  AI_FEATURE_NAMES,
  BEC_AI_LABELS,
  BEC_AI_LAYERS,
  BEC_FEEDBACK_KINDS,
  BEC_SUPPRESSIBLE_CODES,
  BEC_SUPPRESSION_SCOPES,
  BEC_TRUSTED_SENDER_KINDS,
  becReasonCodeSchema,
  becSuppressibleCodeSchema,
  becVerdictSchema,
} from '@email-gateway/security-contracts';
import { z } from 'zod';
import { PageQuerySchema } from '../../../http/pagination';

/**
 * Shapes of the BEC tenant data routes (step 4.4 B7, B11, B12, B18,
 * docs/plan/steps/12-phishing-bec.md): executive and vendor profiles, trusted senders, analyst
 * feedback on a scan's `bec` result with optional bounded suppressions, the retraining export
 * (NDJSON) and the communication-history purge. Every id the API shows is a public id (UUIDv7).
 * Names and addresses are the organization's own directory data; message content never appears.
 */

const noControl = (value: string): boolean => {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return false;
  }
  return true;
};

const unique = (values: readonly unknown[]): boolean => new Set(values).size === values.length;

const Text = (min: number, max: number) =>
  z.string().trim().min(min).max(max).refine(noControl, 'Must not contain control characters');

/** A display name or alias as entered (B5 normalizes it for matching; 2–128 characters). */
const Name = Text(2, 128);
/** An e-mail address as entered (normalized: IDNA domain, lower case). */
const RawAddress = Text(3, 320);
/** A domain as entered (normalized by url-security; public suffixes refused). */
const RawDomain = Text(1, 253);

export const BecIdSchema = z.uuid();

/** Optimistic version (row `version`, starts at 1). */
const Version = z.number().int().min(1).max(4_294_967_295);

const IsoDate = z.iso.datetime();

/** `enabled` filter of the profile lists (`true`/`false`). */
const BoolQuery = z.enum(['true', 'false']).transform((value) => value === 'true');

export const BecProfileListQuerySchema = PageQuerySchema.extend({
  enabled: BoolQuery.optional().describe('Only enabled (`true`) or disabled (`false`) profiles'),
}).strict();
export type BecProfileListQuery = z.output<typeof BecProfileListQuerySchema>;

/** `?version=` of a DELETE (optional compare-and-set). */
export const BecDeleteQuerySchema = z.strictObject({
  version: z.coerce
    .number()
    .int()
    .min(1)
    .max(4_294_967_295)
    .optional()
    .describe('When given, the delete applies only to this version (409 version_conflict)'),
});
export type BecDeleteQuery = z.output<typeof BecDeleteQuerySchema>;

// --------------------------------------------------------------------------------------------
// Executives (B5, B6 X1–X3)
// --------------------------------------------------------------------------------------------

const Aliases = z
  .array(Name)
  .max(10)
  .describe('Other names the executive is known by (≤ 10, 2–128 characters)');
const KnownAddresses = z
  .array(RawAddress)
  .max(20)
  .describe('Addresses the executive really uses (≤ 20; normalized, duplicates removed)');
const Title = Text(1, 128).nullable();

export const BecExecutiveCreateSchema = z.strictObject({
  displayName: Name.describe('Display name; unique per organization after normalization'),
  aliases: Aliases.default([]),
  knownAddresses: KnownAddresses.default([]),
  title: Title.optional().describe('Job title (informational)'),
  enabled: z.boolean().default(true),
});
export type BecExecutiveCreate = z.output<typeof BecExecutiveCreateSchema>;

export const BecExecutiveUpdateSchema = z.strictObject({
  version: Version.describe('The `version` the caller saw (409 version_conflict otherwise)'),
  displayName: Name.optional(),
  aliases: Aliases.optional(),
  knownAddresses: KnownAddresses.optional(),
  title: Title.optional(),
  enabled: z.boolean().optional(),
});
export type BecExecutiveUpdate = z.output<typeof BecExecutiveUpdateSchema>;

const Audit = {
  version: Version,
  createdByUserId: z.uuid().nullable(),
  createdAt: IsoDate,
  updatedAt: IsoDate,
};

export const BecExecutiveViewSchema = z.object({
  id: z.uuid(),
  displayName: z.string(),
  normalizedName: z.string().describe('The B5 normalization the uniqueness check uses'),
  aliases: z.array(z.string()),
  knownAddresses: z.array(z.string()),
  title: z.string().nullable(),
  enabled: z.boolean(),
  updatedByUserId: z.uuid().nullable(),
  ...Audit,
});
export type BecExecutiveView = z.output<typeof BecExecutiveViewSchema>;

export const BecExecutivePageSchema = z.object({
  data: z.array(BecExecutiveViewSchema).describe('Newest first'),
  nextCursor: z.string().nullable(),
});
export type BecExecutivePage = z.output<typeof BecExecutivePageSchema>;

// --------------------------------------------------------------------------------------------
// Vendors (B5, B6 V1–V4, L2)
// --------------------------------------------------------------------------------------------

const VendorDomains = z
  .array(RawDomain)
  .min(1)
  .max(20)
  .describe(
    'The vendor’s domains (1–20; normalized to ASCII registrable domains or hosts; public ' +
      'suffixes and free-mail domains refused)',
  );
const KnownSenders = z
  .array(RawAddress)
  .max(50)
  .describe('Addresses the vendor sends from (≤ 50; V3 fires for other vendor addresses)');

export const BecVendorCreateSchema = z.strictObject({
  name: Name.describe('Vendor name; unique per organization after normalization'),
  aliases: Aliases.default([]),
  domains: VendorDomains,
  knownSenders: KnownSenders.default([]),
  paymentChangeSensitive: z
    .boolean()
    .default(true)
    .describe('Payment-change wording from this vendor fires V4'),
  enabled: z.boolean().default(true),
});
export type BecVendorCreate = z.output<typeof BecVendorCreateSchema>;

export const BecVendorUpdateSchema = z.strictObject({
  version: Version.describe('The `version` the caller saw (409 version_conflict otherwise)'),
  name: Name.optional(),
  aliases: Aliases.optional(),
  domains: VendorDomains.optional(),
  knownSenders: KnownSenders.optional(),
  paymentChangeSensitive: z.boolean().optional(),
  enabled: z.boolean().optional(),
});
export type BecVendorUpdate = z.output<typeof BecVendorUpdateSchema>;

export const BecVendorViewSchema = z.object({
  id: z.uuid(),
  name: z.string(),
  normalizedName: z.string(),
  aliases: z.array(z.string()),
  domains: z.array(z.string()),
  knownSenders: z.array(z.string()),
  paymentChangeSensitive: z.boolean(),
  enabled: z.boolean(),
  updatedByUserId: z.uuid().nullable(),
  ...Audit,
});
export type BecVendorView = z.output<typeof BecVendorViewSchema>;

export const BecVendorPageSchema = z.object({
  data: z.array(BecVendorViewSchema).describe('Newest first'),
  nextCursor: z.string().nullable(),
});
export type BecVendorPage = z.output<typeof BecVendorPageSchema>;

// --------------------------------------------------------------------------------------------
// Trusted senders (B7)
// --------------------------------------------------------------------------------------------

export const BecTrustedSenderKindSchema = z.enum(BEC_TRUSTED_SENDER_KINDS);
const Reason = Text(1, 512);

export const BecTrustedSenderCreateSchema = z.strictObject({
  kind: BecTrustedSenderKindSchema.describe(
    '`address` (exact, case-insensitive) or `domain` (the registrable domain of From)',
  ),
  value: RawAddress.describe(
    'The address, or the domain (normalized; a free-mail domain is refused with ' +
      '`trusted_domain_freemail`)',
  ),
  reason: Reason.describe('Why the sender is trusted (audited)'),
  expiresAt: IsoDate.nullable()
    .optional()
    .describe('Trust ends at this instant (future, at most 365 days ahead); null = no expiry'),
});
export type BecTrustedSenderCreate = z.output<typeof BecTrustedSenderCreateSchema>;

export const BecTrustedSenderUpdateSchema = z.strictObject({
  version: Version.describe('The `version` the caller saw (409 version_conflict otherwise)'),
  reason: Reason.optional(),
  expiresAt: IsoDate.nullable().optional(),
});
export type BecTrustedSenderUpdate = z.output<typeof BecTrustedSenderUpdateSchema>;

export const BecTrustedSenderListQuerySchema = PageQuerySchema.extend({
  kind: BecTrustedSenderKindSchema.optional().describe('Only entries of this kind'),
}).strict();
export type BecTrustedSenderListQuery = z.output<typeof BecTrustedSenderListQuerySchema>;

export const BecTrustedSenderViewSchema = z.object({
  id: z.uuid(),
  kind: BecTrustedSenderKindSchema,
  value: z.string().describe('Normalized address or ASCII registrable domain'),
  reason: z.string(),
  expiresAt: IsoDate.nullable(),
  expired: z.boolean().describe('True once expiresAt has passed (no longer applied)'),
  ...Audit,
});
export type BecTrustedSenderView = z.output<typeof BecTrustedSenderViewSchema>;

export const BecTrustedSenderPageSchema = z.object({
  data: z.array(BecTrustedSenderViewSchema).describe('Newest first'),
  nextCursor: z.string().nullable(),
});
export type BecTrustedSenderPage = z.output<typeof BecTrustedSenderPageSchema>;

// --------------------------------------------------------------------------------------------
// Feedback and suppressions (B11)
// --------------------------------------------------------------------------------------------

export const BecFeedbackKindSchema = z.enum(BEC_FEEDBACK_KINDS);
export const BecSuppressionScopeSchema = z.enum(BEC_SUPPRESSION_SCOPES);

/** Upper bound of the suppression duration (B11: no permanent suppression). */
export const BEC_SUPPRESSION_MAX_DAYS = 90;

/** `{scanId}`: the decimal `email_scans.id` of the round (`scanId` in the scans read API). */
export const BecScanIdSchema = z
  .string()
  .refine(
    (value) => /^[1-9][0-9]{0,19}$/.test(value) && BigInt(value) <= 18_446_744_073_709_551_615n,
    'Expected a decimal scan id',
  );

export const BecFeedbackCreateSchema = z.strictObject({
  kind: BecFeedbackKindSchema.describe(
    '`false_positive` (the verdict was too severe) or `false_negative` (recorded only; never ' +
      'raises verdicts)',
  ),
  reasonCodes: z
    .array(becReasonCodeSchema)
    .max(32)
    .refine(unique, 'Duplicate reason code')
    .optional()
    .describe('Disputed reason codes; for a false positive a subset of the result’s codes'),
  note: Text(1, 500)
    .optional()
    .describe('Analyst note (≤ 500 characters; never exported). Do not paste message content'),
  suppress: z
    .strictObject({
      codes: z
        .array(becSuppressibleCodeSchema)
        .min(1)
        .max(BEC_SUPPRESSIBLE_CODES.length)
        .refine(unique, 'Duplicate reason code')
        .describe('Suppressible codes of the result to suppress for this sender'),
      scope: BecSuppressionScopeSchema.describe(
        '`address` (the From address of the scanned message) or `domain` (its registrable ' +
          'domain; refused for free-mail domains)',
      ),
      days: z.number().int().min(1).max(BEC_SUPPRESSION_MAX_DAYS).describe('Expiry in days'),
    })
    .optional()
    .describe('False positives only: suppress these codes for this sender for a bounded time'),
});
export type BecFeedbackCreate = z.output<typeof BecFeedbackCreateSchema>;

export const BecSuppressionViewSchema = z.object({
  id: z.uuid(),
  reasonCode: z.string(),
  senderScope: BecSuppressionScopeSchema,
  senderValue: z.string().describe('The From address or registrable domain'),
  expiresAt: IsoDate,
  expired: z.boolean(),
  feedbackId: z.uuid().nullable().describe('The feedback that created or renewed the rule'),
  createdByUserId: z.uuid().nullable(),
  createdAt: IsoDate,
});
export type BecSuppressionView = z.output<typeof BecSuppressionViewSchema>;

export const BecSuppressionPageSchema = z.object({
  data: z.array(BecSuppressionViewSchema).describe('Newest first'),
  nextCursor: z.string().nullable(),
});
export type BecSuppressionPage = z.output<typeof BecSuppressionPageSchema>;

export const BecSuppressionListQuerySchema = PageQuerySchema.extend({
  active: BoolQuery.optional().describe('Only unexpired (`true`) or expired (`false`) rules'),
}).strict();
export type BecSuppressionListQuery = z.output<typeof BecSuppressionListQuerySchema>;

export const BecFeedbackViewSchema = z.object({
  id: z.uuid(),
  kind: BecFeedbackKindSchema,
  messageId: z.uuid().nullable().describe('Message public id'),
  scanId: z.string().describe('Decimal scan id'),
  reasonCodes: z.array(z.string()),
  note: z.string().nullable(),
  createdByUserId: z.uuid().nullable(),
  createdAt: IsoDate,
});
export type BecFeedbackView = z.output<typeof BecFeedbackViewSchema>;

export const BecFeedbackCreatedSchema = BecFeedbackViewSchema.extend({
  suppressions: z
    .array(BecSuppressionViewSchema)
    .describe('The suppression rules created or renewed by this feedback'),
});
export type BecFeedbackCreated = z.output<typeof BecFeedbackCreatedSchema>;

const TimeWindow = {
  from: IsoDate.optional().describe('Feedback created at or after this instant'),
  to: IsoDate.optional().describe('Feedback created before this instant'),
};

export const BecFeedbackListQuerySchema = PageQuerySchema.extend({
  kind: BecFeedbackKindSchema.optional(),
  ...TimeWindow,
}).strict();
export type BecFeedbackListQuery = z.output<typeof BecFeedbackListQuerySchema>;

export const BecFeedbackPageSchema = z.object({
  data: z.array(BecFeedbackViewSchema).describe('Newest first'),
  nextCursor: z.string().nullable(),
});
export type BecFeedbackPage = z.output<typeof BecFeedbackPageSchema>;

/** Records per export response (B11). */
export const BEC_EXPORT_MAX_RECORDS = 10_000;

export const BecFeedbackExportQuerySchema = z.strictObject({
  ...TimeWindow,
  cursor: z
    .string()
    .min(1)
    .max(64)
    .optional()
    .describe('`X-Next-Cursor` of the previous response (oldest first)'),
  limit: z.coerce
    .number()
    .int()
    .min(1)
    .max(BEC_EXPORT_MAX_RECORDS)
    .default(BEC_EXPORT_MAX_RECORDS)
    .describe('Records per response (≤ 10 000)'),
});
export type BecFeedbackExportQuery = z.output<typeof BecFeedbackExportQuerySchema>;

/**
 * One NDJSON line of the retraining export (B11), exactly these fields: no bodies, excerpts,
 * span text, addresses, display names, domains, notes or message ids.
 */
export const BecFeedbackExportRecordSchema = z.strictObject({
  feedbackId: z.uuid(),
  kind: BecFeedbackKindSchema,
  createdAt: IsoDate,
  rulesVersion: z.string(),
  engineVersion: z.string(),
  localModel: z.strictObject({ id: z.string(), version: z.string() }).nullable(),
  llm: z
    .strictObject({ modelId: z.string(), promptTemplateVersion: z.string().nullable() })
    .nullable(),
  firedCodes: z.array(z.string()),
  deterministicScore: z.number().int(),
  score: z.number().int(),
  verdict: becVerdictSchema,
  deterministicVerdict: becVerdictSchema,
  features: z
    .partialRecord(z.enum(AI_FEATURE_NAMES), z.union([z.number(), z.boolean()]))
    .describe('The AI feature vector stored with the result (AI_FEATURE_NAMES)'),
  aiLabels: z
    .array(
      z.strictObject({
        layer: z.enum(BEC_AI_LAYERS),
        mode: z.enum(['active', 'shadow']),
        label: z.enum(BEC_AI_LABELS),
        confidence: z.number(),
      }),
    )
    .describe('Top label of every ok assessment (applied and shadow)'),
});
export type BecFeedbackExportRecord = z.output<typeof BecFeedbackExportRecordSchema>;

export const BecHistoryPurgedSchema = z.object({
  deleted: z.number().int().min(0).describe('bec_contact_history rows deleted'),
});
export type BecHistoryPurged = z.output<typeof BecHistoryPurgedSchema>;
