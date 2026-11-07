import {
  DLP_AADHAAR_BASES,
  DLP_ACTION_SOURCES,
  DLP_ACTIONS,
  DLP_COVERAGES,
  DLP_DICTIONARY_CATEGORIES,
  DLP_DIRECTIONS,
  DLP_EXCEPTION_SCOPES,
  DLP_MASK_STYLES,
  DLP_PATTERN_VALIDATORS,
  DLP_POLICY_MODES,
  DLP_TENANT_SEVERITIES,
  DLP_VERDICTS,
  dlpCategoryAggregateSchema,
  dlpCategorySchema,
  dlpDetectorIdSchema,
  dlpEvidenceDocumentSchema,
  dlpExceptionFiltersSchema,
  dlpPolicyViewSchema,
  dlpRuleConditionsSchema,
  dlpSeveritySchema,
} from '@email-gateway/security-contracts';
import { z } from 'zod';
import { PageQuerySchema } from '../../../http/pagination';

/**
 * Shapes of the DLP routes (step 4.5 D8, D9, D11, D12, D16, D17, D21,
 * docs/plan/steps/13-dlp.md): policies and their rules, exceptions, custom patterns (and the
 * pattern test), keyword dictionaries, the Aadhaar compliance basis, incidents and the audited
 * evidence. Every id the API shows is a public id (UUIDv7); scans are decimal ids. Masked values
 * only outside the evidence response; never message content.
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

const isTwoDecimals = (value: number): boolean =>
  Math.abs(Math.round(value * 100) - value * 100) < 1e-6;

export const DlpIdSchema = z.uuid();

/** `{scanId}`: a decimal `email_scans.id`. */
export const DlpScanIdSchema = z
  .string()
  .refine(
    (value) => /^[1-9][0-9]{0,19}$/.test(value) && BigInt(value) <= 18_446_744_073_709_551_615n,
    'Expected a decimal scan id',
  );

/** Optimistic version (row `version`, starts at 1). */
const Version = z.number().int().min(1).max(4_294_967_295);
const IsoDate = z.iso.datetime();
const Priority = z.number().int().min(0).max(1000);
const Confidence = z
  .number()
  .finite()
  .min(0.5)
  .max(1)
  .refine(isTwoDecimals, 'At most two decimals');
const BoolQuery = z.enum(['true', 'false']).transform((value) => value === 'true');
const Directions = z
  .array(z.enum(DLP_DIRECTIONS))
  .min(1)
  .max(DLP_DIRECTIONS.length)
  .refine(unique, 'Duplicate direction');
const Name = Text(1, 128);

/** `?version=` of a DELETE (optional compare-and-set). */
export const DlpDeleteQuerySchema = z.strictObject({
  version: z.coerce
    .number()
    .int()
    .min(1)
    .max(4_294_967_295)
    .optional()
    .describe('When given, the delete applies only to this version (409 version_conflict)'),
});
export type DlpDeleteQuery = z.output<typeof DlpDeleteQuerySchema>;

const Audit = {
  version: Version,
  createdByUserId: z.uuid().nullable(),
  updatedByUserId: z.uuid().nullable(),
  createdAt: IsoDate,
  updatedAt: IsoDate,
};

export const DlpListQuerySchema = PageQuerySchema.extend({
  enabled: BoolQuery.optional().describe('Only enabled (`true`) or disabled (`false`) entries'),
}).strict();
export type DlpListQuery = z.output<typeof DlpListQuerySchema>;

// --------------------------------------------------------------------------------------------
// Policies and rules (D11)
// --------------------------------------------------------------------------------------------

export const DlpPolicyCreateSchema = z.strictObject({
  name: Name.describe('Unique per organization'),
  description: Text(1, 512).nullable().optional(),
  enabled: z.boolean().default(true),
  mode: z
    .enum(DLP_POLICY_MODES)
    .default('enforce')
    .describe('`monitor` records matches and never changes the action'),
  priority: Priority.default(100).describe('Ascending evaluation order (ties broken by id)'),
  directions: Directions.default(['outbound', 'internal']).describe(
    'Directions the policy applies to (inbound only when the tenant scans inbound mail)',
  ),
});
export type DlpPolicyCreate = z.output<typeof DlpPolicyCreateSchema>;

export const DlpPolicyUpdateSchema = z.strictObject({
  version: Version.describe('The `version` the caller saw (409 version_conflict otherwise)'),
  name: Name.optional(),
  description: Text(1, 512).nullable().optional(),
  enabled: z.boolean().optional(),
  mode: z.enum(DLP_POLICY_MODES).optional(),
  priority: Priority.optional(),
  directions: Directions.optional(),
});
export type DlpPolicyUpdate = z.output<typeof DlpPolicyUpdateSchema>;

/** The body shape is validated with `dlpRuleConditionsSchema` after address/domain normalization. */
const RawConditions = z
  .record(z.string(), z.unknown())
  .describe(
    'Rule conditions (`dlpRuleConditionsSchema`, strict): selectors (detectors, categories, ' +
      'customPatternIds, dictionaryIds, coverageReasons; at least one), minCount, ' +
      'minConfidence, minSeverity, directions (⊆ the policy’s), sender {addresses, domains}, ' +
      'recipients {addresses, domains, externalOnly}, attachmentsOnly. Addresses are ' +
      'normalized (lower case, IDNA domain), domains to ASCII (public suffixes and IP literals ' +
      'refused); pattern and dictionary ids must be the organization’s',
  );

export const DlpRuleCreateSchema = z.strictObject({
  name: Name.describe('Unique within the policy'),
  enabled: z.boolean().default(true),
  priority: Priority.default(100).describe('Ascending order within the policy'),
  conditions: RawConditions,
  action: z
    .enum(DLP_ACTIONS)
    .describe('allow < alert < require_approval < quarantine < block (strongest wins)'),
});
export type DlpRuleCreate = z.output<typeof DlpRuleCreateSchema>;

export const DlpRuleUpdateSchema = z.strictObject({
  version: Version.describe('The `version` the caller saw (409 version_conflict otherwise)'),
  name: Name.optional(),
  enabled: z.boolean().optional(),
  priority: Priority.optional(),
  conditions: RawConditions.optional(),
  action: z.enum(DLP_ACTIONS).optional(),
});
export type DlpRuleUpdate = z.output<typeof DlpRuleUpdateSchema>;

/** OpenAPI documentation of the rule bodies (the conditions schema in full). */
export const DlpRuleCreateDocSchema = DlpRuleCreateSchema.extend({
  conditions: dlpRuleConditionsSchema,
});
export const DlpRuleUpdateDocSchema = DlpRuleUpdateSchema.extend({
  conditions: dlpRuleConditionsSchema.optional(),
});

export const DlpRuleViewSchema = z.object({
  id: z.uuid(),
  policyId: z.uuid(),
  name: z.string(),
  enabled: z.boolean(),
  priority: z.number().int(),
  conditions: dlpRuleConditionsSchema,
  action: z.enum(DLP_ACTIONS),
  ...Audit,
});
export type DlpRuleView = z.output<typeof DlpRuleViewSchema>;

export const DlpPolicyViewSchema = z.object({
  id: z.uuid(),
  name: z.string(),
  description: z.string().nullable(),
  enabled: z.boolean(),
  mode: z.enum(DLP_POLICY_MODES),
  priority: z.number().int(),
  directions: z.array(z.enum(DLP_DIRECTIONS)),
  ruleCount: z.number().int().min(0),
  ...Audit,
});
export type DlpPolicyView = z.output<typeof DlpPolicyViewSchema>;

export const DlpPolicyDetailSchema = DlpPolicyViewSchema.extend({
  rules: z.array(DlpRuleViewSchema).describe('By priority, then creation'),
});
export type DlpPolicyDetail = z.output<typeof DlpPolicyDetailSchema>;

export const DlpPolicyPageSchema = z.object({
  data: z.array(DlpPolicyViewSchema).describe('Newest first'),
  nextCursor: z.string().nullable(),
});
export type DlpPolicyPage = z.output<typeof DlpPolicyPageSchema>;

// --------------------------------------------------------------------------------------------
// Exceptions (D12)
// --------------------------------------------------------------------------------------------

export const DlpExceptionCreateSchema = z
  .strictObject({
    scope: z.enum(DLP_EXCEPTION_SCOPES),
    value: Text(1, 320).describe(
      'An address (normalized: lower case, IDNA domain) or a domain (normalized to ASCII; ' +
        'public suffixes and IP literals refused)',
    ),
    policyId: z.uuid().optional().describe('Only this policy’s rules (one target at most)'),
    ruleId: z.uuid().optional().describe('Only this rule'),
    filters: dlpExceptionFiltersSchema
      .optional()
      .describe('Only these detectors or categories are removed (default: every finding)'),
    reason: Text(1, 512).describe('Why the exception exists (shown to investigators)'),
    expiresAt: IsoDate.describe('Required; future and at most DLP_EXCEPTION_MAX_DAYS ahead'),
    enabled: z.boolean().default(true),
  })
  .refine((body) => body.policyId === undefined || body.ruleId === undefined, {
    message: 'Give policyId or ruleId, not both',
    path: ['ruleId'],
  });
export type DlpExceptionCreate = z.output<typeof DlpExceptionCreateSchema>;

export const DlpExceptionUpdateSchema = z.strictObject({
  version: Version.describe('The `version` the caller saw (409 version_conflict otherwise)'),
  reason: Text(1, 512).optional(),
  expiresAt: IsoDate.optional(),
  enabled: z.boolean().optional(),
  filters: dlpExceptionFiltersSchema.nullable().optional().describe('null removes the filters'),
});
export type DlpExceptionUpdate = z.output<typeof DlpExceptionUpdateSchema>;

export const DlpExceptionListQuerySchema = PageQuerySchema.extend({
  scope: z.enum(DLP_EXCEPTION_SCOPES).optional(),
  active: BoolQuery.optional().describe(
    'Only active (`true`: enabled and unexpired) or inactive (`false`) exceptions',
  ),
}).strict();
export type DlpExceptionListQuery = z.output<typeof DlpExceptionListQuerySchema>;

export const DlpExceptionViewSchema = z.object({
  id: z.uuid(),
  scope: z.enum(DLP_EXCEPTION_SCOPES),
  value: z.string(),
  policyId: z.uuid().nullable(),
  ruleId: z.uuid().nullable(),
  filters: dlpExceptionFiltersSchema.nullable(),
  reason: z.string(),
  expiresAt: IsoDate,
  expired: z.boolean().describe('Past `expiresAt`: no longer applied'),
  enabled: z.boolean(),
  ...Audit,
});
export type DlpExceptionView = z.output<typeof DlpExceptionViewSchema>;

export const DlpExceptionPageSchema = z.object({
  data: z.array(DlpExceptionViewSchema).describe('Newest first'),
  nextCursor: z.string().nullable(),
});
export type DlpExceptionPage = z.output<typeof DlpExceptionPageSchema>;

// --------------------------------------------------------------------------------------------
// Custom patterns (D9)
// --------------------------------------------------------------------------------------------

const ContextKeywords = z
  .array(Text(1, 64))
  .max(20)
  .refine(unique, 'Duplicate keyword')
  .describe('Context keywords (≤ 20 × 1–64 characters), +0.30 confidence when nearby');
const PatternText = z
  .string()
  .min(1)
  .max(512)
  .describe(
    'RE2 syntax (re2js: linear time, no backreferences or lookaround), at most ' +
      'DLP_CUSTOM_PATTERN_MAX_LENGTH characters',
  );

export const DlpPatternCreateSchema = z.strictObject({
  name: Name.describe('Unique per organization'),
  pattern: PatternText,
  caseInsensitive: z.boolean().default(false),
  validator: z.enum(DLP_PATTERN_VALIDATORS).default('none').describe('Checksum of each match'),
  contextKeywords: ContextKeywords.default([]),
  requireContext: z
    .boolean()
    .default(false)
    .describe('Only matches with a context keyword nearby are reportable'),
  severity: z.enum(DLP_TENANT_SEVERITIES),
  baseConfidence: Confidence.default(0.8),
  maskStyle: z
    .enum(DLP_MASK_STYLES)
    .default('last4')
    .describe('`last4` keeps the last four characters, `full` masks everything'),
  enabled: z.boolean().default(true),
});
export type DlpPatternCreate = z.output<typeof DlpPatternCreateSchema>;

export const DlpPatternUpdateSchema = z.strictObject({
  version: Version.describe('The `version` the caller saw (409 version_conflict otherwise)'),
  name: Name.optional(),
  pattern: PatternText.optional(),
  caseInsensitive: z.boolean().optional(),
  validator: z.enum(DLP_PATTERN_VALIDATORS).optional(),
  contextKeywords: ContextKeywords.optional(),
  requireContext: z.boolean().optional(),
  severity: z.enum(DLP_TENANT_SEVERITIES).optional(),
  baseConfidence: Confidence.optional(),
  maskStyle: z.enum(DLP_MASK_STYLES).optional(),
  enabled: z.boolean().optional(),
});
export type DlpPatternUpdate = z.output<typeof DlpPatternUpdateSchema>;

export const DlpPatternViewSchema = z.object({
  id: z.uuid(),
  name: z.string(),
  pattern: z.string().describe('Tenant configuration (shown to dlp:read holders)'),
  caseInsensitive: z.boolean(),
  validator: z.enum(DLP_PATTERN_VALIDATORS),
  contextKeywords: z.array(z.string()),
  requireContext: z.boolean(),
  severity: z.enum(DLP_TENANT_SEVERITIES),
  baseConfidence: z.number(),
  maskStyle: z.enum(DLP_MASK_STYLES),
  enabled: z.boolean(),
  ...Audit,
});
export type DlpPatternView = z.output<typeof DlpPatternViewSchema>;

export const DlpPatternPageSchema = z.object({
  data: z.array(DlpPatternViewSchema).describe('Newest first'),
  nextCursor: z.string().nullable(),
});
export type DlpPatternPage = z.output<typeof DlpPatternPageSchema>;

/** Longest test sample (D9). */
export const DLP_PATTERN_TEST_SAMPLE_MAX = 4096;

export const DlpPatternTestSchema = z.strictObject({
  pattern: z.string().max(1024).describe('The pattern to validate (never stored or logged)'),
  caseInsensitive: z.boolean().default(false),
  validator: z.enum(DLP_PATTERN_VALIDATORS).optional(),
  contextKeywords: z.array(z.string().max(64)).max(20).optional(),
  requireContext: z.boolean().optional(),
  maskStyle: z.enum(DLP_MASK_STYLES).optional(),
  sample: z
    .string()
    .max(DLP_PATTERN_TEST_SAMPLE_MAX)
    .describe('Synthetic sample text, at most 4 096 characters (never stored, logged or echoed)'),
});
export type DlpPatternTest = z.output<typeof DlpPatternTestSchema>;

export const DlpPatternTestResultSchema = z.object({
  valid: z.boolean(),
  code: z
    .string()
    .nullable()
    .describe(
      'Rejection code when not valid: pattern_syntax, pattern_unsupported, ' +
        'pattern_too_complex, pattern_matches_empty, pattern_too_broad, pattern_too_slow, ' +
        'pattern_invalid_options',
    ),
  complexity: z.object({
    repetitionProduct: z.number().int().min(0),
    length: z.number().int().min(0),
  }),
  matches: z
    .array(
      z.object({
        start: z.number().int().min(0).describe('UTF-16 offset in the sample'),
        end: z.number().int().min(0),
        masked: z.string().describe('The match masked per maskStyle (never the match itself)'),
        validated: z.boolean().describe('Passed the validator (always true without one)'),
        contextMatched: z.boolean(),
      }),
    )
    .max(50),
});
export type DlpPatternTestResult = z.output<typeof DlpPatternTestResultSchema>;

// --------------------------------------------------------------------------------------------
// Keyword dictionaries (D8)
// --------------------------------------------------------------------------------------------

const Terms = z
  .array(z.string())
  .min(1)
  .max(10_000)
  .describe(
    'Terms (1..DLP_DICTIONARY_MAX_TERMS, each 1–64 characters and 1–8 tokens after ' +
      'normalization, unique after normalization); shown to dlp:read holders only',
  );

export const DlpDictionaryCreateSchema = z.strictObject({
  name: Name.describe('Unique per organization'),
  category: z.enum(DLP_DICTIONARY_CATEGORIES),
  terms: Terms,
  severity: z.enum(DLP_TENANT_SEVERITIES),
  baseConfidence: Confidence.default(0.7),
  minMatches: z
    .number()
    .int()
    .min(1)
    .max(100)
    .default(1)
    .describe('Distinct terms a segment needs'),
  enabled: z.boolean().default(true),
});
export type DlpDictionaryCreate = z.output<typeof DlpDictionaryCreateSchema>;

export const DlpDictionaryUpdateSchema = z.strictObject({
  version: Version.describe('The `version` the caller saw (409 version_conflict otherwise)'),
  name: Name.optional(),
  category: z.enum(DLP_DICTIONARY_CATEGORIES).optional(),
  terms: Terms.optional(),
  severity: z.enum(DLP_TENANT_SEVERITIES).optional(),
  baseConfidence: Confidence.optional(),
  minMatches: z.number().int().min(1).max(100).optional(),
  enabled: z.boolean().optional(),
});
export type DlpDictionaryUpdate = z.output<typeof DlpDictionaryUpdateSchema>;

export const DlpDictionaryViewSchema = z.object({
  id: z.uuid(),
  name: z.string(),
  category: z.enum(DLP_DICTIONARY_CATEGORIES),
  termCount: z.number().int().min(0),
  severity: z.enum(DLP_TENANT_SEVERITIES),
  baseConfidence: z.number(),
  minMatches: z.number().int(),
  enabled: z.boolean(),
  ...Audit,
});
export type DlpDictionaryView = z.output<typeof DlpDictionaryViewSchema>;

export const DlpDictionaryDetailSchema = DlpDictionaryViewSchema.extend({
  terms: z.array(z.string()),
});
export type DlpDictionaryDetail = z.output<typeof DlpDictionaryDetailSchema>;

export const DlpDictionaryPageSchema = z.object({
  data: z.array(DlpDictionaryViewSchema).describe('Newest first (terms omitted: see GET /{id})'),
  nextCursor: z.string().nullable(),
});
export type DlpDictionaryPage = z.output<typeof DlpDictionaryPageSchema>;

// --------------------------------------------------------------------------------------------
// Compliance (D17)
// --------------------------------------------------------------------------------------------

export const DlpComplianceViewSchema = z.object({
  aadhaar: z.object({
    enabled: z.boolean(),
    active: z
      .boolean()
      .describe('Detection runs: enabled, attested, with a basis and a review date in the future'),
    basis: z.enum(DLP_AADHAAR_BASES).nullable(),
    reference: z.string().nullable(),
    attested: z.boolean(),
    recordedByUserId: z.uuid().nullable(),
    recordedAt: IsoDate.nullable(),
    reviewDueAt: IsoDate.nullable(),
  }),
  version: z.number().int().min(0).describe('0 = never recorded'),
  updatedAt: IsoDate.nullable(),
});
export type DlpComplianceView = z.output<typeof DlpComplianceViewSchema>;

const ExpectedVersion = z
  .number()
  .int()
  .min(0)
  .max(4_294_967_295)
  .describe('The `version` the caller saw (0 = never recorded); 409 version_conflict otherwise');

export const DlpAadhaarPutSchema = z.strictObject({
  expectedVersion: ExpectedVersion,
  basis: z.enum(DLP_AADHAAR_BASES),
  reference: Text(1, 256).describe('The organization’s document or approval reference'),
  attested: z
    .literal(true)
    .describe('The caller attests that the organization holds this basis (must be true)'),
  reviewDueAt: IsoDate.describe('Future and at most 365 days ahead; detection stops after it'),
});
export type DlpAadhaarPut = z.output<typeof DlpAadhaarPutSchema>;

export const DlpAadhaarDeleteQuerySchema = z.strictObject({
  expectedVersion: z.coerce
    .number()
    .int()
    .min(0)
    .max(4_294_967_295)
    .optional()
    .describe('When given, applies only at this version'),
});
export type DlpAadhaarDeleteQuery = z.output<typeof DlpAadhaarDeleteQuerySchema>;

// --------------------------------------------------------------------------------------------
// Incidents (D14, D21)
// --------------------------------------------------------------------------------------------

export const DLP_INCIDENT_ACTIONS = ['alert', 'require_approval', 'quarantine', 'block'] as const;

export const DlpIncidentListQuerySchema = PageQuerySchema.extend({
  action: z.enum(DLP_INCIDENT_ACTIONS).optional(),
  direction: z.enum(DLP_DIRECTIONS).optional(),
  from: IsoDate.optional().describe('Received at or after (inclusive)'),
  to: IsoDate.optional().describe('Received before (exclusive)'),
}).strict();
export type DlpIncidentListQuery = z.output<typeof DlpIncidentListQuerySchema>;

export const DlpIncidentFindingSchema = z.object({
  detector: dlpDetectorIdSchema,
  code: z.string(),
  category: dlpCategorySchema,
  severity: dlpSeveritySchema,
  count: z.number().int().min(0),
  capped: z.boolean(),
  customPatternId: z.uuid().optional(),
  dictionaryId: z.uuid().optional(),
});

export const DlpIncidentViewSchema = z.object({
  messageId: z.uuid(),
  scanId: z.string().describe('Decimal scan id of the round'),
  lifecycleRound: z.number().int().min(0),
  receivedAt: IsoDate,
  direction: z.enum(DLP_DIRECTIONS),
  verdict: z.enum(DLP_VERDICTS),
  action: z.enum(DLP_ACTIONS),
  actionSource: z.enum(DLP_ACTION_SOURCES),
  coverage: z.enum(DLP_COVERAGES),
  findingCount: z.number().int().min(0),
  categories: z.array(dlpCategoryAggregateSchema),
  findings: z.array(DlpIncidentFindingSchema).describe('Detector codes and counts, no samples'),
  policy: dlpPolicyViewSchema,
  detectedAt: IsoDate.describe('When the result was recorded (whole seconds)'),
});
export type DlpIncidentView = z.output<typeof DlpIncidentViewSchema>;

export const DlpIncidentPageSchema = z.object({
  data: z.array(DlpIncidentViewSchema).describe('Newest first (received time)'),
  nextCursor: z.string().nullable(),
});
export type DlpIncidentPage = z.output<typeof DlpIncidentPageSchema>;

// --------------------------------------------------------------------------------------------
// Evidence (D16)
// --------------------------------------------------------------------------------------------

export const DlpEvidenceResponseSchema = z.object({
  messageId: z.uuid(),
  scanId: z.string(),
  matchCount: z.number().int().min(0),
  expiresAt: IsoDate,
  evidence: dlpEvidenceDocumentSchema.describe(
    'The decrypted evidence (dlp-evidence/1): matches with offsets, values and redacted ' +
      'context; Aadhaar numbers, secrets and card numbers beyond first 6 + last 4 never appear',
  ),
});
export type DlpEvidenceResponse = z.output<typeof DlpEvidenceResponseSchema>;

export const DlpEvidencePurgedSchema = z.object({
  purged: z.number().int().min(0).describe('Evidence rows crypto-shredded by this request'),
  objectsDeleted: z.number().int().min(0),
  objectsPending: z
    .number()
    .int()
    .min(0)
    .describe('Objects whose delete failed (undecryptable already; retried by the next purge)'),
});
export type DlpEvidencePurged = z.output<typeof DlpEvidencePurgedSchema>;
