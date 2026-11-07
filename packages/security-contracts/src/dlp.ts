import { z } from 'zod';
import type { SettingsViolation } from './settings';
import { MESSAGE_DIRECTIONS, urlDomainSchema } from './url';
import { REASON_CODE_MAX_LENGTH, REASON_CODE_PATTERN } from './verdicts';

/**
 * Data loss prevention contracts (step 4.5, docs/plan/steps/13-dlp.md D5, D10–D12, D15–D20;
 * ADR-0036..0038): the detector vocabulary of the verdict map `dlp-map/1`, the reason codes,
 * coverage and policy vocabularies (their value lists equal the Prisma enums of the
 * `dlp_engine` migration), the strict rule-conditions schema, the platform/tenant settings with
 * their pure resolver, and the strict view sub-schemas of the scans read API and of the
 * decrypted evidence document.
 *
 * Every list lives here once; `@email-gateway/dlp`, the email-worker and the api import them.
 * Engines classify; the DLP policy decides the DLP action; the delivery stage applies it
 * (§2.0 invariant 4): nothing here delivers, quarantines or rejects.
 */

/** Mapping version of the DLP verdict map (D5); also the prefix of `settings_version` (D18). */
export const DLP_MAPPING_VERSION = 'dlp-map/1';

const unique = (values: readonly unknown[]) => new Set(values).size === values.length;

/** Detector categories (D5, 10). */
export const DLP_CATEGORIES = [
  'payment_card',
  'bank_account',
  'national_id',
  'passport',
  'personal_info',
  'confidential',
  'source_code',
  'credential',
  'financial',
  'custom',
] as const;
export type DlpCategory = (typeof DLP_CATEGORIES)[number];
export const dlpCategorySchema = z.enum(DLP_CATEGORIES);

/** Severities, weakest first (D5). */
export const DLP_SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const;
export type DlpSeverity = (typeof DLP_SEVERITIES)[number];
export const dlpSeveritySchema = z.enum(DLP_SEVERITIES);
export const dlpSeverityRank = (severity: DlpSeverity): number => DLP_SEVERITIES.indexOf(severity);

/** Severities a tenant pattern or dictionary may carry (Prisma `DlpSeverity`: no `info`). */
export const DLP_TENANT_SEVERITIES = ['low', 'medium', 'high', 'critical'] as const;
export type DlpTenantSeverity = (typeof DLP_TENANT_SEVERITIES)[number];

/** The 23 detector ids of the D5 table, in table order. */
export const DLP_DETECTOR_IDS = [
  'PC1',
  'BA1',
  'BA2',
  'BA3',
  'NI1',
  'NI2',
  'PP1',
  'PP2',
  'PI1',
  'PI2',
  'PI3',
  'PI4',
  'CF1',
  'CF2',
  'DC1',
  'SC1',
  'CR1',
  'CR2',
  'CR3',
  'CR4',
  'CR5',
  'FI1',
  'CU1',
] as const;
export type DlpDetectorId = (typeof DLP_DETECTOR_IDS)[number];
export const dlpDetectorIdSchema = z.enum(DLP_DETECTOR_IDS);

export interface DlpDetectorDefinition {
  readonly code: string;
  /** null for DC1: the category comes from the tenant dictionary. */
  readonly category: DlpCategory | null;
  /** null for DC1 and CU1: the severity comes from the tenant dictionary or pattern. */
  readonly severity: DlpSeverity | null;
}

const detector = (
  code: string,
  category: DlpCategory | null,
  severity: DlpSeverity | null,
): DlpDetectorDefinition => Object.freeze({ code, category, severity });

/** Detector id → reason code, category and severity (D5). */
export const DLP_DETECTORS: Readonly<Record<DlpDetectorId, DlpDetectorDefinition>> = Object.freeze({
  PC1: detector('dlp.payment_card.number', 'payment_card', 'high'),
  BA1: detector('dlp.bank_account.iban', 'bank_account', 'high'),
  BA2: detector('dlp.bank_account.india_ifsc_account', 'bank_account', 'high'),
  BA3: detector('dlp.bank_account.swift_bic', 'bank_account', 'low'),
  NI1: detector('dlp.national_id.india_pan', 'national_id', 'high'),
  NI2: detector('dlp.national_id.india_aadhaar', 'national_id', 'critical'),
  PP1: detector('dlp.passport.india_number', 'passport', 'high'),
  PP2: detector('dlp.passport.mrz', 'passport', 'high'),
  PI1: detector('dlp.personal_info.email_address', 'personal_info', 'low'),
  PI2: detector('dlp.personal_info.india_mobile', 'personal_info', 'low'),
  PI3: detector('dlp.personal_info.date_of_birth', 'personal_info', 'medium'),
  PI4: detector('dlp.personal_info.india_gstin', 'personal_info', 'low'),
  CF1: detector('dlp.confidential.classification_label', 'confidential', 'medium'),
  CF2: detector('dlp.confidential.business_keyword', 'confidential', 'medium'),
  DC1: detector('dlp.dictionary.match', null, null),
  SC1: detector('dlp.source_code.snippet', 'source_code', 'medium'),
  CR1: detector('dlp.credential.private_key', 'credential', 'critical'),
  CR2: detector('dlp.credential.aws_access_key_id', 'credential', 'high'),
  CR3: detector('dlp.credential.aws_secret_access_key', 'credential', 'critical'),
  CR4: detector('dlp.credential.jwt', 'credential', 'medium'),
  CR5: detector('dlp.credential.api_token', 'credential', 'high'),
  FI1: detector('dlp.financial.document', 'financial', 'medium'),
  CU1: detector('dlp.custom.pattern', 'custom', null),
});

/** The detector reason codes, in `DLP_DETECTOR_IDS` order. */
export const DLP_DETECTOR_CODES: readonly string[] = Object.freeze(
  DLP_DETECTOR_IDS.map((id) => DLP_DETECTORS[id].code),
);

/** Detectors a tenant may switch off (D18: the noisy ones only). */
export const DLP_TENANT_DISABLEABLE_DETECTORS = ['PI1', 'PI2', 'BA3', 'SC1', 'CF2'] as const;
export type DlpTenantDisableableDetector = (typeof DLP_TENANT_DISABLEABLE_DETECTORS)[number];

/** Why an attachment (or part of one) was not extracted (D4, D5). */
export const DLP_NOT_EXTRACTED_REASONS = [
  'encrypted',
  'unsupported_type',
  'image',
  'no_text_layer',
  'oversize',
  'not_stored',
  'parse_error',
  'archive_limit',
  'resource_limit',
  'attachment_cap',
] as const;
export type DlpNotExtractedReason = (typeof DLP_NOT_EXTRACTED_REASONS)[number];
export const dlpNotExtractedReasonSchema = z.enum(DLP_NOT_EXTRACTED_REASONS);

/**
 * Coverage codes (D5, D10): any of them makes the coverage `partial`, so the verdict is never
 * `clean` (§2.0 invariant 1). Rule conditions may select them (`coverageReasons`, D11).
 */
export const DLP_COVERAGE_CODES = [
  'dlp.not_extracted.encrypted',
  'dlp.not_extracted.unsupported_type',
  'dlp.not_extracted.image',
  'dlp.not_extracted.no_text_layer',
  'dlp.not_extracted.oversize',
  'dlp.not_extracted.not_stored',
  'dlp.not_extracted.parse_error',
  'dlp.not_extracted.archive_limit',
  'dlp.not_extracted.resource_limit',
  'dlp.not_extracted.attachment_cap',
  'dlp.text.truncated',
  'dlp.text.body_not_stored',
  'dlp.parse.incomplete',
  'dlp.custom.scan_truncated',
  'dlp.custom.pattern_invalid',
] as const;
export type DlpCoverageCode = (typeof DLP_COVERAGE_CODES)[number];
export const dlpCoverageCodeSchema = z.enum(DLP_COVERAGE_CODES);

/** The coverage code of a not-extracted reason. */
export const dlpNotExtractedCode = (reason: DlpNotExtractedReason): DlpCoverageCode =>
  `dlp.not_extracted.${reason}` as DlpCoverageCode;

/** Outcome codes (D5): informational / verdict codes that do not change the coverage. */
export const DLP_OUTCOME_CODES = [
  'dlp.detector.match_cap',
  'dlp.no_findings',
  'dlp.not_inbound',
  'dlp.coverage.partial',
] as const;
export type DlpOutcomeCode = (typeof DLP_OUTCOME_CODES)[number];

/** Policy codes (D5, D11, D12). */
export const DLP_POLICY_CODES = [
  'dlp.action.alert',
  'dlp.action.quarantine',
  'dlp.action.block',
  'dlp.action.require_approval',
  'dlp.policy.default',
  'dlp.policy.monitor_match',
  'dlp.exception.applied',
] as const;
export type DlpPolicyCode = (typeof DLP_POLICY_CODES)[number];

/** Every reason code of `dlp-map/1`: detector, coverage, outcome and policy codes. */
export const DLP_REASON_CODES: readonly string[] = Object.freeze<string[]>([
  ...DLP_DETECTOR_CODES,
  ...DLP_COVERAGE_CODES,
  ...DLP_OUTCOME_CODES,
  ...DLP_POLICY_CODES,
]);

export const isDlpReasonCode = (value: string): boolean => DLP_REASON_CODES.includes(value);

/** Formats of an extracted source (D4, D10); bounded for metric labels. */
export const DLP_EXTRACT_FORMATS = [
  'text',
  'csv',
  'tsv',
  'html',
  'xml',
  'json',
  'source',
  'eml',
  'pdf',
  'docx',
  'xlsx',
  'pptx',
  'odt',
  'ods',
  'odp',
  'zip',
  'gzip',
  'tar',
  'image',
  'unsupported',
] as const;
export type DlpExtractFormat = (typeof DLP_EXTRACT_FORMATS)[number];
export const dlpExtractFormatSchema = z.enum(DLP_EXTRACT_FORMATS);

/** Extraction status of one attachment (D4). */
export const DLP_EXTRACT_STATUSES = ['extracted', 'partial', 'not_extracted'] as const;
export type DlpExtractStatus = (typeof DLP_EXTRACT_STATUSES)[number];

/** Text source kinds (D10 coverage detail, D16 evidence source). */
export const DLP_SOURCE_KINDS = [
  'subject',
  'body_text',
  'body_html',
  'attachment',
  'attachment_name',
] as const;
export type DlpSourceKind = (typeof DLP_SOURCE_KINDS)[number];

/** Status of one coverage entry (D10): scanned in full, partly, or not at all. */
export const DLP_SOURCE_STATUSES = ['scanned', 'partial', 'not_extracted'] as const;
export type DlpSourceStatus = (typeof DLP_SOURCE_STATUSES)[number];

/** DLP verdicts (`dlp_scan_results.verdict`, D10). Never `malicious` or `spam`. */
export const DLP_VERDICTS = ['clean', 'suspicious', 'unknown', 'skipped'] as const;
export type DlpVerdict = (typeof DLP_VERDICTS)[number];
export const dlpVerdictSchema = z.enum(DLP_VERDICTS);

/** Coverage of a result (D10). */
export const DLP_COVERAGES = ['complete', 'partial'] as const;
export type DlpCoverage = (typeof DLP_COVERAGES)[number];

/** DLP actions, weakest first (D11): the effective action is the strongest matched one. */
export const DLP_ACTIONS = ['allow', 'alert', 'require_approval', 'quarantine', 'block'] as const;
export type DlpAction = (typeof DLP_ACTIONS)[number];
export const dlpActionSchema = z.enum(DLP_ACTIONS);
export const dlpActionRank = (action: DlpAction): number => DLP_ACTIONS.indexOf(action);

/** Where the action came from (D11). */
export const DLP_ACTION_SOURCES = ['none', 'tenant_policy', 'default_policy'] as const;
export type DlpActionSource = (typeof DLP_ACTION_SOURCES)[number];

/** Policy modes (D11): `monitor` records matches and never changes the action. */
export const DLP_POLICY_MODES = ['enforce', 'monitor'] as const;
export type DlpPolicyMode = (typeof DLP_POLICY_MODES)[number];

/** Message directions a policy or rule applies to (Prisma `DlpPolicy.directions` JSON). */
export const DLP_DIRECTIONS = MESSAGE_DIRECTIONS;
export type DlpDirection = (typeof DLP_DIRECTIONS)[number];

/** Exception scopes (D12). */
export const DLP_EXCEPTION_SCOPES = [
  'sender_address',
  'sender_domain',
  'recipient_address',
  'recipient_domain',
] as const;
export type DlpExceptionScope = (typeof DLP_EXCEPTION_SCOPES)[number];

/** Optional checksum validators of tenant patterns (D6, D9). */
export const DLP_PATTERN_VALIDATORS = ['none', 'luhn', 'verhoeff', 'mod97', 'gstin'] as const;
export type DlpPatternValidator = (typeof DLP_PATTERN_VALIDATORS)[number];

/** Mask styles of tenant patterns (D15). */
export const DLP_MASK_STYLES = ['last4', 'full'] as const;
export type DlpMaskStyle = (typeof DLP_MASK_STYLES)[number];

/** Categories of tenant keyword dictionaries (D8). */
export const DLP_DICTIONARY_CATEGORIES = [
  'confidential',
  'financial',
  'personal_info',
  'source_code',
  'custom',
] as const;
export type DlpDictionaryCategory = (typeof DLP_DICTIONARY_CATEGORIES)[number];

/** Recorded compliance bases of Aadhaar detection (D17). */
export const DLP_AADHAAR_BASES = [
  'regulatory_obligation',
  'uidai_authorised_entity',
  'data_protection_policy',
  'other',
] as const;
export type DlpAadhaarBasis = (typeof DLP_AADHAAR_BASES)[number];

/** Evidence states of a result (D16) and purge reasons of an evidence row. */
export const DLP_EVIDENCE_STATUSES = ['none', 'stored', 'disabled', 'failed'] as const;
export type DlpEvidenceStatus = (typeof DLP_EVIDENCE_STATUSES)[number];
export const DLP_EVIDENCE_PURGE_REASONS = [
  'retention',
  'tenant_request',
  'organization_deleted',
] as const;
export type DlpEvidencePurgeReason = (typeof DLP_EVIDENCE_PURGE_REASONS)[number];

/** Algorithm label of the envelope encryption (D16, `dlp_evidence.algorithm`). */
export const DLP_EVIDENCE_ALGORITHM = 'dlp-evidence/1';

// ---------------------------------------------------------------------------------------------
// Rule conditions (D11)
// ---------------------------------------------------------------------------------------------

/** Bounds of a rule's conditions (D11). */
export const DLP_RULE_MAX_REFERENCES = 20;
export const DLP_RULE_MAX_ADDRESSES = 100;
export const DLP_RULE_MAX_DOMAINS = 100;
export const DLP_RULE_MAX_MIN_COUNT = 10_000;
/** Tenant category thresholds and rule confidences (D7, D11). */
export const DLP_THRESHOLD_BOUNDS = Object.freeze({ min: 0.5, max: 0.95 });

const isTwoDecimals = (value: number): boolean =>
  Math.abs(Math.round(value * 100) - value * 100) < 1e-6;

/** A lower-case envelope address (`local@domain`, ≤ 320). */
export const DLP_ADDRESS_PATTERN = /^[^\s@A-Z]{1,64}@[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/;
const addressSchema = z
  .string()
  .max(320)
  .regex(DLP_ADDRESS_PATTERN, 'Expected a lower-case address');

const listOf = <T extends z.ZodTypeAny>(item: T, max: number, label: string) =>
  z
    .array(item)
    .min(1)
    .max(max)
    .refine(unique, { message: `Duplicate ${label}` });

const directionList = listOf(z.enum(DLP_DIRECTIONS), DLP_DIRECTIONS.length, 'direction');

const nonEmptyObject = (value: Record<string, unknown>): boolean =>
  Object.values(value).some((v) => v !== undefined);

export const dlpRuleSelectorsSchema = z
  .strictObject({
    detectors: listOf(dlpDetectorIdSchema, DLP_DETECTOR_IDS.length, 'detector').optional(),
    categories: listOf(dlpCategorySchema, DLP_CATEGORIES.length, 'category').optional(),
    customPatternIds: listOf(z.uuid(), DLP_RULE_MAX_REFERENCES, 'pattern id').optional(),
    dictionaryIds: listOf(z.uuid(), DLP_RULE_MAX_REFERENCES, 'dictionary id').optional(),
    coverageReasons: listOf(dlpCoverageCodeSchema, DLP_COVERAGE_CODES.length, 'reason').optional(),
  })
  .refine(nonEmptyObject, { message: 'At least one selector is required' });

/**
 * `dlp_policy_rules.conditions` (D11): strict at every level. Defaults: `minCount` 1,
 * `minConfidence` the category threshold, `minSeverity` `low`, `directions` the policy's. The
 * api additionally checks that `directions` ⊆ the policy's and that referenced pattern and
 * dictionary ids are the tenant's.
 */
export const dlpRuleConditionsSchema = z.strictObject({
  selectors: dlpRuleSelectorsSchema,
  minCount: z.number().int().min(1).max(DLP_RULE_MAX_MIN_COUNT).optional(),
  minConfidence: z
    .number()
    .finite()
    .min(0.5)
    .max(1)
    .refine(isTwoDecimals, { message: 'At most two decimals' })
    .optional(),
  minSeverity: dlpSeveritySchema.optional(),
  directions: directionList.optional(),
  sender: z
    .strictObject({
      addresses: listOf(addressSchema, DLP_RULE_MAX_ADDRESSES, 'address').optional(),
      domains: listOf(urlDomainSchema, DLP_RULE_MAX_DOMAINS, 'domain').optional(),
    })
    .refine(nonEmptyObject, { message: 'An empty sender scope is not allowed' })
    .optional(),
  recipients: z
    .strictObject({
      addresses: listOf(addressSchema, DLP_RULE_MAX_ADDRESSES, 'address').optional(),
      domains: listOf(urlDomainSchema, DLP_RULE_MAX_DOMAINS, 'domain').optional(),
      externalOnly: z.boolean().optional(),
    })
    .refine(nonEmptyObject, { message: 'An empty recipient scope is not allowed' })
    .optional(),
  attachmentsOnly: z.boolean().optional(),
});
export type DlpRuleConditions = z.infer<typeof dlpRuleConditionsSchema>;

/** Exception filters (`dlp_exceptions.filters`, D12): the exception removes only these findings. */
export const dlpExceptionFiltersSchema = z
  .strictObject({
    detectors: listOf(dlpDetectorIdSchema, DLP_DETECTOR_IDS.length, 'detector').optional(),
    categories: listOf(dlpCategorySchema, DLP_CATEGORIES.length, 'category').optional(),
  })
  .refine(nonEmptyObject, { message: 'Empty filters: omit them instead' });
export type DlpExceptionFilters = z.infer<typeof dlpExceptionFiltersSchema>;

// ---------------------------------------------------------------------------------------------
// Settings (D18)
// ---------------------------------------------------------------------------------------------

/** Hard ceiling of the evidence retention: `dlp_evidence` partitions are dropped at 7 months. */
export const DLP_EVIDENCE_RETENTION_CEILING_DAYS = 180;
export const DLP_CONTEXT_WINDOW_BOUNDS = Object.freeze({ min: 16, max: 256 });
export const DLP_BULK_MIN_DISTINCT_BOUNDS = Object.freeze({ min: 2, max: 100 });

const within = (value: number, bounds: { min: number; max: number }) =>
  value >= bounds.min && value <= bounds.max;

const int = z.number().int();

/**
 * Platform DLP settings (D18; env `DLP_*`, read by the api and the email-worker and validated at
 * start). The confidence threshold is the default of every category threshold; the default
 * policy is the default of the tenant key; evidence enablement and the maximum retention are
 * caps; the context window and the bulk threshold are platform only.
 */
export const dlpPlatformSettingsSchema = z
  .strictObject({
    confidenceThreshold: z
      .number()
      .finite()
      .refine(isTwoDecimals, { message: 'At most two decimals' }),
    defaultPolicy: z.enum(['alert', 'allow']),
    evidenceEnabled: z.boolean(),
    evidenceDefaultRetentionDays: int,
    evidenceMaxRetentionDays: int,
    contextWindowChars: int,
    bulkMinDistinct: int,
  })
  .superRefine((s, ctx) => {
    const bound = (
      path: keyof typeof s,
      value: number,
      bounds: { min: number; max: number },
    ): void => {
      if (!within(value, bounds)) {
        ctx.addIssue({
          code: 'custom',
          path: [path],
          message: `${path} must be within [${bounds.min}, ${bounds.max}]`,
        });
      }
    };
    bound('confidenceThreshold', s.confidenceThreshold, DLP_THRESHOLD_BOUNDS);
    bound('evidenceMaxRetentionDays', s.evidenceMaxRetentionDays, {
      min: 1,
      max: DLP_EVIDENCE_RETENTION_CEILING_DAYS,
    });
    bound('evidenceDefaultRetentionDays', s.evidenceDefaultRetentionDays, {
      min: 1,
      max: s.evidenceMaxRetentionDays,
    });
    bound('contextWindowChars', s.contextWindowChars, DLP_CONTEXT_WINDOW_BOUNDS);
    bound('bulkMinDistinct', s.bulkMinDistinct, DLP_BULK_MIN_DISTINCT_BOUNDS);
  });
export type DlpPlatformSettings = z.infer<typeof dlpPlatformSettingsSchema>;

/** Platform defaults (`.env.example`, §5). */
export const DLP_PLATFORM_DEFAULTS: Readonly<DlpPlatformSettings> = Object.freeze({
  confidenceThreshold: 0.6,
  defaultPolicy: 'alert',
  evidenceEnabled: true,
  evidenceDefaultRetentionDays: 30,
  evidenceMaxRetentionDays: 180,
  contextWindowChars: 64,
  bulkMinDistinct: 5,
});

/** Environment keys of the platform settings (both the api and the email-worker read them). */
export const DLP_PLATFORM_ENV_KEYS = Object.freeze({
  confidenceThreshold: 'DLP_CONFIDENCE_THRESHOLD',
  defaultPolicy: 'DLP_DEFAULT_POLICY',
  evidenceEnabled: 'DLP_EVIDENCE_ENABLED',
  evidenceDefaultRetentionDays: 'DLP_EVIDENCE_DEFAULT_RETENTION_DAYS',
  evidenceMaxRetentionDays: 'DLP_EVIDENCE_MAX_RETENTION_DAYS',
  contextWindowChars: 'DLP_CONTEXT_WINDOW_CHARS',
  bulkMinDistinct: 'DLP_BULK_MIN_DISTINCT',
} as const satisfies Record<keyof DlpPlatformSettings, string>);

const DLP_NUMERIC_KEYS = [
  'confidenceThreshold',
  'evidenceDefaultRetentionDays',
  'evidenceMaxRetentionDays',
  'contextWindowChars',
  'bulkMinDistinct',
] as const satisfies readonly (keyof DlpPlatformSettings)[];

const parseBoolean = (value: string): boolean | string =>
  value === 'true' ? true : value === 'false' ? false : value;

/**
 * Reads the platform settings from environment variables (unset or empty → default) and
 * validates them. Throws a `ZodError` naming the setting on invalid input, so a service refuses
 * to start with inconsistent values. Booleans are exactly `true` or `false`.
 */
export function dlpPlatformSettingsFromEnv(
  env: Readonly<Record<string, string | undefined>>,
): DlpPlatformSettings {
  const read = (key: keyof DlpPlatformSettings): string | undefined => {
    const value = env[DLP_PLATFORM_ENV_KEYS[key]];
    return value === undefined || value.trim() === '' ? undefined : value.trim();
  };
  const numbers = Object.fromEntries(
    DLP_NUMERIC_KEYS.map((key) => {
      const value = read(key);
      return [key, value === undefined ? DLP_PLATFORM_DEFAULTS[key] : Number(value)];
    }),
  );
  const evidence = read('evidenceEnabled');
  return dlpPlatformSettingsSchema.parse({
    ...numbers,
    defaultPolicy: read('defaultPolicy') ?? DLP_PLATFORM_DEFAULTS.defaultPolicy,
    evidenceEnabled:
      evidence === undefined ? DLP_PLATFORM_DEFAULTS.evidenceEnabled : parseBoolean(evidence),
  });
}

const thresholdSchema = z
  .number()
  .finite()
  .refine(isTwoDecimals, { message: 'At most two decimals' });

/**
 * A tenant override (`scan_engine_settings.settings` of engine `dlp`, D18): strict at every
 * level, every key optional. Bounds that depend on the platform (evidence cap, maximum
 * retention) and the threshold bounds are checked by `resolveDlpSettings`.
 */
export const dlpTenantSettingsSchema = z.strictObject({
  inboundEnabled: z.boolean().optional(),
  thresholds: z
    .strictObject(
      Object.fromEntries(DLP_CATEGORIES.map((c) => [c, thresholdSchema.optional()])) as Record<
        DlpCategory,
        z.ZodOptional<typeof thresholdSchema>
      >,
    )
    .optional(),
  disabledDetectors: z
    .array(z.enum(DLP_TENANT_DISABLEABLE_DETECTORS))
    .max(DLP_TENANT_DISABLEABLE_DETECTORS.length)
    .refine(unique, { message: 'Duplicate detector' })
    .optional(),
  defaultPolicy: z.enum(['alert', 'allow']).optional(),
  evidence: z
    .strictObject({
      enabled: z.boolean().optional(),
      retentionDays: int.optional(),
    })
    .optional(),
});
export type DlpTenantSettings = z.infer<typeof dlpTenantSettingsSchema>;

/** The settings the DLP engine uses for one tenant (D18). */
export interface DlpEffectiveSettings {
  inboundEnabled: boolean;
  thresholds: Record<DlpCategory, number>;
  disabledDetectors: DlpTenantDisableableDetector[];
  defaultPolicy: 'alert' | 'allow';
  evidence: { enabled: boolean; retentionDays: number };
  /** Platform only. */
  contextWindowChars: number;
  /** Platform only. */
  bulkMinDistinct: number;
}

export type DlpSettingsResolution =
  | { ok: true; settings: DlpEffectiveSettings; overridden: boolean }
  | { ok: false; violations: SettingsViolation[] };

/** The bounds a tenant override must respect (the settings API returns them). */
export interface DlpSettingsBounds {
  inboundEnabled: readonly boolean[];
  thresholds: { categories: readonly DlpCategory[]; min: number; max: number };
  disabledDetectors: readonly DlpTenantDisableableDetector[];
  defaultPolicy: readonly ('alert' | 'allow')[];
  evidence: { enabled: readonly boolean[]; retentionDays: { min: number; max: number } };
}

/** The values a tenant may choose given the platform settings. */
export function dlpSettingsBounds(platform: DlpPlatformSettings): DlpSettingsBounds {
  return {
    inboundEnabled: [false, true],
    thresholds: { categories: DLP_CATEGORIES, ...DLP_THRESHOLD_BOUNDS },
    disabledDetectors: DLP_TENANT_DISABLEABLE_DETECTORS,
    defaultPolicy: ['alert', 'allow'],
    evidence: {
      enabled: platform.evidenceEnabled ? [false, true] : [false],
      retentionDays: { min: 1, max: platform.evidenceMaxRetentionDays },
    },
  };
}

const platformThresholds = (platform: DlpPlatformSettings): Record<DlpCategory, number> =>
  Object.fromEntries(DLP_CATEGORIES.map((c) => [c, platform.confidenceThreshold])) as Record<
    DlpCategory,
    number
  >;

const dlpPlatformEffective = (platform: DlpPlatformSettings): DlpEffectiveSettings => ({
  inboundEnabled: false,
  thresholds: platformThresholds(platform),
  disabledDetectors: [],
  defaultPolicy: platform.defaultPolicy,
  evidence: {
    enabled: platform.evidenceEnabled,
    retentionDays: platform.evidenceDefaultRetentionDays,
  },
  contextWindowChars: platform.contextWindowChars,
  bulkMinDistinct: platform.bulkMinDistinct,
});

const hasDefinedValue = (value: unknown): boolean => {
  if (value === undefined) return false;
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    return Object.values(value as Record<string, unknown>).some(hasDefinedValue);
  }
  return true;
};

/**
 * Merges a tenant override (raw JSON from `scan_engine_settings.settings`, or null/undefined for
 * none) into the platform settings (D18). Pure; mirrors `resolveBecSettings`. An invalid override
 * yields every violation found (dotted paths: `thresholds.payment_card`); the caller decides what
 * to do (the api answers 422; the engine ignores the row and applies the platform settings).
 *
 * Bounds: category thresholds within [0.5, 0.95] (two decimals); `disabledDetectors` only the
 * noisy detectors; `evidence.enabled` never above the platform cap; `evidence.retentionDays`
 * within [1, platform maximum]; unknown keys refused.
 */
export function resolveDlpSettings(
  platform: DlpPlatformSettings,
  override: unknown,
): DlpSettingsResolution {
  if (override === null || override === undefined) {
    return { ok: true, settings: dlpPlatformEffective(platform), overridden: false };
  }
  const parsed = dlpTenantSettingsSchema.safeParse(override);
  if (!parsed.success) {
    return {
      ok: false,
      violations: parsed.error.issues.flatMap((issue): SettingsViolation[] => {
        const base = issue.path.map(String);
        if (issue.code === 'unrecognized_keys') {
          return issue.keys.map((key) => ({
            path: [...base, key].join('.'),
            code: 'unknown_key',
            message: `Unknown setting: ${[...base, key].join('.')}`,
          }));
        }
        return [
          {
            path: base.length > 0 ? base.join('.') : 'settings',
            code: 'invalid',
            message: issue.message,
          },
        ];
      }),
    };
  }
  const tenant = parsed.data;
  const base = dlpPlatformEffective(platform);
  const limits = dlpSettingsBounds(platform);
  const violations: SettingsViolation[] = [];
  const thresholds = { ...base.thresholds };
  for (const category of DLP_CATEGORIES) {
    const value = tenant.thresholds?.[category];
    if (value === undefined) continue;
    if (!within(value, DLP_THRESHOLD_BOUNDS)) {
      violations.push({
        path: `thresholds.${category}`,
        code: 'out_of_bounds',
        message: `thresholds.${category} must be within [${DLP_THRESHOLD_BOUNDS.min}, ${DLP_THRESHOLD_BOUNDS.max}]`,
      });
    }
    thresholds[category] = value;
  }
  if (tenant.evidence?.enabled === true && !platform.evidenceEnabled) {
    violations.push({
      path: 'evidence.enabled',
      code: 'out_of_bounds',
      message: 'evidence.enabled may not exceed the platform cap (evidence disabled)',
    });
  }
  const retentionDays = tenant.evidence?.retentionDays;
  if (retentionDays !== undefined && !within(retentionDays, limits.evidence.retentionDays)) {
    violations.push({
      path: 'evidence.retentionDays',
      code: 'out_of_bounds',
      message: `evidence.retentionDays must be within [1, ${platform.evidenceMaxRetentionDays}]`,
    });
  }
  if (violations.length > 0) return { ok: false, violations };
  return {
    ok: true,
    overridden: hasDefinedValue(tenant),
    settings: {
      inboundEnabled: tenant.inboundEnabled ?? base.inboundEnabled,
      thresholds,
      disabledDetectors: [...(tenant.disabledDetectors ?? base.disabledDetectors)].sort(),
      defaultPolicy: tenant.defaultPolicy ?? base.defaultPolicy,
      evidence: {
        enabled: tenant.evidence?.enabled ?? base.evidence.enabled,
        retentionDays: retentionDays ?? base.evidence.retentionDays,
      },
      contextWindowChars: base.contextWindowChars,
      bulkMinDistinct: base.bulkMinDistinct,
    },
  };
}

// ---------------------------------------------------------------------------------------------
// Scans read API: the `dlp` section (D20) and the decrypted evidence document (D16)
// ---------------------------------------------------------------------------------------------

/** Bounds of a stored result / view (D10, D11, D20). */
export const DLP_MAX_FINDINGS = 64;
export const DLP_MAX_COVERAGE_ENTRIES = 64;
export const DLP_MAX_SOURCES_PER_FINDING = 5;
export const DLP_MAX_MASKED_SAMPLES = 3;
export const DLP_MAX_MATCHED_RULES = 16;
export const DLP_MAX_EXCEPTIONS_APPLIED = 16;
export const DLP_MAX_FINDING_COUNT = 1_000_000;
export const DLP_MAX_TEXT_CHARS = 4_000_000;
/** Ceilings of the evidence document (D16; the configured values are at most these). */
export const DLP_EVIDENCE_MAX_MATCHES_CEILING = 50;
export const DLP_EVIDENCE_MAX_PER_DETECTOR = 5;
export const DLP_EVIDENCE_CONTEXT_CHARS = 48;
export const DLP_EVIDENCE_MAX_BYTES_CEILING = 32_768;

/**
 * Whether `value` looks like it holds a raw sensitive number (§2.0 invariant 2): a run of
 * digits (single spaces or dashes allowed between them) with 9 or more digits — this covers
 * every card, account, Aadhaar (`dddd dddd dddd`) and mobile number, grouped or not.
 */
export function dlpHoldsRawNumber(value: string): boolean {
  let digits = 0;
  let previousSeparator = false;
  for (let i = 0; i < value.length; i += 1) {
    const c = value.charCodeAt(i);
    if (c >= 48 && c <= 57) {
      digits += 1;
      previousSeparator = false;
      if (digits >= 9) return true;
    } else if ((c === 32 || c === 45) && digits > 0 && !previousSeparator) {
      previousSeparator = true;
    } else {
      digits = 0;
      previousSeparator = false;
    }
  }
  return false;
}

/** A masked sample (D15): bounded, and never a raw-looking number. */
export const dlpMaskedValueSchema = z
  .string()
  .min(1)
  .max(96)
  .refine((value) => !dlpHoldsRawNumber(value), {
    message: 'A masked value must not hold a run of 9 or more digits',
  });

const versionText = (max: number) =>
  z
    .string()
    .min(1)
    .max(max)
    .regex(/^[\x21-\x7e]+$/, 'Expected a printable ASCII version');

const confidence2 = z
  .number()
  .finite()
  .min(0)
  .max(1)
  .refine(isTwoDecimals, { message: 'At most two decimals' });

/** An index path of an archive entry (`"2/0/5"`, D4): never a name. */
export const DLP_INDEX_PATH_PATTERN = /^[0-9]{1,5}(?:\/[0-9]{1,5}){0,15}$/;
const indexPath = z.string().max(96).regex(DLP_INDEX_PATH_PATTERN, 'Expected an index path');
const partIndex = z.number().int().min(0).max(65_535);

export const dlpSourceRefSchema = z.strictObject({
  kind: z.enum(DLP_SOURCE_KINDS),
  partIndex: partIndex.optional(),
  path: indexPath.optional(),
});
export type DlpSourceRef = z.infer<typeof dlpSourceRefSchema>;

/** One finding of the read API (D20): masked samples only. */
export const dlpFindingViewSchema = z
  .strictObject({
    detector: dlpDetectorIdSchema,
    code: z.string().max(REASON_CODE_MAX_LENGTH).regex(REASON_CODE_PATTERN),
    category: dlpCategorySchema,
    severity: dlpSeveritySchema,
    confidence: confidence2,
    count: z.number().int().min(0).max(DLP_MAX_FINDING_COUNT),
    capped: z.boolean(),
    sources: z.array(dlpSourceRefSchema).max(DLP_MAX_SOURCES_PER_FINDING),
    masked: z.array(dlpMaskedValueSchema).max(DLP_MAX_MASKED_SAMPLES),
    customPatternId: z.uuid().optional(),
    dictionaryId: z.uuid().optional(),
  })
  .superRefine((finding, ctx) => {
    const definition = DLP_DETECTORS[finding.detector];
    if (finding.code !== definition.code) {
      ctx.addIssue({
        code: 'custom',
        path: ['code'],
        message: `${finding.detector} has code ${definition.code}`,
      });
    }
    if (definition.category !== null && finding.category !== definition.category) {
      ctx.addIssue({
        code: 'custom',
        path: ['category'],
        message: `${finding.detector} has category ${definition.category}`,
      });
    }
    if (definition.severity !== null && finding.severity !== definition.severity) {
      ctx.addIssue({
        code: 'custom',
        path: ['severity'],
        message: `${finding.detector} has severity ${definition.severity}`,
      });
    }
    if ((finding.customPatternId !== undefined) !== (finding.detector === 'CU1')) {
      ctx.addIssue({
        code: 'custom',
        path: ['customPatternId'],
        message: 'customPatternId belongs to CU1 findings only (and is required there)',
      });
    }
    if ((finding.dictionaryId !== undefined) !== (finding.detector === 'DC1')) {
      ctx.addIssue({
        code: 'custom',
        path: ['dictionaryId'],
        message: 'dictionaryId belongs to DC1 findings only (and is required there)',
      });
    }
  });
export type DlpFindingView = z.infer<typeof dlpFindingViewSchema>;

/** One source of the coverage detail (D10). */
export const dlpCoverageEntrySchema = z
  .strictObject({
    source: z.enum(DLP_SOURCE_KINDS),
    partIndex: partIndex.optional(),
    path: indexPath.optional(),
    format: dlpExtractFormatSchema,
    status: z.enum(DLP_SOURCE_STATUSES),
    reasons: z
      .array(dlpCoverageCodeSchema)
      .max(DLP_COVERAGE_CODES.length)
      .refine(unique, { message: 'Duplicate reason' }),
    chars: z.number().int().min(0).max(DLP_MAX_TEXT_CHARS),
    truncated: z.boolean(),
  })
  .superRefine((entry, ctx) => {
    if (entry.status === 'scanned' && (entry.reasons.length > 0 || entry.truncated)) {
      ctx.addIssue({
        code: 'custom',
        path: ['status'],
        message: 'A fully scanned source has no coverage reason',
      });
    }
    if (entry.status !== 'scanned' && entry.reasons.length === 0) {
      ctx.addIssue({
        code: 'custom',
        path: ['reasons'],
        message: 'A partial or not extracted source names its reason',
      });
    }
  });
export type DlpCoverageEntry = z.infer<typeof dlpCoverageEntrySchema>;

/** Per-category aggregate (D7). */
export const dlpCategoryAggregateSchema = z.strictObject({
  category: dlpCategorySchema,
  count: z.number().int().min(0).max(DLP_MAX_FINDING_COUNT),
  maxSeverity: dlpSeveritySchema,
  maxConfidence: confidence2,
});
export type DlpCategoryAggregate = z.infer<typeof dlpCategoryAggregateSchema>;

/** The policy section of the read API (D20): public ids only. */
export const dlpPolicyViewSchema = z.strictObject({
  winner: z.strictObject({ policyId: z.uuid(), ruleId: z.uuid() }).nullable(),
  matched: z
    .array(
      z.strictObject({
        policyId: z.uuid(),
        ruleId: z.uuid(),
        action: dlpActionSchema,
        mode: z.enum(DLP_POLICY_MODES),
      }),
    )
    .max(DLP_MAX_MATCHED_RULES),
  exceptionsApplied: z
    .array(z.uuid())
    .max(DLP_MAX_EXCEPTIONS_APPLIED)
    .refine(unique, { message: 'Duplicate exception id' }),
});
export type DlpPolicyView = z.infer<typeof dlpPolicyViewSchema>;

/** Aadhaar detection state of a result (D17): `disabled` = NI2 did not run at all. */
export const DLP_AADHAAR_STATES = ['enabled', 'disabled'] as const;

/**
 * The `dlp` section of an engine entry in `GET /api/v1/messages/{id}/scans` (D20), returned only
 * to callers holding `dlp:read`. Never raw values, context text, evidence offsets, dictionary
 * terms, pattern text or durations.
 */
export const dlpResultViewSchema = z
  .strictObject({
    engineVersion: versionText(96),
    rulesVersion: versionText(16),
    settingsVersion: versionText(96),
    policyVersion: versionText(32),
    extractorVersion: versionText(32),
    verdict: dlpVerdictSchema,
    action: dlpActionSchema,
    actionSource: z.enum(DLP_ACTION_SOURCES),
    coverage: z.enum(DLP_COVERAGES),
    coverageDetail: z.array(dlpCoverageEntrySchema).max(DLP_MAX_COVERAGE_ENTRIES),
    aadhaar: z.enum(DLP_AADHAAR_STATES),
    categories: z.array(dlpCategoryAggregateSchema).max(DLP_CATEGORIES.length),
    findings: z.array(dlpFindingViewSchema).max(DLP_MAX_FINDINGS),
    policy: dlpPolicyViewSchema,
    evidence: z.strictObject({
      status: z.enum(DLP_EVIDENCE_STATUSES),
      expiresAt: z.iso.datetime().nullable(),
      purged: z.boolean(),
    }),
  })
  .superRefine((view, ctx) => {
    const issue = (path: string, message: string) =>
      ctx.addIssue({ code: 'custom', path: [path], message });
    if (!unique(view.categories.map((c) => c.category))) {
      issue('categories', 'A category appears at most once');
    }
    const findings = view.findings.length;
    if (view.verdict === 'clean' && (findings > 0 || view.coverage !== 'complete')) {
      issue('verdict', 'clean requires complete coverage and no finding (§2.0 invariant 1)');
    }
    if (view.verdict === 'unknown' && (findings > 0 || view.coverage !== 'partial')) {
      issue('verdict', 'unknown means partial coverage without a reportable finding');
    }
    if (view.verdict === 'suspicious' && findings === 0) {
      issue('verdict', 'suspicious requires at least one reportable finding');
    }
    if (view.verdict === 'skipped' && (findings > 0 || view.action !== 'allow')) {
      issue('verdict', 'skipped results carry no finding and the allow action');
    }
    if (view.action !== 'allow' && view.actionSource === 'none') {
      issue('actionSource', 'An action other than allow comes from a policy');
    }
    if (view.policy.winner !== null && view.actionSource !== 'tenant_policy') {
      issue('policy', 'Only a tenant policy has a winning rule');
    }
  });
export type DlpResultView = z.infer<typeof dlpResultViewSchema>;

/** Detectors whose value is never stored raw, even inside the encrypted evidence (D16, D17). */
export const DLP_EVIDENCE_MASKED_DETECTORS = ['PC1', 'NI2', 'CR1', 'CR3', 'CR4', 'CR5'] as const;

/** PC1 in evidence: first 6 + last 4 (D16; PCI DSS scope, ADR-0038). */
export const DLP_EVIDENCE_CARD_PATTERN = /^[0-9]{6}\*{3,9}[0-9]{4}$/;

const evidenceContext = z.string().max(DLP_EVIDENCE_CONTEXT_CHARS * 4);

/** One evidence match (D16): offsets in the extracted segment text (`dlp-extract/1` + `dlp-text/1`). */
export const dlpEvidenceMatchSchema = z
  .strictObject({
    detector: dlpDetectorIdSchema,
    code: z.string().max(REASON_CODE_MAX_LENGTH).regex(REASON_CODE_PATTERN),
    source: z.strictObject({
      kind: z.enum(DLP_SOURCE_KINDS),
      partIndex: partIndex.optional(),
      path: indexPath.optional(),
      segment: z.number().int().min(0).max(199),
    }),
    start: z.number().int().min(0).max(DLP_MAX_TEXT_CHARS),
    end: z.number().int().min(0).max(DLP_MAX_TEXT_CHARS),
    value: z.string().min(1).max(1024),
    context: z.strictObject({ before: evidenceContext, after: evidenceContext }),
  })
  .superRefine((match, ctx) => {
    if (!(match.start < match.end)) {
      ctx.addIssue({ code: 'custom', path: ['end'], message: 'Expected start < end' });
    }
    if (match.code !== DLP_DETECTORS[match.detector].code) {
      ctx.addIssue({ code: 'custom', path: ['code'], message: 'Code of another detector' });
    }
    if (match.detector === 'PC1' && !DLP_EVIDENCE_CARD_PATTERN.test(match.value)) {
      ctx.addIssue({
        code: 'custom',
        path: ['value'],
        message: 'Card numbers are kept as first 6 + last 4 only',
      });
    }
    if (
      (DLP_EVIDENCE_MASKED_DETECTORS as readonly string[]).includes(match.detector) &&
      match.detector !== 'PC1' &&
      dlpHoldsRawNumber(match.value)
    ) {
      ctx.addIssue({ code: 'custom', path: ['value'], message: 'This value is stored masked' });
    }
  });
export type DlpEvidenceMatch = z.infer<typeof dlpEvidenceMatchSchema>;

/** The decrypted evidence JSON (D16). */
export const dlpEvidenceDocumentSchema = z.strictObject({
  format: z.literal(DLP_EVIDENCE_ALGORITHM),
  textDerivationVersion: versionText(32),
  extractorVersion: versionText(32),
  aadhaar: z.enum(DLP_AADHAAR_STATES),
  matches: z.array(dlpEvidenceMatchSchema).min(1).max(DLP_EVIDENCE_MAX_MATCHES_CEILING),
  /** Matches left out by the bounds (count only). */
  dropped: z.number().int().min(0).max(DLP_MAX_FINDING_COUNT),
});
export type DlpEvidenceDocument = z.infer<typeof dlpEvidenceDocumentSchema>;
