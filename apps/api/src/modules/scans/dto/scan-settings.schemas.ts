import {
  ATTACHMENT_RULE_VERDICTS,
  AUTH_FAILURE_VERDICTS,
  BEC_AI_MODES,
  CLICK_SUSPICIOUS_ACTIONS,
  CLICK_UNKNOWN_ACTIONS,
  DKIM_SIGNED_POLICIES,
  DMARC_REJECT_VERDICTS,
  FILE_TYPE_IDS,
  MESSAGE_DIRECTIONS,
  PHISHING_VERDICTS,
  SCAN_TIME_FETCH_MODES,
} from '@email-gateway/security-contracts';
import { z } from 'zod';

/**
 * Request and response shapes of the scan settings routes (step 4.1 S8, S16; step 4.2 A8):
 * `GET /scan-settings`, `PUT /scan-settings/{engine}`, `DELETE /scan-settings/{engine}`.
 * Engines with tenant settings: `rspamd` (thresholds and severities), `attachment` (type
 * rules, raise-only verdicts, a tighter size limit) and `url` (step 4.3 U13: domain lists,
 * fetch mode, rewriting, click policy, dynamic inspection) and `bec` (step 4.4 B13: score
 * thresholds, extra free-mail domains, history opt-in and retention, AI layer modes within the
 * platform caps); one view shape per engine.
 */

const Version = z
  .number()
  .int()
  .min(0)
  .max(4_294_967_295)
  .describe('Version of the override row (0 = no row yet); +1 per change');

export const ScanSettingsPutSchema = z.strictObject({
  expectedVersion: Version.describe(
    'The `version` the caller saw (0 = no override yet); 409 `version_conflict` otherwise',
  ),
  settings: z
    .record(z.string(), z.unknown())
    .describe(
      'The override, all keys optional (rspamd: spamScore, suspiciousScore, phishingVerdict, ' +
        'dmarcRejectVerdict, authFailureVerdict; attachment: deniedTypes, allowedTypes, ' +
        'deniedTypeVerdict, typeMismatchVerdict, encryptedArchiveVerdict, ' +
        'maxAttachmentBytes; url: allowedDomains, blockedDomains, scanTimeFetch, ' +
        'lookalike.extraProtectedDomains, rewrite.{enabled, directions, expiryDays, ' +
        'excludedDomains, dkimSignedPolicy, plainText}, click.{suspicious, unknown, ' +
        'allowContinue}, dynamicInspection; bec: suspiciousScore, maliciousScore, ' +
        'freemailExtraDomains, history.{enabled, retentionDays}, ai.{localModel, llm, ' +
        'llmDailyCallLimit, raiseConfidence}); replaces the previous override. Unknown keys are ' +
        'refused (422)',
    ),
});
export type ScanSettingsPut = z.output<typeof ScanSettingsPutSchema>;

export const ScanSettingsDeleteQuerySchema = z.strictObject({
  expectedVersion: z.coerce
    .number()
    .int()
    .min(0)
    .max(4_294_967_295)
    .describe('The `version` the caller saw'),
});
export type ScanSettingsDeleteQuery = z.output<typeof ScanSettingsDeleteQuerySchema>;

const Score = z.number();

/** Rspamd settings as the API shows them (thresholds and severities). */
export const RspamdPlatformSettingsDoc = z.object({
  spamScore: Score,
  suspiciousScore: Score,
  scoreMin: Score,
  scoreMax: Score,
  phishingVerdict: z.enum(PHISHING_VERDICTS),
  dmarcRejectVerdict: z.enum(DMARC_REJECT_VERDICTS),
  authFailureVerdict: z.enum(AUTH_FAILURE_VERDICTS),
});

export const RspamdEffectiveSettingsDoc = RspamdPlatformSettingsDoc.omit({
  scoreMin: true,
  scoreMax: true,
});

export const RspamdOverrideDoc = RspamdEffectiveSettingsDoc.partial();

const Range = z.object({ min: Score, max: Score });
export const RspamdBoundsDoc = z.object({
  spamScore: Range,
  suspiciousScore: Range.describe('Also below the effective spamScore'),
  phishingVerdict: z.array(z.enum(PHISHING_VERDICTS)).describe('Allowed values (raise-only)'),
  dmarcRejectVerdict: z.array(z.enum(DMARC_REJECT_VERDICTS)).describe('Allowed values'),
  authFailureVerdict: z.array(z.enum(AUTH_FAILURE_VERDICTS)).describe('Allowed values'),
});

export const SettingsViolationSchema = z.object({
  path: z.string(),
  code: z.enum(['invalid', 'unknown_key', 'out_of_bounds', 'threshold_order', 'severity_lowered']),
  message: z.string(),
});

const viewCommon = {
  required: z.boolean().describe('Required for every scan round'),
  tenantMayDisable: z.boolean(),
  overrideApplied: z
    .boolean()
    .describe('False when there is no override or it no longer fits the platform settings'),
  violations: z
    .array(SettingsViolationSchema)
    .describe('Why a stored override is ignored (platform settings tightened since it was saved)'),
  version: Version,
  updatedAt: z.iso.datetime().nullable(),
};

export const RspamdSettingsViewSchema = z.object({
  engine: z.literal('rspamd').describe('Engine name (ENGINE_CATALOG)'),
  platform: RspamdPlatformSettingsDoc.describe('Platform settings (SCAN_RSPAMD_*)'),
  bounds: RspamdBoundsDoc.describe('What an override may choose'),
  override: RspamdOverrideDoc.nullable().describe('The organization override; null for none'),
  effective: RspamdEffectiveSettingsDoc.describe('What the scan stage applies'),
  ...viewCommon,
});

const FileTypeId = z.enum(FILE_TYPE_IDS);
const RuleVerdict = z.enum(ATTACHMENT_RULE_VERDICTS);
const ByteCount = z.number().int().min(0);

/** Attachment platform settings (`ATTACHMENT_*`, step 4.2 A8); archive limits are platform-only. */
export const AttachmentPlatformSettingsDoc = z.object({
  maxAttachmentBytes: ByteCount.describe('Largest attachment that is content-scanned'),
  archiveMaxDepth: z.number().int().describe('Archive nesting depth inspected'),
  archiveMaxEntries: z.number().int().describe('Archive entries inspected, over all levels'),
  maxEntryBytes: ByteCount.describe('Largest archive entry inspected'),
  maxDecompressedBytes: ByteCount.describe('Decompressed bytes per attachment, over all levels'),
  maxCompressionRatio: z.number().int().describe('Largest compression ratio'),
  maxEntryFindings: z.number().int().describe('Archive entry findings kept per attachment'),
  deniedTypes: z.array(FileTypeId).describe('Platform deny list (never removable)'),
  deniedTypeVerdict: RuleVerdict,
  typeMismatchVerdict: RuleVerdict,
  encryptedArchiveVerdict: RuleVerdict,
});

export const AttachmentOverrideDoc = z.object({
  deniedTypes: z.array(FileTypeId).optional().describe('Added to the platform deny list'),
  allowedTypes: z
    .array(FileTypeId)
    .optional()
    .describe('Allow-list mode: only these types (never a platform-denied type)'),
  deniedTypeVerdict: RuleVerdict.optional().describe('Raise-only'),
  typeMismatchVerdict: RuleVerdict.optional().describe('Raise-only'),
  encryptedArchiveVerdict: RuleVerdict.optional().describe('Raise-only'),
  maxAttachmentBytes: ByteCount.optional().describe('Tighten-only'),
});

export const AttachmentEffectiveSettingsDoc = z.object({
  maxAttachmentBytes: ByteCount,
  deniedTypes: z.array(FileTypeId).describe('Platform plus organization deny list'),
  allowedTypes: z
    .array(FileTypeId)
    .nullable()
    .describe('Allow list; null = every type that is not denied'),
  deniedTypeVerdict: RuleVerdict,
  typeMismatchVerdict: RuleVerdict,
  encryptedArchiveVerdict: RuleVerdict,
});

export const AttachmentBoundsDoc = z.object({
  maxAttachmentBytes: z.object({ min: ByteCount, max: ByteCount }),
  deniedTypes: z.array(FileTypeId).describe('Types an override may add to the deny list'),
  platformDeniedTypes: z.array(FileTypeId).describe('Always denied, never allowed'),
  allowedTypes: z.array(FileTypeId).describe('Types an allow list may contain'),
  maxAllowedTypes: z.number().int().describe('Most entries of deniedTypes / allowedTypes'),
  deniedTypeVerdict: z.array(RuleVerdict).describe('Allowed values (raise-only)'),
  typeMismatchVerdict: z.array(RuleVerdict).describe('Allowed values (raise-only)'),
  encryptedArchiveVerdict: z.array(RuleVerdict).describe('Allowed values (raise-only)'),
});

export const AttachmentSettingsViewSchema = z.object({
  engine: z.literal('attachment').describe('Engine name (ENGINE_CATALOG)'),
  platform: AttachmentPlatformSettingsDoc.describe('Platform settings (ATTACHMENT_*)'),
  bounds: AttachmentBoundsDoc.describe('What an override may choose'),
  override: AttachmentOverrideDoc.nullable().describe('The organization override; null for none'),
  effective: AttachmentEffectiveSettingsDoc.describe('What the attachment engine applies'),
  ...viewCommon,
});

const Domain = z.string().describe('Lower-case ASCII domain or host (A-labels after IDNA)');
const DomainList = z.array(Domain);
const MaxItems = z.object({ maxItems: z.number().int() });
const FetchMode = z.enum(SCAN_TIME_FETCH_MODES);
const Direction = z.enum(MESSAGE_DIRECTIONS);
const DkimPolicy = z.enum(DKIM_SIGNED_POLICIES);
const SuspiciousAction = z.enum(CLICK_SUSPICIOUS_ACTIONS);
const UnknownAction = z.enum(CLICK_UNKNOWN_ACTIONS);

/** URL platform settings (`URL_SCAN_TIME_FETCH`, `URL_REWRITE_*`, `URL_TOKEN_*_EXPIRY_DAYS`, …). */
export const UrlPlatformSettingsDoc = z.object({
  scanTimeFetch: FetchMode.describe('The most scan-time fetching a tenant may choose'),
  rewrite: z.object({
    enabled: z.boolean().describe('Platform switch: false = no rewriting for any tenant'),
    directions: z.array(Direction).describe('Default directions'),
    defaultExpiryDays: z.number().int(),
    maxExpiryDays: z.number().int(),
    dkimSignedPolicy: DkimPolicy,
  }),
  dynamicInspection: z.boolean().describe('Platform switch of the isolated browser inspection'),
});

export const UrlOverrideDoc = z.object({
  allowedDomains: DomainList.optional().describe(
    'Suppresses lookalike/structure/landing rules and excludes from rewriting (never feed or ' +
      'DNSBL malicious findings)',
  ),
  blockedDomains: DomainList.optional().describe('→ malicious (rule M4) for this organization'),
  scanTimeFetch: FetchMode.optional().describe('At most the platform mode'),
  lookalike: z
    .object({ extraProtectedDomains: DomainList.optional() })
    .optional()
    .describe('Further domains protected against lookalikes'),
  rewrite: z
    .object({
      enabled: z.boolean().optional(),
      directions: z.array(Direction).optional(),
      expiryDays: z.number().int().optional(),
      excludedDomains: DomainList.optional(),
      dkimSignedPolicy: DkimPolicy.optional(),
      plainText: z.boolean().optional(),
    })
    .optional(),
  click: z
    .object({
      suspicious: SuspiciousAction.optional(),
      unknown: UnknownAction.optional(),
      allowContinue: z.boolean().optional(),
    })
    .optional()
    .describe('Time-of-click policy (clean is always allowed, malicious always blocked)'),
  dynamicInspection: z.boolean().optional(),
});

export const UrlEffectiveSettingsDoc = z.object({
  allowedDomains: DomainList,
  blockedDomains: DomainList,
  scanTimeFetch: FetchMode,
  lookalike: z.object({ extraProtectedDomains: DomainList }),
  rewrite: z.object({
    enabled: z.boolean(),
    directions: z.array(Direction),
    expiryDays: z.number().int(),
    excludedDomains: DomainList,
    dkimSignedPolicy: DkimPolicy,
    plainText: z.boolean(),
  }),
  click: z.object({
    suspicious: SuspiciousAction,
    unknown: UnknownAction,
    allowContinue: z.boolean(),
  }),
  dynamicInspection: z.boolean(),
});

export const UrlBoundsDoc = z.object({
  allowedDomains: MaxItems,
  blockedDomains: MaxItems,
  scanTimeFetch: z.array(FetchMode).describe('Modes up to the platform mode'),
  lookalike: z.object({ extraProtectedDomains: MaxItems }),
  rewrite: z.object({
    enabled: z.array(z.boolean()).describe('[false] when the platform disabled rewriting'),
    directions: z.array(Direction),
    expiryDays: z.object({ min: z.number().int(), max: z.number().int() }),
    excludedDomains: MaxItems,
    dkimSignedPolicy: z.array(DkimPolicy),
  }),
  click: z.object({
    suspicious: z.array(SuspiciousAction),
    unknown: z.array(UnknownAction),
  }),
  dynamicInspection: z
    .array(z.boolean())
    .describe('[false] when the platform disabled dynamic inspection'),
});

export const UrlSettingsViewSchema = z.object({
  engine: z.literal('url').describe('Engine name (ENGINE_CATALOG)'),
  platform: UrlPlatformSettingsDoc.describe('Platform settings (URL_*)'),
  bounds: UrlBoundsDoc.describe('What an override may choose'),
  override: UrlOverrideDoc.nullable().describe(
    'The organization override (domains normalized to ASCII); null for none',
  ),
  effective: UrlEffectiveSettingsDoc.describe(
    'What the URL engine (rewrite and scan settings) and the click-service (click policy and ' +
      'lists, read live) apply',
  ),
  ...viewCommon,
});

const AiMode = z.enum(BEC_AI_MODES);
const IntRange = z.object({ min: z.number().int(), max: z.number().int() });

/** BEC platform settings (`BEC_*`, step 4.4 B13); the modes and limits are tenant caps. */
export const BecPlatformSettingsDoc = z.object({
  suspiciousScore: z.number().int(),
  maliciousScore: z.number().int(),
  aiRaiseConfidence: z.number(),
  aiCorroborateConfidence: z.number().describe('Platform only'),
  aiMaliciousBand: z.number().int().describe('Platform only'),
  localModelMode: AiMode.describe('Cap of the tenant local-model mode'),
  llmMode: AiMode.describe('Cap of the tenant LLM mode'),
  llmMaxCallsPerTenantPerDay: z.number().int(),
  historyDefaultRetentionDays: z.number().int(),
  historyMaxRetentionDays: z.number().int(),
});

export const BecOverrideDoc = z.object({
  suspiciousScore: z.number().int().optional(),
  maliciousScore: z.number().int().optional(),
  freemailExtraDomains: DomainList.optional().describe(
    'Further free-mail domains (normalized to ASCII; public suffixes refused)',
  ),
  history: z
    .object({ enabled: z.boolean().optional(), retentionDays: z.number().int().optional() })
    .optional()
    .describe('Historical communication context (opt-in, keyed hashes only, ADR-0035)'),
  ai: z
    .object({
      localModel: AiMode.optional(),
      llm: AiMode.optional(),
      llmDailyCallLimit: z.number().int().optional(),
      raiseConfidence: z.number().optional(),
    })
    .optional(),
});

export const BecEffectiveSettingsDoc = z.object({
  suspiciousScore: z.number().int(),
  maliciousScore: z.number().int(),
  freemailExtraDomains: DomainList,
  history: z.object({ enabled: z.boolean(), retentionDays: z.number().int() }),
  ai: z.object({
    localModel: AiMode,
    llm: AiMode,
    llmDailyCallLimit: z.number().int(),
    raiseConfidence: z.number(),
    corroborateConfidence: z.number(),
    maliciousBand: z.number().int(),
  }),
});

export const BecBoundsDoc = z.object({
  suspiciousScore: IntRange.describe('Also below the effective maliciousScore'),
  maliciousScore: IntRange,
  freemailExtraDomains: MaxItems,
  history: z.object({ enabled: z.array(z.boolean()), retentionDays: IntRange }),
  ai: z.object({
    localModel: z.array(AiMode).describe('Modes up to the platform cap'),
    llm: z.array(AiMode).describe('Modes up to the platform cap'),
    llmDailyCallLimit: IntRange,
    raiseConfidence: z.object({ min: z.number(), max: z.number() }),
  }),
});

export const BecSettingsViewSchema = z.object({
  engine: z.literal('bec').describe('Engine name (ENGINE_CATALOG)'),
  platform: BecPlatformSettingsDoc.describe('Platform settings (BEC_*)'),
  bounds: BecBoundsDoc.describe('What an override may choose'),
  override: BecOverrideDoc.nullable().describe('The organization override; null for none'),
  effective: BecEffectiveSettingsDoc.describe('What the BEC engine applies'),
  ...viewCommon,
});

/** The settings of one engine, by `engine`. */
export const EngineSettingsViewSchema = z.discriminatedUnion('engine', [
  RspamdSettingsViewSchema,
  AttachmentSettingsViewSchema,
  UrlSettingsViewSchema,
  BecSettingsViewSchema,
]);
export type EngineSettingsView = z.output<typeof EngineSettingsViewSchema>;

/** How quickly the scan stage applies a change (S8 settings cache). */
export const SETTINGS_APPLY_NOTE =
  'Scan workers cache the settings per organization and engine for up to ' +
  'SCAN_SETTINGS_CACHE_TTL_MS (default 30 seconds): a change applies to messages scanned after ' +
  'that; rounds already scanned keep their results.';

export const ScanSettingsListSchema = z.object({
  data: z.array(EngineSettingsViewSchema).describe('Every registered engine (catalog order)'),
  note: z.string().describe(SETTINGS_APPLY_NOTE),
});
export type ScanSettingsList = z.output<typeof ScanSettingsListSchema>;

const Note = z.string().describe(SETTINGS_APPLY_NOTE);
export const ScanSettingsResponseSchema = z.discriminatedUnion('engine', [
  RspamdSettingsViewSchema.extend({ note: Note }),
  AttachmentSettingsViewSchema.extend({ note: Note }),
  UrlSettingsViewSchema.extend({ note: Note }),
  BecSettingsViewSchema.extend({ note: Note }),
]);
export type ScanSettingsResponse = z.output<typeof ScanSettingsResponseSchema>;
