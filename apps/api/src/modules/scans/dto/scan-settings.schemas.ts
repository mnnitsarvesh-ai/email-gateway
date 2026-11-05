import {
  ATTACHMENT_RULE_VERDICTS,
  AUTH_FAILURE_VERDICTS,
  DMARC_REJECT_VERDICTS,
  FILE_TYPE_IDS,
  PHISHING_VERDICTS,
} from '@email-gateway/security-contracts';
import { z } from 'zod';

/**
 * Request and response shapes of the scan settings routes (step 4.1 S8, S16; step 4.2 A8):
 * `GET /scan-settings`, `PUT /scan-settings/{engine}`, `DELETE /scan-settings/{engine}`.
 * Engines with tenant settings: `rspamd` (thresholds and severities) and `attachment` (type
 * rules, raise-only verdicts, a tighter size limit); one view shape per engine.
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
        'maxAttachmentBytes); replaces the previous override. Unknown keys are refused (422)',
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

/** The settings of one engine, by `engine`. */
export const EngineSettingsViewSchema = z.discriminatedUnion('engine', [
  RspamdSettingsViewSchema,
  AttachmentSettingsViewSchema,
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
]);
export type ScanSettingsResponse = z.output<typeof ScanSettingsResponseSchema>;
