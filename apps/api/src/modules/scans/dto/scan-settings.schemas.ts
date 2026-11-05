import {
  AUTH_FAILURE_VERDICTS,
  DMARC_REJECT_VERDICTS,
  PHISHING_VERDICTS,
} from '@email-gateway/security-contracts';
import { z } from 'zod';

/**
 * Request and response shapes of the scan settings routes (step 4.1 S8, S16):
 * `GET /scan-settings`, `PUT /scan-settings/{engine}`, `DELETE /scan-settings/{engine}`.
 * Step 4.1 registers one engine (`rspamd`); its settings are the Rspamd thresholds.
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
        'dmarcRejectVerdict, authFailureVerdict); replaces the previous override. Unknown keys ' +
        'are refused (422)',
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

export const EngineSettingsViewSchema = z.object({
  engine: z.string().describe('Engine name (ENGINE_CATALOG; step 4.1: rspamd)'),
  required: z.boolean().describe('Required for every scan round'),
  tenantMayDisable: z.boolean(),
  platform: RspamdPlatformSettingsDoc.describe('Platform settings (SCAN_RSPAMD_*)'),
  bounds: RspamdBoundsDoc.describe('What an override may choose'),
  override: RspamdOverrideDoc.nullable().describe('The organization override; null for none'),
  effective: RspamdEffectiveSettingsDoc.describe('What the scan stage applies'),
  overrideApplied: z
    .boolean()
    .describe('False when there is no override or it no longer fits the platform settings'),
  violations: z
    .array(SettingsViolationSchema)
    .describe('Why a stored override is ignored (platform settings tightened since it was saved)'),
  version: Version,
  updatedAt: z.iso.datetime().nullable(),
});
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

export const ScanSettingsResponseSchema = EngineSettingsViewSchema.extend({
  note: z.string().describe(SETTINGS_APPLY_NOTE),
});
export type ScanSettingsResponse = z.output<typeof ScanSettingsResponseSchema>;
