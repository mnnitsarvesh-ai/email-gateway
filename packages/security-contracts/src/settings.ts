import { createHash } from 'node:crypto';
import { z } from 'zod';

/**
 * Rspamd thresholds and per-tenant settings (docs/plan/steps/09-rspamd.md S8).
 *
 * Platform settings come from the environment (`SCAN_RSPAMD_*`, read by the api and the
 * email-worker and validated at start). A tenant may override them through one
 * `scan_engine_settings` row per engine; `resolveRspamdSettings` merges the two and returns the
 * effective settings or the list of violations:
 *
 * - score thresholds anywhere inside the platform bounds `[scoreMin, scoreMax]`, with
 *   `suspiciousScore < spamScore` after merging (thresholds are tuning: a tenant may loosen or
 *   tighten them; the non-score rules are not tunable down);
 * - severity settings may only be raised relative to the platform value, in the order
 *   `reason_only < suspicious < malicious`;
 * - a required engine can never be disabled (the strict tenant schema has no such key);
 * - unknown keys are refused.
 */

/** Severity ladder of the severity settings (raise-only for tenants). */
export const SETTING_SEVERITIES = ['reason_only', 'suspicious', 'malicious'] as const;
export type SettingSeverity = (typeof SETTING_SEVERITIES)[number];

const severityRank = (value: SettingSeverity): number => SETTING_SEVERITIES.indexOf(value);

export const PHISHING_VERDICTS = ['suspicious', 'malicious'] as const;
export const DMARC_REJECT_VERDICTS = ['suspicious', 'malicious'] as const;
export const AUTH_FAILURE_VERDICTS = ['reason_only', 'suspicious'] as const;

export type PhishingVerdict = (typeof PHISHING_VERDICTS)[number];
export type DmarcRejectVerdict = (typeof DMARC_REJECT_VERDICTS)[number];
export type AuthFailureVerdict = (typeof AUTH_FAILURE_VERDICTS)[number];

/** The severity settings and their allowed values. */
const SEVERITY_SETTINGS = {
  phishingVerdict: PHISHING_VERDICTS,
  dmarcRejectVerdict: DMARC_REJECT_VERDICTS,
  authFailureVerdict: AUTH_FAILURE_VERDICTS,
} as const;
type SeverityKey = keyof typeof SEVERITY_SETTINGS;
const SEVERITY_KEYS = Object.keys(SEVERITY_SETTINGS) as SeverityKey[];

/** Absolute bounds of the platform score range (`0 < SCORE_MIN < SCORE_MAX ≤ 100`). */
export const RSPAMD_SCORE_LIMIT = 100;

/** A score with at most two decimals (`DECIMAL(8,3)` columns; API input). */
const isTwoDecimals = (value: number): boolean =>
  Math.abs(Math.round(value * 100) - value * 100) < 1e-6;

const scoreSchema = z
  .number()
  .finite()
  .min(0)
  .max(RSPAMD_SCORE_LIMIT)
  .refine(isTwoDecimals, { message: 'At most two decimals' });

export const rspamdPlatformSettingsSchema = z
  .strictObject({
    spamScore: scoreSchema,
    suspiciousScore: scoreSchema,
    scoreMin: scoreSchema,
    scoreMax: scoreSchema,
    phishingVerdict: z.enum(PHISHING_VERDICTS),
    dmarcRejectVerdict: z.enum(DMARC_REJECT_VERDICTS),
    authFailureVerdict: z.enum(AUTH_FAILURE_VERDICTS),
  })
  .superRefine((s, ctx) => {
    if (!(s.scoreMin > 0 && s.scoreMin < s.scoreMax)) {
      ctx.addIssue({
        code: 'custom',
        path: ['scoreMin'],
        message: 'Expected 0 < scoreMin < scoreMax ≤ 100',
      });
    }
    if (s.spamScore < s.scoreMin || s.spamScore > s.scoreMax) {
      ctx.addIssue({
        code: 'custom',
        path: ['spamScore'],
        message: 'spamScore must be within [scoreMin, scoreMax]',
      });
    }
    if (s.suspiciousScore < s.scoreMin || !(s.suspiciousScore < s.spamScore)) {
      ctx.addIssue({
        code: 'custom',
        path: ['suspiciousScore'],
        message: 'Expected scoreMin ≤ suspiciousScore < spamScore',
      });
    }
  });
export type RspamdPlatformSettings = z.infer<typeof rspamdPlatformSettingsSchema>;

/** Defaults of the platform settings (`.env.example`, S8). */
export const RSPAMD_PLATFORM_DEFAULTS: Readonly<RspamdPlatformSettings> = Object.freeze({
  spamScore: 6,
  suspiciousScore: 4,
  scoreMin: 1,
  scoreMax: 15,
  phishingVerdict: 'suspicious',
  dmarcRejectVerdict: 'suspicious',
  authFailureVerdict: 'reason_only',
});

/** Environment keys of the platform settings (both the api and the email-worker read them). */
export const RSPAMD_PLATFORM_ENV_KEYS = Object.freeze({
  spamScore: 'SCAN_RSPAMD_SPAM_SCORE',
  suspiciousScore: 'SCAN_RSPAMD_SUSPICIOUS_SCORE',
  scoreMin: 'SCAN_RSPAMD_SCORE_MIN',
  scoreMax: 'SCAN_RSPAMD_SCORE_MAX',
  phishingVerdict: 'SCAN_RSPAMD_PHISHING_VERDICT',
  dmarcRejectVerdict: 'SCAN_RSPAMD_DMARC_REJECT_VERDICT',
  authFailureVerdict: 'SCAN_RSPAMD_AUTH_FAILURE_VERDICT',
} as const satisfies Record<keyof RspamdPlatformSettings, string>);

/**
 * Reads the platform settings from environment variables (unset or empty → default) and
 * validates them. Throws a `ZodError` naming the setting on invalid input, so a service refuses
 * to start with inconsistent thresholds.
 */
export function rspamdPlatformSettingsFromEnv(
  env: Readonly<Record<string, string | undefined>>,
): RspamdPlatformSettings {
  const read = (key: keyof RspamdPlatformSettings): string | undefined => {
    const value = env[RSPAMD_PLATFORM_ENV_KEYS[key]];
    return value === undefined || value.trim() === '' ? undefined : value.trim();
  };
  const number = (key: 'spamScore' | 'suspiciousScore' | 'scoreMin' | 'scoreMax'): number => {
    const value = read(key);
    return value === undefined ? RSPAMD_PLATFORM_DEFAULTS[key] : Number(value);
  };
  return rspamdPlatformSettingsSchema.parse({
    spamScore: number('spamScore'),
    suspiciousScore: number('suspiciousScore'),
    scoreMin: number('scoreMin'),
    scoreMax: number('scoreMax'),
    phishingVerdict: read('phishingVerdict') ?? RSPAMD_PLATFORM_DEFAULTS.phishingVerdict,
    dmarcRejectVerdict: read('dmarcRejectVerdict') ?? RSPAMD_PLATFORM_DEFAULTS.dmarcRejectVerdict,
    authFailureVerdict: read('authFailureVerdict') ?? RSPAMD_PLATFORM_DEFAULTS.authFailureVerdict,
  });
}

/** A tenant override (`scan_engine_settings.settings` of engine `rspamd`): strict, all optional. */
export const rspamdTenantSettingsSchema = z.strictObject({
  spamScore: scoreSchema.optional(),
  suspiciousScore: scoreSchema.optional(),
  phishingVerdict: z.enum(PHISHING_VERDICTS).optional(),
  dmarcRejectVerdict: z.enum(DMARC_REJECT_VERDICTS).optional(),
  authFailureVerdict: z.enum(AUTH_FAILURE_VERDICTS).optional(),
});
export type RspamdTenantSettings = z.infer<typeof rspamdTenantSettingsSchema>;

/** The settings the Rspamd verdict mapping uses for one tenant. */
export interface RspamdEffectiveSettings {
  spamScore: number;
  suspiciousScore: number;
  phishingVerdict: PhishingVerdict;
  dmarcRejectVerdict: DmarcRejectVerdict;
  authFailureVerdict: AuthFailureVerdict;
}

export type SettingsViolationCode =
  'invalid' | 'unknown_key' | 'out_of_bounds' | 'threshold_order' | 'severity_lowered';

export interface SettingsViolation {
  /** The setting concerned (`settings` for the object itself). */
  path: string;
  code: SettingsViolationCode;
  message: string;
}

export type RspamdSettingsResolution =
  | { ok: true; settings: RspamdEffectiveSettings; overridden: boolean }
  | { ok: false; violations: SettingsViolation[] };

/** The bounds a tenant override must respect (the settings API returns them, S16). */
export interface RspamdSettingsBounds {
  spamScore: { min: number; max: number };
  suspiciousScore: { min: number; max: number };
  phishingVerdict: readonly PhishingVerdict[];
  dmarcRejectVerdict: readonly DmarcRejectVerdict[];
  authFailureVerdict: readonly AuthFailureVerdict[];
}

const raisedFrom = <T extends SettingSeverity>(values: readonly T[], floor: T): T[] =>
  values.filter((value) => severityRank(value) >= severityRank(floor));

/** The values a tenant may choose given the platform settings. */
export function rspamdSettingsBounds(platform: RspamdPlatformSettings): RspamdSettingsBounds {
  return {
    spamScore: { min: platform.scoreMin, max: platform.scoreMax },
    suspiciousScore: { min: platform.scoreMin, max: platform.scoreMax },
    phishingVerdict: raisedFrom(PHISHING_VERDICTS, platform.phishingVerdict),
    dmarcRejectVerdict: raisedFrom(DMARC_REJECT_VERDICTS, platform.dmarcRejectVerdict),
    authFailureVerdict: raisedFrom(AUTH_FAILURE_VERDICTS, platform.authFailureVerdict),
  };
}

const platformEffective = (platform: RspamdPlatformSettings): RspamdEffectiveSettings => ({
  spamScore: platform.spamScore,
  suspiciousScore: platform.suspiciousScore,
  phishingVerdict: platform.phishingVerdict,
  dmarcRejectVerdict: platform.dmarcRejectVerdict,
  authFailureVerdict: platform.authFailureVerdict,
});

/**
 * Merges a tenant override (raw JSON from `scan_engine_settings.settings`, or null/undefined for
 * none) into the platform settings (S8). Pure. An invalid override yields every violation found;
 * the caller decides what to do (the api answers 422; the worker ignores the row and applies the
 * platform settings).
 */
export function resolveRspamdSettings(
  platform: RspamdPlatformSettings,
  override: unknown,
): RspamdSettingsResolution {
  if (override === null || override === undefined) {
    return { ok: true, settings: platformEffective(platform), overridden: false };
  }
  const parsed = rspamdTenantSettingsSchema.safeParse(override);
  if (!parsed.success) {
    return {
      ok: false,
      violations: parsed.error.issues.flatMap((issue): SettingsViolation[] => {
        if (issue.code === 'unrecognized_keys') {
          return issue.keys.map((key) => ({
            path: key,
            code: 'unknown_key',
            message: `Unknown setting: ${key}`,
          }));
        }
        return [
          {
            path: issue.path.length > 0 ? issue.path.join('.') : 'settings',
            code: 'invalid',
            message: issue.message,
          },
        ];
      }),
    };
  }
  const tenant = parsed.data;
  const settings: RspamdEffectiveSettings = {
    ...platformEffective(platform),
    ...Object.fromEntries(Object.entries(tenant).filter(([, value]) => value !== undefined)),
  };
  const violations: SettingsViolation[] = [];
  for (const key of ['spamScore', 'suspiciousScore'] as const) {
    const value = tenant[key];
    if (value !== undefined && (value < platform.scoreMin || value > platform.scoreMax)) {
      violations.push({
        path: key,
        code: 'out_of_bounds',
        message: `${key} must be within [${platform.scoreMin}, ${platform.scoreMax}]`,
      });
    }
  }
  if (!(settings.suspiciousScore < settings.spamScore)) {
    violations.push({
      path: tenant.suspiciousScore !== undefined ? 'suspiciousScore' : 'spamScore',
      code: 'threshold_order',
      message: `suspiciousScore (${settings.suspiciousScore}) must be below spamScore (${settings.spamScore})`,
    });
  }
  for (const key of SEVERITY_KEYS) {
    const value = tenant[key];
    if (value !== undefined && severityRank(value) < severityRank(platform[key])) {
      violations.push({
        path: key,
        code: 'severity_lowered',
        message: `${key} may only be raised from the platform value ${platform[key]}`,
      });
    }
  }
  if (violations.length > 0) return { ok: false, violations };
  return { ok: true, settings, overridden: Object.keys(tenant).length > 0 };
}

/** Canonical JSON: object keys sorted recursively, so equal settings hash equally. */
function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

/**
 * `scan_engine_results.settings_version` (S8), for any engine's platform settings object (Rspamd,
 * attachment):
 * `<mapping version>;p=<first 12 hex of SHA-256 of the canonical platform settings>;t=<row
 * version | none>`. `rowVersion` is the `scan_engine_settings.version` of the override that was
 * applied, or null when the platform settings were applied unchanged (no row, or a row that
 * failed validation at use and was ignored).
 */
export function settingsVersion(
  mappingVersion: string,
  platform: object,
  rowVersion: number | null,
): string {
  const hash = createHash('sha256').update(canonicalJson(platform), 'utf8').digest('hex');
  return `${mappingVersion};p=${hash.slice(0, 12)};t=${rowVersion === null ? 'none' : String(rowVersion)}`;
}
