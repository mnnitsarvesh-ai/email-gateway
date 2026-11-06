import { z } from 'zod';
import type { SettingsViolation } from './settings';

/**
 * Contracts of the URL engine, the rewriter and the time-of-click service
 * (docs/plan/steps/11-url-protection.md U1, U4, U7, U10, U11, U13, U14, U16; ADR-0029–0031):
 * URL verdicts, the bounded reason-code enum of the verdict map `url-map/1` (also the metric label
 * set of `scan_url_findings_total`), click decisions, rewrite skip reasons, threat categories, the
 * platform/tenant settings with their pure resolver, and the normalized per-URL result that
 * `url_scan_results` rows and the scans read API carry. URLs, hashes, hosts, codes, counts and
 * bounded structured findings only: never page bodies, titles, anchor text or HTML (§2.0
 * invariant 3).
 */

/** Mapping version of the URL verdict map (U10). */
export const URL_MAPPING_VERSION = 'url-map/1';

/** Verdict of one URL (U10): `malicious > suspicious > unknown > clean` (Prisma `UrlVerdict`). */
export const URL_VERDICTS = ['clean', 'suspicious', 'malicious', 'unknown'] as const;
export type UrlVerdict = (typeof URL_VERDICTS)[number];
export const urlVerdictSchema = z.enum(URL_VERDICTS);

const URL_VERDICT_RANK: Readonly<Record<UrlVerdict, number>> = Object.freeze({
  clean: 0,
  unknown: 1,
  suspicious: 2,
  malicious: 3,
});

/** Severity rank of a URL verdict (U10). */
export const urlVerdictRank = (verdict: UrlVerdict): number => URL_VERDICT_RANK[verdict];

/**
 * The reason codes of the URL engine, in the order of the U10 table (rules M1–C1; S1 expanded
 * with the U7 lookalike codes), followed by the engine-level codes (U0, E1, the per-message
 * scheme and limit codes of U4, and `url.invalid` of U5). `@email-gateway/url-security` holds the
 * same list as `URL_MAPPER_CODES` (a contract test asserts equality). Every code matches
 * `REASON_CODE_PATTERN`. Engine attempt failures (`engine.*`) are not URL reason codes: they are
 * the 4.1 failure codes of the email-worker.
 */
export const URL_REASON_CODES = [
  // M1: local feed hit (high/critical).
  'url.feed_malicious',
  // M2: DNSBL phishing / malware / c2.
  'url.dnsbl_phishing',
  'url.dnsbl_malware',
  'url.dnsbl_c2',
  // M3: high-confidence lookalike and a credential form.
  'url.phishing_high_confidence',
  // M4: tenant blocked domain.
  'url.tenant_blocked',
  // M5 (click time): dynamic phishing.
  'url.dynamic_phishing',
  // S1: lookalikes (U7 L1, L2, L3, L4, tenant L5).
  'url.lookalike_homoglyph',
  'url.lookalike_edit_distance',
  'url.lookalike_combosquat',
  'url.mixed_script',
  'url.lookalike_tld_swap',
  // S2: rdap new domain.
  'url.new_domain',
  // S3: IP literal hosts.
  'url.ip_host',
  'url.redirect_to_ip',
  // S4: redirect counts.
  'url.redirect_limit',
  'url.many_redirects',
  // S5 (and S9): redirect into a blocked address or name.
  'url.redirect_blocked_internal',
  // S6: feed low/medium, DNSBL spam/scam/other.
  'url.feed_suspicious',
  'url.dnsbl_spam',
  // S7: URL structure.
  'url.userinfo',
  'url.obfuscated_host',
  'url.ip_obfuscated',
  'url.entity_obfuscation',
  'url.control_chars',
  'url.text_mismatch',
  'url.too_long',
  // S8: landing page credential forms.
  'url.credential_form',
  'url.credential_form_cross_origin',
  // S9 (click time): dynamic signals.
  'url.dynamic_download',
  'url.dynamic_cross_origin_form',
  // U1: fetch attempted and not completed; required fetch not performed.
  'url.fetch_timeout',
  'url.fetch_dns_error',
  'url.fetch_tls_error',
  'url.fetch_connection_error',
  'url.fetch_http_error',
  'url.fetch_too_large',
  'url.fetch_blocked_port',
  'url.fetch_not_performed',
  // U2: provider error or open breaker.
  'url.reputation_unavailable',
  // U3 (click time): dynamic inspection failed.
  'url.dynamic_failed',
  // R: informational.
  'url.shortened',
  'url.redirected',
  'url.meta_refresh',
  'url.idn',
  'url.brand_tld_variant',
  'url.nonstandard_port',
  'url.trailing_dot',
  'url.in_attachment',
  'url.allowlisted',
  'url.charset_guess',
  'url.fetch_skipped_limit',
  // C1: clean.
  'clean.no_findings',
  // Engine level: U0 (no URLs), E1 (incomplete content), message codes (U4), invalid IDN (U5).
  'url.none',
  'url.content_incomplete',
  'url.script_scheme',
  'url.data_uri',
  'url.unsafe_scheme',
  'limit.url_count',
  'url.invalid',
] as const;
export type UrlReasonCode = (typeof URL_REASON_CODES)[number];
export const urlReasonCodeSchema = z.enum(URL_REASON_CODES);

export const isUrlReasonCode = (value: string): value is UrlReasonCode =>
  (URL_REASON_CODES as readonly string[]).includes(value);

/**
 * Codes that describe the engine's result as a whole, never one URL (U0, E1, U4 message codes,
 * U5 `url.invalid`).
 */
export const URL_ENGINE_LEVEL_CODES = Object.freeze([
  'url.none',
  'url.content_incomplete',
  'url.script_scheme',
  'url.data_uri',
  'url.unsafe_scheme',
  'limit.url_count',
  'url.invalid',
] as const satisfies readonly UrlReasonCode[]);

/** Informational codes (rule R): they never change a verdict. */
export const URL_INFORMATIONAL_CODES = Object.freeze([
  'url.shortened',
  'url.redirected',
  'url.meta_refresh',
  'url.idn',
  'url.brand_tld_variant',
  'url.nonstandard_port',
  'url.trailing_dot',
  'url.in_attachment',
  'url.allowlisted',
  'url.charset_guess',
  'url.fetch_skipped_limit',
] as const satisfies readonly UrlReasonCode[]);

/** Decisions of the click-service (U14; Prisma `UrlClickDecision`). */
export const CLICK_DECISIONS = [
  'allowed',
  'warned',
  'blocked',
  'continued',
  'expired',
  'not_found',
] as const;
export type ClickDecision = (typeof CLICK_DECISIONS)[number];
export const clickDecisionSchema = z.enum(CLICK_DECISIONS);

/** Why a round's EML was not rewritten (U11, `url_rewrites.skip_reason`); never a failure. */
export const REWRITE_SKIP_REASONS = [
  'disabled',
  'direction',
  'no_urls',
  'parse_incomplete',
  'too_large',
  'signed_smime',
  'signed_pgp',
  'encrypted',
  'dkim_policy',
  'structure_mismatch',
  'error',
] as const;
export type RewriteSkipReason = (typeof REWRITE_SKIP_REASONS)[number];
export const rewriteSkipReasonSchema = z.enum(REWRITE_SKIP_REASONS);

/** Categories of a threat indicator or reputation answer (U6; Prisma `ThreatCategory`). */
export const THREAT_CATEGORIES = ['phishing', 'malware', 'spam', 'scam', 'c2', 'other'] as const;
export type ThreatCategory = (typeof THREAT_CATEGORIES)[number];
export const threatCategorySchema = z.enum(THREAT_CATEGORIES);

// ---------------------------------------------------------------------------------------------
// Settings (U13)
// ---------------------------------------------------------------------------------------------

/** Scan-time fetch selection (U9), ordered from no fetching to fetching every URL. */
export const SCAN_TIME_FETCH_MODES = ['off', 'shorteners', 'suspicious', 'all'] as const;
export type ScanTimeFetchMode = (typeof SCAN_TIME_FETCH_MODES)[number];
const fetchRank = (mode: ScanTimeFetchMode): number => SCAN_TIME_FETCH_MODES.indexOf(mode);

export const MESSAGE_DIRECTIONS = ['inbound', 'outbound', 'internal'] as const;
export type MessageDirection = (typeof MESSAGE_DIRECTIONS)[number];

export const DKIM_SIGNED_POLICIES = ['rewrite', 'skip'] as const;
export type DkimSignedPolicy = (typeof DKIM_SIGNED_POLICIES)[number];

export const CLICK_SUSPICIOUS_ACTIONS = ['warn', 'block'] as const;
export type ClickSuspiciousAction = (typeof CLICK_SUSPICIOUS_ACTIONS)[number];
export const CLICK_UNKNOWN_ACTIONS = ['allow', 'warn', 'block'] as const;
export type ClickUnknownAction = (typeof CLICK_UNKNOWN_ACTIONS)[number];

/** At most this many domains in `allowedDomains` / `blockedDomains` (U13). */
export const URL_MAX_LISTED_DOMAINS = 500;
/** At most this many domains in `rewrite.excludedDomains` (U13). */
export const URL_MAX_EXCLUDED_DOMAINS = 200;
/** At most this many domains in `lookalike.extraProtectedDomains` (U13). */
export const URL_MAX_EXTRA_PROTECTED_DOMAINS = 50;
/**
 * Upper bound of `URL_TOKEN_MAX_EXPIRY_DAYS`: a click token must expire before its
 * `message_urls` row is dropped (6 monthly partitions are kept, i.e. at least 181 days, U12).
 */
export const URL_TOKEN_EXPIRY_DAYS_CEILING = 180;

/**
 * A domain or host of a tenant list: lower-case ASCII (A-labels after IDNA), at least two labels,
 * labels of 1–63 characters of `[a-z0-9-]` not starting or ending with `-`, at most 253
 * characters, no trailing dot. The api additionally normalizes through `@email-gateway/url-security`
 * and refuses public suffixes (WP5); the engine validates again at use.
 */
export const URL_DOMAIN_PATTERN =
  /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
export const urlDomainSchema = z
  .string()
  .regex(URL_DOMAIN_PATTERN, 'Expected a lower-case ASCII domain with at least two labels');

const unique = (values: readonly unknown[]) => new Set(values).size === values.length;

const domainList = (max: number) =>
  z.array(urlDomainSchema).max(max).refine(unique, { message: 'Duplicate domain' });

const directionList = z
  .array(z.enum(MESSAGE_DIRECTIONS))
  .min(1)
  .max(MESSAGE_DIRECTIONS.length)
  .refine(unique, { message: 'Duplicate direction' });

/**
 * Platform URL settings that tenants can override (§5; env `URL_SCAN_TIME_FETCH`,
 * `URL_REWRITE_*`, `URL_TOKEN_*_EXPIRY_DAYS`, `URL_DYNAMIC_INSPECTION`; read by the api and the
 * email-worker). Every other `URL_*` key is platform-only and validated by the services.
 */
export const urlPlatformSettingsSchema = z
  .strictObject({
    /** The most fetching a tenant may choose (U9). */
    scanTimeFetch: z.enum(SCAN_TIME_FETCH_MODES),
    rewrite: z.strictObject({
      /** Platform switch: false = no rewriting for any tenant. */
      enabled: z.boolean(),
      /** Default directions (U11; tenants may opt in to the others). */
      directions: directionList.readonly(),
      defaultExpiryDays: z.number().int().min(1).max(URL_TOKEN_EXPIRY_DAYS_CEILING),
      maxExpiryDays: z.number().int().min(1).max(URL_TOKEN_EXPIRY_DAYS_CEILING),
      dkimSignedPolicy: z.enum(DKIM_SIGNED_POLICIES),
    }),
    /** Platform switch: false = no dynamic inspection for any tenant (U15). */
    dynamicInspection: z.boolean(),
  })
  .superRefine((s, ctx) => {
    if (s.rewrite.defaultExpiryDays > s.rewrite.maxExpiryDays) {
      ctx.addIssue({
        code: 'custom',
        path: ['rewrite', 'defaultExpiryDays'],
        message: 'defaultExpiryDays must not exceed maxExpiryDays',
      });
    }
  });
export type UrlPlatformSettings = z.infer<typeof urlPlatformSettingsSchema>;

/** Platform defaults (`.env.example`, §5). */
export const URL_PLATFORM_DEFAULTS: Readonly<UrlPlatformSettings> = Object.freeze({
  scanTimeFetch: 'suspicious',
  rewrite: Object.freeze({
    enabled: true,
    directions: Object.freeze(['inbound'] as const),
    defaultExpiryDays: 30,
    maxExpiryDays: 90,
    dkimSignedPolicy: 'rewrite',
  }),
  dynamicInspection: true,
});

/** Environment keys of the platform settings (§5). */
export const URL_PLATFORM_ENV_KEYS = Object.freeze({
  scanTimeFetch: 'URL_SCAN_TIME_FETCH',
  rewriteEnabled: 'URL_REWRITE_ENABLED',
  rewriteDirections: 'URL_REWRITE_DIRECTIONS',
  defaultExpiryDays: 'URL_TOKEN_DEFAULT_EXPIRY_DAYS',
  maxExpiryDays: 'URL_TOKEN_MAX_EXPIRY_DAYS',
  dkimSignedPolicy: 'URL_REWRITE_DKIM_SIGNED',
  dynamicInspection: 'URL_DYNAMIC_INSPECTION',
} as const);

/** Parses `true`/`false` (and `on`/`off`, `1`/`0`); anything else is returned unchanged. */
const flag = (value: string): unknown => {
  const v = value.toLowerCase();
  if (v === 'true' || v === 'on' || v === '1') return true;
  if (v === 'false' || v === 'off' || v === '0') return false;
  return value;
};

/**
 * Reads the platform settings from environment variables (unset or empty → default) and
 * validates them. `URL_REWRITE_DIRECTIONS` is a comma-separated list; `URL_DYNAMIC_INSPECTION`
 * is `on`/`off` (`true`/`false` accepted). Throws a `ZodError` naming the setting on invalid
 * input, so a service refuses to start with inconsistent settings.
 */
export function urlPlatformSettingsFromEnv(
  env: Readonly<Record<string, string | undefined>>,
): UrlPlatformSettings {
  const read = (key: keyof typeof URL_PLATFORM_ENV_KEYS): string | undefined => {
    const value = env[URL_PLATFORM_ENV_KEYS[key]];
    return value === undefined || value.trim() === '' ? undefined : value.trim();
  };
  const d = URL_PLATFORM_DEFAULTS;
  const number = (key: 'defaultExpiryDays' | 'maxExpiryDays'): unknown => {
    const value = read(key);
    return value === undefined ? d.rewrite[key] : Number(value);
  };
  const enabled = read('rewriteEnabled');
  const dynamic = read('dynamicInspection');
  const directions = read('rewriteDirections');
  return urlPlatformSettingsSchema.parse({
    scanTimeFetch: read('scanTimeFetch') ?? d.scanTimeFetch,
    rewrite: {
      enabled: enabled === undefined ? d.rewrite.enabled : flag(enabled),
      directions:
        directions === undefined
          ? [...d.rewrite.directions]
          : directions
              .split(',')
              .map((v) => v.trim())
              .filter((v) => v.length > 0),
      defaultExpiryDays: number('defaultExpiryDays'),
      maxExpiryDays: number('maxExpiryDays'),
      dkimSignedPolicy: read('dkimSignedPolicy') ?? d.rewrite.dkimSignedPolicy,
    },
    dynamicInspection: dynamic === undefined ? d.dynamicInspection : flag(dynamic),
  });
}

/**
 * A tenant override (`scan_engine_settings.settings` of engine `url`, U13): strict at every level,
 * every key optional. Bounds that depend on the platform (expiry, fetch mode, the platform
 * switches) are checked by `resolveUrlSettings`.
 */
export const urlTenantSettingsSchema = z
  .strictObject({
    allowedDomains: domainList(URL_MAX_LISTED_DOMAINS).optional(),
    blockedDomains: domainList(URL_MAX_LISTED_DOMAINS).optional(),
    scanTimeFetch: z.enum(SCAN_TIME_FETCH_MODES).optional(),
    lookalike: z
      .strictObject({
        extraProtectedDomains: domainList(URL_MAX_EXTRA_PROTECTED_DOMAINS).optional(),
      })
      .optional(),
    rewrite: z
      .strictObject({
        enabled: z.boolean().optional(),
        directions: directionList.optional(),
        expiryDays: z.number().int().optional(),
        excludedDomains: domainList(URL_MAX_EXCLUDED_DOMAINS).optional(),
        dkimSignedPolicy: z.enum(DKIM_SIGNED_POLICIES).optional(),
        plainText: z.boolean().optional(),
      })
      .optional(),
    click: z
      .strictObject({
        suspicious: z.enum(CLICK_SUSPICIOUS_ACTIONS).optional(),
        unknown: z.enum(CLICK_UNKNOWN_ACTIONS).optional(),
        allowContinue: z.boolean().optional(),
      })
      .optional(),
    dynamicInspection: z.boolean().optional(),
  })
  .superRefine((s, ctx) => {
    if (s.allowedDomains && s.blockedDomains) {
      const allowed = new Set(s.allowedDomains);
      const both = s.blockedDomains.filter((domain) => allowed.has(domain));
      if (both.length > 0) {
        ctx.addIssue({
          code: 'custom',
          path: ['blockedDomains'],
          message: `A domain cannot be both allowed and blocked: ${both.join(', ')}`,
        });
      }
    }
  });
export type UrlTenantSettings = z.infer<typeof urlTenantSettingsSchema>;

/**
 * The settings the URL engine and the click-service use for one tenant (U13). `clean` is always
 * allowed and `malicious` always blocked (not configurable).
 */
export interface UrlEffectiveSettings {
  allowedDomains: string[];
  blockedDomains: string[];
  scanTimeFetch: ScanTimeFetchMode;
  lookalike: { extraProtectedDomains: string[] };
  rewrite: {
    enabled: boolean;
    /** In `MESSAGE_DIRECTIONS` order. */
    directions: MessageDirection[];
    expiryDays: number;
    excludedDomains: string[];
    dkimSignedPolicy: DkimSignedPolicy;
    plainText: boolean;
  };
  click: {
    suspicious: ClickSuspiciousAction;
    unknown: ClickUnknownAction;
    allowContinue: boolean;
  };
  dynamicInspection: boolean;
}

/** Defaults of the tenant-only settings (no platform key, U13). */
export const URL_TENANT_DEFAULTS: Readonly<{
  plainText: boolean;
  click: Readonly<UrlEffectiveSettings['click']>;
}> = Object.freeze({
  plainText: true,
  click: Object.freeze({ suspicious: 'warn', unknown: 'warn', allowContinue: true }),
});

export type UrlSettingsResolution =
  | { ok: true; settings: UrlEffectiveSettings; overridden: boolean }
  | { ok: false; violations: SettingsViolation[] };

/** The bounds a tenant override must respect (the settings API returns them). */
export interface UrlSettingsBounds {
  allowedDomains: { maxItems: number };
  blockedDomains: { maxItems: number };
  /** Fetch modes up to the platform's (a tenant may fetch less, never more). */
  scanTimeFetch: readonly ScanTimeFetchMode[];
  lookalike: { extraProtectedDomains: { maxItems: number } };
  rewrite: {
    /** `[false]` when the platform disabled rewriting, else `[false, true]`. */
    enabled: readonly boolean[];
    directions: readonly MessageDirection[];
    expiryDays: { min: number; max: number };
    excludedDomains: { maxItems: number };
    dkimSignedPolicy: readonly DkimSignedPolicy[];
  };
  click: {
    suspicious: readonly ClickSuspiciousAction[];
    unknown: readonly ClickUnknownAction[];
  };
  /** `[false]` when the platform disabled dynamic inspection, else `[false, true]`. */
  dynamicInspection: readonly boolean[];
}

/** The values a tenant may choose given the platform settings. */
export function urlSettingsBounds(platform: UrlPlatformSettings): UrlSettingsBounds {
  return {
    allowedDomains: { maxItems: URL_MAX_LISTED_DOMAINS },
    blockedDomains: { maxItems: URL_MAX_LISTED_DOMAINS },
    scanTimeFetch: SCAN_TIME_FETCH_MODES.filter(
      (mode) => fetchRank(mode) <= fetchRank(platform.scanTimeFetch),
    ),
    lookalike: { extraProtectedDomains: { maxItems: URL_MAX_EXTRA_PROTECTED_DOMAINS } },
    rewrite: {
      enabled: platform.rewrite.enabled ? [false, true] : [false],
      directions: MESSAGE_DIRECTIONS,
      expiryDays: { min: 1, max: platform.rewrite.maxExpiryDays },
      excludedDomains: { maxItems: URL_MAX_EXCLUDED_DOMAINS },
      dkimSignedPolicy: DKIM_SIGNED_POLICIES,
    },
    click: { suspicious: CLICK_SUSPICIOUS_ACTIONS, unknown: CLICK_UNKNOWN_ACTIONS },
    dynamicInspection: platform.dynamicInspection ? [false, true] : [false],
  };
}

const inDirectionOrder = (values: Iterable<MessageDirection>): MessageDirection[] => {
  const set = new Set(values);
  return MESSAGE_DIRECTIONS.filter((d) => set.has(d));
};

const platformEffective = (platform: UrlPlatformSettings): UrlEffectiveSettings => ({
  allowedDomains: [],
  blockedDomains: [],
  scanTimeFetch: platform.scanTimeFetch,
  lookalike: { extraProtectedDomains: [] },
  rewrite: {
    enabled: platform.rewrite.enabled,
    directions: inDirectionOrder(platform.rewrite.directions),
    expiryDays: platform.rewrite.defaultExpiryDays,
    excludedDomains: [],
    dkimSignedPolicy: platform.rewrite.dkimSignedPolicy,
    plainText: URL_TENANT_DEFAULTS.plainText,
  },
  click: { ...URL_TENANT_DEFAULTS.click },
  dynamicInspection: platform.dynamicInspection,
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
 * none) into the platform settings (U13). Pure; mirrors `resolveAttachmentSettings`. An invalid
 * override yields every violation found (paths are dotted: `rewrite.expiryDays`); the caller
 * decides what to do (the api answers 422; the engine and the click-service ignore the row and
 * apply the platform settings).
 *
 * Bounds: `scanTimeFetch` at most the platform mode (a tenant may fetch less, never more);
 * `rewrite.enabled` and `dynamicInspection` may be switched on only when the platform has them
 * on; `rewrite.expiryDays` within [1, platform maxExpiryDays]. A domain may not be both allowed
 * and blocked (`invalid`).
 */
export function resolveUrlSettings(
  platform: UrlPlatformSettings,
  override: unknown,
): UrlSettingsResolution {
  if (override === null || override === undefined) {
    return { ok: true, settings: platformEffective(platform), overridden: false };
  }
  const parsed = urlTenantSettingsSchema.safeParse(override);
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
  const base = platformEffective(platform);
  const violations: SettingsViolation[] = [];

  if (
    tenant.scanTimeFetch !== undefined &&
    fetchRank(tenant.scanTimeFetch) > fetchRank(platform.scanTimeFetch)
  ) {
    violations.push({
      path: 'scanTimeFetch',
      code: 'out_of_bounds',
      message: `scanTimeFetch may not exceed the platform mode ${platform.scanTimeFetch}`,
    });
  }
  if (tenant.rewrite?.enabled === true && !platform.rewrite.enabled) {
    violations.push({
      path: 'rewrite.enabled',
      code: 'out_of_bounds',
      message: 'URL rewriting is disabled on the platform',
    });
  }
  const expiryDays = tenant.rewrite?.expiryDays;
  if (expiryDays !== undefined && (expiryDays < 1 || expiryDays > platform.rewrite.maxExpiryDays)) {
    violations.push({
      path: 'rewrite.expiryDays',
      code: 'out_of_bounds',
      message: `rewrite.expiryDays must be within [1, ${platform.rewrite.maxExpiryDays}]`,
    });
  }
  if (tenant.dynamicInspection === true && !platform.dynamicInspection) {
    violations.push({
      path: 'dynamicInspection',
      code: 'out_of_bounds',
      message: 'Dynamic inspection is disabled on the platform',
    });
  }
  if (violations.length > 0) return { ok: false, violations };

  return {
    ok: true,
    overridden: hasDefinedValue(tenant),
    settings: {
      allowedDomains: tenant.allowedDomains ?? base.allowedDomains,
      blockedDomains: tenant.blockedDomains ?? base.blockedDomains,
      scanTimeFetch: tenant.scanTimeFetch ?? base.scanTimeFetch,
      lookalike: {
        extraProtectedDomains:
          tenant.lookalike?.extraProtectedDomains ?? base.lookalike.extraProtectedDomains,
      },
      rewrite: {
        enabled: tenant.rewrite?.enabled ?? base.rewrite.enabled,
        directions:
          tenant.rewrite?.directions !== undefined
            ? inDirectionOrder(tenant.rewrite.directions)
            : base.rewrite.directions,
        expiryDays: expiryDays ?? base.rewrite.expiryDays,
        excludedDomains: tenant.rewrite?.excludedDomains ?? base.rewrite.excludedDomains,
        dkimSignedPolicy: tenant.rewrite?.dkimSignedPolicy ?? base.rewrite.dkimSignedPolicy,
        plainText: tenant.rewrite?.plainText ?? base.rewrite.plainText,
      },
      click: {
        suspicious: tenant.click?.suspicious ?? base.click.suspicious,
        unknown: tenant.click?.unknown ?? base.click.unknown,
        allowContinue: tenant.click?.allowContinue ?? base.click.allowContinue,
      },
      dynamicInspection: tenant.dynamicInspection ?? base.dynamicInspection,
    },
  };
}

// ---------------------------------------------------------------------------------------------
// Normalized per-URL result (U16 without `clicks`)
// ---------------------------------------------------------------------------------------------

/** At most this many URLs per message are stored and returned (U4 `URL_MAX_PER_MESSAGE`). */
export const URL_MAX_RESULTS = 200;
/** At most this many reputation answers per URL (§3 `url_scan_results.reputation`). */
export const URL_MAX_REPUTATION_ANSWERS = 12;
/** At most this many lookalike findings per URL (U7). */
export const URL_MAX_LOOKALIKE_FINDINGS = 5;
/** At most this many redirect-chain entries per URL (U8, §3 `redirect_chain`). */
export const URL_MAX_CHAIN_ENTRIES = 10;
/** Longest stored URL (U4 `URL_MAX_LENGTH`). */
export const URL_MAX_LENGTH = 2048;

/** Extraction sources (U4, U18 `scan_url_extracted_total{source}`). */
export const URL_SOURCES = [
  'text',
  'html_href',
  'html_src',
  'form_action',
  'meta_refresh',
  'srcset',
  'attachment',
] as const;
export type UrlSource = (typeof URL_SOURCES)[number];

/** Host kinds (U5; Prisma `UrlHostKind`). */
export const URL_HOST_KINDS = ['domain', 'ipv4', 'ipv6'] as const;
export type UrlHostKind = (typeof URL_HOST_KINDS)[number];

export const REPUTATION_KINDS = ['url', 'domain', 'ip'] as const;
export const REPUTATION_STATUSES = ['listed', 'clear', 'error'] as const;
export type ReputationStatus = (typeof REPUTATION_STATUSES)[number];

/** Lookalike rules (U7). L4 (mixed script) and L6 (IDN) have no target. */
export const LOOKALIKE_RULES = ['L1', 'L2', 'L3', 'L4', 'L5', 'L6'] as const;
export const LOOKALIKE_TARGET_KINDS = ['brand', 'tenant', 'extra'] as const;

/** Fetch outcomes of an attempted fetch (U8; `not_attempted` is a null `fetch`). */
export const URL_FETCH_STATUSES = ['completed', 'error', 'blocked'] as const;
export const URL_FETCH_ERRORS = [
  'timeout',
  'dns_error',
  'tls_error',
  'connection_error',
  'http_error',
  'too_large',
  'header_limit',
  'redirect_limit',
] as const;
/** SSRF guard reasons (U8, `url_fetch_blocked_total{reason}`). */
export const URL_BLOCKED_REASONS = [
  'loopback',
  'private',
  'link_local',
  'cgnat',
  'multicast',
  'reserved',
  'documentation',
  'metadata',
  'ula',
  'unspecified',
  'mapped',
  'name',
  'scheme',
  'port',
  'deny_list',
] as const;
export const URL_HOP_KINDS = ['initial', 'http', 'meta'] as const;
export const URL_DYNAMIC_STATUSES = ['pending', 'completed', 'failed', 'expired'] as const;

/**
 * An ASCII host as WHATWG `URL.hostname` serializes it: lower-case name (A-labels) or dotted
 * IPv4, or a bracketed IPv6 literal. Mirrors `URL_HOST_PATTERN` of event-contracts.
 */
export const URL_HOST_PATTERN =
  /^(?:(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)*|\[[0-9a-f:.]{2,45}\])$/;
const hostSchema = z.string().max(253).regex(URL_HOST_PATTERN, 'Expected an ASCII host');
/** A brand id of the protected brand list. */
export const BRAND_ID_PATTERN = /^[a-z0-9][a-z0-9_-]{0,31}$/;
const brandIdSchema = z.string().regex(BRAND_ID_PATTERN, 'Expected a brand id');
/** A reputation provider id (`local_feed`, `dnsbl`, `rdap`, …). */
export const PROVIDER_ID_PATTERN = /^[a-z][a-z0-9_]{0,31}$/;

const noControlOrSpace = (value: string): boolean => {
  for (let i = 0; i < value.length; i += 1) {
    const c = value.charCodeAt(i);
    if (c <= 0x20 || c === 0x7f) return false;
  }
  return true;
};

/** A normalized http(s) URL (U5 redirect form; never userinfo), ≤ 2 048 characters. */
const storedUrlSchema = z
  .string()
  .min(1)
  .max(URL_MAX_LENGTH)
  .refine((value) => /^https?:\/\//.test(value) && noControlOrSpace(value), {
    message: 'Expected a normalized http(s) URL',
  })
  .refine(
    (value) => {
      try {
        const url = new URL(value);
        return url.username === '' && url.password === '';
      } catch {
        // A truncated URL (U4) need not parse; it still has the scheme prefix checked above.
        return true;
      }
    },
    { message: 'A stored URL never carries userinfo' },
  );

const urlReasonCodeList = (max: number) =>
  z.array(urlReasonCodeSchema).max(max).refine(unique, { message: 'Duplicate reason code' });

const ENGINE_LEVEL: ReadonlySet<string> = new Set(URL_ENGINE_LEVEL_CODES);

export const urlReputationAnswerSchema = z.strictObject({
  provider: z.string().regex(PROVIDER_ID_PATTERN, 'Expected a provider id'),
  kind: z.enum(REPUTATION_KINDS),
  status: z.enum(REPUTATION_STATUSES),
  category: threatCategorySchema.nullable(),
});
export type UrlReputationAnswer = z.infer<typeof urlReputationAnswerSchema>;

export const urlLookalikeFindingSchema = z.strictObject({
  rule: z.enum(LOOKALIKE_RULES),
  targetKind: z.enum(LOOKALIKE_TARGET_KINDS).nullable(),
  targetDomain: urlDomainSchema.nullable(),
  score: z.number().finite().min(0).max(1),
});
export type UrlLookalikeFinding = z.infer<typeof urlLookalikeFindingSchema>;

export const urlChainEntrySchema = z.strictObject({
  host: hostSchema,
  status: z.number().int().min(100).max(599).nullable(),
  kind: z.enum(URL_HOP_KINDS),
  blocked: z.enum(URL_BLOCKED_REASONS).nullable(),
});

export const urlFetchResultSchema = z
  .strictObject({
    status: z.enum(URL_FETCH_STATUSES),
    error: z.enum(URL_FETCH_ERRORS).nullable(),
    hops: z.number().int().min(0).max(255),
    chain: z.array(urlChainEntrySchema).max(URL_MAX_CHAIN_ENTRIES),
    finalUrl: storedUrlSchema.nullable(),
    finalStatus: z.number().int().min(100).max(599).nullable(),
  })
  .superRefine((fetch, ctx) => {
    if ((fetch.status === 'error') !== (fetch.error !== null)) {
      ctx.addIssue({
        code: 'custom',
        path: ['error'],
        message: 'error is set exactly when status is error',
      });
    }
  });

export const urlLandingSchema = z.strictObject({
  passwordFields: z.number().int().min(0).max(1000),
  forms: z.number().int().min(0).max(1000),
  crossOriginFormAction: z.boolean(),
  titleBrandMatches: z.array(brandIdSchema).max(5).refine(unique, { message: 'Duplicate brand' }),
});

export const urlDynamicSignalsSchema = z.strictObject({
  passwordFields: z.number().int().min(0).max(1000),
  forms: z.number().int().min(0).max(1000),
  crossOriginFormAction: z.boolean(),
  formActionHosts: z.array(hostSchema).max(5),
  downloadAttempted: z.boolean(),
  blockedRequests: z.number().int().min(0).max(100_000),
  requests: z.number().int().min(0).max(100_000),
  bytes: z.number().int().nonnegative(),
  titleBrandMatches: z.array(brandIdSchema).max(5),
  jsRedirect: z.boolean(),
  dialogs: z.number().int().min(0).max(1000),
});

export const urlDynamicResultSchema = z.strictObject({
  status: z.enum(URL_DYNAMIC_STATUSES),
  verdict: urlVerdictSchema.nullable(),
  reasonCodes: urlReasonCodeList(16),
  signals: urlDynamicSignalsSchema.nullable(),
});

/**
 * One URL's normalized result (U16 without `clicks`): the shape of a `message_urls` row joined
 * with its `url_scan_results` row of the round (and the latest dynamic inspection). Strict, so no
 * anchor text, title, body or cache flag can be added. `clean` (rule C1) requires
 * `clean.no_findings`, which no other verdict carries, every provider answered (no `error`) and
 * any attempted fetch completed (§2.0 invariant 1). Engine-level codes never appear on a URL.
 */
export const urlResultSchema = z
  .strictObject({
    urlSeq: z.number().int().min(0).max(65_535),
    url: storedUrlSchema,
    host: hostSchema,
    unicodeHost: z.string().min(1).max(253).nullable(),
    registrableDomain: z.string().min(1).max(253).nullable(),
    hostKind: z.enum(URL_HOST_KINDS),
    sources: z.partialRecord(z.enum(URL_SOURCES), z.number().int().min(1).max(65_535)),
    flags: urlReasonCodeList(32),
    verdict: urlVerdictSchema,
    reasonCodes: urlReasonCodeList(32).min(1),
    reputation: z.array(urlReputationAnswerSchema).max(URL_MAX_REPUTATION_ANSWERS),
    lookalike: z.array(urlLookalikeFindingSchema).max(URL_MAX_LOOKALIKE_FINDINGS),
    fetch: urlFetchResultSchema.nullable(),
    landing: urlLandingSchema.nullable(),
    dynamic: urlDynamicResultSchema.nullable(),
    rewritten: z.boolean(),
  })
  .superRefine((result, ctx) => {
    if (Object.keys(result.sources).length === 0) {
      ctx.addIssue({ code: 'custom', path: ['sources'], message: 'At least one source' });
    }
    if ((result.hostKind === 'domain') !== (result.registrableDomain !== null)) {
      ctx.addIssue({
        code: 'custom',
        path: ['registrableDomain'],
        message: 'registrableDomain is set exactly for domain hosts',
      });
    }
    const cleanCode = result.reasonCodes.includes('clean.no_findings');
    if (result.verdict === 'clean') {
      if (!cleanCode) {
        ctx.addIssue({
          code: 'custom',
          path: ['reasonCodes'],
          message: 'clean requires clean.no_findings',
        });
      }
      if (result.reputation.some((answer) => answer.status === 'error')) {
        ctx.addIssue({
          code: 'custom',
          path: ['reputation'],
          message: 'clean requires every provider to have answered',
        });
      }
      if (result.fetch !== null && result.fetch.status !== 'completed') {
        ctx.addIssue({
          code: 'custom',
          path: ['fetch'],
          message: 'clean requires any attempted fetch to have completed',
        });
      }
    } else if (cleanCode) {
      ctx.addIssue({
        code: 'custom',
        path: ['reasonCodes'],
        message: 'clean.no_findings is reserved for the clean verdict',
      });
    }
    for (const [list, codes] of [
      ['reasonCodes', result.reasonCodes],
      ['flags', result.flags],
    ] as const) {
      for (const [index, code] of codes.entries()) {
        if (ENGINE_LEVEL.has(code)) {
          ctx.addIssue({
            code: 'custom',
            path: [list, index],
            message: 'Engine-level code in a URL result',
          });
        }
      }
    }
  });
export type UrlResult = z.infer<typeof urlResultSchema>;
