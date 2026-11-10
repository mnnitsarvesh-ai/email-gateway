import {
  type AttachmentPlatformSettings,
  attachmentSettingsBounds,
  type BecPlatformSettings,
  becSettingsBounds,
  becTenantSettingsSchema,
  attachmentTenantSettingsSchema,
  type DlpPlatformSettings,
  dlpSettingsBounds,
  dlpTenantSettingsSchema,
  type EngineCatalogEntry,
  ENGINE_CATALOG,
  resolveAttachmentSettings,
  resolveBecSettings,
  resolveDlpSettings,
  resolveRspamdSettings,
  type RspamdPlatformSettings,
  rspamdSettingsBounds,
  rspamdTenantSettingsSchema,
  resolveSandboxSettings,
  type SandboxPlatformSettings,
  sandboxSettingsBounds,
  sandboxTenantSettingsSchema,
  type SettingsViolation,
  resolveUrlSettings,
  type UrlPlatformSettings,
  urlSettingsBounds,
  urlTenantSettingsSchema,
} from '@email-gateway/security-contracts';
import { normalizeDomainInput } from '@email-gateway/url-security';
import type { EngineSettingsView, SandboxExecutionMode } from '../dto/scan-settings.schemas';

/**
 * Tenant settings per registered engine (step 4.1 S8, S16; step 4.2 A8; step 4.3 U13; step 4.4
 * B13; step 4.5 D18; step 4.6 X17), pure: `rspamd`, `attachment`, `url`, `bec`, `dlp` and
 * `sandbox`. An engine of the catalog without a settings definition has no settings routes
 * (404).
 */

export interface StoredOverride {
  settings: unknown;
  version: number;
  updatedAt: Date;
}

export type OverrideCheck =
  { ok: true; settings: Record<string, unknown> } | { ok: false; violations: SettingsViolation[] };

/** Organization facts a view may show (read by the service from the writer). */
export interface EngineViewContext {
  /** `organization_features.attachment_sandbox` (step 4.6 X17). */
  attachmentSandbox: boolean;
}

/** The plan feature key the sandbox opt-in needs (FEATURE_KEYS). */
export const SANDBOX_FEATURE_KEY = 'attachment_sandbox';

export interface EngineSettingsDefinition {
  readonly catalog: EngineCatalogEntry;
  /** Validates an override against the platform settings; returns the normalized override. */
  check(override: unknown): OverrideCheck;
  /**
   * The settings view of the engine for one organization. Without `context` the organization is
   * shown without plan features (the service always passes it).
   */
  view(stored: StoredOverride | null, context?: EngineViewContext): EngineSettingsView;
  /**
   * The plan feature a (checked) override needs, or null (step 4.6 X17: `sandbox.enabled =
   * true` needs `attachment_sandbox`; the service answers `409 feature_not_enabled`).
   */
  requiredFeature?(settings: Record<string, unknown>): string | null;
}

/** The platform settings of every engine that has tenant settings. */
export interface PlatformEngineSettings {
  rspamd: RspamdPlatformSettings;
  attachment: AttachmentPlatformSettings;
  url: UrlPlatformSettings;
  bec: BecPlatformSettings;
  dlp: DlpPlatformSettings;
  sandbox: { settings: SandboxPlatformSettings; execution: SandboxExecutionMode };
}

/** The parsed override without undefined keys (what is stored). */
const definedKeys = (parsed: Record<string, unknown>): Record<string, unknown> =>
  Object.fromEntries(Object.entries(parsed).filter(([, v]) => v !== undefined));

const isEmptyObject = (value: unknown): boolean =>
  value !== null &&
  typeof value === 'object' &&
  !Array.isArray(value) &&
  Object.keys(value).length === 0;

/** An override row with `{}` holds no override (what a reset leaves, keeping the version). */
export const holdsOverride = (stored: StoredOverride | null): stored is StoredOverride =>
  stored !== null && !isEmptyObject(stored.settings);

function rspamdDefinition(
  catalog: EngineCatalogEntry,
  platform: RspamdPlatformSettings,
): EngineSettingsDefinition {
  const check = (override: unknown): OverrideCheck => {
    const resolution = resolveRspamdSettings(platform, override);
    if (!resolution.ok) return { ok: false, violations: resolution.violations };
    return { ok: true, settings: definedKeys(rspamdTenantSettingsSchema.parse(override)) };
  };
  const bounds = rspamdSettingsBounds(platform);
  const platformEffective = resolveRspamdSettings(platform, null);
  if (!platformEffective.ok) throw new Error('The platform Rspamd settings do not resolve');
  return {
    catalog,
    check,
    view(stored) {
      const override = holdsOverride(stored) ? stored.settings : null;
      const resolution = resolveRspamdSettings(platform, override);
      // An override that no longer fits the platform settings is ignored, as the worker does.
      const effective = resolution.ok ? resolution.settings : platformEffective.settings;
      return {
        engine: 'rspamd',
        required: catalog.requiredByDefault,
        tenantMayDisable: catalog.tenantMayDisable,
        platform: { ...platform },
        bounds: {
          spamScore: { ...bounds.spamScore },
          suspiciousScore: { ...bounds.suspiciousScore },
          phishingVerdict: [...bounds.phishingVerdict],
          dmarcRejectVerdict: [...bounds.dmarcRejectVerdict],
          authFailureVerdict: [...bounds.authFailureVerdict],
        },
        override: override as Extract<EngineSettingsView, { engine: 'rspamd' }>['override'],
        effective: { ...effective },
        overrideApplied: override !== null && resolution.ok,
        violations: resolution.ok ? [] : resolution.violations,
        version: stored?.version ?? 0,
        updatedAt: stored ? stored.updatedAt.toISOString() : null,
      };
    },
  };
}

function attachmentDefinition(
  catalog: EngineCatalogEntry,
  platform: AttachmentPlatformSettings,
): EngineSettingsDefinition {
  const check = (override: unknown): OverrideCheck => {
    const resolution = resolveAttachmentSettings(platform, override);
    if (!resolution.ok) return { ok: false, violations: resolution.violations };
    return { ok: true, settings: definedKeys(attachmentTenantSettingsSchema.parse(override)) };
  };
  const bounds = attachmentSettingsBounds(platform);
  const platformEffective = resolveAttachmentSettings(platform, null);
  if (!platformEffective.ok) throw new Error('The platform attachment settings do not resolve');
  return {
    catalog,
    check,
    view(stored) {
      const override = holdsOverride(stored) ? stored.settings : null;
      const resolution = resolveAttachmentSettings(platform, override);
      // An override that no longer fits the platform settings is ignored, as the worker does.
      const effective = resolution.ok ? resolution.settings : platformEffective.settings;
      return {
        engine: 'attachment',
        required: catalog.requiredByDefault,
        tenantMayDisable: catalog.tenantMayDisable,
        platform: { ...platform, deniedTypes: [...platform.deniedTypes] },
        bounds: {
          maxAttachmentBytes: { ...bounds.maxAttachmentBytes },
          deniedTypes: [...bounds.deniedTypes],
          platformDeniedTypes: [...bounds.platformDeniedTypes],
          allowedTypes: [...bounds.allowedTypes],
          maxAllowedTypes: bounds.maxAllowedTypes,
          deniedTypeVerdict: [...bounds.deniedTypeVerdict],
          typeMismatchVerdict: [...bounds.typeMismatchVerdict],
          encryptedArchiveVerdict: [...bounds.encryptedArchiveVerdict],
        },
        override: override as Extract<EngineSettingsView, { engine: 'attachment' }>['override'],
        effective: {
          ...effective,
          deniedTypes: [...effective.deniedTypes],
          allowedTypes: effective.allowedTypes === null ? null : [...effective.allowedTypes],
        },
        overrideApplied: override !== null && resolution.ok,
        violations: resolution.ok ? [] : resolution.violations,
        version: stored?.version ?? 0,
        updatedAt: stored ? stored.updatedAt.toISOString() : null,
      };
    },
  };
}

/** The domain lists of a URL override (U13), as paths into the override object. */
const URL_DOMAIN_LISTS: readonly (readonly [string, string?])[] = [
  ['allowedDomains'],
  ['blockedDomains'],
  ['lookalike', 'extraProtectedDomains'],
  ['rewrite', 'excludedDomains'],
];

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === 'object' && !Array.isArray(value);

const DOMAIN_INPUT_MESSAGES: Record<string, string> = {
  invalid: 'Not a valid domain or host name',
  ip_literal: 'An IP address is not a domain',
  single_label: 'A single label is not a registrable domain',
  public_suffix: 'A public suffix (e.g. co.uk, github.io) is not allowed',
};

/**
 * Normalizes every domain of the URL override's lists through `@email-gateway/url-security`
 * (U13, WP5): IDNA to ASCII A-labels, lower case, trailing dots removed; IP literals, single
 * labels and public suffixes are refused (`invalid`, path `<list>.<index>`). Entries that are not
 * strings are left for the schema to refuse. Returns a copy; the input is never modified.
 */
export function normalizeUrlOverrideDomains(override: unknown): {
  override: unknown;
  violations: SettingsViolation[];
} {
  if (!isRecord(override)) return { override, violations: [] };
  const copy: Record<string, unknown> = { ...override };
  const violations: SettingsViolation[] = [];
  for (const [first, second] of URL_DOMAIN_LISTS) {
    const parent: Record<string, unknown> | null =
      second === undefined ? copy : isRecord(copy[first]) ? { ...(copy[first] as object) } : null;
    if (parent === null) continue;
    const key = second ?? first;
    const list = parent[key];
    if (!Array.isArray(list)) continue;
    const path = second === undefined ? first : `${first}.${second}`;
    parent[key] = list.map((entry: unknown, index) => {
      if (typeof entry !== 'string') return entry;
      const normalized = normalizeDomainInput(entry);
      if (normalized.ok) return normalized.domain;
      violations.push({
        path: `${path}.${index}`,
        code: 'invalid',
        message: DOMAIN_INPUT_MESSAGES[normalized.code] ?? 'Not a valid domain',
      });
      return entry;
    });
    if (second !== undefined) copy[first] = parent;
  }
  return { override: copy, violations };
}

function urlDefinition(
  catalog: EngineCatalogEntry,
  platform: UrlPlatformSettings,
): EngineSettingsDefinition {
  const check = (raw: unknown): OverrideCheck => {
    const normalized = normalizeUrlOverrideDomains(raw);
    if (normalized.violations.length > 0) return { ok: false, violations: normalized.violations };
    const resolution = resolveUrlSettings(platform, normalized.override);
    if (!resolution.ok) return { ok: false, violations: resolution.violations };
    return {
      ok: true,
      settings: definedKeys(
        stripUndefined(urlTenantSettingsSchema.parse(normalized.override)) as Record<
          string,
          unknown
        >,
      ),
    };
  };
  const bounds = urlSettingsBounds(platform);
  const platformEffective = resolveUrlSettings(platform, null);
  if (!platformEffective.ok) throw new Error('The platform URL settings do not resolve');
  return {
    catalog,
    check,
    view(stored) {
      const override = holdsOverride(stored) ? stored.settings : null;
      const resolution = resolveUrlSettings(platform, override);
      // An override that no longer fits the platform settings is ignored, as the worker and the
      // click-service do.
      const effective = resolution.ok ? resolution.settings : platformEffective.settings;
      return {
        engine: 'url',
        required: catalog.requiredByDefault,
        tenantMayDisable: catalog.tenantMayDisable,
        platform: {
          scanTimeFetch: platform.scanTimeFetch,
          rewrite: { ...platform.rewrite, directions: [...platform.rewrite.directions] },
          dynamicInspection: platform.dynamicInspection,
        },
        bounds: {
          allowedDomains: { ...bounds.allowedDomains },
          blockedDomains: { ...bounds.blockedDomains },
          scanTimeFetch: [...bounds.scanTimeFetch],
          lookalike: { extraProtectedDomains: { ...bounds.lookalike.extraProtectedDomains } },
          rewrite: {
            enabled: [...bounds.rewrite.enabled],
            directions: [...bounds.rewrite.directions],
            expiryDays: { ...bounds.rewrite.expiryDays },
            excludedDomains: { ...bounds.rewrite.excludedDomains },
            dkimSignedPolicy: [...bounds.rewrite.dkimSignedPolicy],
          },
          click: {
            suspicious: [...bounds.click.suspicious],
            unknown: [...bounds.click.unknown],
          },
          dynamicInspection: [...bounds.dynamicInspection],
        },
        override: override as Extract<EngineSettingsView, { engine: 'url' }>['override'],
        effective: {
          allowedDomains: [...effective.allowedDomains],
          blockedDomains: [...effective.blockedDomains],
          scanTimeFetch: effective.scanTimeFetch,
          lookalike: { extraProtectedDomains: [...effective.lookalike.extraProtectedDomains] },
          rewrite: {
            ...effective.rewrite,
            directions: [...effective.rewrite.directions],
            excludedDomains: [...effective.rewrite.excludedDomains],
          },
          click: { ...effective.click },
          dynamicInspection: effective.dynamicInspection,
        },
        overrideApplied: override !== null && resolution.ok,
        violations: resolution.ok ? [] : resolution.violations,
        version: stored?.version ?? 0,
        updatedAt: stored ? stored.updatedAt.toISOString() : null,
      };
    },
  };
}

/** Removes undefined keys at every level (nested URL groups), so the stored JSON is minimal. */
function stripUndefined(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stripUndefined);
  if (!isRecord(value)) return value;
  return Object.fromEntries(
    Object.entries(value)
      .filter(([, v]) => v !== undefined)
      .map(([k, v]) => [k, stripUndefined(v)]),
  );
}

/**
 * Normalizes `freemailExtraDomains` of a BEC override through `@email-gateway/url-security`
 * (B13): IDNA to ASCII A-labels, lower case; IP literals, single labels and public suffixes are
 * refused (`invalid`, path `freemailExtraDomains.<index>`). Returns a copy.
 */
export function normalizeBecOverrideDomains(override: unknown): {
  override: unknown;
  violations: SettingsViolation[];
} {
  if (!isRecord(override) || !Array.isArray(override.freemailExtraDomains)) {
    return { override, violations: [] };
  }
  const violations: SettingsViolation[] = [];
  const list = override.freemailExtraDomains.map((entry: unknown, index) => {
    if (typeof entry !== 'string') return entry;
    const normalized = normalizeDomainInput(entry);
    if (normalized.ok) return normalized.domain;
    violations.push({
      path: `freemailExtraDomains.${index}`,
      code: 'invalid',
      message: DOMAIN_INPUT_MESSAGES[normalized.code] ?? 'Not a valid domain',
    });
    return entry;
  });
  return { override: { ...override, freemailExtraDomains: list }, violations };
}

function becDefinition(
  catalog: EngineCatalogEntry,
  platform: BecPlatformSettings,
): EngineSettingsDefinition {
  const check = (raw: unknown): OverrideCheck => {
    const normalized = normalizeBecOverrideDomains(raw);
    if (normalized.violations.length > 0) return { ok: false, violations: normalized.violations };
    const resolution = resolveBecSettings(platform, normalized.override);
    if (!resolution.ok) return { ok: false, violations: resolution.violations };
    return {
      ok: true,
      settings: definedKeys(
        stripUndefined(becTenantSettingsSchema.parse(normalized.override)) as Record<
          string,
          unknown
        >,
      ),
    };
  };
  const bounds = becSettingsBounds(platform);
  const platformEffective = resolveBecSettings(platform, null);
  if (!platformEffective.ok) throw new Error('The platform BEC settings do not resolve');
  return {
    catalog,
    check,
    view(stored) {
      const override = holdsOverride(stored) ? stored.settings : null;
      const resolution = resolveBecSettings(platform, override);
      // An override that no longer fits the platform settings is ignored, as the worker does.
      const effective = resolution.ok ? resolution.settings : platformEffective.settings;
      return {
        engine: 'bec',
        required: catalog.requiredByDefault,
        tenantMayDisable: catalog.tenantMayDisable,
        platform: { ...platform },
        bounds: {
          suspiciousScore: { ...bounds.suspiciousScore },
          maliciousScore: { ...bounds.maliciousScore },
          freemailExtraDomains: { ...bounds.freemailExtraDomains },
          history: {
            enabled: [...bounds.history.enabled],
            retentionDays: { ...bounds.history.retentionDays },
          },
          ai: {
            localModel: [...bounds.ai.localModel],
            llm: [...bounds.ai.llm],
            llmDailyCallLimit: { ...bounds.ai.llmDailyCallLimit },
            raiseConfidence: { ...bounds.ai.raiseConfidence },
          },
        },
        override: override as Extract<EngineSettingsView, { engine: 'bec' }>['override'],
        effective: {
          suspiciousScore: effective.suspiciousScore,
          maliciousScore: effective.maliciousScore,
          freemailExtraDomains: [...effective.freemailExtraDomains],
          history: { ...effective.history },
          ai: { ...effective.ai },
        },
        overrideApplied: override !== null && resolution.ok,
        violations: resolution.ok ? [] : resolution.violations,
        version: stored?.version ?? 0,
        updatedAt: stored ? stored.updatedAt.toISOString() : null,
      };
    },
  };
}

/**
 * The `dlp` engine settings (step 4.5 D18): inbound opt-in, category thresholds (0.5–0.95, two
 * decimals), the noisy detectors a tenant may switch off, the default policy, evidence
 * enablement (never above the platform cap) and retention (1..platform maximum). The context
 * window and the bulk threshold are platform only (shown in `platform` and `effective`).
 */
function dlpDefinition(
  catalog: EngineCatalogEntry,
  platform: DlpPlatformSettings,
): EngineSettingsDefinition {
  const check = (raw: unknown): OverrideCheck => {
    const resolution = resolveDlpSettings(platform, raw);
    if (!resolution.ok) return { ok: false, violations: resolution.violations };
    return {
      ok: true,
      settings: definedKeys(
        stripUndefined(dlpTenantSettingsSchema.parse(raw)) as Record<string, unknown>,
      ),
    };
  };
  const bounds = dlpSettingsBounds(platform);
  const platformEffective = resolveDlpSettings(platform, null);
  if (!platformEffective.ok) throw new Error('The platform DLP settings do not resolve');
  return {
    catalog,
    check,
    view(stored) {
      const override = holdsOverride(stored) ? stored.settings : null;
      const resolution = resolveDlpSettings(platform, override);
      // An override that no longer fits the platform settings is ignored, as the worker does.
      const effective = resolution.ok ? resolution.settings : platformEffective.settings;
      return {
        engine: 'dlp',
        required: catalog.requiredByDefault,
        tenantMayDisable: catalog.tenantMayDisable,
        platform: { ...platform },
        bounds: {
          inboundEnabled: [...bounds.inboundEnabled],
          thresholds: {
            categories: [...bounds.thresholds.categories],
            min: bounds.thresholds.min,
            max: bounds.thresholds.max,
          },
          disabledDetectors: [...bounds.disabledDetectors],
          defaultPolicy: [...bounds.defaultPolicy],
          evidence: {
            enabled: [...bounds.evidence.enabled],
            retentionDays: { ...bounds.evidence.retentionDays },
          },
        },
        override: override as Extract<EngineSettingsView, { engine: 'dlp' }>['override'],
        effective: {
          inboundEnabled: effective.inboundEnabled,
          thresholds: { ...effective.thresholds },
          disabledDetectors: [...effective.disabledDetectors],
          defaultPolicy: effective.defaultPolicy,
          evidence: { ...effective.evidence },
          contextWindowChars: effective.contextWindowChars,
          bulkMinDistinct: effective.bulkMinDistinct,
        },
        overrideApplied: override !== null && resolution.ok,
        violations: resolution.ok ? [] : resolution.violations,
        version: stored?.version ?? 0,
        updatedAt: stored ? stored.updatedAt.toISOString() : null,
      };
    },
  };
}

/**
 * The `sandbox` engine settings (step 4.6 X17): the opt-in (`enabled`; `true` needs the plan
 * feature `attachment_sandbox`), a non-empty subset of the platform file types, a sample size
 * within [1, platform maximum] and browser analysis within the platform setting. The backend,
 * limits and timeouts are platform-only configuration. The view adds the plan feature and the
 * environment's execution mode, so a client can state plainly whether files are executed.
 */
function sandboxDefinition(
  catalog: EngineCatalogEntry,
  platform: SandboxPlatformSettings,
  execution: SandboxExecutionMode,
): EngineSettingsDefinition {
  const check = (raw: unknown): OverrideCheck => {
    const resolution = resolveSandboxSettings(platform, raw);
    if (!resolution.ok) return { ok: false, violations: resolution.violations };
    return { ok: true, settings: definedKeys(sandboxTenantSettingsSchema.parse(raw)) };
  };
  const bounds = sandboxSettingsBounds(platform);
  const platformEffective = resolveSandboxSettings(platform, null);
  if (!platformEffective.ok) throw new Error('The platform sandbox settings do not resolve');
  return {
    catalog,
    check,
    requiredFeature: (settings) => (settings.enabled === true ? SANDBOX_FEATURE_KEY : null),
    view(stored, context) {
      const override = holdsOverride(stored) ? stored.settings : null;
      const resolution = resolveSandboxSettings(platform, override);
      // An override that no longer fits the platform settings is ignored, as the worker does.
      const effective = resolution.ok ? resolution.settings : platformEffective.settings;
      return {
        engine: 'sandbox',
        mode: 'asynchronous',
        required: catalog.requiredByDefault,
        tenantMayDisable: catalog.tenantMayDisable,
        platform: { ...platform, fileTypes: [...platform.fileTypes] },
        bounds: {
          enabled: [...bounds.enabled],
          fileTypes: [...bounds.fileTypes],
          maxSampleBytes: { ...bounds.maxSampleBytes },
          browserAnalysis: [...bounds.browserAnalysis],
        },
        override: override as Extract<EngineSettingsView, { engine: 'sandbox' }>['override'],
        effective: { ...effective, fileTypes: [...effective.fileTypes] },
        feature: { attachmentSandbox: context?.attachmentSandbox ?? false },
        execution,
        overrideApplied: override !== null && resolution.ok,
        violations: resolution.ok ? [] : resolution.violations,
        version: stored?.version ?? 0,
        updatedAt: stored ? stored.updatedAt.toISOString() : null,
      };
    },
  };
}

/** The settings definitions of every catalog engine that has tenant settings (catalog order). */
export function engineSettingsDefinitions(
  platform: PlatformEngineSettings,
): ReadonlyMap<string, EngineSettingsDefinition> {
  const out = new Map<string, EngineSettingsDefinition>();
  for (const entry of ENGINE_CATALOG) {
    if (entry.name === 'rspamd') out.set(entry.name, rspamdDefinition(entry, platform.rspamd));
    if (entry.name === 'attachment') {
      out.set(entry.name, attachmentDefinition(entry, platform.attachment));
    }
    if (entry.name === 'url') out.set(entry.name, urlDefinition(entry, platform.url));
    if (entry.name === 'bec') out.set(entry.name, becDefinition(entry, platform.bec));
    if (entry.name === 'dlp') out.set(entry.name, dlpDefinition(entry, platform.dlp));
    if (entry.name === 'sandbox') {
      out.set(
        entry.name,
        sandboxDefinition(entry, platform.sandbox.settings, platform.sandbox.execution),
      );
    }
  }
  return out;
}
