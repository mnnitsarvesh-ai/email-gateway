import {
  type EngineCatalogEntry,
  ENGINE_CATALOG,
  resolveRspamdSettings,
  type RspamdPlatformSettings,
  rspamdSettingsBounds,
  rspamdTenantSettingsSchema,
  type SettingsViolation,
} from '@email-gateway/security-contracts';
import type { EngineSettingsView } from '../dto/scan-settings.schemas';

/**
 * Tenant settings per registered engine (step 4.1 S8, S16), pure. Step 4.1 registers Rspamd
 * only; an engine of the catalog without a settings definition has no settings routes (404).
 */

export interface StoredOverride {
  settings: unknown;
  version: number;
  updatedAt: Date;
}

export type OverrideCheck =
  { ok: true; settings: Record<string, unknown> } | { ok: false; violations: SettingsViolation[] };

export interface EngineSettingsDefinition {
  readonly catalog: EngineCatalogEntry;
  /** Validates an override against the platform settings; returns the normalized override. */
  check(override: unknown): OverrideCheck;
  /** The settings view of the engine for one organization. */
  view(stored: StoredOverride | null): EngineSettingsView;
}

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
    const parsed = rspamdTenantSettingsSchema.parse(override);
    return {
      ok: true,
      settings: Object.fromEntries(Object.entries(parsed).filter(([, v]) => v !== undefined)),
    };
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
        engine: catalog.name,
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
        override: override as EngineSettingsView['override'],
        effective: { ...effective },
        overrideApplied: override !== null && resolution.ok,
        violations: resolution.ok ? [] : resolution.violations,
        version: stored?.version ?? 0,
        updatedAt: stored ? stored.updatedAt.toISOString() : null,
      };
    },
  };
}

/** The settings definitions of every catalog engine that has tenant settings. */
export function engineSettingsDefinitions(
  platform: RspamdPlatformSettings,
): ReadonlyMap<string, EngineSettingsDefinition> {
  const out = new Map<string, EngineSettingsDefinition>();
  for (const entry of ENGINE_CATALOG) {
    if (entry.name === 'rspamd') out.set(entry.name, rspamdDefinition(entry, platform));
  }
  return out;
}
