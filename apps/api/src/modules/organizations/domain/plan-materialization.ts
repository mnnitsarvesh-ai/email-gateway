import {
  FEATURE_KEYS,
  type FeatureKey,
  LIMIT_KEYS,
  type LimitKey,
  type SettingSource,
} from '@email-gateway/database';

const LIMIT_KEY_SET: ReadonlySet<string> = new Set(LIMIT_KEYS);
const FEATURE_KEY_SET: ReadonlySet<string> = new Set(FEATURE_KEYS);

export const isLimitKey = (key: string): key is LimitKey => LIMIT_KEY_SET.has(key);
export const isFeatureKey = (key: string): key is FeatureKey => FEATURE_KEY_SET.has(key);

/** The defaults of a plan (`organization_plans.default_limits` / `default_features`). */
export interface PlanDefaults {
  limits: ReadonlyMap<LimitKey, bigint>;
  features: ReadonlyMap<FeatureKey, boolean>;
}

/**
 * Reads a plan's JSON defaults. Only catalog keys (`LIMIT_KEYS`, `FEATURE_KEYS`) are kept; limit
 * values must be non-negative integers and feature values booleans, anything else is ignored so
 * a malformed plan row can never materialize garbage.
 */
export function parsePlanDefaults(defaultLimits: unknown, defaultFeatures: unknown): PlanDefaults {
  const limits = new Map<LimitKey, bigint>();
  const features = new Map<FeatureKey, boolean>();
  if (defaultLimits && typeof defaultLimits === 'object' && !Array.isArray(defaultLimits)) {
    for (const [key, value] of Object.entries(defaultLimits)) {
      if (
        isLimitKey(key) &&
        typeof value === 'number' &&
        Number.isSafeInteger(value) &&
        value >= 0
      ) {
        limits.set(key, BigInt(value));
      }
    }
  }
  if (defaultFeatures && typeof defaultFeatures === 'object' && !Array.isArray(defaultFeatures)) {
    for (const [key, value] of Object.entries(defaultFeatures)) {
      if (isFeatureKey(key) && typeof value === 'boolean') features.set(key, value);
    }
  }
  return { limits, features };
}

/** An existing `organization_limits` / `organization_features` row, reduced to what matters. */
export interface ExistingEntitlement {
  key: string;
  source: SettingSource;
}

export interface EntitlementChanges<V> {
  /** Rows to create or update with `source = plan`. */
  set: Array<{ key: string; value: V }>;
  /** Plan-sourced rows whose key the new plan no longer defines. */
  remove: string[];
}

/**
 * What a plan change does to one entitlement table (D12): every key of the new plan is
 * (re)written with `source = plan` unless the organization overrides it; plan-sourced rows the
 * new plan does not define are removed; overrides are always kept.
 */
export function planChanges<V>(
  existing: readonly ExistingEntitlement[],
  planValues: ReadonlyMap<string, V>,
): EntitlementChanges<V> {
  const overridden = new Set(existing.filter((r) => r.source === 'override').map((r) => r.key));
  const set = [...planValues]
    .filter(([key]) => !overridden.has(key))
    .map(([key, value]) => ({ key, value }));
  const remove = existing
    .filter((r) => r.source === 'plan' && !planValues.has(r.key))
    .map((r) => r.key);
  return { set, remove };
}
