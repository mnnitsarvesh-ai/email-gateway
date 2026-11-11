import { canonicalJson, sha256Hex } from './canonical';
import { RISK_HARD_BLOCKS } from './hard-blocks';
import {
  type EffectiveProfile,
  effectiveProfileSchema,
  RISK_PLATFORM_PROFILE_IDS,
  type RiskPlatformProfileId,
  type RiskProfileOverrides,
  riskProfileOverridesSchema,
  type Violation,
} from './profile-schema';
import { RSK_DEFAULT_1 } from './profiles/rsk-default-1';
import { RISK_GROUP_DEFINITIONS, RISK_SIGNAL_GROUPS } from './signals';
import { actionRank, levelRank, RISK_LEVELS, type RiskAction, type RiskLevel } from './vocabulary';

/**
 * Platform profiles, tenant overrides and their resolution (step 5.1 R10; ADR-0041 decision 7).
 * Pure: the caller loads the version row and passes its public id, number, base and overrides.
 */

const deepFreeze = <T>(value: T): T => {
  if (value !== null && typeof value === 'object') {
    for (const v of Object.values(value as Record<string, unknown>)) deepFreeze(v);
    Object.freeze(value);
  }
  return value;
};

/** The shipped platform profiles, keyed by id (data in the library, never edited). */
export const RISK_PLATFORM_PROFILES: Readonly<Record<RiskPlatformProfileId, EffectiveProfile>> =
  deepFreeze({ 'rsk-default/1': effectiveProfileSchema.parse(RSK_DEFAULT_1) });

export const RISK_DEFAULT_PLATFORM_PROFILE_ID: RiskPlatformProfileId = 'rsk-default/1';

export const isPlatformProfileId = (id: unknown): id is RiskPlatformProfileId =>
  typeof id === 'string' && (RISK_PLATFORM_PROFILE_IDS as readonly string[]).includes(id);

/** Why a resolution fell back to the platform default (`null`: it did not). */
export type ProfileFallback = 'invalid' | 'missing' | 'foreign' | 'base_profile_retired';

export interface ResolvedProfile {
  profile: EffectiveProfile;
  source: 'platform' | 'tenant';
  /** `rsk-default/1` or `rsk-default/1+t:<version public id>#<versionNo>` (≤ 96 chars). */
  id: string;
  versionNo: number | null;
  /** SHA-256 of the canonical effective profile. */
  sha256: string;
  violations: Violation[];
  fallback: ProfileFallback | null;
}

export class RiskProfileError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RiskProfileError';
  }
}

/** Tenant bounds of the R10 table. */
export const RISK_OVERRIDE_BOUNDS = Object.freeze({
  thresholds: Object.freeze({
    low: Object.freeze([50, 250] as const),
    medium: Object.freeze([200, 450] as const),
    high: Object.freeze([400, 700] as const),
    critical: Object.freeze([650, 950] as const),
  }),
  thresholdMinGap: 50,
  actions: Object.freeze({
    none: Object.freeze(['deliver'] as RiskAction[]),
    low: Object.freeze(['deliver', 'tag'] as RiskAction[]),
    medium: Object.freeze(['tag', 'require_approval', 'quarantine'] as RiskAction[]),
    high: Object.freeze(['require_approval', 'quarantine', 'block'] as RiskAction[]),
    critical: Object.freeze(['quarantine', 'block'] as RiskAction[]),
  }),
  groupMultiplierPermille: Object.freeze([500, 2000] as const),
  failures: Object.freeze({
    engineFailureWeight: Object.freeze([200, 600] as const),
    groupCap: Object.freeze([300, 1000] as const),
    unknownWeight: Object.freeze([30, 200] as const),
    minLevel: Object.freeze(['medium', 'high', 'critical'] as RiskLevel[]),
    unknownMinLevel: Object.freeze(['low', 'medium', 'high'] as RiskLevel[]),
    action: Object.freeze(['require_approval', 'quarantine'] as RiskAction[]),
    unknownAction: Object.freeze(['tag', 'require_approval', 'quarantine'] as RiskAction[]),
  }),
  floors: Object.freeze({
    engineMalicious: Object.freeze(['high', 'critical'] as RiskLevel[]),
    becSuspicious: Object.freeze(['low', 'medium', 'high'] as RiskLevel[]),
  }),
  trustContentFactorPermille: Object.freeze([250, 1000] as const),
});

const THRESHOLD_LEVELS = ['low', 'medium', 'high', 'critical'] as const;

/**
 * Checks a merged profile against the R10 bounds, relative to its platform default `platform`
 * (raise-only keys). Paths are those of the overrides document.
 */
export function validateEffectiveProfile(
  profile: EffectiveProfile,
  platform: EffectiveProfile,
): Violation[] {
  const v: Violation[] = [];
  const B = RISK_OVERRIDE_BOUNDS;
  const range = (path: string, value: number, [min, max]: readonly [number, number]) => {
    if (value < min || value > max) v.push({ path, message: `must be between ${min} and ${max}` });
  };
  const oneOf = <T extends string>(path: string, value: T, allowed: readonly T[]) => {
    if (!allowed.includes(value)) v.push({ path, message: `must be one of ${allowed.join(', ')}` });
  };

  for (const level of THRESHOLD_LEVELS) {
    range(`thresholds.${level}`, profile.thresholds[level], B.thresholds[level]);
  }
  for (let i = 1; i < THRESHOLD_LEVELS.length; i += 1) {
    const lower = THRESHOLD_LEVELS[i - 1]!;
    const upper = THRESHOLD_LEVELS[i]!;
    if (profile.thresholds[upper] - profile.thresholds[lower] < B.thresholdMinGap) {
      v.push({
        path: `thresholds.${upper}`,
        message: `must exceed thresholds.${lower} by at least ${B.thresholdMinGap}`,
      });
    }
  }

  for (const level of RISK_LEVELS)
    oneOf(`actions.${level}`, profile.actions[level], B.actions[level]);
  for (let i = 1; i < RISK_LEVELS.length; i += 1) {
    const lower = RISK_LEVELS[i - 1]!;
    const upper = RISK_LEVELS[i]!;
    if (actionRank(profile.actions[upper]) < actionRank(profile.actions[lower])) {
      v.push({
        path: `actions.${upper}`,
        message: `must be at least as strict as actions.${lower}`,
      });
    }
  }

  for (const g of RISK_SIGNAL_GROUPS) {
    const value = profile.groupMultipliersPermille[g];
    if (RISK_GROUP_DEFINITIONS[g].locked) {
      if (value !== 1000)
        v.push({ path: `groupMultipliersPermille.${g}`, message: 'locked at 1000' });
    } else {
      range(`groupMultipliersPermille.${g}`, value, B.groupMultiplierPermille);
    }
  }

  for (const def of RISK_HARD_BLOCKS) {
    const setting = profile.hardBlocks[def.id];
    if (def.control === 'locked' && !setting.enabled) {
      v.push({ path: `hardBlocks.${def.id}.enabled`, message: 'locked on' });
    }
    oneOf(`hardBlocks.${def.id}.action`, setting.action, def.allowedActions);
  }

  const f = profile.failures;
  const pf = platform.failures;
  range('failures.engineFailureWeight', f.engineFailureWeight, B.failures.engineFailureWeight);
  range('failures.groupCap', f.groupCap, B.failures.groupCap);
  range('failures.unknownWeight', f.unknownWeight, B.failures.unknownWeight);
  oneOf('failures.minLevel', f.minLevel, B.failures.minLevel);
  if (levelRank(f.minLevel) < levelRank(pf.minLevel)) {
    v.push({ path: 'failures.minLevel', message: `must not be below ${pf.minLevel}` });
  }
  oneOf('failures.unknownMinLevel', f.unknownMinLevel, B.failures.unknownMinLevel);
  if (levelRank(f.unknownMinLevel) < levelRank(pf.unknownMinLevel)) {
    v.push({
      path: 'failures.unknownMinLevel',
      message: `must not be below ${pf.unknownMinLevel}`,
    });
  }
  oneOf('failures.action', f.action, B.failures.action);
  if (actionRank(f.action) < actionRank(pf.action)) {
    v.push({ path: 'failures.action', message: `must not be weaker than ${pf.action}` });
  }
  oneOf('failures.unknownAction', f.unknownAction, B.failures.unknownAction);
  if (actionRank(f.unknownAction) < actionRank(pf.unknownAction)) {
    v.push({
      path: 'failures.unknownAction',
      message: `must not be weaker than ${pf.unknownAction}`,
    });
  }
  if (actionRank(f.unknownAction) > actionRank(f.action)) {
    v.push({
      path: 'failures.unknownAction',
      message: 'must not be stricter than failures.action',
    });
  }

  oneOf('floors.engineMalicious', profile.floors.engineMalicious, B.floors.engineMalicious);
  if (levelRank(profile.floors.engineMalicious) < levelRank(platform.floors.engineMalicious)) {
    v.push({
      path: 'floors.engineMalicious',
      message: `must not be below ${platform.floors.engineMalicious}`,
    });
  }
  oneOf('floors.becSuspicious', profile.floors.becSuspicious, B.floors.becSuspicious);
  if (levelRank(profile.floors.becSuspicious) < levelRank(platform.floors.becSuspicious)) {
    v.push({
      path: 'floors.becSuspicious',
      message: `must not be below ${platform.floors.becSuspicious}`,
    });
  }

  range(
    'trust.contentFactorPermille',
    profile.trust.contentFactorPermille,
    B.trustContentFactorPermille,
  );
  return v;
}

/** Merges `overrides` into `platform` (one level per section; hard blocks per indicator). */
export function mergeOverrides(
  platform: EffectiveProfile,
  overrides: RiskProfileOverrides,
): EffectiveProfile {
  const hardBlocks = { ...platform.hardBlocks };
  for (const def of RISK_HARD_BLOCKS) {
    const o = overrides.hardBlocks?.[def.id];
    if (o) hardBlocks[def.id] = { ...platform.hardBlocks[def.id], ...definedOnly(o) };
  }
  return {
    base: platform.base,
    thresholds: { ...platform.thresholds, ...definedOnly(overrides.thresholds) },
    actions: { ...platform.actions, ...definedOnly(overrides.actions) },
    groupMultipliersPermille: {
      ...platform.groupMultipliersPermille,
      ...definedOnly(overrides.groupMultipliersPermille),
    },
    hardBlocks,
    failures: { ...platform.failures, ...definedOnly(overrides.failures) },
    floors: { ...platform.floors, ...definedOnly(overrides.floors) },
    trust: { ...platform.trust, ...definedOnly(overrides.trust) },
    ai: { ...platform.ai, ...definedOnly(overrides.ai) },
  };
}

function definedOnly<T extends object>(value: T | undefined): Partial<T> {
  if (!value) return {};
  return Object.fromEntries(Object.entries(value).filter(([, v]) => v !== undefined)) as Partial<T>;
}

/**
 * Validates a tenant overrides document (R10): the strict schema (types, unknown keys), the
 * keys a tenant may not set (the enable switch of locked hard blocks, the action of
 * `hb.dlp_block`), then every bound of the merged profile against `platformId` (default
 * `rsk-default/1`). Returns the violations by path; empty = valid.
 */
export function validateOverrides(
  doc: unknown,
  platformId: string = RISK_DEFAULT_PLATFORM_PROFILE_ID,
): Violation[] {
  if (!isPlatformProfileId(platformId)) {
    return [{ path: 'baseProfile', message: 'base_profile_retired' }];
  }
  const parsed = riskProfileOverridesSchema.safeParse(doc);
  if (!parsed.success) {
    const violations: Violation[] = [];
    for (const issue of parsed.error.issues) {
      const base = issue.path.map(String).join('.');
      if (issue.code === 'unrecognized_keys') {
        for (const key of issue.keys) {
          violations.push({ path: base ? `${base}.${key}` : key, message: 'unknown key' });
        }
      } else {
        violations.push({ path: base || '$', message: issue.message });
      }
    }
    return violations;
  }
  const overrides = parsed.data;
  const violations: Violation[] = [];
  for (const def of RISK_HARD_BLOCKS) {
    const o = overrides.hardBlocks?.[def.id];
    if (!o) continue;
    if (o.enabled !== undefined && def.control === 'locked') {
      violations.push({ path: `hardBlocks.${def.id}.enabled`, message: 'locked on' });
    }
    if (o.action !== undefined && def.allowedActions.length === 1) {
      violations.push({ path: `hardBlocks.${def.id}.action`, message: 'locked' });
    }
  }
  const platform = RISK_PLATFORM_PROFILES[platformId];
  const merged = mergeOverrides(platform, overrides);
  for (const violation of validateEffectiveProfile(merged, platform)) {
    if (!violations.some((x) => x.path === violation.path)) violations.push(violation);
  }
  return violations;
}

const profileSha = (profile: EffectiveProfile): string => sha256Hex(canonicalJson(profile));

function platformResolution(
  platformId: RiskPlatformProfileId,
  fallback: ProfileFallback | null,
  violations: Violation[],
): ResolvedProfile {
  const profile = RISK_PLATFORM_PROFILES[platformId];
  return {
    profile,
    source: 'platform',
    id: platformId,
    versionNo: null,
    sha256: profileSha(profile),
    violations,
    fallback,
  };
}

const assertPlatformId: (id: string) => asserts id is RiskPlatformProfileId = (id) => {
  if (!isPlatformProfileId(id)) throw new RiskProfileError(`Unknown platform risk profile: ${id}`);
};

/**
 * The platform profile `platformId`, for callers that use the platform default or could not
 * load a tenant version (`fallback`: `missing` = the version row does not exist, `foreign` =
 * it belongs to another organization or is not published, `invalid` = it failed validation).
 * Throws `RiskProfileError` for an id that is not shipped (validated at start-up).
 */
export function platformProfile(
  platformId: string,
  fallback?: 'missing' | 'foreign' | 'invalid',
): ResolvedProfile {
  assertPlatformId(platformId);
  return platformResolution(platformId, fallback ?? null, []);
}

const PUBLIC_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * Resolves the effective profile (R10): `version` null → the platform default; otherwise the
 * version's overrides merged into its base profile and validated. A base that is no longer
 * shipped → the platform default `platformId` with the violation `base_profile_retired`; any
 * violation → the platform default with `fallback: 'invalid'` (the caller records
 * `risk.profile.invalid_fallback`, which the scorer adds from `fallback`).
 */
export function resolveProfile(
  platformId: string,
  version: { publicId: string; versionNo: number; baseProfile: string; overrides: unknown } | null,
): ResolvedProfile {
  assertPlatformId(platformId);
  if (version === null) return platformResolution(platformId, null, []);
  if (!PUBLIC_ID.test(version.publicId)) {
    throw new RiskProfileError('Risk profile version public id is not a UUID');
  }
  if (!Number.isSafeInteger(version.versionNo) || version.versionNo < 1) {
    throw new RiskProfileError('Risk profile version number must be a positive integer');
  }
  if (!isPlatformProfileId(version.baseProfile)) {
    return platformResolution(platformId, 'base_profile_retired', [
      { path: 'baseProfile', message: 'base_profile_retired' },
    ]);
  }
  const violations = validateOverrides(version.overrides, version.baseProfile);
  if (violations.length > 0) return platformResolution(platformId, 'invalid', violations);
  const base = RISK_PLATFORM_PROFILES[version.baseProfile];
  const profile = effectiveProfileSchema.parse(
    mergeOverrides(base, riskProfileOverridesSchema.parse(version.overrides)),
  );
  return {
    profile,
    source: 'tenant',
    id: `${version.baseProfile}+t:${version.publicId}#${version.versionNo}`,
    versionNo: version.versionNo,
    sha256: profileSha(profile),
    violations: [],
    fallback: null,
  };
}
