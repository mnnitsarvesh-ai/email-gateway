import type { RequestBody, SuccessBody } from '@/lib/api/types';

/**
 * Risk-profile draft editing (step 7.3 design B13): the form shows the effective values (the
 * platform profile with the draft's overrides applied, a plain data merge) and saves an
 * overrides document holding only the values that differ from the platform profile. The api
 * checks every bound (`400 risk_profile_invalid` with violations by path); nothing here scores.
 */

export type PlatformView = SuccessBody<'RiskProfilesController_platformProfile_v1'>;
export type EffectiveProfile = PlatformView['profile'];
export type RiskBounds = PlatformView['bounds'];
export type RiskOverrides = NonNullable<
  RequestBody<'RiskProfilesController_updateDraft_v1'>['overrides']
>;
export type RiskViolation = { path: string; message: string };

/** The parts of a profile a tenant may override (the keys of the overrides document). */
export const OVERRIDE_SECTIONS = [
  'thresholds',
  'actions',
  'groupMultipliersPermille',
  'hardBlocks',
  'failures',
  'floors',
  'trust',
  'ai',
] as const;

/** Trust modes of the request schema (the platform view lists no vocabulary for them). */
export const TRUST_MODES = ['off', 'reduce_content'] as const satisfies ReadonlyArray<
  EffectiveProfile['trust']['mode']
>;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/** Plain JSON copy. */
const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

function mergeInto(target: Record<string, unknown>, patch: Record<string, unknown>): void {
  for (const [key, value] of Object.entries(patch)) {
    if (!(key in target)) continue; // keys the platform profile does not have are not offered
    const current = target[key];
    if (isRecord(current) && isRecord(value)) mergeInto(current, value);
    else if (!isRecord(current) && !isRecord(value) && value !== undefined) target[key] = value;
  }
}

/** The platform profile with an overrides document applied (unknown keys ignored). */
export function mergeOverrides(platform: EffectiveProfile, overrides: unknown): EffectiveProfile {
  const out = clone(platform);
  if (!isRecord(overrides)) return out;
  const patch: Record<string, unknown> = {};
  for (const section of OVERRIDE_SECTIONS) {
    if (section in overrides) patch[section] = overrides[section];
  }
  mergeInto(out, patch);
  return out;
}

function diffLeaves(value: unknown, base: unknown): unknown {
  if (isRecord(value) && isRecord(base)) {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value)) {
      const d = diffLeaves(value[key], base[key]);
      if (d !== undefined) out[key] = d;
    }
    return Object.keys(out).length > 0 ? out : undefined;
  }
  return Object.is(value, base) ? undefined : value;
}

/**
 * The overrides document of the form values: only keys whose value differs from the platform
 * profile; group multipliers only for the tunable groups (locked groups are not overridable).
 */
export function overridesOf(
  values: EffectiveProfile,
  platform: EffectiveProfile,
  tunableGroups: readonly string[],
): RiskOverrides {
  const out: Record<string, unknown> = {};
  for (const section of OVERRIDE_SECTIONS) {
    let value: unknown = values[section];
    if (section === 'groupMultipliersPermille' && isRecord(value)) {
      value = Object.fromEntries(Object.entries(value).filter(([g]) => tunableGroups.includes(g)));
    }
    const d = diffLeaves(value, platform[section]);
    if (d !== undefined) out[section] = d;
  }
  return out;
}

/** Violations of one input (`path` equal or below it). */
export function violationsAt(violations: readonly RiskViolation[], path: string): RiskViolation[] {
  return violations.filter((v) => v.path === path || v.path.startsWith(`${path}.`));
}

/** The violations no input of the form shows (listed at form level). */
export function unplacedViolations(
  violations: readonly RiskViolation[],
  inputPaths: readonly string[],
): RiskViolation[] {
  return violations.filter(
    (v) => !inputPaths.some((path) => v.path === path || v.path.startsWith(`${path}.`)),
  );
}

/** Every input path of the generated form (thresholds, actions, groups, hard blocks, …). */
export function inputPathsOf(platform: PlatformView): string[] {
  const b = platform.bounds;
  return [
    ...Object.keys(b.thresholds).map((level) => `thresholds.${level}`),
    ...Object.keys(b.actions).map((level) => `actions.${level}`),
    ...b.tunableGroups.map((group) => `groupMultipliersPermille.${group}`),
    ...platform.hardBlocks.flatMap((hb) => [
      `hardBlocks.${hb.id}.enabled`,
      `hardBlocks.${hb.id}.action`,
    ]),
    ...Object.keys(b.failures).map((key) => `failures.${key}`),
    ...Object.keys(b.floors).map((key) => `floors.${key}`),
    'trust.mode',
    'trust.contentFactorPermille',
    'ai.tagOnAiOnlyRaise',
  ];
}

/** Sets one leaf of a profile copy (`thresholds.low`, `hardBlocks.hb.dlp_block.enabled`, …). */
export function setLeaf(
  profile: EffectiveProfile,
  section: (typeof OVERRIDE_SECTIONS)[number],
  key: string,
  value: unknown,
  subkey?: string,
): EffectiveProfile {
  const next = clone(profile) as unknown as Record<string, Record<string, unknown>>;
  const part = next[section];
  if (!part) return profile;
  if (subkey !== undefined) {
    const holder = part[key];
    if (!isRecord(holder)) return profile;
    holder[subkey] = value;
  } else {
    part[key] = value;
  }
  return next as unknown as EffectiveProfile;
}
