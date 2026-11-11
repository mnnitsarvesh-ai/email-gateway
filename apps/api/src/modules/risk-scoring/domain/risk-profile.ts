import {
  canonicalJson,
  effectiveProfileSchema,
  isPlatformProfileId,
  mergeOverrides,
  platformProfile,
  RISK_GROUP_DEFINITIONS,
  RISK_HARD_BLOCKS,
  RISK_INPUT_VERSION,
  RISK_LOCKED_GROUPS,
  RISK_OVERRIDE_BOUNDS,
  RISK_PLATFORM_PROFILES,
  RISK_SCORER_VERSION,
  RISK_SIGNAL_GROUPS,
  RISK_SIGNAL_MAP_VERSION,
  RISK_SIGNALS,
  RISK_TUNABLE_GROUPS,
  resolveProfile,
  type ResolvedProfile,
  type RiskProfileOverrides,
  riskProfileOverridesSchema,
  sha256Hex,
  validateOverrides,
  type Violation,
} from '@email-gateway/risk-scoring';
import type {
  RiskPlatformProfileView,
  RiskProfileView,
  RiskVersionDetail,
  RiskVersionSummary,
} from '../dto/risk-scoring.schemas';
import type {
  ProfileRow,
  VersionCounts,
  VersionRow,
} from '../repositories/risk-profiles.repository';

/**
 * Pure helpers of the risk profile routes (step 5.1 R10, R15): overrides validation and hashing,
 * the changed-path list of audit metadata, the resolution of the active profile and the row →
 * view mapping. No I/O.
 */

/** The statement every risk scoring route repeats (§2.0-3, §8; ADR-0041). */
export const RISK_NOTICE =
  'Step 5.1 recommends and never enforces: policy (5.2) decides and quarantine (5.3) acts. The ' +
  'default weights and thresholds are engineering defaults calibrated on a synthetic dataset; ' +
  'they are not validated detection accuracy. A profile change applies to the next scan round ' +
  'only; open rounds and stored scores never change.';

/** Most changed paths one audit row lists (the document has fewer leaves than this). */
export const MAX_CHANGED_PATHS = 128;

export type OverridesCheck =
  | { ok: true; overrides: RiskProfileOverrides; sha256: string }
  | { ok: false; violations: Violation[] };

/**
 * Validates an overrides document against `baseProfile` (strict keys, every R10 bound, the
 * locked keys) and returns the normalized document and its SHA-256 (canonical JSON), or the
 * violations by path.
 */
export function checkOverrides(doc: unknown, baseProfile: string): OverridesCheck {
  const violations = validateOverrides(doc, baseProfile);
  if (violations.length > 0) return { ok: false, violations };
  const overrides = riskProfileOverridesSchema.parse(doc);
  return { ok: true, overrides, sha256: overridesSha256(overrides) };
}

export const overridesSha256 = (overrides: unknown): string => sha256Hex(canonicalJson(overrides));

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === 'object' && !Array.isArray(value);

function leaves(value: unknown, prefix: string, out: Map<string, string>): void {
  if (isRecord(value)) {
    for (const [key, child] of Object.entries(value)) {
      if (child === undefined) continue;
      leaves(child, prefix === '' ? key : `${prefix}.${key}`, out);
    }
    return;
  }
  if (prefix !== '') out.set(prefix, canonicalJson(value ?? null));
}

/**
 * The dotted override paths whose value differs between two documents (added, removed or
 * changed leaves), sorted, at most MAX_CHANGED_PATHS. Paths only, never values (audit metadata).
 */
export function changedPaths(before: unknown, after: unknown): string[] {
  const a = new Map<string, string>();
  const b = new Map<string, string>();
  leaves(before, '', a);
  leaves(after, '', b);
  const paths = new Set<string>();
  for (const [path, value] of a) if (b.get(path) !== value) paths.add(path);
  for (const [path, value] of b) if (a.get(path) !== value) paths.add(path);
  return [...paths].sort().slice(0, MAX_CHANGED_PATHS);
}

/** The resolution of a stored version (R10) against the configured platform profile. */
export const resolveVersion = (platformId: string, row: VersionRow): ResolvedProfile =>
  resolveProfile(platformId, {
    publicId: row.publicId,
    versionNo: row.versionNo,
    baseProfile: row.baseProfile,
    overrides: row.overrides,
  });

/**
 * The active profile of an organization: the pointer's published version of the same
 * organization, else the platform default (`missing`: the pointed row does not exist; `foreign`:
 * it is not a published version of the organization — the email-worker applies the same rule).
 */
export function resolveActive(
  platformId: string,
  profile: ProfileRow | null,
  active: VersionRow | null,
): ResolvedProfile {
  if (profile === null || profile.activeVersionId === null) return platformProfile(platformId);
  if (active === null) return platformProfile(platformId, 'missing');
  if (
    active.id !== profile.activeVersionId ||
    active.organizationId !== profile.organizationId ||
    active.status !== 'published'
  ) {
    return platformProfile(platformId, 'foreign');
  }
  return resolveVersion(platformId, active);
}

/**
 * An inline, unsaved overrides document for the dry-run: merged into the platform profile and
 * labelled `<platform>+t:inline` (no version number). The caller validated it first.
 */
export function inlineProfile(
  platformId: string,
  overrides: RiskProfileOverrides,
): ResolvedProfile {
  if (!isPlatformProfileId(platformId)) throw new Error('Unknown platform risk profile');
  const profile = effectiveProfileSchema.parse(
    mergeOverrides(RISK_PLATFORM_PROFILES[platformId], overrides),
  );
  return {
    profile,
    source: 'tenant',
    id: `${platformId}+t:inline`,
    versionNo: null,
    sha256: sha256Hex(canonicalJson(profile)),
    violations: [],
    fallback: null,
  };
}

const iso = (value: Date | null): string | null => (value === null ? null : value.toISOString());

const recordOf = (value: unknown): Record<string, unknown> => (isRecord(value) ? value : {});

export function versionSummary(row: VersionRow, activeId: bigint | null): RiskVersionSummary {
  return {
    id: row.publicId,
    versionNo: row.versionNo,
    status: row.status,
    baseProfile: row.baseProfile,
    overridesSha256: row.overridesSha256,
    profileSha256: row.profileSha256,
    changeNote: row.changeNote,
    rowVersion: row.rowVersion,
    active: activeId !== null && row.id === activeId,
    createdByUserId: row.createdBy?.publicId ?? null,
    updatedByUserId: row.updatedBy?.publicId ?? null,
    publishedByUserId: row.publishedBy?.publicId ?? null,
    publishedAt: iso(row.publishedAt),
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

export function versionDetail(
  row: VersionRow,
  activeId: bigint | null,
  platformId: string,
): RiskVersionDetail {
  const resolved = resolveVersion(platformId, row);
  return {
    ...versionSummary(row, activeId),
    overrides: recordOf(row.overrides),
    resolved: {
      valid: resolved.source === 'tenant',
      profileId: resolved.id,
      sha256: resolved.sha256,
      effectiveProfile: resolved.profile,
      violations: resolved.violations,
    },
  };
}

export function profileView(
  platformId: string,
  limit: number,
  profile: ProfileRow | null,
  active: VersionRow | null,
  counts: VersionCounts,
): RiskProfileView {
  const resolved = resolveActive(platformId, profile, active);
  const tenant = resolved.source === 'tenant' && active !== null;
  return {
    id: profile?.publicId ?? null,
    profileVersion: profile?.version ?? 0,
    platformProfile: platformId,
    active: {
      source: resolved.source,
      versionId: tenant ? active.publicId : null,
      versionNo: tenant ? active.versionNo : null,
      profileId: resolved.id,
      sha256: resolved.sha256,
      fallback: resolved.fallback,
      violations: resolved.violations,
    },
    effectiveProfile: resolved.profile,
    counts: { drafts: counts.drafts, published: counts.published, limit },
    updatedByUserId: profile?.updatedBy?.publicId ?? null,
    updatedAt: iso(profile?.updatedAt ?? null),
  };
}

const range = ([min, max]: readonly [number, number]) => ({ min, max });

/** The platform profile, its bounds, groups, signals and hard blocks (library data, R15). */
export function platformProfileView(platformId: string): RiskPlatformProfileView {
  const resolved = platformProfile(platformId);
  const B = RISK_OVERRIDE_BOUNDS;
  return {
    id: resolved.id,
    sha256: resolved.sha256,
    profile: resolved.profile,
    versions: {
      scorer: RISK_SCORER_VERSION,
      signalMap: RISK_SIGNAL_MAP_VERSION,
      input: RISK_INPUT_VERSION,
    },
    bounds: {
      thresholds: {
        low: range(B.thresholds.low),
        medium: range(B.thresholds.medium),
        high: range(B.thresholds.high),
        critical: range(B.thresholds.critical),
      },
      thresholdMinGap: B.thresholdMinGap,
      actions: {
        none: [...B.actions.none],
        low: [...B.actions.low],
        medium: [...B.actions.medium],
        high: [...B.actions.high],
        critical: [...B.actions.critical],
      },
      groupMultiplierPermille: range(B.groupMultiplierPermille),
      tunableGroups: [...RISK_TUNABLE_GROUPS],
      lockedGroups: [...RISK_LOCKED_GROUPS],
      failures: {
        engineFailureWeight: range(B.failures.engineFailureWeight),
        groupCap: range(B.failures.groupCap),
        unknownWeight: range(B.failures.unknownWeight),
        minLevel: [...B.failures.minLevel],
        unknownMinLevel: [...B.failures.unknownMinLevel],
        action: [...B.failures.action],
        unknownAction: [...B.failures.unknownAction],
      },
      floors: {
        engineMalicious: [...B.floors.engineMalicious],
        becSuspicious: [...B.floors.becSuspicious],
      },
      trustContentFactorPermille: range(B.trustContentFactorPermille),
      raiseOnly: [
        'failures.minLevel',
        'failures.unknownMinLevel',
        'failures.action',
        'failures.unknownAction',
        'floors.engineMalicious',
        'floors.becSuspicious',
      ],
    },
    groups: RISK_SIGNAL_GROUPS.map((g) => ({ ...RISK_GROUP_DEFINITIONS[g] })),
    signals: RISK_SIGNALS.map((s) => ({
      id: s.id,
      group: s.group,
      codes: [...s.codes],
      weight: s.weight,
      weightFrom: s.weightFrom,
      trustReducible: s.trustReducible,
      directions: [...s.directions],
      source: s.source,
    })),
    hardBlocks: RISK_HARD_BLOCKS.map((h) => ({
      id: h.id,
      verdict: h.verdict,
      defaultEnabled: h.defaultEnabled,
      defaultAction: h.defaultAction,
      control: h.control,
      allowedActions: [...h.allowedActions],
      firesWhen: h.firesWhen,
    })),
    notice: RISK_NOTICE,
  };
}
