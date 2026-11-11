import { z } from 'zod';
import { RISK_HARD_BLOCK_IDS, type RiskHardBlockId } from './hard-blocks';
import { RISK_LOCKED_GROUPS, RISK_SIGNAL_GROUPS, type RiskSignalGroup } from './signals';
import { riskActionSchema, riskLevelSchema } from './vocabulary';

/**
 * Profile schemas (step 5.1 R10). The effective profile is what the scorer reads and what
 * `profile_sha256` hashes (canonical JSON); the overrides document is the tenant's bounded
 * change set stored in `risk_scoring_profile_versions.overrides` (strict: every key optional,
 * unknown keys refused). Bounds are checked by `validateOverrides` (profile.ts), which reports
 * violations by path.
 */

export const RISK_PLATFORM_PROFILE_IDS = ['rsk-default/1'] as const;
export type RiskPlatformProfileId = (typeof RISK_PLATFORM_PROFILE_IDS)[number];
export const riskPlatformProfileIdSchema = z.enum(RISK_PLATFORM_PROFILE_IDS);

const int = z.number().int().min(0).max(1_000_000);

const thresholdsShape = {
  low: int,
  medium: int,
  high: int,
  critical: int,
};
const actionsShape = {
  none: riskActionSchema,
  low: riskActionSchema,
  medium: riskActionSchema,
  high: riskActionSchema,
  critical: riskActionSchema,
};
const failuresShape = {
  engineFailureWeight: int,
  groupCap: int,
  unknownWeight: int,
  minLevel: riskLevelSchema,
  unknownMinLevel: riskLevelSchema,
  action: riskActionSchema,
  unknownAction: riskActionSchema,
};
const floorsShape = { engineMalicious: riskLevelSchema, becSuspicious: riskLevelSchema };
export const TRUST_MODES = ['off', 'reduce_content'] as const;
const trustShape = { mode: z.enum(TRUST_MODES), contentFactorPermille: int };
const aiShape = { tagOnAiOnlyRaise: z.boolean() };

const hardBlockSettingSchema = z.strictObject({ enabled: z.boolean(), action: riskActionSchema });

const allGroupsShape = Object.fromEntries(RISK_SIGNAL_GROUPS.map((g) => [g, int])) as Record<
  RiskSignalGroup,
  typeof int
>;
const allHardBlocksShape = Object.fromEntries(
  RISK_HARD_BLOCK_IDS.map((id) => [id, hardBlockSettingSchema]),
) as Record<RiskHardBlockId, typeof hardBlockSettingSchema>;

export const effectiveProfileSchema = z.strictObject({
  base: riskPlatformProfileIdSchema,
  thresholds: z.strictObject(thresholdsShape),
  actions: z.strictObject(actionsShape),
  groupMultipliersPermille: z.strictObject(allGroupsShape),
  hardBlocks: z.strictObject(allHardBlocksShape),
  failures: z.strictObject(failuresShape),
  floors: z.strictObject(floorsShape),
  trust: z.strictObject(trustShape),
  ai: z.strictObject(aiShape),
});
export type EffectiveProfile = z.infer<typeof effectiveProfileSchema>;

/** Groups whose multiplier a tenant may change (all but the locked ones). */
export const RISK_TUNABLE_GROUPS: readonly RiskSignalGroup[] = Object.freeze(
  RISK_SIGNAL_GROUPS.filter((g) => !RISK_LOCKED_GROUPS.includes(g)),
);

const optionalShape = <T extends Record<string, z.ZodType>>(shape: T) =>
  z.strictObject(
    Object.fromEntries(Object.entries(shape).map(([k, v]) => [k, v.optional()])) as {
      [K in keyof T]: z.ZodOptional<T[K]>;
    },
  );

const tunableGroupsShape = Object.fromEntries(RISK_TUNABLE_GROUPS.map((g) => [g, int])) as Record<
  string,
  typeof int
>;

const hardBlockOverrideSchema = z.strictObject({
  enabled: z.boolean().optional(),
  action: riskActionSchema.optional(),
});

/** The tenant overrides document (R10 table; bounds in `validateOverrides`). */
export const riskProfileOverridesSchema = z.strictObject({
  thresholds: optionalShape(thresholdsShape).optional(),
  actions: optionalShape(actionsShape).optional(),
  groupMultipliersPermille: optionalShape(tunableGroupsShape).optional(),
  hardBlocks: z
    .strictObject(
      Object.fromEntries(
        RISK_HARD_BLOCK_IDS.map((id) => [id, hardBlockOverrideSchema.optional()]),
      ) as Record<RiskHardBlockId, z.ZodOptional<typeof hardBlockOverrideSchema>>,
    )
    .optional(),
  failures: optionalShape(failuresShape).optional(),
  floors: optionalShape(floorsShape).optional(),
  trust: optionalShape(trustShape).optional(),
  ai: optionalShape(aiShape).optional(),
});
export type RiskProfileOverrides = z.infer<typeof riskProfileOverridesSchema>;

/** One bound or schema violation of an overrides document or merged profile. */
export interface Violation {
  /** Dotted path of the offending key (`$` for the document itself). */
  path: string;
  message: string;
}

export const violationSchema = z.strictObject({
  path: z.string().max(128),
  message: z.string().max(256),
});
