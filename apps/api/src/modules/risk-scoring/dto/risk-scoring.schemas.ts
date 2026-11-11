import {
  effectiveProfileSchema,
  RISK_ACTIONS,
  RISK_HARD_BLOCK_IDS,
  RISK_LEVELS,
  RISK_SIGNAL_GROUPS,
  riskProfileOverridesSchema,
  riskResultSchema,
  violationSchema,
} from '@email-gateway/risk-scoring';
import { z } from 'zod';
import { PageQuerySchema } from '../../../http/pagination';

/**
 * Shapes of the risk scoring routes (step 5.1 R15, docs/plan/steps/15-risk-scoring.md): the
 * platform profile with its override bounds, signal map and hard-block catalog; the
 * organization's active profile; its versions (drafts are editable, published versions are
 * immutable); and the dry-run of a stored round. Every id is a public id (UUIDv7); scans are
 * decimal ids. 5.1 recommends and never enforces; the defaults are engineering defaults
 * calibrated on a synthetic dataset, not validated detection accuracy.
 */

const noControl = (value: string): boolean => {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return false;
  }
  return true;
};

const IsoDate = z.iso.datetime();
const Counter = z.number().int().min(1).max(4_294_967_295);
const Sha256 = z.string().regex(/^[0-9a-f]{64}$/);

export const RiskVersionIdSchema = z.uuid();

/** `{scanId}`: a decimal `email_scans.id`. */
export const RiskScanIdSchema = z
  .string()
  .refine(
    (value) => /^[1-9][0-9]{0,19}$/.test(value) && BigInt(value) <= 18_446_744_073_709_551_615n,
    'Expected a decimal scan id',
  );

const ChangeNote = z
  .string()
  .trim()
  .min(1)
  .max(512)
  .refine(noControl, 'Must not contain control characters')
  .nullable()
  .optional()
  .describe('Why the version exists (≤ 512 characters; never shown in audit metadata)');

/**
 * The overrides document as received: any JSON object. The bounds and the strict key set are
 * checked by `validateOverrides`, which answers `400 risk_profile_invalid` with the violations
 * by path (the documented shape is `RiskProfileOverridesDocSchema`).
 */
const OverridesInput = z.record(z.string(), z.unknown());

// --------------------------------------------------------------------------------------------
// Platform profile (read-only library data)
// --------------------------------------------------------------------------------------------

const Range = z.strictObject({ min: z.number().int(), max: z.number().int() });

export const RiskOverrideBoundsSchema = z.strictObject({
  thresholds: z.strictObject({ low: Range, medium: Range, high: Range, critical: Range }),
  thresholdMinGap: z.number().int().describe('Minimum distance between neighbouring thresholds'),
  actions: z
    .strictObject(
      Object.fromEntries(RISK_LEVELS.map((l) => [l, z.array(z.enum(RISK_ACTIONS))])) as Record<
        (typeof RISK_LEVELS)[number],
        z.ZodArray<z.ZodEnum<{ [K in (typeof RISK_ACTIONS)[number]]: K }>>
      >,
    )
    .describe('Allowed action per level; actions must not decrease with the level'),
  groupMultiplierPermille: Range,
  tunableGroups: z.array(z.enum(RISK_SIGNAL_GROUPS)),
  lockedGroups: z
    .array(z.enum(RISK_SIGNAL_GROUPS))
    .describe('Groups whose multiplier is locked at 1000'),
  failures: z.strictObject({
    engineFailureWeight: Range,
    groupCap: Range,
    unknownWeight: Range,
    minLevel: z.array(z.enum(RISK_LEVELS)),
    unknownMinLevel: z.array(z.enum(RISK_LEVELS)),
    action: z.array(z.enum(RISK_ACTIONS)),
    unknownAction: z
      .array(z.enum(RISK_ACTIONS))
      .describe('Action floor for an unknown engine result; never stricter than failures.action'),
  }),
  floors: z.strictObject({
    engineMalicious: z.array(z.enum(RISK_LEVELS)),
    becSuspicious: z.array(z.enum(RISK_LEVELS)),
  }),
  trustContentFactorPermille: Range,
  raiseOnly: z
    .array(z.string())
    .describe('Keys a tenant may only raise above the platform default (never lower)'),
});

export const RiskSignalViewSchema = z.strictObject({
  id: z.string(),
  group: z.enum(RISK_SIGNAL_GROUPS),
  codes: z.array(z.string()).describe('`engine:code` assertions (or `engine:<input fact>`)'),
  weight: z.number().int().describe('Default points on the 0–1000 scale'),
  weightFrom: z.enum(['map', 'failures.engineFailureWeight', 'failures.unknownWeight']),
  trustReducible: z.boolean(),
  directions: z.array(z.enum(['inbound', 'outbound', 'internal'])),
  source: z.enum(['code', 'input']),
});

export const RiskGroupViewSchema = z.strictObject({
  group: z.enum(RISK_SIGNAL_GROUPS),
  rule: z.enum(['max', 'capped_sum']),
  cap: z.number().int().nullable(),
  capFromProfile: z.boolean(),
  verdict: z.string(),
  locked: z.boolean(),
});

export const RiskHardBlockViewSchema = z.strictObject({
  id: z.enum(RISK_HARD_BLOCK_IDS),
  verdict: z.string(),
  defaultEnabled: z.boolean(),
  defaultAction: z.enum(RISK_ACTIONS),
  control: z.enum(['locked', 'may_disable', 'may_enable']),
  allowedActions: z.array(z.enum(RISK_ACTIONS)),
  firesWhen: z.string(),
});

export const RiskPlatformProfileViewSchema = z.strictObject({
  id: z.string().describe('The shipped platform profile (RISK_PLATFORM_PROFILE)'),
  sha256: Sha256.describe('SHA-256 of the canonical effective profile'),
  profile: effectiveProfileSchema,
  versions: z.strictObject({ scorer: z.string(), signalMap: z.string(), input: z.string() }),
  bounds: RiskOverrideBoundsSchema,
  groups: z.array(RiskGroupViewSchema),
  signals: z.array(RiskSignalViewSchema),
  hardBlocks: z.array(RiskHardBlockViewSchema),
  notice: z.string(),
});
export type RiskPlatformProfileView = z.output<typeof RiskPlatformProfileViewSchema>;

// --------------------------------------------------------------------------------------------
// The organization's profile and versions
// --------------------------------------------------------------------------------------------

const FallbackSchema = z
  .enum(['invalid', 'missing', 'foreign', 'base_profile_retired'])
  .nullable()
  .describe('Why the platform default applies instead of the active version (null: it does not)');

export const RiskActiveProfileSchema = z.strictObject({
  source: z.enum(['platform', 'tenant']),
  versionId: z.uuid().nullable().describe('Public id of the active version; null = platform'),
  versionNo: z.number().int().min(1).nullable(),
  profileId: z
    .string()
    .describe('`rsk-default/1` or `rsk-default/1+t:<version id>#<n>` (as stored with scores)'),
  sha256: Sha256,
  fallback: FallbackSchema,
  violations: z.array(violationSchema),
});

export const RiskProfileViewSchema = z.strictObject({
  id: z.uuid().nullable().describe('Public id of the profile row; null before the first change'),
  profileVersion: z
    .number()
    .int()
    .min(0)
    .describe('Counter of pointer changes (`expectedProfileVersion`); 0 before the first change'),
  platformProfile: z.string(),
  active: RiskActiveProfileSchema,
  effectiveProfile: effectiveProfileSchema.describe(
    'What the next round opened for the organization is scored with',
  ),
  counts: z.strictObject({
    drafts: z.number().int().min(0),
    published: z.number().int().min(0),
    limit: z.number().int().min(1).describe('RISK_PROFILE_MAX_VERSIONS'),
  }),
  updatedByUserId: z.uuid().nullable(),
  updatedAt: IsoDate.nullable(),
});
export type RiskProfileView = z.output<typeof RiskProfileViewSchema>;

export const RiskVersionSummarySchema = z.strictObject({
  id: z.uuid(),
  versionNo: z.number().int().min(1),
  status: z.enum(['draft', 'published']),
  baseProfile: z.string(),
  overridesSha256: Sha256,
  profileSha256: Sha256.nullable().describe('Set at publish'),
  changeNote: z.string().nullable(),
  rowVersion: Counter.describe('`expectedRowVersion` of PUT, DELETE and publish'),
  active: z.boolean(),
  createdByUserId: z.uuid().nullable(),
  updatedByUserId: z.uuid().nullable(),
  publishedByUserId: z.uuid().nullable(),
  publishedAt: IsoDate.nullable(),
  createdAt: IsoDate,
  updatedAt: IsoDate,
});
export type RiskVersionSummary = z.output<typeof RiskVersionSummarySchema>;

export const RiskVersionDetailSchema = RiskVersionSummarySchema.extend({
  overrides: z.record(z.string(), z.unknown()).describe('The stored overrides document'),
  resolved: z
    .strictObject({
      valid: z.boolean().describe('False when the platform bounds no longer accept the overrides'),
      profileId: z.string(),
      sha256: Sha256,
      effectiveProfile: effectiveProfileSchema,
      violations: z.array(violationSchema),
    })
    .describe('Resolved now against the platform profile (with violations if bounds changed)'),
});
export type RiskVersionDetail = z.output<typeof RiskVersionDetailSchema>;

export const RiskVersionPageSchema = z.strictObject({
  data: z.array(RiskVersionSummarySchema).describe('Newest first'),
  nextCursor: z.string().nullable(),
});
export type RiskVersionPage = z.output<typeof RiskVersionPageSchema>;

export const RiskVersionListQuerySchema = PageQuerySchema.extend({
  status: z.enum(['draft', 'published']).optional().describe('Only drafts or published versions'),
}).strict();
export type RiskVersionListQuery = z.output<typeof RiskVersionListQuerySchema>;

export const RiskVersionCreateSchema = z.strictObject({
  overrides: OverridesInput.optional().describe(
    'The overrides document; default: the overrides of `basedOnVersionId`, else `{}`',
  ),
  changeNote: ChangeNote,
  basedOnVersionId: z
    .uuid()
    .optional()
    .describe('Copy the overrides (and base profile) of this version of the organization'),
});
export type RiskVersionCreate = z.output<typeof RiskVersionCreateSchema>;
export const RiskVersionCreateDocSchema = RiskVersionCreateSchema.extend({
  overrides: riskProfileOverridesSchema.optional(),
});

export const RiskVersionUpdateSchema = z.strictObject({
  overrides: OverridesInput.describe('Replaces the draft overrides document'),
  changeNote: ChangeNote,
  expectedRowVersion: Counter.describe('Current `rowVersion` (409 risk_profile_version_conflict)'),
});
export type RiskVersionUpdate = z.output<typeof RiskVersionUpdateSchema>;
export const RiskVersionUpdateDocSchema = RiskVersionUpdateSchema.extend({
  overrides: riskProfileOverridesSchema,
});

export const RiskVersionDeleteQuerySchema = z.strictObject({
  expectedRowVersion: z.coerce
    .number()
    .int()
    .min(1)
    .max(4_294_967_295)
    .optional()
    .describe('When given, the delete applies only at this rowVersion'),
});
export type RiskVersionDeleteQuery = z.output<typeof RiskVersionDeleteQuerySchema>;

export const RiskVersionPublishSchema = z.strictObject({
  activate: z.boolean().default(true).describe('Also make it the active version (default true)'),
  expectedRowVersion: Counter,
});
export type RiskVersionPublish = z.output<typeof RiskVersionPublishSchema>;

/** Optional body of activate and reset (an empty body is accepted). */
export const RiskPointerChangeSchema = z.preprocess(
  (value) => value ?? {},
  z.strictObject({
    expectedProfileVersion: z
      .number()
      .int()
      .min(0)
      .max(4_294_967_295)
      .optional()
      .describe('When given, the change applies only at this `profileVersion`'),
  }),
);
export type RiskPointerChange = z.output<typeof RiskPointerChangeSchema>;
export const RiskPointerChangeDocSchema = z.strictObject({
  expectedProfileVersion: z.number().int().min(0).max(4_294_967_295).optional(),
});

export const RiskPublishResultSchema = z.strictObject({
  version: RiskVersionDetailSchema,
  profile: RiskProfileViewSchema,
});
export type RiskPublishResult = z.output<typeof RiskPublishResultSchema>;

// --------------------------------------------------------------------------------------------
// Dry-run
// --------------------------------------------------------------------------------------------

export const RiskDryRunSchema = z.strictObject({
  profile: z
    .union([
      z.literal('active'),
      z.literal('platform'),
      z.strictObject({ versionId: z.uuid() }),
      z.strictObject({ overrides: OverridesInput }),
    ])
    .describe(
      '`active`: the profile the round was scored with (its snapshot, platform when none); ' +
        '`platform`: the platform default; `{ versionId }`: a draft or published version of ' +
        'the organization; `{ overrides }`: an inline, unsaved overrides document',
    ),
  revision: z
    .union([z.literal(0), z.literal(1)])
    .default(0)
    .describe('0: the round; 1: the round with its late sandbox result'),
});
export type RiskDryRun = z.output<typeof RiskDryRunSchema>;
export const RiskDryRunDocSchema = RiskDryRunSchema.extend({
  profile: z.union([
    z.literal('active'),
    z.literal('platform'),
    z.strictObject({ versionId: z.uuid() }),
    z.strictObject({ overrides: riskProfileOverridesSchema }),
  ]),
});

export const RiskStoredSummarySchema = z.strictObject({
  revision: z.union([z.literal(0), z.literal(1)]),
  score: z.number().int().min(0).max(1000),
  level: z.enum(RISK_LEVELS),
  recommendedAction: z.enum(RISK_ACTIONS),
  inputSha256: Sha256,
  profileSha256: Sha256,
});

export const RiskDryRunResultSchema = riskResultSchema.extend({
  revision: z.union([z.literal(0), z.literal(1)]),
});

export const RiskDryRunResponseSchema = z.strictObject({
  result: RiskDryRunResultSchema,
  stored: RiskStoredSummarySchema.nullable().describe(
    'The stored score of that revision; null when none is stored (yet)',
  ),
  reproducible: z
    .boolean()
    .describe('`stored.inputSha256 === result.inputSha256` (false without a stored score)'),
});
export type RiskDryRunResponse = z.output<typeof RiskDryRunResponseSchema>;
