import { FEATURE_KEYS, LIMIT_KEYS } from '@email-gateway/database';
import { z } from 'zod';
import { PageQuerySchema } from '../../../http/pagination';
import {
  isValidCron,
  isValidLocale,
  isValidTimeZone,
  MAX_PREFERENCES_BYTES,
  serializedSize,
} from '../domain/settings-validation';

/**
 * Request and response shapes of the organization endpoints (§4.3, D12). The zod schemas are
 * the single source of truth: controllers validate with them (`ZodValidationPipe`, `400` with
 * `"<path>: <issue>"` messages) and document them with `zodToOpenApi`.
 */

/** Slugs that name parts of the product, not tenants (D12). */
export const RESERVED_SLUGS: ReadonlySet<string> = new Set([
  'platform',
  'admin',
  'api',
  'www',
  'system',
]);

const SLUG_PATTERN = /^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])$/;
const REGION_PATTERN = /^[a-z]{2}-[a-z]+-\d$/;
const ENVIRONMENT_PATTERN = /^[a-z][a-z0-9-]{1,31}$/;

const NameSchema = z.string().trim().min(1).max(255);
const PlanCodeSchema = z
  .string()
  .trim()
  .min(1)
  .max(32)
  .regex(/^[a-z0-9_-]+$/, 'must be a plan code');
const RegionSchema = z.string().regex(REGION_PATTERN, 'must be a region such as ap-south-1');
const ReasonSchema = z.string().trim().min(10).max(512);
const EmailSchema = z.string().trim().toLowerCase().max(320).pipe(z.email());

export const SlugSchema = z
  .string()
  .regex(SLUG_PATTERN, 'must be 3–63 lower-case letters, digits or hyphens')
  .refine((slug) => !RESERVED_SLUGS.has(slug), 'is reserved');

export const OrganizationStatusSchema = z.enum([
  'active',
  'suspended',
  'pending_deletion',
  'deleted',
]);
export const OrganizationKindSchema = z.enum(['customer', 'platform']);
export const DeploymentModeSchema = z.enum(['saas', 'dedicated']);
export const FeatureKeySchema = z.enum(FEATURE_KEYS);
export const LimitKeySchema = z.enum(LIMIT_KEYS);

/** JSON object of at most `max` bytes when serialized. */
const boundedJsonObject = (max: number) =>
  z
    .record(z.string(), z.unknown())
    .refine((value) => serializedSize(value) <= max, `must be at most ${max} bytes as JSON`);

// ---- Settings ----------------------------------------------------------------------------

const settingsFields = {
  timezone: z.string().refine(isValidTimeZone, 'must be an IANA time zone'),
  locale: z.string().refine(isValidLocale, 'must be a BCP 47 language tag (2–16 characters)'),
  /** Further bounded by the organization limit and the platform maximum (service). */
  quarantineRetentionDays: z.number().int().min(1).max(65_535),
  digestEnabled: z.boolean(),
  digestSchedule: z.string().refine(isValidCron, 'must be a 5-field cron expression'),
  notificationEmail: EmailSchema.nullable(),
  mfaRequired: z.boolean(),
  preferences: boundedJsonObject(MAX_PREFERENCES_BYTES),
};

/** `PUT /organizations/{id}/settings`: the fields to change (at least one). */
export const SettingsUpdateSchema = z
  .strictObject({
    timezone: settingsFields.timezone.optional(),
    locale: settingsFields.locale.optional(),
    quarantineRetentionDays: settingsFields.quarantineRetentionDays.optional(),
    digestEnabled: settingsFields.digestEnabled.optional(),
    digestSchedule: settingsFields.digestSchedule.optional(),
    notificationEmail: settingsFields.notificationEmail.optional(),
    mfaRequired: settingsFields.mfaRequired.optional(),
    preferences: settingsFields.preferences.optional(),
  })
  .refine((v) => Object.values(v).some((field) => field !== undefined), {
    message: 'provide at least one setting',
  });
export type SettingsUpdate = z.output<typeof SettingsUpdateSchema>;

// ---- Organizations -----------------------------------------------------------------------

export const CreateOrganizationSchema = z
  .strictObject({
    name: NameSchema,
    slug: SlugSchema,
    planCode: PlanCodeSchema,
    deploymentMode: DeploymentModeSchema,
    dataRegion: RegionSchema,
    deployment: z
      .strictObject({
        region: RegionSchema,
        environment: z
          .string()
          .regex(ENVIRONMENT_PATTERN, 'must be 2–32 lower-case letters, digits or hyphens'),
      })
      .optional(),
    settings: SettingsUpdateSchema.optional(),
    initialAdmin: z.strictObject({ email: EmailSchema, displayName: NameSchema }).optional(),
  })
  .superRefine((value, ctx) => {
    if (value.deploymentMode === 'dedicated' && value.deployment === undefined) {
      ctx.addIssue({
        code: 'custom',
        path: ['deployment'],
        message: 'is required for a dedicated deployment',
      });
    }
    if (value.deploymentMode === 'saas' && value.deployment !== undefined) {
      ctx.addIssue({
        code: 'custom',
        path: ['deployment'],
        message: 'is only accepted for a dedicated deployment',
      });
    }
  });
export type CreateOrganizationInput = z.output<typeof CreateOrganizationSchema>;

/** Fields fixed at creation (D12); present in an update body they are a `400`. */
export const IMMUTABLE_ORGANIZATION_FIELDS = [
  'slug',
  'kind',
  'deploymentMode',
  'dataRegion',
] as const;

export const UpdateOrganizationSchema = z
  .strictObject({
    name: NameSchema,
    planCode: PlanCodeSchema.optional(),
    slug: z.unknown().optional(),
    kind: z.unknown().optional(),
    deploymentMode: z.unknown().optional(),
    dataRegion: z.unknown().optional(),
  })
  .superRefine((value, ctx) => {
    for (const field of IMMUTABLE_ORGANIZATION_FIELDS) {
      if (value[field] !== undefined) {
        ctx.addIssue({ code: 'custom', path: [field], message: 'is immutable' });
      }
    }
  })
  .transform(({ name, planCode }) => ({ name, ...(planCode !== undefined && { planCode }) }));
export type UpdateOrganizationInput = z.output<typeof UpdateOrganizationSchema>;

/** Documented body of `PUT /organizations/{id}` (the immutable fields are not part of it). */
export const UpdateOrganizationDocSchema = z.strictObject({
  name: NameSchema,
  planCode: PlanCodeSchema.optional(),
});

export const StatusChangeSchema = z
  .strictObject({
    status: z.enum(['active', 'suspended']),
    reason: z.string().trim().min(3).max(512).optional(),
  })
  .refine((v) => v.status !== 'suspended' || v.reason !== undefined, {
    path: ['reason'],
    message: 'is required when suspending',
  });
export type StatusChangeInput = z.output<typeof StatusChangeSchema>;

export const ListOrganizationsQuerySchema = PageQuerySchema.extend({
  status: OrganizationStatusSchema.optional(),
  kind: OrganizationKindSchema.optional(),
  planCode: PlanCodeSchema.optional(),
  deploymentMode: DeploymentModeSchema.optional(),
  /** Prefix of the slug or the name. */
  q: z.string().trim().min(1).max(63).optional(),
}).strict();
export type ListOrganizationsQuery = z.output<typeof ListOrganizationsQuerySchema>;

const IsoDateTimeSchema = z.iso.datetime({ offset: true }).transform((value) => new Date(value));

export const UsageQuerySchema = z.strictObject({
  from: IsoDateTimeSchema.optional(),
  to: IsoDateTimeSchema.optional(),
});
export type UsageQuery = z.output<typeof UsageQuerySchema>;

export const FeatureOverrideSchema = z.strictObject({
  enabled: z.boolean(),
  config: boundedJsonObject(MAX_PREFERENCES_BYTES).nullable().optional(),
});
export type FeatureOverrideInput = z.output<typeof FeatureOverrideSchema>;

export const LimitOverrideSchema = z.strictObject({
  value: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
});
export type LimitOverrideInput = z.output<typeof LimitOverrideSchema>;

export const DeletionRequestSchema = z.strictObject({
  reason: ReasonSchema,
  confirmSlug: z.string().min(1).max(63),
});
export type DeletionRequestInput = z.output<typeof DeletionRequestSchema>;

export const DeletionConfirmSchema = z.strictObject({ confirmSlug: z.string().min(1).max(63) });
export type DeletionConfirmInput = z.output<typeof DeletionConfirmSchema>;

export const DeletionCancelSchema = z.strictObject({ reason: ReasonSchema });
export type DeletionCancelInput = z.output<typeof DeletionCancelSchema>;

export const UuidParamSchema = z.uuid();

// ---- Responses ---------------------------------------------------------------------------

const IsoString = z.string().describe('ISO 8601 date-time');

export const DeploymentResponseSchema = z.object({
  deploymentMode: DeploymentModeSchema,
  region: z.string(),
  environment: z.string(),
  status: z.enum(['provisioning', 'active', 'degraded', 'decommissioning', 'decommissioned']),
  endpointHostname: z.string().nullable(),
  mxHostname: z.string().nullable(),
  releaseVersion: z.string().nullable(),
  provisionedAt: IsoString.nullable(),
  createdAt: IsoString,
});

export const DeletionSummarySchema = z.object({
  state: z.enum(['pending_deletion', 'deleted']),
  requestedAt: IsoString,
  reason: z.string().nullable(),
  confirmedAt: IsoString.nullable(),
  purgeAfter: IsoString.nullable(),
});

export const OrganizationResponseSchema = z.object({
  id: z.uuid(),
  slug: z.string(),
  name: z.string(),
  kind: OrganizationKindSchema,
  status: OrganizationStatusSchema,
  statusReason: z.string().nullable(),
  statusChangedAt: IsoString.nullable(),
  plan: z.object({ code: z.string(), name: z.string() }),
  deploymentMode: DeploymentModeSchema,
  dataRegion: z.string(),
  deployments: z.array(DeploymentResponseSchema),
  deletion: DeletionSummarySchema.nullable(),
  createdAt: IsoString,
  updatedAt: IsoString,
});

export const CreatedOrganizationResponseSchema = OrganizationResponseSchema.extend({
  initialAdmin: z
    .object({
      id: z.uuid(),
      email: z.string(),
      status: z.literal('invited'),
      invitationExpiresAt: IsoString,
      invitationSent: z.boolean(),
    })
    .nullable(),
});

export const OrganizationPageResponseSchema = z.object({
  data: z.array(OrganizationResponseSchema),
  nextCursor: z.string().nullable(),
});

export const SettingsResponseSchema = z.object({
  organizationId: z.uuid(),
  timezone: z.string(),
  locale: z.string(),
  quarantineRetentionDays: z.number().int(),
  /** Upper bound currently accepted for `quarantineRetentionDays` (null = unbounded). */
  quarantineRetentionMaxDays: z.number().int().nullable(),
  digestEnabled: z.boolean(),
  digestSchedule: z.string(),
  notificationEmail: z.string().nullable(),
  mfaRequired: z.boolean(),
  preferences: z.record(z.string(), z.unknown()),
  updatedAt: IsoString,
});

export const FeatureResponseSchema = z.object({
  key: z.string(),
  enabled: z.boolean(),
  config: z.record(z.string(), z.unknown()).nullable(),
  source: z.enum(['plan', 'override']),
  updatedAt: IsoString,
});
export const FeatureListResponseSchema = z.object({
  organizationId: z.uuid(),
  data: z.array(FeatureResponseSchema),
});

export const LimitResponseSchema = z.object({
  key: z.string(),
  value: z.number().int(),
  source: z.enum(['plan', 'override']),
  updatedAt: IsoString,
});
export const LimitListResponseSchema = z.object({
  organizationId: z.uuid(),
  data: z.array(LimitResponseSchema),
});

export const UsageResponseSchema = z.object({
  organizationId: z.uuid(),
  period: z.object({ from: IsoString, to: IsoString }),
  users: z.object({
    total: z.number().int(),
    active: z.number().int(),
    invited: z.number().int(),
    disabled: z.number().int(),
    locked: z.number().int(),
  }),
  domains: z.object({
    total: z.number().int().describe('Non-deleted domains'),
    verified: z.number().int().describe('Ownership verified (verified, active or suspended)'),
    pendingVerification: z.number().int(),
    active: z.number().int(),
    suspended: z.number().int(),
  }),
  messages: z.object({
    total: z.number().int(),
    inbound: z.number().int(),
    outbound: z.number().int(),
    internal: z.number().int(),
    today: z.number().int(),
  }),
  quarantine: z.object({ active: z.number().int() }),
  apiKeys: z.object({ active: z.number().int() }),
  sessions: z.object({ active: z.number().int() }),
  limits: z.array(
    z.object({
      key: z.string(),
      value: z.number().int(),
      source: z.enum(['plan', 'override']),
      used: z.number().int().nullable(),
    }),
  ),
});

export const DeletionStateResponseSchema = z.object({
  organizationId: z.uuid(),
  status: OrganizationStatusSchema,
  state: z.enum(['none', 'pending_deletion', 'deleted']),
  requestedAt: IsoString.nullable(),
  requestedBy: z.uuid().nullable().describe('Public id of the requesting platform user'),
  reason: z.string().nullable(),
  confirmationDeadline: IsoString.nullable(),
  confirmedAt: IsoString.nullable(),
  confirmedBy: z.uuid().nullable(),
  purgeAfter: IsoString.nullable(),
  cancellable: z.boolean(),
});
