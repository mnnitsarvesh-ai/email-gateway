import type { z } from 'zod';
import { toIso, toIsoOrNull } from '../../http/serialization';
import type {
  DeletionStateResponseSchema,
  FeatureResponseSchema,
  LimitResponseSchema,
  OrganizationResponseSchema,
  SettingsResponseSchema,
} from './dto/organizations.schemas';
import { confirmationDeadline, deletionStateOf } from './domain/deletion-state';
import type {
  FeatureRecord,
  LimitRecord,
  OrganizationRecord,
  SettingsRecord,
} from './organizations.repository';

export type OrganizationResponse = z.output<typeof OrganizationResponseSchema>;
export type SettingsResponse = z.output<typeof SettingsResponseSchema>;
export type FeatureResponse = z.output<typeof FeatureResponseSchema>;
export type LimitResponse = z.output<typeof LimitResponseSchema>;
export type DeletionStateResponse = z.output<typeof DeletionStateResponseSchema>;

/** Limit values are unsigned BIGINT; the API accepts and returns safe integers only. */
export function limitNumber(value: bigint): number {
  const n = Number(value);
  return Number.isSafeInteger(n) ? n : Number.MAX_SAFE_INTEGER;
}

const jsonObjectOrNull = (value: unknown): Record<string, unknown> | null =>
  value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;

/** D12 response: explicit fields only; numeric ids and internal user ids never leave. */
export function toOrganizationResponse(org: OrganizationRecord): OrganizationResponse {
  const deletionState = deletionStateOf(org.status);
  return {
    id: org.publicId,
    slug: org.slug,
    name: org.name,
    kind: org.kind,
    status: org.status,
    statusReason: org.statusReason,
    statusChangedAt: toIsoOrNull(org.statusChangedAt),
    plan: { code: org.plan.code, name: org.plan.name },
    deploymentMode: org.deploymentMode,
    dataRegion: org.dataRegion,
    deployments: org.deployments.map((d) => ({
      deploymentMode: d.deploymentMode,
      region: d.region,
      environment: d.environment,
      status: d.status,
      endpointHostname: d.endpointHostname,
      mxHostname: d.mxHostname,
      releaseVersion: d.releaseVersion,
      provisionedAt: toIsoOrNull(d.provisionedAt),
      createdAt: toIso(d.createdAt),
    })),
    deletion:
      deletionState !== 'none' && org.deletionRequestedAt !== null
        ? {
            state: deletionState,
            requestedAt: toIso(org.deletionRequestedAt),
            reason: org.deletionReason,
            confirmedAt: toIsoOrNull(org.deletionConfirmedAt),
            purgeAfter: toIsoOrNull(org.purgeAfter),
          }
        : null,
    createdAt: toIso(org.createdAt),
    updatedAt: toIso(org.updatedAt),
  };
}

export function toSettingsResponse(
  org: OrganizationRecord,
  settings: SettingsRecord,
  quarantineRetentionMaxDays: number | null,
): SettingsResponse {
  return {
    organizationId: org.publicId,
    timezone: settings.timezone,
    locale: settings.locale,
    quarantineRetentionDays: settings.quarantineRetentionDays,
    quarantineRetentionMaxDays,
    digestEnabled: settings.digestEnabled,
    digestSchedule: settings.digestSchedule,
    notificationEmail: settings.notificationEmail,
    mfaRequired: settings.mfaRequired,
    preferences: jsonObjectOrNull(settings.preferences) ?? {},
    updatedAt: toIso(settings.updatedAt),
  };
}

export function toFeatureResponse(row: FeatureRecord): FeatureResponse {
  return {
    key: row.featureKey,
    enabled: row.enabled,
    config: jsonObjectOrNull(row.config),
    source: row.source,
    updatedAt: toIso(row.updatedAt),
  };
}

export function toLimitResponse(row: LimitRecord): LimitResponse {
  return {
    key: row.limitKey,
    value: limitNumber(row.limitValue),
    source: row.source,
    updatedAt: toIso(row.updatedAt),
  };
}

export function toDeletionStateResponse(
  org: OrganizationRecord,
  userPublicIds: ReadonlyMap<bigint, string>,
  windowHours: number,
  now: Date,
): DeletionStateResponse {
  const state = deletionStateOf(org.status);
  const requested = state !== 'none' ? org.deletionRequestedAt : null;
  const userId = (id: bigint | null) => (id === null ? null : (userPublicIds.get(id) ?? null));
  return {
    organizationId: org.publicId,
    status: org.status,
    state,
    requestedAt: toIsoOrNull(requested),
    requestedBy: requested ? userId(org.deletionRequestedByUserId) : null,
    reason: requested ? org.deletionReason : null,
    confirmationDeadline:
      state === 'pending_deletion' && requested
        ? toIso(confirmationDeadline(requested, windowHours))
        : null,
    confirmedAt: state === 'deleted' ? toIsoOrNull(org.deletionConfirmedAt) : null,
    confirmedBy: state === 'deleted' ? userId(org.deletionConfirmedByUserId) : null,
    purgeAfter: state === 'deleted' ? toIsoOrNull(org.purgeAfter) : null,
    cancellable:
      state === 'pending_deletion' ||
      (state === 'deleted' && org.purgeAfter !== null && now < org.purgeAfter),
  };
}
