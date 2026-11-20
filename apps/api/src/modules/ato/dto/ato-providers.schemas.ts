import { PROVIDER_ACTION_TYPES, PROVIDER_STREAMS } from '@email-gateway/ato-detection';
import { MAILBOX_ITEM_KINDS } from '@email-gateway/idp-adapters';
import { z } from 'zod';
import { PublicIdSchema } from './ato.schemas';

/**
 * Request and response schemas of the identity-provider routes of step 8.5
 * (docs/plan/steps/26-ato-provider-adapters.md §6, D4, D6, D8, D10). Requests are strict
 * (`z.strictObject`, step 6.1 D1); the binding settings travel as a record and are validated as
 * a whole by `validateBindingSettings` (`400 ato_provider_settings_invalid` with the failing
 * paths, never values). Responses are documentation of what the services build: public ids,
 * provider kinds, states, permission names, domain names of the tenant's own directory, hashes
 * and trait codes only — never a token, a credential, a forwarding or delegate address or a rule
 * keyword.
 */

const isoInstant = z.iso.datetime({ offset: true });
const nullableInstant = isoInstant.nullable();
const count = z.number().int().min(0);

export const ProviderKindSchema = z.enum(['microsoft_entra', 'google_workspace']);
export const ConnectionProviderSchema = z.enum(['microsoft_365', 'google_workspace']);
export const IntegrationStatusSchema = z.enum(['active', 'paused', 'error', 'disabled']);
export const IntegrationHealthSchema = z.enum(['unknown', 'healthy', 'degraded', 'unhealthy']);
export const StreamNameSchema = z.enum(PROVIDER_STREAMS);
export const ActionTypeSchema = z.enum(PROVIDER_ACTION_TYPES);
const availability = z.enum([
  'unknown',
  'available',
  'missing_permission',
  'missing_license',
  'not_configured',
  'not_offered',
  'error',
]);
/** The capability of a stream or action as the api shows it (D6: stale or never probed = unknown). */
const capabilityView = z.enum([
  'available',
  'missing_permission',
  'missing_license',
  'not_configured',
  'not_offered',
  'error',
  'unknown',
  'disabled',
]);

/** Analyst text with line breaks allowed (pause and removal reasons). */
const reasonText = (min: number, max: number) =>
  z
    .string()
    .trim()
    .min(min)
    .max(max)
    // eslint-disable-next-line no-control-regex -- control characters except CR/LF/TAB are refused
    .regex(/^[^\x00-\x08\x0b\x0c\x0e-\x1f\x7f]*$/, 'must not contain control characters');

// ------------------------------------------------------------------------------- requests

export const ProviderListQuerySchema = z.strictObject({
  includeDisabled: z.enum(['true', 'false']).optional(),
});
export type ProviderListQuery = z.infer<typeof ProviderListQuerySchema>;

/**
 * `POST /ato/providers`: the 8.2 connection and optionally the full `ato-idp-binding/1` settings
 * (defaults when absent). The settings are checked by `validateBindingSettings`.
 */
export const CreateProviderBodySchema = z.strictObject({
  connectionId: PublicIdSchema,
  settings: z.record(z.string(), z.unknown()).optional(),
});
export type CreateProviderBody = z.infer<typeof CreateProviderBodySchema>;

/** `PATCH /ato/providers/{id}`: the full settings document with the row version (CAS). */
export const UpdateProviderBodySchema = z.strictObject({
  rowVersion: z.number().int().min(1),
  settings: z.record(z.string(), z.unknown()),
});
export type UpdateProviderBody = z.infer<typeof UpdateProviderBodySchema>;

/** Pause and removal: why (≤ 512 characters, audited). */
export const ProviderReasonBodySchema = z.strictObject({ reason: reasonText(3, 512) });
export type ProviderReasonBody = z.infer<typeof ProviderReasonBodySchema>;

/** Resume and the health check take no fields (an empty object or no body). */
export const EmptyProviderBodySchema = z.strictObject({});
export type EmptyProviderBody = z.infer<typeof EmptyProviderBodySchema>;

/** `POST /ato/providers/{id}/backfill`: the start of the range and optionally the primary streams. */
export const BackfillBodySchema = z.strictObject({
  from: isoInstant,
  streams: z.array(StreamNameSchema).min(1).max(PROVIDER_STREAMS.length).optional(),
});
export type BackfillBody = z.infer<typeof BackfillBodySchema>;

// ------------------------------------------------------------------------------ responses

export const ProviderConnectionRefSchema = z.object({
  id: PublicIdSchema,
  provider: ConnectionProviderSchema,
  displayName: z.string(),
  /** 8.2 state mapped by the binding (`missing` = 8.2 no longer returns the connection). */
  status: z.enum(['configuring', 'active', 'error', 'disabled', 'missing']),
});

export const HealthSummarySchema = z.object({
  status: IntegrationHealthSchema,
  checkedAt: nullableInstant,
  /** The last probe is missing or older than 3 × ATO_IDP_HEALTH_INTERVAL_SECONDS. */
  stale: z.boolean(),
});

export const StreamSummarySchema = z.object({
  /** Enabled primary streams (the polled ones). */
  enabled: count,
  available: count,
  failing: count,
  backfilling: count,
  /** Largest `now − watermark` of the enabled primary streams, seconds. */
  maxLagSeconds: count.nullable(),
});

export const ProviderSummarySchema = z.object({
  id: PublicIdSchema,
  provider: ProviderKindSchema,
  displayName: z.string().nullable(),
  status: IntegrationStatusSchema,
  pausedReason: z.string().nullable(),
  disabledReason: z.string().nullable(),
  disabledAt: nullableInstant,
  connection: ProviderConnectionRefSchema.nullable(),
  health: HealthSummarySchema,
  streams: StreamSummarySchema,
  capabilities: z.object({
    streams: z.array(StreamNameSchema),
    actions: z.array(ActionTypeSchema),
  }),
  createdAt: isoInstant,
  updatedAt: isoInstant,
});
export type ProviderSummaryView = z.infer<typeof ProviderSummarySchema>;

export const ProviderListSchema = z.object({
  featureEnabled: z.boolean(),
  /** ATO_IDP_MAX_INTEGRATIONS_PER_ORG and the non-disabled integrations counted against it. */
  limit: z.object({ max: count, used: count }),
  data: z.array(ProviderSummarySchema),
});
export type ProviderListView = z.infer<typeof ProviderListSchema>;

export const ProviderStreamViewSchema = z.object({
  stream: StreamNameSchema,
  role: z.enum(['primary', 'companion', 'unsupported']),
  /** The primary stream whose polls carry a companion's events. */
  primary: StreamNameSchema.nullable(),
  enabled: z.boolean(),
  status: z.enum(['active', 'backfilling', 'paused', 'error', 'unsupported']),
  availability,
  availabilityCode: z.string().nullable(),
  capability: capabilityView,
  watermarkAt: nullableInstant,
  lagSeconds: count.nullable(),
  nextPollAt: nullableInstant,
  lastAttemptAt: nullableInstant,
  lastSuccessAt: nullableInstant,
  lastEventAt: nullableInstant,
  lastErrorCode: z.string().nullable(),
  consecutiveFailures: count,
  throttledUntil: nullableInstant,
  backfill: z.object({
    active: z.boolean(),
    from: nullableInstant,
    requestedAt: nullableInstant,
    completedAt: nullableInstant,
  }),
  eventsTotal: count,
  pagesTotal: count,
});

export const ProviderActionViewSchema = z.object({
  action: ActionTypeSchema,
  enabled: z.boolean(),
  capability: capabilityView,
  code: z.string().nullable(),
  rollback: z.boolean(),
  confirmation: z.enum(['synchronous', 'polling']),
  /** The settings field the action needs (`require_mfa`). */
  requiresConfiguration: z.string().nullable(),
});

export const ProviderProfileViewSchema = z.object({
  profile: z.string(),
  purpose: z.enum(['ato_telemetry', 'ato_response']),
  title: z.string(),
  readOnly: z.boolean(),
  required: z.array(z.string()),
  /** Proven only by the worker's probe (another API resource than 8.2's token). */
  notObservable: z.array(z.string()),
  grant: z
    .object({
      id: PublicIdSchema,
      status: z.enum(['active', 'pending', 'error', 'revoked']),
      /** null while step 8.2 never verified the grant. */
      observed: z.array(z.string()).nullable(),
      missing: z.array(z.string()),
      excess: z.array(z.string()),
    })
    .nullable(),
});

export const ProviderDetailSchema = ProviderSummarySchema.extend({
  rowVersion: z.number().int().min(1),
  settingsVersion: z.number().int().min(1),
  settingsSchema: z.literal('ato-idp-binding/1'),
  /** The stored settings (the defaults when the stored document is not valid any more). */
  settings: z.record(z.string(), z.unknown()),
  settingsInvalid: z.boolean(),
  healthDetail: z.object({
    status: IntegrationHealthSchema,
    checkedAt: nullableInstant,
    nextCheckAt: nullableInstant,
    stale: z.boolean(),
    ok: z.boolean().nullable(),
    code: z.string().nullable(),
    grants: z.array(
      z.object({
        profile: z.string(),
        status: z.enum(['active', 'pending', 'error', 'revoked', 'absent']),
        missingPermissions: z.array(z.string()),
      }),
    ),
  }),
  streamDetails: z.array(ProviderStreamViewSchema),
  actions: z.array(ProviderActionViewSchema),
  permissions: z.object({
    /** Permission names observed on the connection's ATO grants when the integration was bound. */
    granted: z.array(z.string()),
    profiles: z.array(ProviderProfileViewSchema),
  }),
  directory: z.object({ domainCount: count }),
});
export type ProviderDetailView = z.infer<typeof ProviderDetailSchema>;

export const ProviderHealthCheckSchema = z.object({
  id: PublicIdSchema,
  status: IntegrationStatusSchema,
  health: HealthSummarySchema,
  /** When the probe was requested (the worker probes at its next tick). */
  requestedAt: isoInstant,
});
export type ProviderHealthCheckView = z.infer<typeof ProviderHealthCheckSchema>;

export const ProviderRequirementsSchema = z.object({
  providers: z.array(
    z.object({
      provider: ProviderKindSchema,
      connectionProvider: ConnectionProviderSchema,
      profiles: z.array(
        z.object({
          key: z.string(),
          version: count,
          purpose: z.enum(['ato_telemetry', 'ato_response']),
          readOnly: z.boolean(),
          title: z.string(),
          description: z.string(),
          permissions: z.array(
            z.object({
              name: z.string(),
              api: z.enum(['graph', 'o365_management', 'google_oauth_scope']),
            }),
          ),
        }),
      ),
      streams: z.array(
        z.object({
          stream: StreamNameSchema,
          role: z.enum(['primary', 'companion', 'unsupported']),
          primary: StreamNameSchema.nullable(),
          profile: z.string().nullable(),
          permissions: z.array(z.string()),
          optionalPermissions: z.array(z.string()),
          licences: z.array(z.string()),
          retentionDays: count,
          notes: z.string(),
        }),
      ),
      actions: z.array(
        z.object({
          action: ActionTypeSchema,
          supported: z.boolean(),
          profile: z.string().nullable(),
          permissions: z.array(z.string()),
          rollback: z.boolean(),
          confirmation: z.enum(['synchronous', 'polling']),
          impact: z.enum(['low', 'medium', 'high']),
          requiresConfiguration: z.string().nullable(),
          notes: z.string(),
        }),
      ),
      licences: z.array(z.object({ code: z.string(), title: z.string(), enables: z.string() })),
      notes: z.array(z.string()),
    }),
  ),
});
export type ProviderRequirementsView = z.infer<typeof ProviderRequirementsSchema>;

export const ProviderConnectionCandidateSchema = z.object({
  id: PublicIdSchema,
  provider: ConnectionProviderSchema,
  /** The ATO provider kind of the connection (null for a provider ATO does not support). */
  kind: ProviderKindSchema.nullable(),
  displayName: z.string(),
  status: z.enum(['configuring', 'active', 'error', 'disabled']),
  eligibility: z.enum(['eligible', 'already_bound', 'wrong_provider', 'inactive']),
  reasons: z.array(
    z.enum([
      'already_bound',
      'wrong_provider',
      'connection_inactive',
      'telemetry_grant_missing',
      'telemetry_grant_inactive',
    ]),
  ),
  /** The non-disabled integration bound to the connection. */
  integrationId: PublicIdSchema.nullable(),
  providerVerifiedDomainCount: count,
  profiles: z.array(ProviderProfileViewSchema),
});

export const ProviderConnectionsSchema = z.object({
  featureEnabled: z.boolean(),
  limit: z.object({ max: count, used: count }),
  data: z.array(ProviderConnectionCandidateSchema),
});
export type ProviderConnectionsView = z.infer<typeof ProviderConnectionsSchema>;

// ------------------------------------------------------------------------- mailbox state

export const MailboxItemViewSchema = z.object({
  id: PublicIdSchema,
  kind: z.enum(MAILBOX_ITEM_KINDS),
  state: z.enum(['present', 'removed']),
  /** Forwarding or delegate target domain (never the address). */
  targetDomain: z.string().nullable(),
  /** `MAILBOX_RULE_TRAITS` codes (never the rule keywords). */
  traits: z.array(z.string()),
  enabled: z.boolean().nullable(),
  source: z.enum(['snapshot', 'audit']),
  lastChange: z.enum(['added', 'changed', 'removed']),
  provider: ProviderKindSchema,
  integrationId: PublicIdSchema,
  firstSeenAt: isoInstant,
  lastSeenAt: isoInstant,
  removedAt: nullableInstant,
});

export const MailboxStateSchema = z.object({
  accountId: PublicIdSchema,
  /** Present items and items removed in the last 30 days (≤ 500, newest change first per kind). */
  items: z.array(MailboxItemViewSchema),
  truncated: z.boolean(),
  identities: z.array(
    z.object({
      provider: z.string(),
      integrationId: PublicIdSchema.nullable(),
      userPrincipalName: z.string().nullable(),
      directoryStatus: z.enum(['unknown', 'active', 'suspended', 'deleted']),
      directoryStatusAt: nullableInstant,
      refreshRequestedAt: nullableInstant,
      /** Whether `POST …/mailbox-state/refresh` reaches this identity (an active integration). */
      refreshSupported: z.boolean(),
    }),
  ),
  integrations: z.array(
    z.object({
      id: PublicIdSchema,
      provider: ProviderKindSchema,
      displayName: z.string().nullable(),
      status: IntegrationStatusSchema,
      /** Last successful poll of the provider's mailbox-state stream. */
      lastSweepAt: nullableInstant,
    }),
  ),
  refreshRequestedAt: nullableInstant,
});
export type MailboxStateView = z.infer<typeof MailboxStateSchema>;

export const MailboxRefreshSchema = z.object({
  accountId: PublicIdSchema,
  requestedAt: isoInstant,
  /** Identities flagged for the next poll of their integration. */
  identities: count,
  integrationIds: z.array(PublicIdSchema),
});
export type MailboxRefreshView = z.infer<typeof MailboxRefreshSchema>;
