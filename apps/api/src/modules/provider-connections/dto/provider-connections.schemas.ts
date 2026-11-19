import { providerRelayProofPolicySchema } from '@email-gateway/mail-routing';
import { z } from 'zod';
import { defineListQuery } from '../../../http/listing/list-query';
import { stripControlCharacters } from '../../webhooks/domain/control-chars';

/**
 * Request and response shapes of the provider-connection routes (step 8.2 §5,
 * docs/plan/steps/25-m365-google-connectors.md). Every request schema is strict; no response ever
 * carries a credential, a ciphertext, a consent state (except the one-time consent URL), a probe
 * token (except the one-time probe address) or provider error text. Examples use `.example`
 * names and EXAMPLE placeholders only (never secret-shaped values).
 */

export const PROVIDERS = ['microsoft_365', 'google_workspace'] as const;
export const AUTH_METHODS = [
  'platform_app',
  'customer_app_secret',
  'platform_service_account',
  'customer_service_account',
] as const;
export const CONNECTION_STATUSES = [
  'draft',
  'connecting',
  'configuring',
  'active',
  'disabled',
] as const;
export const OUTBOUND_MODES = ['off', 'probe_only', 'active', 'suspended'] as const;
export const HEALTH_STATUSES = ['unknown', 'healthy', 'warning', 'critical'] as const;
export const GRANT_STATUSES = [
  'pending_consent',
  'verifying',
  'active',
  'error',
  'revoked',
] as const;
export const DOMAIN_VERIFICATIONS = [
  'unknown',
  'verified',
  'unverified',
  'absent',
  'alias',
] as const;
export const VALIDATION_KINDS = ['full', 'credentials', 'inbound', 'outbound'] as const;
export const VALIDATION_STATUSES = [
  'queued',
  'running',
  'awaiting_probe',
  'passed',
  'warning',
  'failed',
  'expired',
  'cancelled',
] as const;
export const CHECK_STATUSES = ['pass', 'warn', 'fail', 'skipped', 'error'] as const;
export const CHECK_SEVERITIES = ['info', 'warning', 'critical'] as const;
export const WIZARD_STEPS = [
  'connect',
  'domains',
  'inbound',
  'outbound',
  'validate',
  'activate',
] as const;
export const WIZARD_STEP_STATUSES = [
  'not_started',
  'in_progress',
  'done',
  'blocked',
  'skipped',
] as const;
export const CHANGE_KINDS = [
  'inbound',
  'outbound',
  'activate',
  'proof',
  'suspend',
  'disable_outbound',
  'disable',
] as const;
export type ChangeKind = (typeof CHANGE_KINDS)[number];

export const ProviderSchema = z.enum(PROVIDERS);
export const PublicIdSchema = z.uuid();
const IsoDate = z.iso.datetime();

/** Tenant text: control characters stripped, trimmed. */
const tenantText = (max: number) =>
  z
    .string()
    .max(max * 4)
    .transform((value) => stripControlCharacters(value).trim())
    .pipe(z.string().min(1, 'must not be empty').max(max));

const displayName = tenantText(128).describe(
  'Display name, unique in your organization (1-128; control characters removed)',
);

// ---- Requests --------------------------------------------------------------------------------

export const CreateConnectionBodySchema = z.strictObject({
  provider: ProviderSchema,
  displayName,
});
export type CreateConnectionBody = z.output<typeof CreateConnectionBodySchema>;

export const UpdateConnectionBodySchema = z.strictObject({
  displayName,
  rowVersion: z
    .number()
    .int()
    .min(1)
    .describe('`rowVersion` of the connection as last read (`409 connection_version_conflict`)'),
});
export type UpdateConnectionBody = z.output<typeof UpdateConnectionBodySchema>;

export const ConnectionListQuerySchema = defineListQuery({
  filters: {
    provider: { type: 'enum', values: PROVIDERS, maxValues: 2 },
    status: { type: 'enum', values: CONNECTION_STATUSES, maxValues: 5 },
    health: { type: 'enum', values: HEALTH_STATUSES, maxValues: 4 },
  },
  sorts: ['-id'],
  defaultSort: '-id',
});
export type ConnectionListQuery = z.output<typeof ConnectionListQuerySchema>;

export const CONNECTION_LIST_PARAMETERS: Record<string, string> = {
  provider: '`microsoft_365`, `google_workspace`; comma list',
  status: '`draft`, `connecting`, `configuring`, `active`, `disabled`; comma list',
  health: '`unknown`, `healthy`, `warning`, `critical`; comma list',
  limit: 'Page size, 1-100 (default 25)',
  cursor: '`nextCursor` of the previous page',
  sort: '`-id` (the only order: newest first)',
};

export const CreateGrantBodySchema = z.strictObject({
  profile: z
    .string()
    .regex(/^[a-z0-9]+(\.[a-z0-9_]+)+$/, 'must be a permission profile key')
    .max(48)
    .describe('Permission profile key (`m365.mail_flow`, `google.mail_flow`)'),
  authMethod: z.enum(AUTH_METHODS),
});
export type CreateGrantBody = z.output<typeof CreateGrantBodySchema>;

export const CompleteConsentBodySchema = z.strictObject({
  state: z
    .string()
    .regex(/^[A-Za-z0-9_-]{43}$/, 'must be the consent state of the redirect')
    .describe('The `state` of the consent redirect (single use, 10 minutes, your session only)'),
  tenant: z
    .string()
    .max(64)
    .optional()
    .describe('The `tenant` of the redirect (a claim: verified by the worker before any use)'),
  adminConsent: z.boolean().optional().describe('`admin_consent=True` of the redirect'),
  error: z.string().max(128).optional().describe('`error` of the redirect (consent declined)'),
  errorDescription: z
    .string()
    .max(2048)
    .optional()
    .describe('`error_description` of the redirect (≤ 256 sanitized characters are audited)'),
});
export type CompleteConsentBody = z.output<typeof CompleteConsentBodySchema>;

/** Microsoft 365 `customer_app_secret` upload (D2, D5). */
export const M365CredentialsBodySchema = z.strictObject({
  tenantId: z
    .string()
    .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/, 'must be a GUID')
    .describe('Directory (tenant) id of your Microsoft 365 tenant (lower-case GUID)'),
  clientId: z
    .string()
    .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/, 'must be a GUID')
    .describe('Application (client) id of your app registration'),
  clientSecret: z
    .string()
    .min(1)
    .max(1024)
    .describe('Client secret value: encrypted at rest, never shown, logged or audited again'),
  expiresAt: IsoDate.optional().describe(
    'When the secret expires (expiry warnings at 30 / 7 days)',
  ),
});

/** Google `customer_service_account` upload (D2, D5). */
export const GoogleCredentialsBodySchema = z.strictObject({
  serviceAccountKey: z
    .record(z.string(), z.unknown())
    .describe(
      'The service account JSON key file (object). Kept: type, client_email, private_key, ' +
        'private_key_id, token_uri (must equal the platform Google token URL), client_id; every ' +
        'other field is dropped. Encrypted at rest, never shown again',
    ),
  subjectEmail: z
    .string()
    .max(320)
    .describe('The delegated administrator the service account acts as (domain-wide delegation)'),
});

export const SetCredentialsBodySchema = z.union([
  M365CredentialsBodySchema,
  GoogleCredentialsBodySchema,
]);
export type SetCredentialsBody = z.output<typeof SetCredentialsBodySchema>;

export const VerifyGrantBodySchema = z.strictObject({
  subjectEmail: z
    .string()
    .max(320)
    .optional()
    .describe(
      'Google platform service account: the delegated administrator (required the first time)',
    ),
});
export type VerifyGrantBody = z.output<typeof VerifyGrantBodySchema>;

export const ReplaceDomainsBodySchema = z.strictObject({
  domainIds: z
    .array(PublicIdSchema)
    .max(5000)
    .refine((ids) => new Set(ids.map((id) => id.toLowerCase())).size === ids.length, {
      message: 'Duplicate value',
    })
    .describe(
      'The gateway domains to link (public ids; replaces the set; at most ' +
        'PROVIDER_MAX_DOMAINS_PER_CONNECTION). Each must be an `active` (TXT-verified) domain of ' +
        'your organization not linked to another connection',
    ),
});
export type ReplaceDomainsBody = z.output<typeof ReplaceDomainsBodySchema>;

const HostSchema = z.string().trim().min(1).max(253);

export const MailFlowChangeSchema = z.discriminatedUnion('kind', [
  z
    .strictObject({
      kind: z.literal('inbound'),
      domainIds: z
        .array(PublicIdSchema)
        .min(1)
        .max(500)
        .refine((ids) => new Set(ids.map((id) => id.toLowerCase())).size === ids.length, {
          message: 'Duplicate value',
        }),
      microsoftHosts: z
        .record(PublicIdSchema, HostSchema)
        .optional()
        .describe(
          'Microsoft 365 only: the destination host per domain id (default: the MX target the ' +
            'tenant reports, else `<domain>.mail.protection.outlook.com`)',
        ),
    })
    .describe('Deliver inbound mail of linked domains to the provider (destination preset)'),
  z
    .strictObject({ kind: z.literal('outbound'), mode: z.literal('probe_only') })
    .describe('Create (or re-enable) the provider relay connector in probe-only mode'),
  z
    .strictObject({
      kind: z.literal('activate'),
      outboundMode: z.enum(['active', 'off']),
      internalRouting: z.boolean(),
    })
    .describe('Activate outbound (and internal) routing, or finish the wizard with outbound off'),
  z
    .strictObject({ kind: z.literal('proof'), relayProof: providerRelayProofPolicySchema })
    .describe('Change the relay proof policy (provider-relay-proof/1, bounded per provider)'),
  z.strictObject({ kind: z.literal('suspend') }).describe('Suspend outbound routing (451)'),
  z
    .strictObject({ kind: z.literal('disable_outbound') })
    .describe('Turn outbound and internal routing off and disable the relay connector'),
  z
    .strictObject({ kind: z.literal('disable') })
    .describe('Disconnect (preview only here; applied by `DELETE /provider-connections/{id}`)'),
]);
export type MailFlowChange = z.output<typeof MailFlowChangeSchema>;

export const PreviewBodySchema = z.strictObject({ change: MailFlowChangeSchema });
export type PreviewBody = z.output<typeof PreviewBodySchema>;

const ImpactTokenSchema = z
  .string()
  .min(1)
  .max(128)
  .describe('`impactToken` of the preview of exactly this change (15 minutes, your user only)');

export const ApplyBodySchema = z.strictObject({
  change: MailFlowChangeSchema,
  impactToken: ImpactTokenSchema,
  confirm: z.literal(true).describe('Explicit confirmation (ADR-0080)'),
});
export type ApplyBody = z.output<typeof ApplyBodySchema>;

export const DisconnectBodySchema = z.strictObject({
  impactToken: ImpactTokenSchema.describe('`impactToken` of the preview of the `disable` change'),
  confirm: z.literal(true).describe('Explicit confirmation (ADR-0080)'),
});
export type DisconnectBody = z.output<typeof DisconnectBodySchema>;

export const AttestationBodySchema = z.strictObject({
  code: z
    .string()
    .max(64)
    .regex(/^[a-z0-9]+(\.[a-z0-9_]+)+$/, 'must be an attestation code')
    .describe('An attestation code of the provider’s setup guide'),
  attested: z.boolean().describe('`true` records the statement, `false` withdraws it'),
});
export type AttestationBody = z.output<typeof AttestationBodySchema>;

export const CreateValidationBodySchema = z.strictObject({ kind: z.enum(VALIDATION_KINDS) });
export type CreateValidationBody = z.output<typeof CreateValidationBodySchema>;

export const ValidationListQuerySchema = defineListQuery({
  filters: {
    kind: { type: 'enum', values: VALIDATION_KINDS, maxValues: 4 },
    status: { type: 'enum', values: VALIDATION_STATUSES, maxValues: 8 },
  },
  sorts: ['-id'],
  defaultSort: '-id',
});
export type ValidationListQuery = z.output<typeof ValidationListQuerySchema>;

export const VALIDATION_LIST_PARAMETERS: Record<string, string> = {
  kind: '`full`, `credentials`, `inbound`, `outbound`; comma list',
  status:
    '`queued`, `running`, `awaiting_probe`, `passed`, `warning`, `failed`, `expired`, ' +
    '`cancelled`; comma list',
  limit: 'Page size, 1-100 (default 25)',
  cursor: '`nextCursor` of the previous page',
  sort: '`-id` (the only order: newest first)',
};

export const GuideQuerySchema = z.strictObject({
  format: z.enum(['json', 'markdown']).optional(),
});
export type GuideQuery = z.output<typeof GuideQuerySchema>;

// ---- Responses -------------------------------------------------------------------------------

export const ConnectionSummarySchema = z.object({
  id: PublicIdSchema,
  provider: ProviderSchema,
  displayName: z.string(),
  status: z.enum(CONNECTION_STATUSES),
  tenantName: z.string().nullable(),
  outboundMode: z.enum(OUTBOUND_MODES),
  internalRouting: z.boolean(),
  health: z.enum(HEALTH_STATUSES),
  healthChangedAt: IsoDate.nullable(),
  domainCount: z.number().int(),
  createdAt: IsoDate,
});
export type ConnectionSummaryView = z.output<typeof ConnectionSummarySchema>;

export const ConnectionPageSchema = z.object({
  data: z.array(ConnectionSummarySchema),
  nextCursor: z.string().nullable(),
});
export type ConnectionPage = z.output<typeof ConnectionPageSchema>;

export const GrantSchema = z.object({
  id: PublicIdSchema,
  profile: z.string(),
  profileVersion: z.number().int(),
  authMethod: z.enum(AUTH_METHODS),
  status: z.enum(GRANT_STATUSES),
  clientId: z.string().nullable().describe('Application / OAuth client id (not a secret)'),
  subjectEmail: z.string().nullable().describe('Google delegated administrator, masked'),
  credentialFingerprint: z
    .string()
    .nullable()
    .describe('First 12 hex characters of the credential fingerprint (never the credential)'),
  credentialVersion: z.number().int(),
  credentialSetAt: IsoDate.nullable(),
  credentialExpiresAt: IsoDate.nullable(),
  requestedPermissions: z.array(z.string()),
  observedPermissions: z.array(z.string()).nullable(),
  missingPermissions: z.array(z.string()).nullable(),
  excessPermissions: z.array(z.string()).nullable(),
  consentedAt: IsoDate.nullable(),
  verifyRequestedAt: IsoDate.nullable(),
  verifiedAt: IsoDate.nullable(),
  lastErrorCode: z.string().nullable(),
  createdAt: IsoDate,
  updatedAt: IsoDate,
});
export type GrantView = z.output<typeof GrantSchema>;

export const AttestationEntrySchema = z.object({
  code: z.string(),
  userId: z.string().nullable(),
  at: IsoDate,
});

export const ConnectionDetailSchema = ConnectionSummarySchema.extend({
  tenantId: z.string().nullable().describe('Verified provider tenant / customer id'),
  tenantVerifiedAt: IsoDate.nullable(),
  grants: z.array(GrantSchema),
  domains: z.array(
    z.object({
      id: PublicIdSchema,
      name: z.string(),
      providerVerification: z.enum(DOMAIN_VERIFICATIONS),
    }),
  ),
  relayConnectorId: PublicIdSchema.nullable(),
  relayProof: z.record(z.string(), z.unknown()).describe('provider-relay-proof/1 in effect'),
  relayProofIsDefault: z.boolean(),
  attestations: z.array(AttestationEntrySchema).describe('Statements, not proofs'),
  routeTokenVersion: z.number().int(),
  routeTokenPendingVersion: z.number().int().nullable(),
  healthCheckedAt: IsoDate.nullable(),
  nextHealthCheckAt: IsoDate.nullable(),
  disabledAt: IsoDate.nullable(),
  rowVersion: z.number().int(),
  updatedAt: IsoDate,
});
export type ConnectionDetailView = z.output<typeof ConnectionDetailSchema>;

export const WizardSchema = z.object({
  connectionId: PublicIdSchema,
  provider: ProviderSchema,
  connectionStatus: z.enum(CONNECTION_STATUSES),
  steps: z.array(
    z.object({
      step: z.enum(WIZARD_STEPS),
      status: z.enum(WIZARD_STEP_STATUSES),
      blockers: z.array(z.string()).describe('Blocker codes (empty when done)'),
    }),
  ),
  nextAction: z
    .object({ step: z.enum(WIZARD_STEPS), action: z.string() })
    .nullable()
    .describe('The first step that is not done, with an action code'),
  missingAttestations: z.array(z.string()),
});
export type WizardView = z.output<typeof WizardSchema>;

const ConsentSchema = z.object({
  consentUrl: z
    .string()
    .nullable()
    .describe('Microsoft admin consent URL with a single-use state: shown ONLY in this response'),
  expiresAt: IsoDate.nullable(),
});

export const CreatedGrantSchema = z.object({
  grant: GrantSchema,
  next: z.enum(['consent', 'delegation', 'credentials']),
  consent: ConsentSchema.nullable().describe('`platform_app` only'),
  delegation: z
    .object({
      clientId: z.string(),
      scopes: z.array(z.string()),
      adminConsoleSteps: z.array(z.string()),
    })
    .nullable()
    .describe('`platform_service_account` only: what to authorize under domain-wide delegation'),
});
export type CreatedGrantView = z.output<typeof CreatedGrantSchema>;

export const ConsentCompletedSchema = z.object({
  connectionId: PublicIdSchema,
  grantId: PublicIdSchema,
  status: z.enum(GRANT_STATUSES),
});
export type ConsentCompletedView = z.output<typeof ConsentCompletedSchema>;

export const RevokedGrantSchema = z.object({
  grant: GrantSchema,
  providerRemovalSteps: z.array(z.string()),
});
export type RevokedGrantView = z.output<typeof RevokedGrantSchema>;

export const LinkedDomainSchema = z.object({
  id: PublicIdSchema,
  name: z.string(),
  gatewayStatus: z.string(),
  providerVerification: z.enum(DOMAIN_VERIFICATIONS),
  providerCheckedAt: IsoDate.nullable(),
  providerMxHost: z.string().nullable(),
  destinationProvider: z.enum(['custom', 'microsoft_365', 'google_workspace']).nullable(),
  inboundAppliedAt: IsoDate.nullable(),
  dns: z.object({
    mx: z.string().nullable(),
    spf: z.string().nullable(),
    dkim: z.string().nullable(),
  }),
});
export type LinkedDomainView = z.output<typeof LinkedDomainSchema>;

export const LinkedDomainListSchema = z.object({ data: z.array(LinkedDomainSchema) });
export type LinkedDomainList = z.output<typeof LinkedDomainListSchema>;

const ServerSchema = z.object({
  host: z.string(),
  port: z.number().int(),
  priority: z.number().int(),
  tlsMode: z.string(),
});
const DestinationStateSchema = z.object({
  provider: z.enum(['custom', 'microsoft_365', 'google_workspace']).nullable(),
  servers: z.array(ServerSchema),
});

export const ChangeSetSchema = z.object({
  kind: z.enum(CHANGE_KINDS),
  domains: z.array(
    z.object({
      domainId: PublicIdSchema,
      name: z.string(),
      current: DestinationStateSchema,
      proposed: DestinationStateSchema,
      changed: z.boolean(),
    }),
  ),
  connector: z
    .object({
      action: z.enum(['create', 'enable', 'disable', 'none']),
      id: PublicIdSchema.nullable(),
    })
    .nullable(),
  connection: z.array(
    z.object({
      field: z.enum(['status', 'outboundMode', 'internalRouting', 'relayProof']),
      from: z.unknown(),
      to: z.unknown(),
    }),
  ),
  grantsRevoked: z.number().int(),
});
export type ChangeSetView = z.output<typeof ChangeSetSchema>;

export const PreviewSchema = z.object({
  change: z.record(z.string(), z.unknown()),
  changeSet: ChangeSetSchema,
  impactToken: z.string(),
  expiresAt: IsoDate,
  warnings: z.array(z.string()).describe('Warning codes (e.g. `domain_not_provider_verified`)'),
});
export type PreviewView = z.output<typeof PreviewSchema>;

export const AppliedSchema = z.object({
  connection: ConnectionDetailSchema,
  changeSet: ChangeSetSchema,
  appliedAt: IsoDate,
});
export type AppliedView = z.output<typeof AppliedSchema>;

export const DisconnectedSchema = z.object({
  connection: ConnectionDetailSchema,
  providerCleanupSteps: z.array(z.string()),
  destinationsKept: z
    .literal(true)
    .describe('Inbound destinations are kept (removing them would break inbound mail)'),
});
export type DisconnectedView = z.output<typeof DisconnectedSchema>;

export const MailFlowStateSchema = z.object({
  connectionId: PublicIdSchema,
  outboundMode: z.enum(OUTBOUND_MODES),
  internalRouting: z.boolean(),
  relayProof: z.record(z.string(), z.unknown()),
  relayProofIsDefault: z.boolean(),
  relayConnector: z.object({ id: PublicIdSchema, status: z.string() }).nullable(),
  domains: z.array(
    z.object({
      id: PublicIdSchema,
      name: z.string(),
      destinations: DestinationStateSchema,
      inboundAppliedAt: IsoDate.nullable(),
      dns: z.object({ mx: z.string().nullable(), spf: z.string().nullable() }),
    }),
  ),
  relayActivity24h: z.object({
    accepted: z.number().int(),
    proofFailed: z.number().int(),
    tempFailed: z.number().int(),
    probes: z.number().int(),
    lastAcceptedAt: IsoDate.nullable(),
  }),
  routeToken: z
    .object({
      version: z.number().int(),
      pendingVersion: z.number().int().nullable(),
      value: z.string().nullable().describe('Only with `integration:manage`'),
      masked: z.string(),
    })
    .nullable()
    .describe('Microsoft 365 only'),
});
export type MailFlowStateView = z.output<typeof MailFlowStateSchema>;

export const AttestationsSchema = z.object({
  connectionId: PublicIdSchema,
  attestations: z.array(AttestationEntrySchema),
  rowVersion: z.number().int(),
});
export type AttestationsView = z.output<typeof AttestationsSchema>;

const ValidationResultSchema = z.object({
  code: z.string(),
  subject: z.string(),
  status: z.enum(CHECK_STATUSES),
  severity: z.enum(CHECK_SEVERITIES),
  evidence: z.record(z.string(), z.unknown()),
  remediation: z.string().nullable(),
});

export const ValidationRunSchema = z.object({
  id: PublicIdSchema,
  kind: z.enum(VALIDATION_KINDS),
  status: z.enum(VALIDATION_STATUSES),
  requestedBy: z.object({ type: z.string(), id: z.string().nullable() }),
  probeExpiresAt: IsoDate.nullable(),
  summary: z
    .object({
      pass: z.number().int(),
      warn: z.number().int(),
      fail: z.number().int(),
      skipped: z.number().int(),
      error: z.number().int(),
    })
    .nullable(),
  startedAt: IsoDate.nullable(),
  completedAt: IsoDate.nullable(),
  createdAt: IsoDate,
});
export type ValidationRunView = z.output<typeof ValidationRunSchema>;

export const ValidationRunDetailSchema = ValidationRunSchema.extend({
  results: z.array(ValidationResultSchema),
  probeObservations: z.array(
    z.object({
      receivedAt: IsoDate,
      clientIp: z.string(),
      tlsProtocol: z.string().nullable(),
      envelopeFromDomain: z.string(),
      headerFromDomain: z.string().nullable(),
      tenantHeader: z.string(),
      dkim: z.string(),
      dkimDomains: z.array(z.string()),
      proofResult: z.string(),
      failureCode: z.string().nullable(),
    }),
  ),
});
export type ValidationRunDetailView = z.output<typeof ValidationRunDetailSchema>;

export const CreatedValidationSchema = ValidationRunSchema.extend({
  probeAddress: z
    .string()
    .nullable()
    .describe(
      'Single-use probe address (outbound/full runs with outbound mode not `off`): shown ONLY ' +
        'in this response; only its SHA-256 is stored',
    ),
});
export type CreatedValidationView = z.output<typeof CreatedValidationSchema>;

export const ValidationPageSchema = z.object({
  data: z.array(ValidationRunSchema),
  nextCursor: z.string().nullable(),
});
export type ValidationPage = z.output<typeof ValidationPageSchema>;

export const HealthSchema = z.object({
  connectionId: PublicIdSchema,
  status: z.enum(HEALTH_STATUSES),
  checkedAt: IsoDate.nullable(),
  changedAt: IsoDate.nullable(),
  nextCheckAt: IsoDate.nullable(),
  checks: z.array(
    z.object({
      code: z.string(),
      title: z.string(),
      subject: z.string(),
      status: z.enum(CHECK_STATUSES),
      severity: z.enum(CHECK_SEVERITIES),
      evidence: z.record(z.string(), z.unknown()).nullable(),
      firstFailedAt: IsoDate.nullable(),
      checkedAt: IsoDate,
    }),
  ),
  transitions: z.array(
    z.object({
      from: z.enum(HEALTH_STATUSES),
      to: z.enum(HEALTH_STATUSES),
      failingChecks: z.array(z.string()),
      at: IsoDate,
    }),
  ),
});
export type HealthView = z.output<typeof HealthSchema>;

export const HealthCheckAcceptedSchema = z.object({
  connectionId: PublicIdSchema,
  nextHealthCheckAt: IsoDate,
});
export type HealthCheckAccepted = z.output<typeof HealthCheckAcceptedSchema>;

export const CatalogSchema = z.object({
  providers: z.array(
    z.object({
      provider: ProviderSchema,
      displayName: z.string(),
      profiles: z.array(
        z.object({
          key: z.string(),
          version: z.number().int(),
          purpose: z.string(),
          title: z.string(),
          description: z.string(),
          permissions: z.array(z.string()),
          readOnly: z.boolean(),
          authMethods: z.array(z.enum(AUTH_METHODS)),
          availableAuthMethods: z.array(z.enum(AUTH_METHODS)),
        }),
      ),
      attestations: z.array(
        z.object({
          code: z.string(),
          phase: z.string(),
          statement: z.string(),
          requiredFor: z.string().nullable(),
        }),
      ),
      egressSet: z
        .object({
          version: z.number().int(),
          publishedAt: IsoDate.nullable(),
          importedAt: IsoDate,
          rangeCount: z.number().int(),
        })
        .nullable(),
    }),
  ),
  probeDomain: z.string(),
  gateway: z.object({
    mxHosts: z.array(z.string()),
    egressNetworks: z.array(z.string()),
    relayHosts: z.array(z.string()),
    relayTlsName: z.string(),
    spfInclude: z.string(),
  }),
});
export type CatalogView = z.output<typeof CatalogSchema>;

const GuideStepSchema = z.object({
  id: z.string(),
  title: z.string(),
  paragraphs: z.array(z.string()),
  values: z.array(z.object({ label: z.string(), value: z.string() })).optional(),
  commands: z
    .array(z.object({ language: z.enum(['powershell', 'dns', 'text']), code: z.string() }))
    .optional(),
  warning: z.string().optional(),
  attestation: z
    .object({
      code: z.string(),
      statement: z.string(),
      attested: z.boolean(),
      attestedAt: z.string().nullable(),
    })
    .optional(),
});

export const SetupGuideSchema = z.object({
  schema: z.literal('setup-guide/1'),
  provider: ProviderSchema,
  connection: z.object({
    id: PublicIdSchema,
    displayName: z.string(),
    tenantId: z.string().nullable(),
    tenantName: z.string().nullable(),
  }),
  generatedAt: IsoDate,
  notice: z.string(),
  sections: z.array(
    z.object({
      id: z.string(),
      number: z.number().int(),
      title: z.string(),
      paragraphs: z.array(z.string()),
      steps: z.array(GuideStepSchema),
    }),
  ),
});

// ---- Examples (EXAMPLE placeholders; never secret-shaped) ------------------------------------

const CONNECTION_ID = '0192f0c4-d466-7173-8c84-6f708192a3b4';
const GRANT_ID = '0192f0c4-d577-7284-9d95-708192a3b4c5';
const DOMAIN_ID = '0192f0c4-7d1e-7b6a-9c55-6f3e2a1d4b11';
const RUN_ID = '0192f0c4-e688-7395-8ea6-8192a3b4c5d6';
const CONNECTOR_ID = '0192f0c4-f799-74a6-9fb7-92a3b4c5d6e7';
const TENANT_ID = '11111111-2222-3333-4444-555555555555';
const AT = '2026-11-18T09:00:00.000Z';

const exampleGrant: GrantView = {
  id: GRANT_ID,
  profile: 'm365.mail_flow',
  profileVersion: 1,
  authMethod: 'platform_app',
  status: 'active',
  clientId: TENANT_ID,
  subjectEmail: null,
  credentialFingerprint: null,
  credentialVersion: 0,
  credentialSetAt: null,
  credentialExpiresAt: null,
  requestedPermissions: ['Organization.Read.All', 'Domain.Read.All'],
  observedPermissions: ['Organization.Read.All', 'Domain.Read.All'],
  missingPermissions: [],
  excessPermissions: [],
  consentedAt: AT,
  verifyRequestedAt: AT,
  verifiedAt: AT,
  lastErrorCode: null,
  createdAt: AT,
  updatedAt: AT,
};

const exampleSummary: ConnectionSummaryView = {
  id: CONNECTION_ID,
  provider: 'microsoft_365',
  displayName: 'Contoso tenant',
  status: 'active',
  tenantName: 'Contoso Ltd',
  outboundMode: 'probe_only',
  internalRouting: false,
  health: 'healthy',
  healthChangedAt: AT,
  domainCount: 1,
  createdAt: AT,
};

const exampleDetail: ConnectionDetailView = {
  ...exampleSummary,
  tenantId: TENANT_ID,
  tenantVerifiedAt: AT,
  grants: [exampleGrant],
  domains: [{ id: DOMAIN_ID, name: 'contoso.example', providerVerification: 'verified' }],
  relayConnectorId: CONNECTOR_ID,
  relayProof: { tenantHeader: 'required', dkimAligned: 'required' },
  relayProofIsDefault: true,
  attestations: [
    {
      code: 'm365.inbound_connector_created',
      userId: '0192f0c4-0000-7000-8000-0000000000a1',
      at: AT,
    },
  ],
  routeTokenVersion: 1,
  routeTokenPendingVersion: null,
  healthCheckedAt: AT,
  nextHealthCheckAt: '2026-11-18T09:15:00.000Z',
  disabledAt: null,
  rowVersion: 7,
  updatedAt: AT,
};

const exampleChangeSet: ChangeSetView = {
  kind: 'inbound',
  domains: [
    {
      domainId: DOMAIN_ID,
      name: 'contoso.example',
      current: { provider: null, servers: [] },
      proposed: {
        provider: 'microsoft_365',
        servers: [
          {
            host: 'contoso-example.mail.protection.outlook.com',
            port: 25,
            priority: 10,
            tlsMode: 'verify',
          },
        ],
      },
      changed: true,
    },
  ],
  connector: null,
  connection: [],
  grantsRevoked: 0,
};

const exampleRun: ValidationRunView = {
  id: RUN_ID,
  kind: 'full',
  status: 'passed',
  requestedBy: { type: 'user', id: '0192f0c4-0000-7000-8000-0000000000a1' },
  probeExpiresAt: '2026-11-19T09:00:00.000Z',
  summary: { pass: 12, warn: 1, fail: 0, skipped: 2, error: 0 },
  startedAt: AT,
  completedAt: '2026-11-18T09:05:00.000Z',
  createdAt: AT,
};

export const PROVIDER_EXAMPLES = {
  create: { provider: 'microsoft_365', displayName: 'Contoso tenant' },
  update: { displayName: 'Contoso production tenant', rowVersion: 7 },
  summary: exampleSummary,
  page: { data: [exampleSummary], nextCursor: null },
  detail: exampleDetail,
  created: { ...exampleDetail, status: 'draft', grants: [], domains: [], rowVersion: 1 },
  wizard: {
    connectionId: CONNECTION_ID,
    provider: 'microsoft_365',
    connectionStatus: 'active',
    steps: [
      { step: 'connect', status: 'done', blockers: [] },
      { step: 'domains', status: 'done', blockers: [] },
      { step: 'inbound', status: 'in_progress', blockers: ['attestations_missing'] },
      { step: 'outbound', status: 'skipped', blockers: [] },
      { step: 'validate', status: 'blocked', blockers: ['inbound'] },
      { step: 'activate', status: 'blocked', blockers: ['validate'] },
    ],
    nextAction: { step: 'inbound', action: 'record_attestations' },
    missingAttestations: ['m365.enhanced_filtering_enabled'],
  } satisfies WizardView,
  createGrant: { profile: 'm365.mail_flow', authMethod: 'platform_app' },
  createdGrant: {
    grant: { ...exampleGrant, status: 'pending_consent', verifiedAt: null, consentedAt: null },
    next: 'consent',
    consent: {
      consentUrl:
        'https://login.microsoftonline.com/organizations/v2.0/adminconsent?client_id=' +
        `${TENANT_ID}&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default&redirect_uri=` +
        'https%3A%2F%2Fportal.example%2Fintegrations%2Fproviders%2Fconsent-callback&state=EXAMPLE',
      expiresAt: '2026-11-18T09:10:00.000Z',
    },
    delegation: null,
  } satisfies CreatedGrantView,
  completeConsent: {
    state: 'EXAMPLEstateEXAMPLEstateEXAMPLEstateEXAMPLE',
    tenant: TENANT_ID,
    adminConsent: true,
  },
  consentCompleted: { connectionId: CONNECTION_ID, grantId: GRANT_ID, status: 'verifying' },
  setM365Credentials: {
    tenantId: TENANT_ID,
    clientId: '66666666-7777-8888-9999-000000000000',
    clientSecret: 'EXAMPLE-client-secret-value',
    expiresAt: '2027-11-18T00:00:00.000Z',
  },
  setGoogleCredentials: {
    serviceAccountKey: {
      type: 'service_account',
      client_email: 'gateway-reader@example-project.iam.gserviceaccount.example',
      private_key: 'EXAMPLE-private-key',
      private_key_id: '0123456789abcdef',
      token_uri: 'https://oauth2.googleapis.com/token',
    },
    subjectEmail: 'admin@contoso.example',
  },
  grantWithCredential: {
    ...exampleGrant,
    authMethod: 'customer_app_secret',
    status: 'verifying',
    clientId: '66666666-7777-8888-9999-000000000000',
    credentialFingerprint: '3f2a9c1d7b4e',
    credentialVersion: 1,
    credentialSetAt: AT,
    credentialExpiresAt: '2027-11-18T00:00:00.000Z',
    verifiedAt: null,
  } satisfies GrantView,
  verify: { subjectEmail: 'admin@contoso.example' },
  revoked: {
    grant: { ...exampleGrant, status: 'revoked' },
    providerRemovalSteps: [
      'In Microsoft Entra admin center → Enterprise applications, delete the email security ' +
        'gateway application to remove its admin consent.',
    ],
  } satisfies RevokedGrantView,
  domains: {
    data: [
      {
        id: DOMAIN_ID,
        name: 'contoso.example',
        gatewayStatus: 'active',
        providerVerification: 'verified',
        providerCheckedAt: AT,
        providerMxHost: 'contoso-example.mail.protection.outlook.com',
        destinationProvider: 'microsoft_365',
        inboundAppliedAt: AT,
        dns: { mx: 'valid', spf: 'valid', dkim: 'valid' },
      },
    ],
  } satisfies LinkedDomainList,
  replaceDomains: { domainIds: [DOMAIN_ID] },
  preview: { change: { kind: 'inbound', domainIds: [DOMAIN_ID] } },
  previewed: {
    change: { kind: 'inbound', domainIds: [DOMAIN_ID] },
    changeSet: exampleChangeSet,
    impactToken: 'EXAMPLEimpactTokenEXAMPLEimpactTokenEXAMPLE.1795000000',
    expiresAt: '2026-11-18T09:15:00.000Z',
    warnings: [],
  } satisfies PreviewView,
  apply: {
    change: { kind: 'inbound', domainIds: [DOMAIN_ID] },
    impactToken: 'EXAMPLEimpactTokenEXAMPLEimpactTokenEXAMPLE.1795000000',
    confirm: true,
  },
  applied: { connection: exampleDetail, changeSet: exampleChangeSet, appliedAt: AT },
  disconnect: {
    impactToken: 'EXAMPLEimpactTokenEXAMPLEimpactTokenEXAMPLE.1795000000',
    confirm: true,
  },
  disconnected: {
    connection: { ...exampleDetail, status: 'disabled', outboundMode: 'off', disabledAt: AT },
    providerCleanupSteps: [
      'Remove the inbound connector "Email security gateway" and the outbound connector ' +
        '"Email security gateway outbound" in the Exchange admin center.',
    ],
    destinationsKept: true,
  } satisfies DisconnectedView,
  mailFlow: {
    connectionId: CONNECTION_ID,
    outboundMode: 'probe_only',
    internalRouting: false,
    relayProof: { tenantHeader: 'required', dkimAligned: 'required' },
    relayProofIsDefault: true,
    relayConnector: { id: CONNECTOR_ID, status: 'active' },
    domains: [
      {
        id: DOMAIN_ID,
        name: 'contoso.example',
        destinations: exampleChangeSet.domains[0]!.proposed,
        inboundAppliedAt: AT,
        dns: { mx: 'valid', spf: 'valid' },
      },
    ],
    relayActivity24h: {
      accepted: 0,
      proofFailed: 0,
      tempFailed: 0,
      probes: 1,
      lastAcceptedAt: null,
    },
    routeToken: { version: 1, pendingVersion: null, value: null, masked: '••••wxyz' },
  } satisfies MailFlowStateView,
  attestation: { code: 'm365.inbound_connector_created', attested: true },
  attestations: {
    connectionId: CONNECTION_ID,
    attestations: exampleDetail.attestations,
    rowVersion: 8,
  } satisfies AttestationsView,
  createValidation: { kind: 'full' },
  createdValidation: {
    ...exampleRun,
    status: 'queued',
    summary: null,
    startedAt: null,
    completedAt: null,
    probeAddress: 'eg-probe-abcdefghijklmnopqrstuvwxyz@probe.mail-gateway.example',
  } satisfies CreatedValidationView,
  validationPage: { data: [exampleRun], nextCursor: null } satisfies ValidationPage,
  validation: {
    ...exampleRun,
    results: [
      {
        code: 'inbound.smtp',
        subject: 'contoso-example.mail.protection.outlook.com',
        status: 'pass',
        severity: 'critical',
        evidence: { tlsVersion: 'TLSv1.3', rcptReplyClass: '2xx' },
        remediation: '#inbound-destination',
      },
    ],
    probeObservations: [
      {
        receivedAt: '2026-11-18T09:03:00.000Z',
        clientIp: '40.92.0.10',
        tlsProtocol: 'TLSv1.3',
        envelopeFromDomain: 'contoso.example',
        headerFromDomain: 'contoso.example',
        tenantHeader: 'match',
        dkim: 'aligned_pass',
        dkimDomains: ['contoso.example'],
        proofResult: 'pass',
        failureCode: null,
      },
    ],
  } satisfies ValidationRunDetailView,
  health: {
    connectionId: CONNECTION_ID,
    status: 'warning',
    checkedAt: AT,
    changedAt: AT,
    nextCheckAt: '2026-11-18T09:15:00.000Z',
    checks: [
      {
        code: 'dns.dkim_provider',
        title: 'Provider DKIM signing is published',
        subject: 'contoso.example',
        status: 'warn',
        severity: 'warning',
        evidence: { selectors: [] },
        firstFailedAt: AT,
        checkedAt: AT,
      },
    ],
    transitions: [{ from: 'healthy', to: 'warning', failingChecks: ['dns.dkim_provider'], at: AT }],
  } satisfies HealthView,
  healthCheck: { connectionId: CONNECTION_ID, nextHealthCheckAt: AT } satisfies HealthCheckAccepted,
} as const;
