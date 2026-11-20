import {
  AUTH_OUTCOMES,
  AUTH_SOURCES,
  RESPONSE_ACTION_TYPES,
  RESPONSE_IMPACTS,
  RESPONSE_STATUSES,
  SIGNAL_CATEGORIES,
  SIGNAL_STATUSES,
  SIGNAL_STRENGTHS,
} from '@email-gateway/ato-detection';
import {
  ATO_ACCOUNT_KINDS,
  ATO_RISK_LEVELS,
  SECURITY_INCIDENT_SEVERITIES,
  SECURITY_INCIDENT_STATUSES,
} from '@email-gateway/security-contracts';
import { z } from 'zod';
import { defineListQuery } from '../../../http/listing';

/**
 * Request and response schemas of the account takeover routes (step 8.4 §5.1). Requests are
 * strict (`z.strictObject`, D1 of step 6.1); responses are documentation of what the services
 * build. Public ids only; a tenant's own account addresses are returned to `ato:read` holders
 * (sender identities, ADR-0062); recipient data only as domains and counts; never a password,
 * token, subject or recipient address.
 */

export const PublicIdSchema = z.uuid();
const isoInstant = z.iso.datetime({ offset: true });
const nullableInstant = isoInstant.nullable();
const kind = z.enum(ATO_ACCOUNT_KINDS);
const level = z.enum(ATO_RISK_LEVELS);
const severity = z.enum(SECURITY_INCIDENT_SEVERITIES);
const incidentStatus = z.enum(SECURITY_INCIDENT_STATUSES);
const score = z.number().int().min(0).max(100);
const count = z.number().int().min(0);

/** Tenant text: trimmed, no control characters (C0, DEL). */
const text = (min: number, max: number) =>
  z
    .string()
    .trim()
    .min(min)
    .max(max)
    // eslint-disable-next-line no-control-regex -- control characters are exactly what is refused
    .regex(/^[^\x00-\x1f\x7f]*$/, 'must not contain control characters');

/** Multi-line analyst text (reasons may span lines; other control characters refused). */
const reasonText = (min: number, max: number) =>
  z
    .string()
    .trim()
    .min(min)
    .max(max)
    // eslint-disable-next-line no-control-regex -- control characters except CR/LF/TAB are refused
    .regex(/^[^\x00-\x08\x0b\x0c\x0e-\x1f\x7f]*$/, 'must not contain control characters');

// ---------------------------------------------------------------- shared views

export const ActiveIncidentRefSchema = z.object({
  id: PublicIdSchema,
  severity,
  status: incidentStatus,
});

export const OverrideSummarySchema = z.object({
  verdict: z.enum(['benign', 'compromised']),
  expiresAt: isoInstant,
});

export const AccountSummarySchema = z.object({
  id: PublicIdSchema,
  kind,
  /** The tenant's own mailbox (or gateway user) address; null for a connector. */
  address: z.string().nullable(),
  /** User display name or connector name; null for a mailbox. */
  displayName: z.string().nullable(),
  domainId: PublicIdSchema.nullable(),
  status: z.enum(['active', 'retired']),
  riskScore: score,
  riskLevel: level,
  riskUpdatedAt: nullableInstant,
  lastSignalAt: nullableInstant,
  firstSeenAt: isoInstant,
  lastSeenAt: isoInstant,
  protected: z.boolean(),
  activeIncident: ActiveIncidentRefSchema.nullable(),
  override: OverrideSummarySchema.nullable(),
});
export type AccountSummaryView = z.infer<typeof AccountSummarySchema>;

const capabilityState = z.enum(['available', 'unavailable', 'stale', 'unknown']);
export const CapabilitiesSchema = z.object({
  /** `known` from a fresh worker report (≤ 15 min), else `unknown` (every capability unknown). */
  status: z.enum(['known', 'unknown']),
  updatedAt: nullableInstant,
  geoipCity: capabilityState,
  geoipAsn: capabilityState,
  geoipAnonymous: capabilityState,
  dnsbl: capabilityState,
  breachIntel: capabilityState,
  becObservations: capabilityState,
  /** Identity-provider adapters registered in the worker (8.5); empty in 8.4. */
  providers: z.array(z.string()),
});
export type CapabilitiesView = z.infer<typeof CapabilitiesSchema>;

export const RestrictionSchema = z.object({
  id: PublicIdSchema,
  kind: z.enum(['send_block', 'auth_block']),
  scope: z.enum(['mailbox', 'connector', 'connector_ip']),
  /** Connector public id (connector scopes). */
  connectorId: PublicIdSchema.nullable(),
  connectorName: z.string().nullable(),
  /** The tenant's own mailbox (mailbox scope). */
  mailboxAddress: z.string().nullable(),
  ipCidr: z.string().nullable(),
  mode: z.enum(['reject', 'defer']),
  status: z.enum(['active', 'lifted', 'expired']),
  reasonCode: z.string(),
  responseId: PublicIdSchema.nullable(),
  startsAt: isoInstant,
  expiresAt: isoInstant,
  liftedAt: nullableInstant,
  liftReason: z.string().nullable(),
});
export type RestrictionView = z.infer<typeof RestrictionSchema>;

const counted = <K extends string>(key: K) =>
  z.object({ [key]: z.string(), count } as Record<K | 'count', z.ZodType>);

export const BaselineSummarySchema = z.object({
  version: z.string(),
  mature: z.boolean(),
  eventCount: count,
  activeDays: count,
  windowStart: nullableInstant,
  windowEnd: nullableInstant,
  rebuiltAt: nullableInstant,
  timeZone: z.string(),
  prefixes: z.array(counted('prefix')),
  countries: z.array(counted('countryCode')),
  asns: z.array(z.object({ asn: count, count })),
  devices: z.array(counted('deviceHash')),
  channels: z.array(z.string()),
  /** Authentications per local hour (24 values). */
  hourHistogram: z.array(count),
  /** Outbound messages per local hour (24 values). */
  messageHourHistogram: z.array(count),
  volume: z.object({
    medianDailyMessages: count,
    maxDailyMessages: count,
    medianDailyRecipients: count,
    maxHourlyMessages: count,
  }),
});

export const TrustedContextSchema = z.object({
  id: PublicIdSchema,
  kind: z.enum(['ip_cidr', 'asn', 'country', 'device']),
  value: z.string(),
  reason: z.string(),
  source: z.enum(['analyst', 'false_positive_feedback']),
  incidentId: PublicIdSchema.nullable(),
  createdAt: isoInstant,
  expiresAt: isoInstant,
});

export const AccountDetailSchema = AccountSummarySchema.extend({
  rowVersion: z.number().int().min(1),
  explanation: z.object({
    /** One-line summary (rule titles and contributions). */
    text: z.string().nullable(),
    /** The stored `ato-score/1` explanation (contributions, groups, gates, override). */
    structured: z.unknown().nullable(),
  }),
  overrideDetail: z
    .object({
      id: PublicIdSchema,
      verdict: z.enum(['benign', 'compromised']),
      reason: z.string(),
      expiresAt: isoInstant,
      createdAt: isoInstant,
      contradictedAt: nullableInstant,
    })
    .nullable(),
  protection: z.object({
    protected: z.boolean(),
    reason: z.string().nullable(),
    at: nullableInstant,
  }),
  restrictions: z.array(RestrictionSchema),
  baseline: BaselineSummarySchema.nullable(),
  trustedContexts: z.array(TrustedContextSchema),
  linkedAccounts: z.array(z.object({ id: PublicIdSchema, kind, riskLevel: level })),
  identities: z.array(
    z.object({
      provider: z.string(),
      userPrincipalName: z.string().nullable(),
      firstSeenAt: isoInstant,
      lastSeenAt: isoInstant,
      /** Step 8.5: the identity-provider integration that resolved the identity. */
      integrationId: PublicIdSchema.nullable(),
      directoryStatus: z.enum(['unknown', 'active', 'suspended', 'deleted']),
    }),
  ),
  capabilities: CapabilitiesSchema,
});
export type AccountDetailView = z.infer<typeof AccountDetailSchema>;

export const SignalSchema = z.object({
  id: z.string(),
  ruleCode: z.string(),
  title: z.string(),
  category: z.enum(SIGNAL_CATEGORIES),
  strength: z.enum(SIGNAL_STRENGTHS),
  weight: count,
  status: z.enum(SIGNAL_STATUSES),
  occurrences: count,
  detectedAt: isoInstant,
  firstOccurredAt: isoInstant,
  lastOccurredAt: isoInstant,
  explanation: z.string(),
  /** Allow-listed rule evidence (codes, counts, prefixes, countries; never a secret or content). */
  evidence: z.record(z.string(), z.unknown()),
  sourceKind: z.string(),
  incidentId: PublicIdSchema.nullable(),
  rulesVersion: z.string(),
  dismissedAt: nullableInstant,
  dismissReason: z.string().nullable(),
});
export type SignalView = z.infer<typeof SignalSchema>;

export const AuthEventSchema = z.object({
  id: z.string(),
  occurredAt: isoInstant,
  lastOccurredAt: isoInstant,
  source: z.enum(AUTH_SOURCES),
  channel: z.enum(['portal', 'api', 'smtp', 'idp']),
  outcome: z.enum(AUTH_OUTCOMES),
  failureCode: z.string().nullable(),
  ipAddress: z.string().nullable(),
  ipPrefix: z.string().nullable(),
  geo: z.object({
    status: z.enum(['located', 'not_found', 'private', 'unavailable', 'stale']),
    countryCode: z.string().nullable(),
    region: z.string().nullable(),
    city: z.string().nullable(),
    latitude: z.number().nullable(),
    longitude: z.number().nullable(),
    accuracyKm: z.number().nullable(),
  }),
  asn: z.number().int().nullable(),
  asnOrg: z.string().nullable(),
  anonymizerFlags: z.number().int().nullable(),
  reputation: z.unknown().nullable(),
  device: z.object({ hash: z.string(), label: z.string().nullable() }).nullable(),
  mechanism: z.string().nullable(),
  attemptCount: count,
});
export type AuthEventView = z.infer<typeof AuthEventSchema>;

export const ScorePointSchema = z.object({
  id: z.string(),
  computedAt: isoInstant,
  score,
  level,
  previousScore: score,
  previousLevel: level,
  trigger: z.enum(['signal', 'decay', 'override', 'dismissal', 'settings', 'feedback']),
  explanation: z.unknown(),
  scorerVersion: z.string(),
  rulesVersion: z.string(),
  settingsVersion: count,
});
export type ScorePointView = z.infer<typeof ScorePointSchema>;

export const ActivityDaySchema = z.object({
  day: isoInstant,
  authSuccess: count,
  authFailure: count,
  messages: count,
  recipients: count,
  externalRecipients: count,
  internalRecipients: count,
  attachments: count,
  findings: count,
  maxHourMessages: count,
  /** Top recipient domains of the day (domains only, never an address). */
  topRecipientDomains: z.array(z.object({ domain: z.string(), count })),
  content: z.record(z.string(), z.unknown()),
});
export const ActivitySchema = z.object({
  account: PublicIdSchema,
  from: isoInstant,
  to: isoInstant,
  days: z.array(ActivityDaySchema),
});
export type ActivityView = z.infer<typeof ActivitySchema>;

const pageOf = <T extends z.ZodType>(item: T) =>
  z.object({ data: z.array(item), nextCursor: z.string().nullable() });

export const AccountPageSchema = pageOf(AccountSummarySchema);
export const SignalPageSchema = pageOf(SignalSchema);
export const AuthEventPageSchema = pageOf(AuthEventSchema);
export const ScorePageSchema = pageOf(ScorePointSchema);
export const RestrictionPageSchema = pageOf(RestrictionSchema);
export type AccountPage = z.infer<typeof AccountPageSchema>;
export type SignalPage = z.infer<typeof SignalPageSchema>;
export type AuthEventPage = z.infer<typeof AuthEventPageSchema>;
export type ScorePage = z.infer<typeof ScorePageSchema>;
export type RestrictionPage = z.infer<typeof RestrictionPageSchema>;

// ---------------------------------------------------------------- responses (actions)

export const ResponseAttemptSchema = z.object({
  phase: z.enum(['authorize', 'execute', 'confirm', 'rollback']),
  attemptNo: count,
  outcome: z.enum(['succeeded', 'pending', 'failed', 'unsupported', 'retry_scheduled', 'skipped']),
  providerStatus: z.string().nullable(),
  errorCode: z.string().nullable(),
  durationMs: count,
  at: isoInstant,
});

export const ResponseActionSchema = z.object({
  id: PublicIdSchema,
  actionType: z.enum(RESPONSE_ACTION_TYPES),
  provider: z.string(),
  impact: z.enum(RESPONSE_IMPACTS),
  status: z.enum(RESPONSE_STATUSES),
  requiresApproval: z.boolean(),
  authorization: z.enum(['manual', 'automation_policy', 'low_impact_default']),
  incidentId: PublicIdSchema.nullable(),
  account: z.object({ id: PublicIdSchema, kind }),
  target: z.object({
    scope: z.enum(['mailbox', 'connector', 'connector_ip', 'account']),
    connectorId: PublicIdSchema.nullable(),
    cidr: z.string().nullable(),
  }),
  params: z.object({
    durationMinutes: count.nullable(),
    mode: z.enum(['reject', 'defer']).nullable(),
    description: z.string().nullable(),
  }),
  requestedBy: z.object({
    type: z.enum(['system', 'user', 'api_key']),
    id: z.string().nullable(),
  }),
  requestReason: z.string().nullable(),
  approvedBy: PublicIdSchema.nullable(),
  decidedAt: nullableInstant,
  decisionReason: z.string().nullable(),
  approvalExpiresAt: nullableInstant,
  executedAt: nullableInstant,
  completedAt: nullableInstant,
  effectiveUntil: nullableInstant,
  providerReference: z.string().nullable(),
  providerStatus: z
    .enum(['applied', 'confirmed', 'pending', 'unconfirmed', 'unsupported', 'failed'])
    .nullable(),
  resultCode: z.string().nullable(),
  attemptCount: count,
  rollbackReason: z.string().nullable(),
  /** The caller may approve/reject (pending, not the requester, user with MFA). */
  canDecide: z.boolean(),
  /** The type supports a rollback and the action succeeded. */
  canRollback: z.boolean(),
  createdAt: isoInstant,
  updatedAt: isoInstant,
});
export type ResponseActionView = z.infer<typeof ResponseActionSchema>;

export const ResponseDetailSchema = ResponseActionSchema.extend({
  attempts: z.array(ResponseAttemptSchema),
  restriction: RestrictionSchema.nullable(),
});
export type ResponseDetailView = z.infer<typeof ResponseDetailSchema>;
export const ResponsePageSchema = pageOf(ResponseActionSchema);
export type ResponsePage = z.infer<typeof ResponsePageSchema>;

// ---------------------------------------------------------------- overview and attention

const bySeverity = z.object({ low: count, medium: count, high: count, critical: count });

export const AttentionSchema = z.object({
  criticalIncidents: count,
  pendingApprovals: count,
});
export type AttentionView = z.infer<typeof AttentionSchema>;

export const OVERVIEW_RANGES = ['24h', '7d', '30d'] as const;
export type OverviewRange = (typeof OVERVIEW_RANGES)[number];

export const OverviewSchema = z.object({
  generatedAt: isoInstant,
  range: z.enum(OVERVIEW_RANGES),
  from: isoInstant,
  to: isoInstant,
  monitoring: z.object({
    featureEnabled: z.boolean(),
    mode: z.enum(['monitor', 'enforce', 'off']),
    learning: z.boolean(),
    learningEndsAt: nullableInstant,
  }),
  accounts: z.object({
    monitored: count,
    byKind: z.object({ mailbox: count, gateway_user: count, smtp_connector: count }),
    highRisk: count,
    criticalRisk: count,
  }),
  incidents: z.object({
    active: count,
    activeBySeverity: bySeverity,
    critical: count,
    openedInRange: count,
    trend: z.array(
      z.object({
        bucketStart: isoInstant,
        low: count,
        medium: count,
        high: count,
        critical: count,
      }),
    ),
    resolvedInRange: z.object({ remediated: count, falsePositive: count, other: count }),
  }),
  logins: z.object({ failedInRange: count, suspiciousInRange: count }),
  outbound: z.object({
    suspiciousInRange: count,
    restrictedAccounts: count,
    policyHeldInRange: count,
  }),
  geography: z.object({
    available: z.boolean(),
    reason: z.enum(['geoip_unavailable', 'capabilities_unknown']).nullable(),
    topCountries: z.array(
      z.object({ countryCode: z.string(), successfulAuth: count, newCountrySignals: count }),
    ),
    impossibleTravelInRange: count,
  }),
  responses: z.object({
    pendingApproval: count,
    executedInRange: count,
    failedInRange: count,
  }),
  attention: AttentionSchema,
});
export type OverviewView = z.infer<typeof OverviewSchema>;

export const OverviewQuerySchema = z.strictObject({
  range: z.enum(OVERVIEW_RANGES).default('7d'),
});
export type OverviewQuery = z.infer<typeof OverviewQuerySchema>;

// ---------------------------------------------------------------- settings and rules

export const SettingsViewSchema = z.object({
  featureEnabled: z.boolean(),
  /** Version of the stored settings (0 when none exist yet). */
  version: count,
  /** Send with PUT as `expectedRowVersion` (0 when none exist yet). */
  rowVersion: count,
  schemaVersion: z.literal('ato-settings/1'),
  /** The tenant's explicit values (`{}` = defaults only). */
  stored: z.record(z.string(), z.unknown()),
  /** Every value with its effective setting (stored over the defaults). */
  effective: z.record(z.string(), z.unknown()),
  /** The stored document did not validate (it is ignored: defaults apply). */
  storedInvalid: z.boolean(),
  learning: z.object({ active: z.boolean(), startedAt: nullableInstant, endsAt: nullableInstant }),
  bounds: z.record(z.string(), z.unknown()),
  capabilities: CapabilitiesSchema,
  sources: z.array(
    z.object({
      source: z.enum([
        'portal_login',
        'account_change',
        'smtp_auth',
        'smtp_submission',
        'outbound_message',
      ]),
      lastEventAt: nullableInstant,
    }),
  ),
  /** Step 8.5: the non-disabled identity-provider integrations of each provider. */
  identityProviders: z.array(
    z.object({
      provider: z.enum(['microsoft_entra', 'google_workspace']),
      integrations: z.array(
        z.object({
          id: PublicIdSchema,
          provider: z.enum(['microsoft_entra', 'google_workspace']),
          health: z.enum(['unknown', 'healthy', 'degraded', 'unhealthy']),
        }),
      ),
    }),
  ),
  policy: z.object({ atoFieldsInUse: z.boolean() }),
  automation: z.object({
    platformEnabled: z.boolean(),
    platformMaxPerHour: count,
    approvalTtlHours: count,
    maxActiveRestrictions: count,
  }),
  updatedAt: nullableInstant,
});
export type SettingsView = z.infer<typeof SettingsViewSchema>;

/**
 * `PUT /ato/settings` envelope: the settings document is validated by the ATO store with
 * `atoSettingsSchema` (`400 ato_settings_invalid` with paths), the version by CAS.
 */
export const UpdateSettingsBodySchema = z.strictObject({
  expectedRowVersion: z.number().int().min(0),
  settings: z.record(z.string(), z.unknown()),
});
export type UpdateSettingsBody = z.infer<typeof UpdateSettingsBodySchema>;

export const RuleViewSchema = z.object({
  id: z.string(),
  code: z.string(),
  title: z.string(),
  category: z.enum(SIGNAL_CATEGORIES),
  strength: z.enum(SIGNAL_STRENGTHS),
  kinds: z.array(kind),
  sources: z.array(z.string()),
  correlation: z.boolean(),
  baselineRelative: z.boolean(),
  defaultWeight: count,
  effective: z.object({
    enabled: z.boolean(),
    weight: count,
    params: z.record(z.string(), z.number()),
  }),
  params: z.array(
    z.object({ name: z.string(), default: z.number(), min: z.number(), max: z.number() }),
  ),
  capabilities: z.array(z.string()),
  availability: z.object({
    available: z.boolean(),
    reason: z.enum(['capability_unavailable', 'capabilities_unknown']).nullable(),
    missing: z.array(z.string()),
  }),
  explanation: z.string(),
});
export const RulesViewSchema = z.object({
  rulesVersion: z.string(),
  capabilities: CapabilitiesSchema,
  data: z.array(RuleViewSchema),
});
export type RulesView = z.infer<typeof RulesViewSchema>;

// ---------------------------------------------------------------- request bodies

export const UpdateAccountBodySchema = z.strictObject({
  protected: z.boolean(),
  reason: reasonText(1, 512).nullable().optional(),
  expectedRowVersion: z.number().int().min(1),
});
export type UpdateAccountBody = z.infer<typeof UpdateAccountBodySchema>;

export const SetOverrideBodySchema = z.strictObject({
  verdict: z.enum(['benign', 'compromised']),
  reason: reasonText(10, 1000),
  expiresInHours: z.number().int().min(1).max(720),
});
export type SetOverrideBody = z.infer<typeof SetOverrideBodySchema>;

export const ClearOverrideBodySchema = z.strictObject({ reason: reasonText(10, 1000) });
export type ClearOverrideBody = z.infer<typeof ClearOverrideBodySchema>;

export const AddTrustedContextBodySchema = z.strictObject({
  kind: z.enum(['ip_cidr', 'asn', 'country', 'device']),
  value: text(1, 64),
  reason: reasonText(1, 512),
  expiresInDays: z.number().int().min(1).max(365),
});
export type AddTrustedContextBody = z.infer<typeof AddTrustedContextBodySchema>;

export const RequestResponseBodySchema = z.strictObject({
  actionType: z.enum(RESPONSE_ACTION_TYPES),
  /** Target scope (default: `mailbox` for a mailbox restriction, `connector` for a connector,
   * `account` otherwise); `connectorId` (public id) and `cidr` for connector scopes. */
  target: z
    .strictObject({
      scope: z.enum(['mailbox', 'connector', 'connector_ip', 'account']),
      connectorId: PublicIdSchema.optional(),
      cidr: text(3, 49).optional(),
    })
    .optional(),
  durationMinutes: z.number().int().min(15).max(10_080).optional(),
  mode: z.enum(['reject', 'defer']).optional(),
  reason: reasonText(10, 1000),
  /** What the analyst did elsewhere (`record_manual_action` only). */
  description: reasonText(10, 1000).optional(),
  /**
   * Step 8.5 (D9.7, D9.8): parameters of identity-provider actions. `remove_forwarding_rule`
   * takes the public id of one present mailbox item of the account (`itemId`, from
   * `GET /ato/accounts/{id}/mailbox-state`) or `scope: 'all_external'` (the default when absent);
   * `revoke_oauth_grant` requires the `appIdHash` of a consent signal's evidence.
   */
  params: z
    .strictObject({
      itemId: PublicIdSchema.optional(),
      scope: z.literal('all_external').optional(),
      appIdHash: z
        .string()
        .regex(/^[0-9a-f]{64}$/, 'must be 64 lower-case hex characters')
        .optional(),
    })
    .optional(),
});
export type RequestResponseBody = z.infer<typeof RequestResponseBodySchema>;

export const ApproveBodySchema = z.strictObject({ reason: reasonText(1, 1000).optional() });
export type ApproveBody = z.infer<typeof ApproveBodySchema>;
export const ReasonBodySchema = z.strictObject({ reason: reasonText(10, 1000) });
export type ReasonBody = z.infer<typeof ReasonBodySchema>;
export const CancelBodySchema = z.strictObject({ reason: reasonText(1, 1000).optional() });
export type CancelBody = z.infer<typeof CancelBodySchema>;

// ---------------------------------------------------------------- list queries

export const AccountListQuerySchema = defineListQuery({
  filters: {
    kind: { type: 'enum', values: ATO_ACCOUNT_KINDS, maxValues: 3 },
    level: { type: 'enum', values: ATO_RISK_LEVELS, maxValues: 4 },
    minScore: { type: 'int', min: 0, max: 100 },
    hasActiveIncident: { type: 'bool' },
    protected: { type: 'bool' },
    domainId: { type: 'publicId' },
    q: { type: 'string', maxLength: 320 },
  },
  sorts: ['-riskScore', '-lastSignalAt', 'address'],
  defaultSort: '-riskScore',
});
export type AccountListQuery = z.output<typeof AccountListQuerySchema>;

export const SignalListQuerySchema = defineListQuery({
  filters: {
    category: { type: 'enum', values: SIGNAL_CATEGORIES, maxValues: 11 },
    status: { type: 'enum', values: SIGNAL_STATUSES, maxValues: 3 },
    strength: { type: 'enum', values: SIGNAL_STRENGTHS, maxValues: 3 },
  },
  sorts: ['-detectedAt'],
  defaultSort: '-detectedAt',
  range: true,
});
export type SignalListQuery = z.output<typeof SignalListQuerySchema>;

export const AuthEventListQuerySchema = defineListQuery({
  filters: {
    outcome: { type: 'enum', values: AUTH_OUTCOMES, maxValues: 8 },
    source: { type: 'enum', values: AUTH_SOURCES, maxValues: 4 },
    ip: { type: 'string', maxLength: 45 },
    country: { type: 'string', maxLength: 2 },
  },
  sorts: ['-occurredAt'],
  defaultSort: '-occurredAt',
  range: true,
});
export type AuthEventListQuery = z.output<typeof AuthEventListQuerySchema>;

export const ScoreHistoryQuerySchema = defineListQuery({
  filters: {},
  sorts: ['-computedAt'],
  defaultSort: '-computedAt',
  range: true,
});
export type ScoreHistoryQuery = z.output<typeof ScoreHistoryQuerySchema>;

export const ActivityQuerySchema = z.strictObject({
  from: isoInstant.transform((v) => new Date(v)).optional(),
  to: isoInstant.transform((v) => new Date(v)).optional(),
});
export type ActivityQuery = z.output<typeof ActivityQuerySchema>;

export const IncidentEvidenceQuerySchema = defineListQuery({
  filters: {},
  sorts: ['-at'],
  defaultSort: '-at',
});
export type IncidentEvidenceQuery = z.output<typeof IncidentEvidenceQuerySchema>;

export const ResponseListQuerySchema = defineListQuery({
  filters: {
    status: { type: 'enum', values: RESPONSE_STATUSES, maxValues: 13 },
    actionType: { type: 'enum', values: RESPONSE_ACTION_TYPES, maxValues: 12 },
    incidentId: { type: 'publicId' },
    accountId: { type: 'publicId' },
  },
  sorts: ['-createdAt'],
  defaultSort: '-createdAt',
});
export type ResponseListQuery = z.output<typeof ResponseListQuerySchema>;

export const RestrictionListQuerySchema = defineListQuery({
  filters: {
    status: { type: 'enum', values: ['active', 'lifted', 'expired'], maxValues: 3 },
    kind: { type: 'enum', values: ['send_block', 'auth_block'], maxValues: 2 },
    scope: { type: 'enum', values: ['mailbox', 'connector', 'connector_ip'], maxValues: 3 },
  },
  sorts: ['-createdAt'],
  defaultSort: '-createdAt',
});
export type RestrictionListQuery = z.output<typeof RestrictionListQuerySchema>;

export const PAGE_PARAMETERS: Record<string, string> = {
  limit: 'Page size, 1-100 (default 25)',
  cursor: '`nextCursor` of the previous page',
};
