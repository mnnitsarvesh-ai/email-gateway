import { applyDecorators } from '@nestjs/common';
import { ApiParam, ApiResponse } from '@nestjs/swagger';
import { idpBindingSettingsSchema } from '@email-gateway/idp-adapters';
import type { z } from 'zod';
import { ApiCodedError } from '../../http/coded-exception';
import { IDEMPOTENCY_REPLAYED_HEADER } from '../../http/idempotency/idempotency-key';
import { zodToOpenApi } from '../../validation/zod-openapi';
import { ATO_ERROR_CODES as C } from './ato.errors';
import { ATO_EXAMPLE_IDS } from './dto/ato.examples';
import type {
  BackfillBody,
  CreateProviderBody,
  MailboxRefreshView,
  MailboxStateView,
  ProviderConnectionsView,
  ProviderDetailView,
  ProviderHealthCheckView,
  ProviderListView,
  ProviderReasonBody,
  ProviderSummaryView,
  UpdateProviderBody,
} from './dto/ato-providers.schemas';
import { requirementsView } from './mappers/ato-providers.mapper';

/**
 * OpenAPI decorators and examples of the step 8.5 identity-provider routes (design note §6;
 * conventions of 6.1 D14 and 8.4 D17). Identifiers are well-formed placeholders, display names
 * and domains carry `EXAMPLE` or reserved example domains, permission names are the documented
 * provider names; no token, credential, address or secret-shaped value appears.
 */

const ID = {
  integration: '0193b0a0-aaaa-7a00-8000-000000000001',
  connection: '0193b0a0-bbbb-7a00-8000-000000000001',
  connection2: '0193b0a0-bbbb-7a00-8000-000000000002',
  grant: '0193b0a0-cccc-7a00-8000-000000000001',
  item: '0193b0a0-dddd-7a00-8000-000000000001',
  item2: '0193b0a0-dddd-7a00-8000-000000000002',
} as const;
export const ATO_PROVIDER_EXAMPLE_IDS = ID;

const settings = {
  streams: {
    sign_ins: { enabled: true },
    risk_events: { enabled: true },
    session_events: { enabled: true },
    oauth_consents: { enabled: true },
    mailbox_audit: { enabled: true },
    forwarding_changes: { enabled: true },
    delegation_changes: { enabled: true },
  },
  pollIntervalSeconds: 300,
  backfillDays: 7,
  snapshot: { sweepIntervalHours: null },
  actions: {
    revoke_sessions: { enabled: true },
    require_mfa: { enabled: true },
    require_password_reset: { enabled: true },
    suspend_account: { enabled: true },
    remove_forwarding_rule: { enabled: true },
    revoke_oauth_grant: { enabled: false },
  },
  mfaEnforcement: { groupId: '11111111-2222-4333-8444-555555555555', orgUnitPath: null },
  forwardingRemoval: { mode: 'disable' },
};

const summary: ProviderSummaryView = {
  id: ID.integration,
  provider: 'microsoft_entra',
  displayName: 'EXAMPLE Contoso Microsoft 365',
  status: 'active',
  pausedReason: null,
  disabledReason: null,
  disabledAt: null,
  connection: {
    id: ID.connection,
    provider: 'microsoft_365',
    displayName: 'EXAMPLE Contoso Microsoft 365',
    status: 'active',
  },
  health: { status: 'healthy', checkedAt: '2026-11-20T08:45:00.000Z', stale: false },
  streams: { enabled: 4, available: 4, failing: 0, backfilling: 0, maxLagSeconds: 420 },
  capabilities: {
    streams: [
      'sign_ins',
      'risk_events',
      'oauth_consents',
      'mailbox_audit',
      'forwarding_changes',
      'delegation_changes',
      'session_events',
    ],
    actions: [
      'revoke_sessions',
      'require_password_reset',
      'suspend_account',
      'remove_forwarding_rule',
    ],
  },
  createdAt: '2026-11-19T10:00:00.000Z',
  updatedAt: '2026-11-20T08:45:00.000Z',
};

const telemetryProfile = {
  profile: 'm365.ato_telemetry',
  purpose: 'ato_telemetry' as const,
  title: 'Account takeover telemetry (read-only)',
  readOnly: true,
  required: [
    'AuditLog.Read.All',
    'Directory.Read.All',
    'IdentityRiskEvent.Read.All',
    'User.Read.All',
    'MailboxSettings.Read',
    'ActivityFeed.Read',
  ],
  notObservable: ['ActivityFeed.Read'],
  grant: {
    id: ID.grant,
    status: 'active' as const,
    observed: [
      'AuditLog.Read.All',
      'Directory.Read.All',
      'IdentityRiskEvent.Read.All',
      'User.Read.All',
      'MailboxSettings.Read',
    ],
    missing: [],
    excess: [],
  },
};

const stream = (
  name: ProviderDetailView['streamDetails'][number]['stream'],
  role: 'primary' | 'companion',
  primary: ProviderDetailView['streamDetails'][number]['stream'] | null,
): ProviderDetailView['streamDetails'][number] => ({
  stream: name,
  role,
  primary,
  enabled: true,
  status: 'active',
  availability: 'available',
  availabilityCode: null,
  capability: 'available',
  watermarkAt: role === 'primary' ? '2026-11-20T08:38:00.000Z' : null,
  lagSeconds: role === 'primary' ? 420 : null,
  nextPollAt: role === 'primary' ? '2026-11-20T08:50:00.000Z' : null,
  lastAttemptAt: role === 'primary' ? '2026-11-20T08:45:00.000Z' : null,
  lastSuccessAt: role === 'primary' ? '2026-11-20T08:45:00.000Z' : null,
  lastEventAt: role === 'primary' ? '2026-11-20T08:31:12.000Z' : null,
  lastErrorCode: null,
  consecutiveFailures: 0,
  throttledUntil: null,
  backfill: {
    active: false,
    from: role === 'primary' ? '2026-11-12T10:00:00.000Z' : null,
    requestedAt: role === 'primary' ? '2026-11-19T10:00:00.000Z' : null,
    completedAt: role === 'primary' ? '2026-11-19T10:20:00.000Z' : null,
  },
  eventsTotal: role === 'primary' ? 18_250 : 0,
  pagesTotal: role === 'primary' ? 412 : 0,
});

const detail: ProviderDetailView = {
  ...summary,
  rowVersion: 3,
  settingsVersion: 2,
  settingsSchema: 'ato-idp-binding/1',
  settings,
  settingsInvalid: false,
  healthDetail: {
    status: 'healthy',
    checkedAt: '2026-11-20T08:45:00.000Z',
    nextCheckAt: '2026-11-20T09:00:00.000Z',
    stale: false,
    ok: true,
    code: null,
    grants: [
      { profile: 'm365.ato_telemetry', status: 'active', missingPermissions: [] },
      { profile: 'm365.ato_response', status: 'active', missingPermissions: [] },
      { profile: 'm365.ato_response_extended', status: 'absent', missingPermissions: [] },
    ],
  },
  streamDetails: [
    stream('sign_ins', 'primary', null),
    stream('risk_events', 'primary', null),
    stream('oauth_consents', 'primary', null),
    stream('mailbox_audit', 'primary', null),
    stream('forwarding_changes', 'companion', 'mailbox_audit'),
    stream('delegation_changes', 'companion', 'mailbox_audit'),
    stream('session_events', 'companion', 'risk_events'),
  ],
  actions: [
    {
      action: 'revoke_sessions',
      enabled: true,
      capability: 'available',
      code: null,
      rollback: false,
      confirmation: 'synchronous',
      requiresConfiguration: null,
    },
    {
      action: 'require_mfa',
      enabled: true,
      capability: 'missing_permission',
      code: 'grant_missing',
      rollback: true,
      confirmation: 'polling',
      requiresConfiguration: 'mfaEnforcement.groupId',
    },
    {
      action: 'require_password_reset',
      enabled: true,
      capability: 'available',
      code: null,
      rollback: false,
      confirmation: 'synchronous',
      requiresConfiguration: null,
    },
    {
      action: 'suspend_account',
      enabled: true,
      capability: 'available',
      code: null,
      rollback: true,
      confirmation: 'polling',
      requiresConfiguration: null,
    },
    {
      action: 'remove_forwarding_rule',
      enabled: true,
      capability: 'available',
      code: null,
      rollback: true,
      confirmation: 'polling',
      requiresConfiguration: null,
    },
    {
      action: 'revoke_oauth_grant',
      enabled: false,
      capability: 'disabled',
      code: null,
      rollback: false,
      confirmation: 'synchronous',
      requiresConfiguration: null,
    },
  ],
  permissions: {
    granted: [...telemetryProfile.grant.observed].sort(),
    profiles: [telemetryProfile],
  },
  directory: { domainCount: 2 },
};

const list: ProviderListView = {
  featureEnabled: true,
  limit: { max: 5, used: 1 },
  data: [summary],
};

const connections: ProviderConnectionsView = {
  featureEnabled: true,
  limit: { max: 5, used: 1 },
  data: [
    {
      id: ID.connection,
      provider: 'microsoft_365',
      kind: 'microsoft_entra',
      displayName: 'EXAMPLE Contoso Microsoft 365',
      status: 'active',
      eligibility: 'already_bound',
      reasons: ['already_bound'],
      integrationId: ID.integration,
      providerVerifiedDomainCount: 2,
      profiles: [telemetryProfile],
    },
    {
      id: ID.connection2,
      provider: 'google_workspace',
      kind: 'google_workspace',
      displayName: 'EXAMPLE Fabrikam Google Workspace',
      status: 'active',
      eligibility: 'inactive',
      reasons: ['telemetry_grant_missing'],
      integrationId: null,
      providerVerifiedDomainCount: 1,
      profiles: [],
    },
  ],
};

const healthCheck: ProviderHealthCheckView = {
  id: ID.integration,
  status: 'active',
  health: { status: 'degraded', checkedAt: '2026-11-20T08:45:00.000Z', stale: false },
  requestedAt: '2026-11-20T08:52:10.000Z',
};

const mailboxState: MailboxStateView = {
  accountId: ATO_EXAMPLE_IDS.account,
  items: [
    {
      id: ID.item,
      kind: 'inbox_rule',
      state: 'present',
      targetDomain: 'external-example.net',
      traits: ['forwards', 'forwards_external', 'matches_finance_keywords', 'marks_read'],
      enabled: true,
      source: 'snapshot',
      lastChange: 'added',
      provider: 'microsoft_entra',
      integrationId: ID.integration,
      firstSeenAt: '2026-11-20T07:12:00.000Z',
      lastSeenAt: '2026-11-20T08:45:00.000Z',
      removedAt: null,
    },
    {
      id: ID.item2,
      kind: 'forwarding',
      state: 'removed',
      targetDomain: 'external-example.net',
      traits: ['forwards_external'],
      enabled: false,
      source: 'audit',
      lastChange: 'removed',
      provider: 'microsoft_entra',
      integrationId: ID.integration,
      firstSeenAt: '2026-11-10T09:00:00.000Z',
      lastSeenAt: '2026-11-18T09:00:00.000Z',
      removedAt: '2026-11-18T09:00:00.000Z',
    },
  ],
  truncated: false,
  identities: [
    {
      provider: 'microsoft_entra',
      integrationId: ID.integration,
      userPrincipalName: 'jane.doe@corp.example',
      directoryStatus: 'active',
      directoryStatusAt: '2026-11-20T08:45:00.000Z',
      refreshRequestedAt: null,
      refreshSupported: true,
    },
  ],
  integrations: [
    {
      id: ID.integration,
      provider: 'microsoft_entra',
      displayName: 'EXAMPLE Contoso Microsoft 365',
      status: 'active',
      lastSweepAt: '2026-11-20T08:45:00.000Z',
    },
  ],
  refreshRequestedAt: null,
};

const mailboxRefresh: MailboxRefreshView = {
  accountId: ATO_EXAMPLE_IDS.account,
  requestedAt: '2026-11-20T08:52:10.000Z',
  identities: 1,
  integrationIds: [ID.integration],
};

const createBody: CreateProviderBody = { connectionId: ID.connection, settings };
const updateBody: UpdateProviderBody = {
  rowVersion: 3,
  settings: { ...settings, pollIntervalSeconds: 600 },
};
const pauseBody: ProviderReasonBody = { reason: 'Planned maintenance of the EXAMPLE tenant' };
const removeBody: ProviderReasonBody = { reason: 'Customer moved to another directory' };
const backfillBody: BackfillBody = {
  from: '2026-11-13T00:00:00.000Z',
  streams: ['sign_ins', 'risk_events'],
};

export const ATO_PROVIDER_EXAMPLES = {
  list,
  requirements: requirementsView(),
  connections,
  detail,
  healthCheck,
  mailboxState,
  mailboxRefresh,
  createBody,
  updateBody,
  pauseBody,
  removeBody,
  backfillBody,
  emptyBody: {},
} as const;

/** The OpenAPI schema of the binding settings (`ato-idp-binding/1`, strict). */
export const BINDING_SETTINGS_DOC = {
  ...zodToOpenApi(idpBindingSettingsSchema, { io: 'input' }),
  description:
    '`ato-idp-binding/1` (strict, every field required): per-stream and per-action `enabled`, ' +
    '`pollIntervalSeconds` (60–3600), `backfillDays` (0–30, ≤ ATO_IDP_BACKFILL_MAX_DAYS), ' +
    '`snapshot.sweepIntervalHours` (6–168 or null = provider default), `mfaEnforcement` ' +
    '(`groupId` for Microsoft, `orgUnitPath` for Google) and `forwardingRemoval.mode`. A ' +
    'companion stream may be enabled only with its primary. `400 ato_provider_settings_invalid` ' +
    'lists the failing paths.',
};

/** A request body schema whose `settings` property documents `ato-idp-binding/1`. */
export function withSettingsDoc(schema: z.ZodType): Record<string, unknown> {
  const envelope = zodToOpenApi(schema, { io: 'input' }) as {
    properties?: Record<string, unknown>;
  };
  return {
    ...envelope,
    properties: { ...(envelope.properties ?? {}), settings: BINDING_SETTINGS_DOC },
  };
}

const REPLAYED_HEADER = {
  [IDEMPOTENCY_REPLAYED_HEADER]: {
    description: '`true` when this is the stored response of an earlier identical request',
    schema: { type: 'string', enum: ['true'] },
  },
};

/** A 2xx (incl. `202`) with the zod-derived schema and an example (replay header when keyed). */
export const ApiProviderResponse = (
  status: 200 | 201 | 202,
  schema: z.ZodType,
  example: unknown,
  description: string,
  keyed = false,
): MethodDecorator =>
  ApiResponse({
    status,
    description,
    schema: { ...zodToOpenApi(schema), example },
    ...(keyed && { headers: REPLAYED_HEADER }),
  });

export const ApiIntegrationIdParam = (): MethodDecorator =>
  ApiParam({
    name: 'integrationId',
    description: 'Identity-provider integration public id (UUID)',
    format: 'uuid',
  });

export const ApiProviderNotFound = (): MethodDecorator =>
  ApiCodedError(
    404,
    'Unknown integration, one of another organization, or ATO is not enabled ' +
      '(`ato_provider_not_found`)',
    [C.providerNotFound],
  );

/** `404` of a body-referenced connection (create). */
export const ApiProviderConnectionNotFound = (): MethodDecorator =>
  applyDecorators(
    ApiCodedError(404, 'The connection is not one of your organization', [
      C.providerConnectionNotFound,
    ]),
  );

/** The rule of every identity-provider mutation (§6). */
export const PROVIDER_MUTATION_RULE =
  ' Requires the Idempotency-Key header (transactional: the change, its audit row and the ' +
  'stored response commit together); rate class `sensitive`; `403 ato_not_enabled` while ATO ' +
  'is not enabled for the organization.';
