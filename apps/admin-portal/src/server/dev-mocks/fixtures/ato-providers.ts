import 'server-only';
import { defaultBindingSettings } from '@/features/ato/providers/model';
import { REQUIREMENTS } from '@/features/ato/providers/requirements.data';
import { candidate, detail, mailboxItem, profilesOf } from '@/features/ato/providers/test-data';
import type { SuccessBody } from '@/lib/api/types';
import { fixtureAnchor, stableUuid } from '../generator';
import {
  apiError,
  ok,
  type FixtureHandler,
  type FixtureHandlers,
  type FixtureRequest,
  type FixtureResponse,
} from '../types';
import {
  atoOrgOf,
  bodyOf,
  fixtures as atoFixtures,
  idempotent,
  mfa,
  principalOf,
  viewOf,
  type OrgAto,
} from './ato';
import { fixtureGuard } from './messages';

export { DEV_MOCK_MARKER } from '../types';

/**
 * Dev fixtures of the identity-provider pages (step 8.5 WP6, §6 #1–#13, design P9): the 13
 * operations over an in-memory state per organization, plus three wrappers of the 8.4 fixtures
 * (`GET /ato/settings` lists the integrations; requesting, approving and rolling back a provider
 * response behaves like a connected provider that confirms). Rules kept: permissions, MFA routes
 * (`403 mfa_required`), Idempotency-Key with replays, `rowVersion` CAS (`409
 * ato_provider_conflict`), eligibility and the per-organization limit, companion streams, backfill
 * bounds and `already active`, pause/resume/remove states. One Microsoft integration is seeded;
 * a Google Workspace connection is eligible for the connect dialog. Everything is synthetic.
 */

export const ATO_PROVIDER_OPERATIONS = [
  'AtoProvidersController_list_v1',
  'AtoProvidersController_requirements_v1',
  'AtoProvidersController_connections_v1',
  'AtoProvidersController_create_v1',
  'AtoProvidersController_get_v1',
  'AtoProvidersController_update_v1',
  'AtoProvidersController_pause_v1',
  'AtoProvidersController_resume_v1',
  'AtoProvidersController_healthCheck_v1',
  'AtoProvidersController_backfill_v1',
  'AtoProvidersController_remove_v1',
  'AtoAccountMailboxController_get_v1',
  'AtoAccountMailboxController_refresh_v1',
] as const;

type Detail = SuccessBody<'AtoProvidersController_get_v1'>;
type Candidate = SuccessBody<'AtoProvidersController_connections_v1'>['data'][number];
type MailboxState = SuccessBody<'AtoAccountMailboxController_get_v1'>;
type Item = MailboxState['items'][number];
type Response = SuccessBody<'AtoResponsesController_get_v1'>;

interface OrgProviders {
  integrations: Map<string, Detail>;
  candidates: Candidate[];
  items: Map<string, Item[]>;
  refreshRequestedAt: Map<string, string>;
}

const MAX_INTEGRATIONS = 5;
const PROVIDER_ACTION_TYPES = [
  'revoke_sessions',
  'require_mfa',
  'require_password_reset',
  'suspend_account',
  'remove_forwarding_rule',
  'revoke_oauth_grant',
];
const ROLLBACK_TYPES = ['require_mfa', 'suspend_account', 'remove_forwarding_rule'];
const iso = (ms: number) => new Date(ms).toISOString();

const globalState = globalThis as typeof globalThis & {
  __egDevFixtureAtoProviders?: Map<string, OrgProviders>;
};

function build(organizationId: string, ato: OrgAto): OrgProviders {
  const id = (name: string) => stableUuid(`ato-providers:${organizationId}:${name}`);
  const anchor = fixtureAnchor();
  const integrationId = id('integration:microsoft');
  const microsoftConnection = id('connection:microsoft');
  const seeded = detail({
    id: integrationId,
    connection: {
      id: microsoftConnection,
      provider: 'microsoft_365',
      displayName: 'EXAMPLE Contoso Microsoft 365',
      status: 'active',
    },
    createdAt: iso(anchor - 86_400_000),
    updatedAt: iso(anchor - 300_000),
  });
  const state: OrgProviders = {
    integrations: new Map([[integrationId, seeded]]),
    candidates: [
      candidate({
        id: microsoftConnection,
        displayName: 'EXAMPLE Contoso Microsoft 365',
        eligibility: 'already_bound',
        reasons: ['already_bound'],
        integrationId,
        profiles: profilesOf('microsoft_entra'),
      }),
      candidate({
        id: id('connection:google'),
        provider: 'google_workspace',
        kind: 'google_workspace',
        displayName: 'EXAMPLE Northwind Google Workspace',
        providerVerifiedDomainCount: 1,
        profiles: profilesOf('google_workspace', [], ['google.ato_response_extended']),
      }),
      candidate({
        id: id('connection:inactive'),
        displayName: 'EXAMPLE Fabrikam Microsoft 365 (setup incomplete)',
        status: 'configuring',
        eligibility: 'inactive',
        reasons: ['connection_inactive', 'telemetry_grant_missing'],
        profiles: profilesOf('microsoft_entra', [], ['m365.ato_telemetry']),
      }),
    ],
    items: new Map(),
    refreshRequestedAt: new Map(),
  };
  // Mailbox state of the seeded mailbox accounts (forwarding rules on the first one).
  const mailboxes = [...ato.accounts.values()].filter((a) => a.kind === 'mailbox');
  mailboxes.forEach((account, index) => {
    const items: Item[] =
      index === 0
        ? [
            mailboxItem({ id: id(`item:${account.id}:rule`), integrationId }),
            mailboxItem({
              id: id(`item:${account.id}:forwarding`),
              kind: 'forwarding',
              traits: ['forwards', 'forwards_external'],
              integrationId,
            }),
            mailboxItem({
              id: id(`item:${account.id}:old-rule`),
              state: 'removed',
              lastChange: 'removed',
              removedAt: iso(anchor - 3 * 86_400_000),
              targetDomain: null,
              traits: ['moves_to_rarely_used_folder', 'marks_read'],
              integrationId,
            }),
          ]
        : [];
    state.items.set(account.id, items);
  });
  return state;
}

function orgOf(request: FixtureRequest): OrgProviders {
  globalState.__egDevFixtureAtoProviders ??= new Map();
  const organizationId = principalOf(request).organizationId;
  let org = globalState.__egDevFixtureAtoProviders.get(organizationId);
  if (!org) {
    org = build(organizationId, atoOrgOf(request));
    globalState.__egDevFixtureAtoProviders.set(organizationId, org);
  }
  return org;
}

/** Resets the in-memory identity-provider state (tests). */
export function resetAtoProviderFixtures(): void {
  globalState.__egDevFixtureAtoProviders = new Map();
}

function route(
  handler: (request: FixtureRequest, org: OrgProviders, ato: OrgAto) => FixtureResponse,
): FixtureHandler {
  return (request) => fixtureGuard(request) ?? handler(request, orgOf(request), atoOrgOf(request));
}

const featureOn = (ato: OrgAto) => ato.settings.featureEnabled;
const notFound = () =>
  apiError(404, 'ato_provider_not_found', 'Identity-provider integration not found');
const used = (org: OrgProviders) =>
  [...org.integrations.values()].filter((i) => i.status !== 'disabled').length;

function summaryOf(d: Detail): SuccessBody<'AtoProvidersController_list_v1'>['data'][number] {
  return {
    id: d.id,
    provider: d.provider,
    displayName: d.displayName,
    status: d.status,
    pausedReason: d.pausedReason,
    disabledReason: d.disabledReason,
    disabledAt: d.disabledAt,
    connection: d.connection,
    health: d.health,
    streams: d.streams,
    capabilities: d.capabilities,
    createdAt: d.createdAt,
    updatedAt: d.updatedAt,
  };
}

function integrationOr404(
  org: OrgProviders,
  ato: OrgAto,
  id: string | undefined,
): Detail | FixtureResponse {
  if (!featureOn(ato)) return notFound();
  return (id ? org.integrations.get(id) : undefined) ?? notFound();
}

const isResponse = (v: unknown): v is FixtureResponse =>
  typeof v === 'object' &&
  v !== null &&
  'status' in v &&
  typeof v.status === 'number' &&
  !('provider' in v);

function reasonOf(request: FixtureRequest): string | FixtureResponse {
  const reason =
    typeof bodyOf(request).reason === 'string' ? (bodyOf(request).reason as string).trim() : '';
  return reason.length < 3 || reason.length > 512
    ? apiError(400, 'validation_failed', ['reason: must be 3-512 characters'])
    : reason;
}

function touch(d: Detail): void {
  d.updatedAt = new Date().toISOString();
}

/** Recomputes the summaries the pages read from a detail's stream and action rows. */
function refreshSummary(d: Detail): void {
  const primaries = d.streamDetails.filter((s) => s.role === 'primary' && s.enabled);
  d.streams = {
    enabled: primaries.length,
    available: primaries.filter((s) => s.availability === 'available').length,
    failing: primaries.filter((s) => s.consecutiveFailures > 0).length,
    backfilling: primaries.filter((s) => s.backfill.active).length,
    maxLagSeconds: primaries.reduce<number | null>(
      (max, s) => (s.lagSeconds === null ? max : Math.max(max ?? 0, s.lagSeconds)),
      null,
    ),
  };
  d.capabilities = {
    streams: d.streamDetails
      .filter((s) => s.enabled && s.capability === 'available')
      .map((s) => s.stream),
    actions: d.actions
      .filter((a) => a.enabled && a.capability === 'available')
      .map((a) => a.action),
  };
}

/** Validates settings like the api (D10 shape, bounds, companion rule, provider fields). */
function validateSettings(
  d: Pick<Detail, 'provider' | 'streamDetails'>,
  raw: unknown,
): Array<{ path: string; message: string }> {
  const issues: Array<{ path: string; message: string }> = [];
  const s = raw as ReturnType<typeof defaultBindingSettings> | null;
  if (!s || typeof s !== 'object') return [{ path: '(root)', message: 'invalid_type' }];
  const int = (v: unknown, min: number, max: number) =>
    typeof v === 'number' && Number.isInteger(v) && v >= min && v <= max;
  if (!int(s.pollIntervalSeconds, 60, 3600))
    issues.push({ path: 'pollIntervalSeconds', message: 'too_small' });
  if (!int(s.backfillDays, 0, 30)) issues.push({ path: 'backfillDays', message: 'too_big' });
  if (s.snapshot?.sweepIntervalHours !== null && !int(s.snapshot?.sweepIntervalHours, 6, 168)) {
    issues.push({ path: 'snapshot.sweepIntervalHours', message: 'too_small' });
  }
  for (const stream of d.streamDetails) {
    if (stream.role === 'companion' && stream.primary) {
      if (s.streams?.[stream.stream]?.enabled && !s.streams?.[stream.primary]?.enabled) {
        issues.push({
          path: `streams.${stream.stream}.enabled`,
          message: 'companion_requires_primary',
        });
      }
    }
  }
  const guid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const group = s.mfaEnforcement?.groupId ?? null;
  const ou = s.mfaEnforcement?.orgUnitPath ?? null;
  if (group !== null && (d.provider !== 'microsoft_entra' || !guid.test(group))) {
    issues.push({
      path: 'mfaEnforcement.groupId',
      message: d.provider === 'microsoft_entra' ? 'invalid_format' : 'not_for_provider',
    });
  }
  if (ou !== null && (d.provider !== 'google_workspace' || !ou.startsWith('/'))) {
    issues.push({
      path: 'mfaEnforcement.orgUnitPath',
      message: d.provider === 'google_workspace' ? 'invalid_format' : 'not_for_provider',
    });
  }
  return issues;
}

/** Applies settings to the stream and action rows (enabled flags and require_mfa configuration). */
function applySettings(d: Detail, settings: ReturnType<typeof defaultBindingSettings>): void {
  d.settings = settings;
  for (const s of d.streamDetails) {
    if (s.role === 'unsupported') continue;
    const enabled = settings.streams[s.stream].enabled;
    s.enabled = enabled;
    s.capability = enabled
      ? s.availability === 'available'
        ? 'available'
        : s.capability
      : 'disabled';
  }
  for (const a of d.actions) {
    a.enabled = settings.actions[a.action].enabled;
    const configured =
      a.action !== 'require_mfa' ||
      (d.provider === 'microsoft_entra'
        ? settings.mfaEnforcement.groupId
        : settings.mfaEnforcement.orgUnitPath) !== null;
    a.capability = !a.enabled ? 'disabled' : configured ? 'available' : 'not_configured';
    a.code = a.enabled && !configured ? 'not_configured' : null;
  }
  refreshSummary(d);
}

function mailboxStateOf(org: OrgProviders, accountId: string): MailboxState {
  const items = org.items.get(accountId) ?? [];
  const integrationIds = [...new Set(items.map((i) => i.integrationId))];
  const integrations = integrationIds
    .map((id) => org.integrations.get(id))
    .filter((d): d is Detail => d !== undefined);
  return {
    accountId,
    items,
    truncated: false,
    identities: integrations.map((d) => ({
      provider: d.provider,
      integrationId: d.id,
      userPrincipalName: null,
      directoryStatus: 'active',
      directoryStatusAt: d.health.checkedAt,
      refreshRequestedAt: org.refreshRequestedAt.get(`${accountId}:${d.id}`) ?? null,
      refreshSupported: d.status === 'active',
    })),
    integrations: integrations.map((d) => ({
      id: d.id,
      provider: d.provider,
      displayName: d.displayName,
      status: d.status,
      lastSweepAt:
        d.streamDetails.find(
          (s) => s.stream === 'mailbox_audit' || s.stream === 'forwarding_changes',
        )?.lastSuccessAt ?? null,
    })),
    refreshRequestedAt: org.refreshRequestedAt.get(accountId) ?? null,
  };
}

/** The active integration that may carry out a provider action, or why none can (D9.2). */
function actionIntegration(org: OrgProviders, type: string): Detail | null {
  return (
    [...org.integrations.values()].find(
      (d) =>
        d.status === 'active' &&
        d.capabilities.actions.includes(type as Detail['capabilities']['actions'][number]),
    ) ?? null
  );
}

const withRollback = (
  request: FixtureRequest,
  r: Response & { requesterUserId: string | null },
) => {
  const view = viewOf(request, r);
  if (r.provider !== 'gateway' && r.provider !== 'manual' && r.provider !== 'provider') {
    view.canRollback =
      principalOf(request).permissions.includes('ato:respond') &&
      r.status === 'succeeded' &&
      r.providerStatus === 'confirmed' &&
      ROLLBACK_TYPES.includes(r.actionType);
  }
  return view;
};

export const fixtures: FixtureHandlers = {
  AtoProvidersController_list_v1: route((request, org, ato) => {
    const includeDisabled = request.query.get('includeDisabled') === 'true';
    const rows = featureOn(ato)
      ? [...org.integrations.values()].filter((d) => includeDisabled || d.status !== 'disabled')
      : [];
    return ok('AtoProvidersController_list_v1', {
      featureEnabled: featureOn(ato),
      limit: { max: MAX_INTEGRATIONS, used: featureOn(ato) ? used(org) : 0 },
      data: rows.map(summaryOf),
    });
  }),

  AtoProvidersController_requirements_v1: route(() =>
    ok('AtoProvidersController_requirements_v1', REQUIREMENTS),
  ),

  AtoProvidersController_connections_v1: route((_request, org, ato) =>
    ok('AtoProvidersController_connections_v1', {
      featureEnabled: featureOn(ato),
      limit: { max: MAX_INTEGRATIONS, used: used(org) },
      data: featureOn(ato) ? org.candidates : [],
    }),
  ),

  AtoProvidersController_create_v1: route(
    (request, org, ato) =>
      mfa(request) ??
      idempotent(request, ato, () => {
        if (!featureOn(ato)) return apiError(403, 'ato_not_enabled', 'ATO is not enabled');
        const body = bodyOf(request);
        const connection = org.candidates.find((c) => c.id === body.connectionId);
        if (!connection)
          return apiError(404, 'ato_provider_connection_not_found', 'Connection not found');
        if (connection.eligibility === 'already_bound') {
          return apiError(409, 'ato_provider_already_bound', 'Already bound', {
            integrationId: connection.integrationId,
          });
        }
        if (connection.eligibility !== 'eligible' || !connection.kind) {
          return apiError(409, 'ato_provider_connection_ineligible', 'Not eligible', {
            reasons: connection.reasons.map((reason) => ({ reason })),
          });
        }
        if (used(org) >= MAX_INTEGRATIONS) {
          return apiError(409, 'ato_provider_limit_reached', 'Limit reached', {
            limit: MAX_INTEGRATIONS,
          });
        }
        const now = Date.now();
        const id = crypto.randomUUID();
        const d = detail({
          id,
          provider: connection.kind,
          displayName: connection.displayName,
          connection: {
            id: connection.id,
            provider: connection.provider,
            displayName: connection.displayName,
            status: 'active',
          },
          health: { status: 'unknown', checkedAt: null, stale: false },
          createdAt: iso(now),
          updatedAt: iso(now),
        });
        d.rowVersion = 1;
        d.settingsVersion = 1;
        const settings =
          body.settings === undefined
            ? defaultBindingSettings()
            : (body.settings as ReturnType<typeof defaultBindingSettings>);
        const issues = validateSettings(d, settings);
        if (issues.length > 0)
          return apiError(400, 'ato_provider_settings_invalid', 'Invalid settings', { issues });
        d.healthDetail = {
          ...d.healthDetail,
          status: 'unknown',
          checkedAt: null,
          ok: null,
          code: null,
          nextCheckAt: iso(now),
        };
        for (const s of d.streamDetails) {
          s.lastEventAt = null;
          s.lastSuccessAt = null;
          s.lastAttemptAt = null;
          s.eventsTotal = 0;
          s.pagesTotal = 0;
          s.lagSeconds = null;
          s.watermarkAt = null;
          if (s.role === 'primary' && settings.backfillDays > 0) {
            s.status = 'backfilling';
            s.backfill = {
              active: true,
              from: iso(now - settings.backfillDays * 86_400_000),
              requestedAt: iso(now),
              completedAt: null,
            };
          }
        }
        applySettings(d, settings);
        org.integrations.set(id, d);
        connection.eligibility = 'already_bound';
        connection.reasons = ['already_bound'];
        connection.integrationId = id;
        return ok('AtoProvidersController_create_v1', d, 201);
      }),
  ),

  AtoProvidersController_get_v1: route((request, org, ato) => {
    const d = integrationOr404(org, ato, request.params.integrationId);
    return isResponse(d) ? d : ok('AtoProvidersController_get_v1', d);
  }),

  AtoProvidersController_update_v1: route((request, org, ato) => {
    const d = integrationOr404(org, ato, request.params.integrationId);
    if (isResponse(d)) return d;
    return (
      mfa(request) ??
      idempotent(request, ato, () => {
        if (d.status === 'disabled') return apiError(409, 'ato_provider_disabled', 'Removed');
        const body = bodyOf(request);
        if (body.rowVersion !== d.rowVersion) {
          return apiError(409, 'ato_provider_conflict', 'Changed by someone else', {
            currentRowVersion: d.rowVersion,
          });
        }
        const issues = validateSettings(d, body.settings);
        if (issues.length > 0)
          return apiError(400, 'ato_provider_settings_invalid', 'Invalid settings', { issues });
        applySettings(d, body.settings as ReturnType<typeof defaultBindingSettings>);
        d.rowVersion += 1;
        d.settingsVersion += 1;
        touch(d);
        return ok('AtoProvidersController_update_v1', d);
      })
    );
  }),

  AtoProvidersController_pause_v1: route((request, org, ato) => {
    const d = integrationOr404(org, ato, request.params.integrationId);
    if (isResponse(d)) return d;
    return idempotent(request, ato, () => {
      const reason = reasonOf(request);
      if (typeof reason !== 'string') return reason;
      if (d.status === 'disabled') return apiError(409, 'ato_provider_disabled', 'Removed');
      d.status = 'paused';
      d.pausedReason = 'user';
      d.rowVersion += 1;
      touch(d);
      return ok('AtoProvidersController_pause_v1', d);
    });
  }),

  AtoProvidersController_resume_v1: route((request, org, ato) => {
    const d = integrationOr404(org, ato, request.params.integrationId);
    if (isResponse(d)) return d;
    return idempotent(request, ato, () => {
      if (d.status === 'disabled') return apiError(409, 'ato_provider_disabled', 'Removed');
      if (d.connection?.status !== 'active') {
        return apiError(409, 'ato_provider_connection_inactive', 'Connection inactive');
      }
      d.status = 'active';
      d.pausedReason = null;
      d.rowVersion += 1;
      d.healthDetail.nextCheckAt = new Date().toISOString();
      touch(d);
      return ok('AtoProvidersController_resume_v1', d);
    });
  }),

  AtoProvidersController_healthCheck_v1: route((request, org, ato) => {
    const d = integrationOr404(org, ato, request.params.integrationId);
    if (isResponse(d)) return d;
    return idempotent(request, ato, () => {
      if (d.status === 'disabled') return apiError(409, 'ato_provider_disabled', 'Removed');
      // The simulated worker probes at once: every grant is fine, the integration is healthy.
      const now = new Date().toISOString();
      d.health = { status: 'healthy', checkedAt: now, stale: false };
      d.healthDetail = {
        ...d.healthDetail,
        status: 'healthy',
        checkedAt: now,
        stale: false,
        ok: true,
        code: null,
      };
      touch(d);
      return ok(
        'AtoProvidersController_healthCheck_v1',
        { id: d.id, status: d.status, health: d.health, requestedAt: now },
        202,
      );
    });
  }),

  AtoProvidersController_backfill_v1: route((request, org, ato) => {
    const d = integrationOr404(org, ato, request.params.integrationId);
    if (isResponse(d)) return d;
    return idempotent(request, ato, () => {
      if (d.status === 'disabled') return apiError(409, 'ato_provider_disabled', 'Removed');
      const body = bodyOf(request);
      const from = typeof body.from === 'string' ? Date.parse(body.from) : Number.NaN;
      const now = Date.now();
      if (!Number.isFinite(from) || from > now || now - from > 30 * 86_400_000) {
        return apiError(422, 'ato_provider_backfill_range_invalid', 'Out of range');
      }
      const wanted = Array.isArray(body.streams) ? (body.streams as string[]) : null;
      const targets = d.streamDetails.filter(
        (s) => s.role === 'primary' && s.enabled && (!wanted || wanted.includes(s.stream)),
      );
      if (targets.some((s) => s.backfill.active)) {
        return apiError(409, 'ato_provider_backfill_active', 'Backfill active');
      }
      for (const s of targets) {
        s.status = 'backfilling';
        s.backfill = { active: true, from: iso(from), requestedAt: iso(now), completedAt: null };
      }
      refreshSummary(d);
      d.rowVersion += 1;
      touch(d);
      return ok('AtoProvidersController_backfill_v1', d, 202);
    });
  }),

  AtoProvidersController_remove_v1: route((request, org, ato) => {
    const d = integrationOr404(org, ato, request.params.integrationId);
    if (isResponse(d)) return d;
    return (
      mfa(request) ??
      idempotent(request, ato, () => {
        const reason = reasonOf(request);
        if (typeof reason !== 'string') return reason;
        if (d.status !== 'disabled') {
          d.status = 'disabled';
          d.disabledReason = 'user';
          d.disabledAt = new Date().toISOString();
          d.pausedReason = null;
          d.rowVersion += 1;
          touch(d);
          const connection = org.candidates.find((c) => c.integrationId === d.id);
          if (connection) {
            connection.eligibility = 'eligible';
            connection.reasons = [];
            connection.integrationId = null;
          }
        }
        return ok('AtoProvidersController_remove_v1', d);
      })
    );
  }),

  AtoAccountMailboxController_get_v1: route((request, org, ato) => {
    const accountId = request.params.accountId ?? '';
    if (!featureOn(ato) || !ato.accounts.has(accountId)) {
      return apiError(404, 'ato_account_not_found', 'Account not found');
    }
    return ok('AtoAccountMailboxController_get_v1', mailboxStateOf(org, accountId));
  }),

  AtoAccountMailboxController_refresh_v1: route((request, org, ato) => {
    const accountId = request.params.accountId ?? '';
    if (!featureOn(ato) || !ato.accounts.has(accountId)) {
      return apiError(404, 'ato_account_not_found', 'Account not found');
    }
    return idempotent(request, ato, () => {
      const state = mailboxStateOf(org, accountId);
      const targets = state.identities.filter((i) => i.refreshSupported && i.integrationId);
      if (targets.length === 0) {
        return apiError(409, 'ato_provider_refresh_unavailable', 'No integration can refresh');
      }
      const now = new Date().toISOString();
      org.refreshRequestedAt.set(accountId, now);
      for (const t of targets) org.refreshRequestedAt.set(`${accountId}:${t.integrationId}`, now);
      return ok(
        'AtoAccountMailboxController_refresh_v1',
        {
          accountId,
          requestedAt: now,
          identities: targets.length,
          integrationIds: targets.map((t) => t.integrationId!),
        },
        202,
      );
    });
  }),

  // ---- 8.4 operations with identity-provider behaviour ---------------------------------------

  AtoSettingsController_get_v1: async (request) => {
    const result = await atoFixtures.AtoSettingsController_get_v1!(request);
    if (result.status !== 200) return result;
    const org = orgOf(request);
    const settings = result.body as SuccessBody<'AtoSettingsController_get_v1'>;
    const live = [...org.integrations.values()].filter((d) => d.status !== 'disabled');
    return ok('AtoSettingsController_get_v1', {
      ...settings,
      identityProviders: settings.identityProviders.map((p) => ({
        provider: p.provider,
        integrations: live
          .filter((d) => d.provider === p.provider)
          .map((d) => ({ id: d.id, provider: d.provider, health: d.health.status })),
      })),
    });
  },

  AtoResponsesController_request_v1: async (request) => {
    const guard = fixtureGuard(request);
    if (guard) return guard;
    const body = bodyOf(request);
    const type = typeof body.actionType === 'string' ? body.actionType : '';
    const rawParams: unknown = body.params;
    const itemId =
      rawParams !== null &&
      typeof rawParams === 'object' &&
      typeof (rawParams as { itemId?: unknown }).itemId === 'string'
        ? (rawParams as { itemId: string }).itemId
        : undefined;
    const ato = atoOrgOf(request);
    if (PROVIDER_ACTION_TYPES.includes(type) && itemId) {
      const items = [...orgOf(request).items.values()].flat();
      if (!items.some((i) => i.id === itemId && i.state === 'present')) {
        return apiError(
          422,
          'ato_response_invalid',
          'The mailbox item is not a present item of this account',
        );
      }
    }
    const result = await atoFixtures.AtoResponsesController_request_v1!(request);
    if (result.status !== 201 || !PROVIDER_ACTION_TYPES.includes(type)) return result;
    const created = result.body as Response;
    const stored = ato.responses.get(created.id);
    const integration = actionIntegration(orgOf(request), type);
    if (!stored || !integration) return result;
    // A connected provider carries the action out after the approval (pending until then).
    stored.provider = integration.provider;
    stored.status = 'pending_approval';
    stored.providerStatus = null;
    stored.resultCode = null;
    stored.params = { ...stored.params };
    (stored as Response & { itemId?: string }).itemId = itemId;
    return ok('AtoResponsesController_request_v1', withRollback(request, stored), 201);
  },

  AtoResponsesController_approve_v1: async (request) => {
    const guard = fixtureGuard(request);
    if (guard) return guard;
    const ato = atoOrgOf(request);
    const stored = ato.responses.get(request.params.responseId ?? '');
    const providerKind = stored && !['gateway', 'manual', 'provider'].includes(stored.provider);
    const result = await atoFixtures.AtoResponsesController_approve_v1!(request);
    if (result.status !== 200 || !stored || !providerKind) return result;
    const itemId = (stored as Response & { itemId?: string }).itemId;
    const org = orgOf(request);
    const item = itemId ? [...org.items.values()].flat().find((i) => i.id === itemId) : undefined;
    if (
      stored.actionType === 'remove_forwarding_rule' &&
      item?.kind === 'forwarding' &&
      item.provider === 'microsoft_entra'
    ) {
      stored.status = 'unsupported';
      stored.providerStatus = 'unsupported';
      stored.resultCode = 'requires_exchange_admin';
    } else {
      stored.status = 'succeeded';
      stored.providerStatus = 'confirmed';
      stored.resultCode = null;
      stored.providerReference = `${stored.provider === 'google_workspace' ? 'gws' : 'msgraph'}:${stored.actionType}:${stored.id}`;
      if (item && stored.actionType === 'remove_forwarding_rule') {
        item.state = 'removed';
        item.lastChange = 'removed';
        item.removedAt = new Date().toISOString();
      }
    }
    return ok('AtoResponsesController_approve_v1', withRollback(request, stored));
  },

  AtoResponsesController_rollback_v1: async (request) => {
    const guard = fixtureGuard(request);
    if (guard) return guard;
    const ato = atoOrgOf(request);
    const stored = ato.responses.get(request.params.responseId ?? '');
    if (!stored || ['gateway', 'manual', 'provider'].includes(stored.provider)) {
      return atoFixtures.AtoResponsesController_rollback_v1!(request);
    }
    return (
      mfa(request) ??
      idempotent(request, ato, () => {
        const reason =
          typeof bodyOf(request).reason === 'string'
            ? (bodyOf(request).reason as string).trim()
            : '';
        if (reason.length < 10)
          return apiError(400, 'validation_failed', ['reason: must be 10-1000 characters']);
        if (stored.status !== 'succeeded' || !ROLLBACK_TYPES.includes(stored.actionType)) {
          return apiError(422, 'ato_rollback_unsupported', 'This response cannot be rolled back');
        }
        stored.status = 'rolled_back';
        stored.rollbackReason = reason;
        stored.updatedAt = new Date().toISOString();
        return ok('AtoResponsesController_rollback_v1', withRollback(request, stored));
      })
    );
  },
};
