import 'server-only';
import type { OperationId, RequestBody, SuccessBody } from '@/lib/api/types';
import { paginate, stableUuid } from '../generator';
import {
  apiError,
  ok,
  type FixtureHandlers,
  type FixtureRequest,
  type FixtureResponse,
} from '../types';
import { DAY, HOUR, MINUTE, bodyOf, domainsOf, guarded, idempotent, isoAgo } from './domains';

export { DEV_MOCK_MARKER } from '../types';

/**
 * Dev fixtures of the Microsoft 365 and Google Workspace connections (step 8.2 WP6, design P9):
 * the 24 operations of §5.2 over an in-memory state per organization. Two seeded connections (an
 * active Microsoft 365 tenant with outbound and internal routing, a Google Workspace organization
 * waiting for delegation), a simulated worker (a verification completes 3 s after it was
 * requested; a validation run passes 3 s after it started, a probe run once the probe "arrives"
 * 6 s later), preview → impact token → apply with `impact_changed`, single-use consent states and
 * Idempotency-Key replay. Every value is synthetic: tenant ids are `11111111-2222-…` style GUIDs,
 * domains are the `*.example.test` fixture domains, and no credential is ever kept (only a
 * fingerprint is derived).
 */

type Connection = SuccessBody<'ProviderConnectionsController_get_v1'>;
type Grant = Connection['grants'][number];
type Wizard = SuccessBody<'ProviderConnectionsController_wizard_v1'>;
type LinkedDomain = SuccessBody<'ProviderDomainsController_list_v1'>['data'][number];
type Run = SuccessBody<'ProviderValidationsController_get_v1'>;
type Health = SuccessBody<'ProviderHealthController_get_v1'>;
type Change = RequestBody<'ProviderMailFlowController_preview_v1'>['change'];
type ChangeSet = SuccessBody<'ProviderMailFlowController_preview_v1'>['changeSet'];
type Provider = Connection['provider'];
type Servers = ChangeSet['domains'][number]['current'];

interface DomainLink {
  domainId: string;
  providerVerification: LinkedDomain['providerVerification'];
  providerCheckedAt: string | null;
  providerMxHost: string | null;
  destination: Servers;
  inboundAppliedAt: string | null;
}

interface ConnectionState {
  connection: Connection;
  links: DomainLink[];
  runs: Run[];
  health: Health;
  routeToken: string;
  impactTokens: Map<string, { changeSet: string; rowVersion: number; expiresAt: number }>;
}

interface OrgState {
  connections: ConnectionState[];
  consentStates: Map<string, { connectionId: string; profile: string; used: boolean }>;
}

interface ProviderFixtureState {
  orgs: Map<string, OrgState>;
  idempotency: Map<string, FixtureResponse>;
}

const globalState = globalThis as typeof globalThis & {
  __egDevFixtureProviders?: ProviderFixtureState;
};
const state: ProviderFixtureState = (globalState.__egDevFixtureProviders ??= {
  orgs: new Map(),
  idempotency: new Map(),
});

/** The operations of §5.2 (24), all answered here. */
export const PROVIDER_OPERATIONS: readonly OperationId[] = [
  'ProviderCatalogController_get_v1',
  'ProviderConnectionsController_list_v1',
  'ProviderConnectionsController_create_v1',
  'ProviderConnectionsController_get_v1',
  'ProviderConnectionsController_update_v1',
  'ProviderConnectionsController_disconnect_v1',
  'ProviderConnectionsController_wizard_v1',
  'ProviderGrantsController_create_v1',
  'ProviderGrantsController_completeConsent_v1',
  'ProviderGrantsController_setCredentials_v1',
  'ProviderGrantsController_verify_v1',
  'ProviderGrantsController_revoke_v1',
  'ProviderDomainsController_list_v1',
  'ProviderDomainsController_replace_v1',
  'ProviderMailFlowController_preview_v1',
  'ProviderMailFlowController_apply_v1',
  'ProviderMailFlowController_get_v1',
  'ProviderAttestationsController_record_v1',
  'ProviderValidationsController_create_v1',
  'ProviderValidationsController_list_v1',
  'ProviderValidationsController_get_v1',
  'ProviderHealthController_get_v1',
  'ProviderHealthController_checkNow_v1',
  'ProviderGuideController_get_v1',
];

/** The public id of the n-th seeded connection (the mail-servers fixture links its relay to 0). */
export function providerConnectionFixtureId(organizationId: string, index: number): string {
  return stableUuid(`${organizationId}:provider-connection:${index}`);
}

export function resetProviderFixtures(): void {
  state.orgs.clear();
  state.idempotency.clear();
}

const PROFILE: Record<Provider, string> = {
  microsoft_365: 'm365.mail_flow',
  google_workspace: 'google.mail_flow',
};
const PERMISSIONS: Record<Provider, string[]> = {
  microsoft_365: ['Organization.Read.All', 'Domain.Read.All'],
  google_workspace: [
    'https://www.googleapis.com/auth/admin.directory.customer.readonly',
    'https://www.googleapis.com/auth/admin.directory.domain.readonly',
  ],
};
const METHODS: Record<Provider, Grant['authMethod'][]> = {
  microsoft_365: ['platform_app', 'customer_app_secret'],
  google_workspace: ['platform_service_account', 'customer_service_account'],
};
/** Step API-1 (D4): the mailbox-access profile of each provider and its permissions. */
export const MAILBOX_PROFILE: Record<Provider, string> = {
  microsoft_365: 'm365.mailbox_remediation',
  google_workspace: 'google.mailbox_remediation',
};
const MAILBOX_PERMISSIONS: Record<Provider, string[]> = {
  microsoft_365: ['Mail.ReadWrite', 'User.Read.All'],
  google_workspace: [
    'https://www.googleapis.com/auth/gmail.modify',
    'https://www.googleapis.com/auth/admin.directory.user.readonly',
  ],
};
const isMailboxProfile = (profile: string | undefined) =>
  profile === MAILBOX_PROFILE.microsoft_365 || profile === MAILBOX_PROFILE.google_workspace;
const permissionsOf = (provider: Provider, profile: string) =>
  isMailboxProfile(profile) ? MAILBOX_PERMISSIONS[provider] : PERMISSIONS[provider];
/** The extra `remediation:write` gate of the mailbox-access grant routes (D4). */
function mailboxGate(profile: string | undefined, permissions: readonly string[]) {
  return isMailboxProfile(profile) && !permissions.includes('remediation:write')
    ? apiError(
        403,
        'remediation_permission_required',
        'Mailbox access for API mode needs the remediation:write permission',
      )
    : null;
}
const ATTESTATIONS: {
  code: string;
  provider: Provider;
  phase: 'inbound' | 'outbound' | 'internal' | 'lockdown';
  statement: string;
  requiredFor: 'inbound' | 'activate' | null;
}[] = [
  {
    code: 'm365.inbound_connector_created',
    provider: 'microsoft_365',
    phase: 'inbound',
    statement:
      'The inbound partner connector "Email security gateway" exists and accepts mail from the gateway only over TLS.',
    requiredFor: 'inbound',
  },
  {
    code: 'm365.enhanced_filtering_enabled',
    provider: 'microsoft_365',
    phase: 'inbound',
    statement: 'Enhanced Filtering for Connectors is enabled on the inbound connector.',
    requiredFor: 'inbound',
  },
  {
    code: 'm365.direct_delivery_locked_down',
    provider: 'microsoft_365',
    phase: 'lockdown',
    statement:
      'Mail that does not arrive through the gateway is rejected or quarantined by Exchange Online.',
    requiredFor: null,
  },
  {
    code: 'm365.outbound_connector_created',
    provider: 'microsoft_365',
    phase: 'outbound',
    statement:
      'The outbound connector "Email security gateway outbound" exists with the gateway relay hosts as smart hosts.',
    requiredFor: null,
  },
  {
    code: 'm365.internal_routing_rules_created',
    provider: 'microsoft_365',
    phase: 'internal',
    statement:
      'The transport rules "Route internal mail through the email security gateway" and "Remove the gateway route token" exist with the current route token.',
    requiredFor: 'activate',
  },
  {
    code: 'google.inbound_gateway_configured',
    provider: 'google_workspace',
    phase: 'inbound',
    statement: 'The Gmail inbound gateway lists the gateway addresses and requires TLS from them.',
    requiredFor: 'inbound',
  },
  {
    code: 'google.reject_non_gateway_enabled',
    provider: 'google_workspace',
    phase: 'lockdown',
    statement: 'Gmail rejects all mail that does not come from the gateway addresses.',
    requiredFor: null,
  },
  {
    code: 'google.outbound_route_configured',
    provider: 'google_workspace',
    phase: 'outbound',
    statement: 'A Gmail outbound route sends outbound mail through the gateway relay hosts.',
    requiredFor: null,
  },
  {
    code: 'google.internal_routing_configured',
    provider: 'google_workspace',
    phase: 'internal',
    statement: 'A Gmail routing rule sends internal mail through the gateway.',
    requiredFor: 'activate',
  },
];
const GATEWAY = {
  mxHosts: ['mx1.gateway.example.test', 'mx2.gateway.example.test'],
  egressNetworks: ['192.0.2.10/32'],
  relayHosts: ['out.gateway.example.test'],
  relayTlsName: 'out.gateway.example.test',
  spfInclude: '_spf.gateway.example.test',
};
const PROBE_DOMAIN = 'probe.gateway.example.test';
const GOOGLE_SERVERS: Servers = {
  provider: 'google_workspace',
  servers: [
    ['aspmx.l.google.com', 1],
    ['alt1.aspmx.l.google.com', 5],
    ['alt2.aspmx.l.google.com', 5],
    ['alt3.aspmx.l.google.com', 10],
    ['alt4.aspmx.l.google.com', 10],
  ].map(([host, priority]) => ({
    host: String(host),
    port: 25,
    priority: Number(priority),
    tlsMode: 'verify',
  })),
};
const CUSTOM_SERVERS: Servers = {
  provider: 'custom',
  servers: [{ host: 'mail.onprem.example.test', port: 25, priority: 10, tlsMode: 'may' }],
};

function m365Servers(host: string): Servers {
  return {
    provider: 'microsoft_365',
    servers: [{ host, port: 25, priority: 0, tlsMode: 'verify' }],
  };
}

function mxHostOf(name: string): string {
  return `${name.replace(/\./g, '-')}.mail.protection.outlook.com`;
}

function fingerprint(seed: string): string {
  return stableUuid(seed).replace(/-/g, '').slice(0, 12);
}

function grantOf(
  connectionId: string,
  provider: Provider,
  authMethod: Grant['authMethod'],
  status: Grant['status'],
  at: string,
  profile: string = PROFILE[provider],
): Grant {
  const active = status === 'active';
  const customer =
    authMethod === 'customer_app_secret' || authMethod === 'customer_service_account';
  return {
    id: stableUuid(`${connectionId}:grant:${profile}:${authMethod}:${at}`),
    profile,
    profileVersion: 1,
    authMethod,
    status,
    clientId:
      authMethod === 'platform_app'
        ? '11111111-2222-3333-4444-555555555555'
        : authMethod === 'platform_service_account'
          ? '100000000000000000001'
          : null,
    subjectEmail: null,
    credentialFingerprint: customer && active ? fingerprint(`${connectionId}:cred`) : null,
    credentialVersion: customer && active ? 1 : 0,
    credentialSetAt: customer && active ? at : null,
    credentialExpiresAt: null,
    requestedPermissions: permissionsOf(provider, profile),
    observedPermissions: active ? permissionsOf(provider, profile) : [],
    missingPermissions: [],
    excessPermissions: [],
    consentedAt: active ? at : null,
    verifyRequestedAt: active ? at : null,
    verifiedAt: active ? at : null,
    lastErrorCode: null,
    createdAt: at,
    updatedAt: at,
  };
}

function emptyHealth(connectionId: string): Health {
  return {
    connectionId,
    status: 'unknown',
    checkedAt: null,
    changedAt: null,
    nextCheckAt: null,
    checks: [],
    transitions: [],
  };
}

function seed(organizationId: string): OrgState {
  const active = domainsOf(organizationId)
    .filter((entry) => entry.domain.status === 'active' && !entry.deleted)
    .map((entry) => entry.domain);
  const created = isoAgo(20 * DAY);
  const m365Id = providerConnectionFixtureId(organizationId, 0);
  const googleId = providerConnectionFixtureId(organizationId, 1);
  const m365Domains = active.slice(0, 2);
  const m365: ConnectionState = {
    connection: {
      id: m365Id,
      provider: 'microsoft_365',
      displayName: 'Contoso production',
      status: 'active',
      tenantName: 'Contoso Ltd (fixture)',
      tenantId: '11111111-2222-3333-4444-555555555555',
      tenantVerifiedAt: created,
      outboundMode: 'active',
      internalRouting: true,
      health: 'healthy',
      healthChangedAt: isoAgo(3 * DAY),
      healthCheckedAt: isoAgo(5 * MINUTE),
      nextHealthCheckAt: isoAgo(-10 * MINUTE),
      domainCount: m365Domains.length,
      createdAt: created,
      updatedAt: created,
      grants: [
        grantOf(m365Id, 'microsoft_365', 'platform_app', 'active', created),
        // Step API-1: mailbox access for API mode (the api-mode fixtures' first connection).
        grantOf(
          m365Id,
          'microsoft_365',
          'platform_app',
          'active',
          created,
          MAILBOX_PROFILE.microsoft_365,
        ),
      ],
      domains: m365Domains.map((d) => ({
        id: d.id,
        name: d.name,
        providerVerification: 'verified',
      })),
      relayConnectorId: stableUuid(`${organizationId}:connector:4`),
      relayProof: { tenantHeader: 'required', dkimAligned: 'required' },
      relayProofIsDefault: true,
      attestations: [
        'm365.inbound_connector_created',
        'm365.enhanced_filtering_enabled',
        'm365.outbound_connector_created',
        'm365.internal_routing_rules_created',
      ].map((code) => ({ code, userId: null, at: created })),
      routeTokenVersion: 1,
      routeTokenPendingVersion: null,
      disabledAt: null,
      rowVersion: 7,
    },
    links: m365Domains.map((d) => ({
      domainId: d.id,
      providerVerification: 'verified',
      providerCheckedAt: isoAgo(2 * HOUR),
      providerMxHost: mxHostOf(d.name),
      destination: m365Servers(mxHostOf(d.name)),
      inboundAppliedAt: created,
    })),
    runs: [],
    health: emptyHealth(m365Id),
    routeToken: 'abcdefghijklmnopqrstuvwxyz234567',
    impactTokens: new Map(),
  };
  m365.runs.push(passedRun(m365.connection, isoAgo(2 * DAY)));
  m365.health = {
    connectionId: m365Id,
    status: 'healthy',
    checkedAt: isoAgo(5 * MINUTE),
    changedAt: isoAgo(3 * DAY),
    nextCheckAt: isoAgo(-10 * MINUTE),
    checks: healthChecks(m365, 'pass'),
    transitions: [
      { from: 'warning', to: 'healthy', failingChecks: [], at: isoAgo(3 * DAY) },
      {
        from: 'unknown',
        to: 'warning',
        failingChecks: ['lockdown.attested'],
        at: isoAgo(19 * DAY),
      },
    ],
  };
  const google: ConnectionState = {
    connection: {
      id: googleId,
      provider: 'google_workspace',
      displayName: 'Fabrikam Google',
      status: 'connecting',
      tenantName: null,
      tenantId: null,
      tenantVerifiedAt: null,
      outboundMode: 'off',
      internalRouting: false,
      health: 'unknown',
      healthChangedAt: null,
      healthCheckedAt: null,
      nextHealthCheckAt: null,
      domainCount: 0,
      createdAt: isoAgo(2 * HOUR),
      updatedAt: isoAgo(2 * HOUR),
      grants: [
        grantOf(
          googleId,
          'google_workspace',
          'platform_service_account',
          'pending_consent',
          isoAgo(2 * HOUR),
        ),
      ],
      domains: [],
      relayConnectorId: null,
      relayProof: { dkimAligned: 'required', dkimMaxAgeSeconds: 3600, dkimReplayMax: 5 },
      relayProofIsDefault: true,
      attestations: [],
      routeTokenVersion: 1,
      routeTokenPendingVersion: null,
      disabledAt: null,
      rowVersion: 2,
    },
    links: [],
    runs: [],
    health: emptyHealth(googleId),
    routeToken: 'qrstuvwxyz234567abcdefghijklmnop',
    impactTokens: new Map(),
  };
  return { connections: [m365, google], consentStates: new Map() };
}

function orgState(organizationId: string): OrgState {
  let org = state.orgs.get(organizationId);
  if (!org) {
    org = seed(organizationId);
    state.orgs.set(organizationId, org);
  }
  return org;
}

/** The organization's 8.2 connections (step API-1: read by the api-mode fixtures). */
export function providerConnectionsOf(organizationId: string): Connection[] {
  const org = orgState(organizationId);
  for (const c of org.connections) tick(organizationId, c);
  return org.connections.map((c) => c.connection);
}

const notFound = () => apiError(404, 'connection_not_found', 'Provider connection not found');

function find(organizationId: string, id: string | undefined): ConnectionState | null {
  return orgState(organizationId).connections.find((c) => c.connection.id === id) ?? null;
}

function touch(c: ConnectionState, bump = true): void {
  c.connection.updatedAt = new Date().toISOString();
  if (bump) c.connection.rowVersion += 1;
}

function linkedDomains(organizationId: string, c: ConnectionState): LinkedDomain[] {
  const all = domainsOf(organizationId);
  return c.links.flatMap((l) => {
    const entry = all.find((e) => e.domain.id === l.domainId);
    if (!entry) return [];
    return [
      {
        id: entry.domain.id,
        name: entry.domain.name,
        gatewayStatus: entry.domain.status,
        providerVerification: l.providerVerification,
        providerCheckedAt: l.providerCheckedAt,
        providerMxHost: l.providerMxHost,
        destinationProvider: l.destination.provider,
        inboundAppliedAt: l.inboundAppliedAt,
        dns: { mx: 'pass', spf: 'pass', dkim: 'pass' },
      },
    ];
  });
}

/** The simulated worker: verifications, domain checks and validation runs complete over time. */
function tick(organizationId: string, c: ConnectionState): void {
  const now = Date.now();
  const conn = c.connection;
  for (const grant of conn.grants) {
    if (grant.status !== 'verifying' || !grant.verifyRequestedAt) continue;
    if (now - Date.parse(grant.verifyRequestedAt) < 3000) continue;
    const at = new Date().toISOString();
    Object.assign(grant, {
      status: 'active',
      verifiedAt: at,
      observedPermissions: permissionsOf(conn.provider, grant.profile),
      missingPermissions: [],
      excessPermissions: [],
      updatedAt: at,
    });
    // As the worker: the tenant stays a claim until a linked domain proves control (D4).
    if (conn.status === 'connecting' || conn.status === 'draft') conn.status = 'configuring';
    touch(c);
  }
  for (const link of c.links) {
    if (link.providerVerification !== 'unknown') continue;
    const entry = domainsOf(organizationId).find((e) => e.domain.id === link.domainId);
    link.providerVerification = 'verified';
    link.providerCheckedAt = new Date().toISOString();
    link.providerMxHost =
      conn.provider === 'microsoft_365' && entry ? mxHostOf(entry.domain.name) : null;
  }
  conn.domains = linkedDomains(organizationId, c).map((d) => ({
    id: d.id,
    name: d.name,
    providerVerification: d.providerVerification,
  }));
  conn.domainCount = conn.domains.length;
  if (
    conn.tenantVerifiedAt === null &&
    conn.grants.some((g) => g.status === 'active') &&
    c.links.some((l) => l.providerVerification === 'verified')
  ) {
    conn.tenantId ??=
      conn.provider === 'microsoft_365' ? '22222222-3333-4444-5555-666666666666' : 'C0fixture1';
    conn.tenantName ??= conn.provider === 'microsoft_365' ? 'Fixture tenant' : 'Fixture Workspace';
    conn.tenantVerifiedAt = new Date().toISOString();
    touch(c);
  }
  const bound =
    conn.grants.some((g) => g.status === 'active') &&
    conn.tenantVerifiedAt !== null &&
    c.links.some((l) => l.providerVerification === 'verified');
  if (bound && conn.status === 'configuring') {
    conn.status = 'active';
    touch(c);
  }
  for (const run of c.runs) {
    if (run.status === 'queued' && now - Date.parse(run.createdAt) > 1500) {
      run.status = run.probeExpiresAt ? 'awaiting_probe' : 'running';
      run.startedAt = new Date().toISOString();
    }
    if (run.status === 'running' && now - Date.parse(run.createdAt) > 3000) {
      Object.assign(run, completedRun(c, run, false));
    }
    if (run.status === 'awaiting_probe' && now - Date.parse(run.createdAt) > 6000) {
      Object.assign(run, completedRun(c, run, true));
    }
  }
}

function healthChecks(c: ConnectionState, status: 'pass' | 'warn'): Health['checks'] {
  const at = isoAgo(5 * MINUTE);
  const codes: [string, string][] = [
    ['credentials.token', 'Access token'],
    ['permissions.granted', 'Granted permissions'],
    ['tenant.identity', 'Tenant identity'],
    ['domains.provider_verified', 'Domains verified in the tenant'],
    ['dns.mx_gateway', 'MX points to the gateway'],
    ['inbound.recent_deliveries', 'Recent inbound deliveries'],
    ['outbound.relay_activity', 'Provider relay activity'],
    ['routing.loops', 'Mail loops'],
  ];
  return codes.map(([code, title]) => ({
    code,
    title,
    subject: '',
    status: code === 'outbound.relay_activity' && status === 'warn' ? 'warn' : 'pass',
    severity: 'info',
    evidence:
      code === 'outbound.relay_activity'
        ? { accepted24h: c.connection.outboundMode === 'active' ? 412 : 0 }
        : {},
    firstFailedAt: null,
    checkedAt: at,
  }));
}

function results(c: ConnectionState, probe: boolean): Run['results'] {
  const codes = [
    'credentials.token',
    'permissions.granted',
    'tenant.identity',
    'domains.gateway_verified',
    'domains.provider_verified',
    'dns.mx_gateway',
    'inbound.destination',
    'inbound.smtp',
    'dns.spf_gateway',
    ...(probe ? ['outbound.probe'] : []),
    'routing.no_loops',
    'lockdown.attested',
  ];
  const lockdown = c.connection.attestations.some(
    (a) => a.code.endsWith('locked_down') || a.code.startsWith('google.reject'),
  );
  return codes.map((code) => ({
    code,
    subject: '',
    status: code === 'lockdown.attested' && !lockdown ? 'warn' : 'pass',
    severity: code === 'lockdown.attested' ? 'warning' : 'info',
    evidence: code === 'inbound.smtp' ? { tlsVersion: 'TLSv1.3', rcptReplyClass: '2xx' } : {},
    remediation: code === 'lockdown.attested' ? '#inbound-lockdown' : null,
  }));
}

function summaryOf(list: Run['results']) {
  const count = (s: string) => list.filter((r) => r.status === s).length;
  return {
    pass: count('pass'),
    warn: count('warn'),
    fail: count('fail'),
    skipped: count('skipped'),
    error: count('error'),
  };
}

function completedRun(c: ConnectionState, run: Run, probe: boolean): Partial<Run> {
  const list = results(c, probe);
  const summary = summaryOf(list);
  return {
    status: summary.fail > 0 ? 'failed' : summary.warn > 0 ? 'warning' : 'passed',
    results: list,
    summary,
    completedAt: new Date().toISOString(),
    probeObservations: probe
      ? [
          {
            receivedAt: new Date().toISOString(),
            clientIp: '192.0.2.70',
            tlsProtocol: 'TLSv1.3',
            envelopeFromDomain: c.connection.domains[0]?.name ?? 'example.test',
            headerFromDomain: c.connection.domains[0]?.name ?? 'example.test',
            tenantHeader: c.connection.provider === 'microsoft_365' ? 'match' : 'not_applicable',
            dkim: 'aligned_pass',
            dkimDomains: [c.connection.domains[0]?.name ?? 'example.test'],
            proofResult: 'pass',
            failureCode: null,
          },
        ]
      : run.probeObservations,
  };
}

function passedRun(connection: Connection, at: string): Run {
  const base: Run = {
    id: stableUuid(`${connection.id}:run:${at}`),
    kind: 'full',
    status: 'queued',
    requestedBy: { type: 'user', id: null },
    probeExpiresAt: null,
    summary: null,
    startedAt: at,
    completedAt: null,
    createdAt: at,
    results: [],
    probeObservations: [],
  };
  const state0: ConnectionState = {
    connection,
    links: [],
    runs: [],
    health: emptyHealth(connection.id),
    routeToken: '',
    impactTokens: new Map(),
  };
  return {
    ...base,
    ...completedRun(state0, base, connection.outboundMode !== 'off'),
    completedAt: at,
  };
}

function wizardOf(c: ConnectionState): Wizard {
  const conn = c.connection;
  const disabled = conn.status === 'disabled';
  const grant = conn.grants.find(
    (g) => g.profile === PROFILE[conn.provider] && g.status !== 'revoked',
  );
  const done = (s: { status: string }) => s.status === 'done' || s.status === 'skipped';
  type Step = Wizard['steps'][number];
  const blocked = (step: Step['step'], ...deps: Step[]): Step | null => {
    const missing = deps.filter((d) => !done(d)).map((d) => d.step);
    return missing.length ? { step, status: 'blocked', blockers: missing } : null;
  };
  const connect: Step = disabled
    ? { step: 'connect', status: 'blocked', blockers: ['connection_disabled'] }
    : grant?.status === 'active'
      ? { step: 'connect', status: 'done', blockers: [] }
      : !grant
        ? { step: 'connect', status: 'not_started', blockers: [] }
        : {
            step: 'connect',
            status: 'in_progress',
            blockers: [
              grant.status === 'error'
                ? 'grant_error'
                : grant.status === 'pending_consent'
                  ? 'consent_pending'
                  : 'verification_pending',
            ],
          };
  const domains: Step =
    blocked('domains', connect) ??
    (c.links.length === 0
      ? { step: 'domains', status: 'not_started', blockers: ['no_domain_linked'] }
      : conn.status === 'active'
        ? { step: 'domains', status: 'done', blockers: [] }
        : { step: 'domains', status: 'in_progress', blockers: ['binding_pending'] });
  const required = ATTESTATIONS.filter(
    (a) => a.provider === conn.provider && a.requiredFor === 'inbound',
  ).map((a) => a.code);
  const attested = conn.attestations.map((a) => a.code);
  const missingInbound = required.filter((code) => !attested.includes(code));
  const inbound: Step =
    blocked('inbound', domains) ??
    (() => {
      const blockers: string[] = [];
      if (c.links.some((l) => l.destination.provider !== conn.provider))
        blockers.push('destinations_missing');
      if (missingInbound.length) blockers.push('attestations_missing');
      return { step: 'inbound', status: blockers.length ? 'in_progress' : 'done', blockers };
    })();
  const outbound: Step =
    blocked('outbound', domains) ??
    (conn.outboundMode === 'off' && !conn.relayConnectorId
      ? { step: 'outbound', status: 'skipped', blockers: [] }
      : conn.relayConnectorId && conn.outboundMode !== 'off'
        ? { step: 'outbound', status: 'done', blockers: [] }
        : { step: 'outbound', status: 'in_progress', blockers: ['relay_connector_disabled'] });
  const latest = c.runs.find((r) => r.kind === 'full');
  const validate: Step =
    blocked('validate', inbound, outbound) ??
    (!latest
      ? { step: 'validate', status: 'not_started', blockers: [] }
      : latest.status === 'passed' || latest.status === 'warning'
        ? { step: 'validate', status: 'done', blockers: [] }
        : { step: 'validate', status: 'in_progress', blockers: [`run_${latest.status}`] });
  const internalCode =
    conn.provider === 'microsoft_365'
      ? 'm365.internal_routing_rules_created'
      : 'google.internal_routing_configured';
  const activate: Step =
    blocked('activate', validate) ??
    (conn.outboundMode === 'active'
      ? conn.internalRouting && !attested.includes(internalCode)
        ? {
            step: 'activate',
            status: 'in_progress',
            blockers: ['internal_routing_attestation_missing'],
          }
        : { step: 'activate', status: 'done', blockers: [] }
      : conn.outboundMode === 'off'
        ? { step: 'activate', status: 'done', blockers: [] }
        : conn.outboundMode === 'suspended'
          ? { step: 'activate', status: 'in_progress', blockers: ['outbound_suspended'] }
          : { step: 'activate', status: 'not_started', blockers: [] });
  const steps = [connect, domains, inbound, outbound, validate, activate];
  const next = disabled ? undefined : steps.find((s) => !done(s) && s.status !== 'blocked');
  const missing = [...missingInbound];
  if (conn.internalRouting && !attested.includes(internalCode)) missing.push(internalCode);
  return {
    connectionId: conn.id,
    provider: conn.provider,
    connectionStatus: conn.status,
    steps,
    nextAction: next
      ? { step: next.step, action: next.step === 'connect' ? 'grant_access' : next.step }
      : null,
    missingAttestations: missing,
  };
}

function changeSetOf(
  organizationId: string,
  c: ConnectionState,
  change: Change,
): ChangeSet | FixtureResponse {
  const conn = c.connection;
  const set: ChangeSet = {
    kind: change.kind,
    domains: [],
    connector: { action: 'none', id: conn.relayConnectorId },
    connection: [],
    grantsRevoked: 0,
  };
  const bound = conn.status === 'active';
  if (change.kind === 'inbound') {
    if (!bound) return apiError(409, 'connection_not_bound', 'The tenant is not bound yet');
    const names = linkedDomains(organizationId, c);
    for (const id of change.domainIds) {
      const link = c.links.find((l) => l.domainId === id);
      const name = names.find((d) => d.id === id)?.name;
      if (!link || !name) return apiError(404, 'domain_not_in_organization', 'Domain not linked');
      const proposed =
        conn.provider === 'google_workspace'
          ? GOOGLE_SERVERS
          : m365Servers(change.microsoftHosts?.[id] ?? link.providerMxHost ?? mxHostOf(name));
      set.domains.push({
        domainId: id,
        name,
        current: link.destination,
        proposed,
        changed: JSON.stringify(link.destination) !== JSON.stringify(proposed),
      });
    }
  } else if (change.kind === 'outbound') {
    if (!bound) return apiError(409, 'connection_not_bound', 'The tenant is not bound yet');
    set.connector = {
      action: conn.relayConnectorId ? 'enable' : 'create',
      id: conn.relayConnectorId,
    };
    set.connection.push({ field: 'outboundMode', from: conn.outboundMode, to: 'probe_only' });
  } else if (change.kind === 'activate') {
    const validated = c.runs.some(
      (r) => r.kind === 'full' && (r.status === 'passed' || r.status === 'warning'),
    );
    if (!validated)
      return apiError(409, 'validation_required', 'A passing full validation is required');
    if (conn.outboundMode !== change.outboundMode)
      set.connection.push({
        field: 'outboundMode',
        from: conn.outboundMode,
        to: change.outboundMode,
      });
    if (conn.internalRouting !== change.internalRouting)
      set.connection.push({
        field: 'internalRouting',
        from: conn.internalRouting,
        to: change.internalRouting,
      });
  } else if (change.kind === 'suspend') {
    set.connection.push({ field: 'outboundMode', from: conn.outboundMode, to: 'suspended' });
  } else if (change.kind === 'disable_outbound') {
    set.connector = { action: 'disable', id: conn.relayConnectorId };
    set.connection.push({ field: 'outboundMode', from: conn.outboundMode, to: 'off' });
    if (conn.internalRouting)
      set.connection.push({ field: 'internalRouting', from: true, to: false });
  } else if (change.kind === 'disable') {
    set.connector = {
      action: conn.relayConnectorId ? 'disable' : 'none',
      id: conn.relayConnectorId,
    };
    set.connection.push({ field: 'status', from: conn.status, to: 'disabled' });
    if (conn.outboundMode !== 'off')
      set.connection.push({ field: 'outboundMode', from: conn.outboundMode, to: 'off' });
    set.grantsRevoked = conn.grants.filter((g) => g.status !== 'revoked').length;
  } else if (change.kind === 'proof') {
    set.connection.push({ field: 'relayProof', from: conn.relayProof, to: change.relayProof });
  }
  return set;
}

function isResponse(value: unknown): value is FixtureResponse {
  return typeof value === 'object' && value !== null && 'status' in value && !('kind' in value);
}

function applyChange(
  organizationId: string,
  c: ConnectionState,
  change: Change,
  set: ChangeSet,
  userId: string | null,
): void {
  const conn = c.connection;
  const at = new Date().toISOString();
  if (change.kind === 'inbound') {
    for (const d of set.domains) {
      const link = c.links.find((l) => l.domainId === d.domainId);
      if (link) {
        link.destination = d.proposed;
        link.inboundAppliedAt = at;
      }
    }
  }
  if (change.kind === 'outbound') {
    conn.relayConnectorId ??= stableUuid(`${organizationId}:relay:${conn.id}`);
    conn.outboundMode = 'probe_only';
  }
  if (change.kind === 'activate') {
    conn.outboundMode = change.outboundMode;
    conn.internalRouting = change.internalRouting;
  }
  if (change.kind === 'suspend') conn.outboundMode = 'suspended';
  if (change.kind === 'disable_outbound') {
    conn.outboundMode = 'off';
    conn.internalRouting = false;
  }
  if (change.kind === 'proof') {
    conn.relayProof = change.relayProof;
    conn.relayProofIsDefault = false;
  }
  if (change.kind === 'disable') {
    conn.status = 'disabled';
    conn.outboundMode = 'off';
    conn.internalRouting = false;
    conn.disabledAt = at;
    for (const g of conn.grants) {
      g.status = 'revoked';
      g.credentialFingerprint = null;
    }
  }
  void userId;
  touch(c);
}

function keyed(
  request: FixtureRequest,
  run: () => FixtureResponse,
  redact?: (r: FixtureResponse) => FixtureResponse,
) {
  return idempotent(state.idempotency, request, run, redact);
}

function guide(
  c: ConnectionState,
  organizationId: string,
): SuccessBody<'ProviderGuideController_get_v1'> {
  const conn = c.connection;
  const m365 = conn.provider === 'microsoft_365';
  const domains = linkedDomains(organizationId, c);
  const attested = (code: string) => {
    const a = conn.attestations.find((x) => x.code === code);
    const def = ATTESTATIONS.find((x) => x.code === code);
    return {
      code,
      statement: def?.statement ?? code,
      attested: Boolean(a),
      attestedAt: a?.at ?? null,
    };
  };
  const section = (
    number: number,
    id: string,
    title: string,
    paragraphs: string[],
    steps: SuccessBody<'ProviderGuideController_get_v1'>['sections'][number]['steps'] = [],
  ) => ({ id, number, title, paragraphs, steps });
  return {
    schema: 'setup-guide/1',
    provider: conn.provider,
    connection: {
      id: conn.id,
      displayName: conn.displayName,
      tenantId: conn.tenantId,
      tenantName: conn.tenantName,
    },
    generatedAt: new Date().toISOString(),
    notice:
      'Dev fixture guide: the real guide is generated by the api for your tenant. The gateway never changes your tenant; you apply every step yourself.',
    sections: [
      section(1, 'overview', 'Overview', [
        'The gateway reads your tenant identity and domain verification only.',
      ]),
      section(2, 'grant-access', 'Grant read-only access', [
        m365
          ? 'A Global Administrator consents to the gateway app with Organization.Read.All and Domain.Read.All.'
          : 'A super administrator authorizes the gateway service account for the two read-only directory scopes.',
      ]),
      section(3, 'domains', 'Domains', [`${domains.length} linked domain(s).`]),
      section(
        4,
        'inbound',
        'Inbound',
        ['Point MX to the gateway and accept mail from it only.'],
        [
          {
            id: 'inbound-mx',
            title: 'MX records',
            paragraphs: ['Publish these MX records for each linked domain.'],
            values: GATEWAY.mxHosts.map((h, i) => ({ label: `MX ${(i + 1) * 10}`, value: h })),
          },
          m365
            ? {
                id: 'inbound-connector',
                title: 'Inbound partner connector',
                paragraphs: ['Exchange Online PowerShell:'],
                commands: [
                  {
                    language: 'powershell',
                    code: `New-InboundConnector -Name "Email security gateway" -ConnectorType Partner -SenderDomains * -RequireTls $true -TlsSenderCertificateName ${GATEWAY.relayTlsName} -RestrictDomainsToCertificate $true`,
                  },
                ],
                attestation: attested('m365.inbound_connector_created'),
              }
            : {
                id: 'inbound-gateway',
                title: 'Inbound gateway',
                paragraphs: [
                  'Admin console → Gmail → Spam, phishing and malware → Inbound gateway.',
                ],
                values: GATEWAY.egressNetworks.map((v) => ({ label: 'Gateway IP', value: v })),
                attestation: attested('google.inbound_gateway_configured'),
              },
          {
            id: 'inbound-lockdown',
            title: 'Reject mail that bypasses the gateway',
            paragraphs: ['Lock down direct delivery so every inbound message is inspected.'],
            warning: 'Without this step attackers can deliver directly to your tenant.',
            attestation: attested(
              m365 ? 'm365.direct_delivery_locked_down' : 'google.reject_non_gateway_enabled',
            ),
          },
        ],
      ),
      section(
        5,
        'outbound',
        'Outbound',
        ['Relay outbound mail through the gateway.'],
        [
          {
            id: 'outbound-spf',
            title: 'SPF',
            paragraphs: ['Add the gateway include to your SPF record.'],
            values: [{ label: 'Include', value: GATEWAY.spfInclude }],
          },
          {
            id: 'outbound-connector',
            title: m365 ? 'Outbound connector' : 'Outbound route',
            paragraphs: ['Send outbound mail to the gateway relay hosts.'],
            values: GATEWAY.relayHosts.map((h) => ({ label: 'Smart host', value: h })),
            attestation: attested(
              m365 ? 'm365.outbound_connector_created' : 'google.outbound_route_configured',
            ),
          },
          {
            id: 'outbound-validate',
            title: 'Validate with the probe address',
            paragraphs: [`Probe domain: ${PROBE_DOMAIN}.`],
          },
        ],
      ),
      section(6, 'internal-routing', 'Internal routing', [
        conn.internalRouting
          ? 'Internal routing is on.'
          : 'Internal routing is off for this connection.',
      ]),
      section(7, 'validate-activate', 'Validate and activate', [
        'Run a full validation, then activate.',
      ]),
      section(8, 'failover', 'Failover and outages', [
        'Your provider queues and retries while the gateway is unavailable.',
      ]),
      section(9, 'disconnect', 'Disconnect and cleanup', [
        'Remove the provider-side configuration after disconnecting.',
      ]),
    ],
  };
}

function guideMarkdown(g: ReturnType<typeof guide>): string {
  const lines = [`# Setup guide: ${g.connection.displayName}`, '', g.notice, ''];
  for (const s of g.sections) {
    lines.push(`<a id="${s.id}"></a>`, `## ${s.number}. ${s.title}`, '', ...s.paragraphs, '');
    for (const step of s.steps) {
      lines.push(`<a id="${step.id}"></a>`, `### ${step.title}`, '', ...step.paragraphs, '');
      for (const v of step.values ?? []) lines.push(`- ${v.label}: \`${v.value}\``);
      for (const cmd of step.commands ?? [])
        lines.push('', `\`\`\`${cmd.language}`, cmd.code, '```');
      lines.push('');
    }
  }
  return lines.join('\n');
}

function principalUser(request: FixtureRequest): string | null {
  return request.token ? stableUuid(`user:${request.token.slice(-12)}`) : null;
}

export const fixtures: FixtureHandlers = {
  ProviderCatalogController_get_v1: guarded('ProviderCatalogController_get_v1', () =>
    ok('ProviderCatalogController_get_v1', {
      providers: (['microsoft_365', 'google_workspace'] as const).map((provider) => ({
        provider,
        displayName: provider === 'microsoft_365' ? 'Microsoft 365' : 'Google Workspace',
        profiles: [
          {
            key: PROFILE[provider],
            version: 1,
            purpose: 'mail_flow',
            title: provider === 'microsoft_365' ? 'Mail flow (read-only)' : 'Mail flow (read-only)',
            description:
              'Reads the tenant identity and the verification of your domains. Never reads mail and never changes settings.',
            permissions: PERMISSIONS[provider],
            readOnly: true,
            authMethods: METHODS[provider],
            availableAuthMethods: METHODS[provider],
          },
          {
            key: MAILBOX_PROFILE[provider],
            version: 1,
            purpose: 'mailbox_remediation',
            title: 'Mailbox access for API mode',
            description:
              'Reads new messages of in-scope mailboxes for scanning and lists users for coverage; from step API-2 moves detected threats. Separate from mail flow and account takeover response.',
            permissions: MAILBOX_PERMISSIONS[provider],
            readOnly: false,
            authMethods: METHODS[provider],
            availableAuthMethods: METHODS[provider],
          },
        ],
        attestations: ATTESTATIONS.filter((a) => a.provider === provider).map(
          ({ code, phase, statement, requiredFor }) => ({ code, phase, statement, requiredFor }),
        ),
        egressSet: {
          version: 1,
          publishedAt: '2026-06-01T00:00:00.000Z',
          importedAt: isoAgo(30 * DAY),
          rangeCount: provider === 'microsoft_365' ? 8 : 27,
        },
      })),
      probeDomain: PROBE_DOMAIN,
      gateway: GATEWAY,
    }),
  ),
  ProviderConnectionsController_list_v1: guarded(
    'ProviderConnectionsController_list_v1',
    (request, p) => {
      const org = orgState(p.organizationId);
      for (const c of org.connections) tick(p.organizationId, c);
      const provider = request.query.get('provider');
      const rows = org.connections
        .map((c) => c.connection)
        .filter((c) => !provider || c.provider === provider)
        .map((c) => ({
          id: c.id,
          provider: c.provider,
          displayName: c.displayName,
          status: c.status,
          tenantName: c.tenantName,
          outboundMode: c.outboundMode,
          internalRouting: c.internalRouting,
          health: c.health,
          healthChangedAt: c.healthChangedAt,
          domainCount: c.domainCount,
          createdAt: c.createdAt,
        }));
      return { status: 200, body: paginate(rows, request.query) };
    },
  ),
  ProviderConnectionsController_create_v1: guarded(
    'ProviderConnectionsController_create_v1',
    (request, p) =>
      keyed(request, () => {
        const org = orgState(p.organizationId);
        const body = bodyOf<RequestBody<'ProviderConnectionsController_create_v1'>>(request);
        const name = String(body.displayName ?? '').trim();
        if (!name || (body.provider !== 'microsoft_365' && body.provider !== 'google_workspace'))
          return apiError(400, 'validation_failed', ['displayName: Required']);
        if (org.connections.some((c) => c.connection.displayName === name))
          return apiError(409, 'conflict', 'A connection with this name exists');
        if (org.connections.length >= 10)
          return apiError(409, 'connection_limit', 'Connection limit reached');
        const at = new Date().toISOString();
        const id = stableUuid(`${p.organizationId}:provider-connection:${name}:${at}`);
        const created: ConnectionState = {
          connection: {
            id,
            provider: body.provider,
            displayName: name,
            status: 'draft',
            tenantName: null,
            tenantId: null,
            tenantVerifiedAt: null,
            outboundMode: 'off',
            internalRouting: false,
            health: 'unknown',
            healthChangedAt: null,
            healthCheckedAt: null,
            nextHealthCheckAt: null,
            domainCount: 0,
            createdAt: at,
            updatedAt: at,
            grants: [],
            domains: [],
            relayConnectorId: null,
            relayProof:
              body.provider === 'microsoft_365'
                ? { tenantHeader: 'required', dkimAligned: 'required' }
                : { dkimAligned: 'required', dkimMaxAgeSeconds: 3600, dkimReplayMax: 5 },
            relayProofIsDefault: true,
            attestations: [],
            routeTokenVersion: 1,
            routeTokenPendingVersion: null,
            disabledAt: null,
            rowVersion: 1,
          },
          links: [],
          runs: [],
          health: emptyHealth(id),
          routeToken: stableUuid(`${id}:route`)
            .replace(/[^a-z2-7]/g, 'a')
            .slice(0, 32),
          impactTokens: new Map(),
        };
        org.connections.unshift(created);
        return ok('ProviderConnectionsController_create_v1', created.connection, 201);
      }),
  ),
  ProviderConnectionsController_get_v1: guarded(
    'ProviderConnectionsController_get_v1',
    (request, p) => {
      const c = find(p.organizationId, request.params.id);
      if (!c) return notFound();
      tick(p.organizationId, c);
      return ok('ProviderConnectionsController_get_v1', c.connection);
    },
  ),
  ProviderConnectionsController_update_v1: guarded(
    'ProviderConnectionsController_update_v1',
    (request, p) => {
      const c = find(p.organizationId, request.params.id);
      if (!c) return notFound();
      const body = bodyOf<RequestBody<'ProviderConnectionsController_update_v1'>>(request);
      if (body.rowVersion !== c.connection.rowVersion)
        return apiError(409, 'connection_version_conflict', 'The connection changed; reload');
      const name = String(body.displayName ?? '').trim();
      if (!name) return apiError(400, 'validation_failed', ['displayName: Required']);
      c.connection.displayName = name;
      touch(c);
      return ok('ProviderConnectionsController_update_v1', c.connection);
    },
  ),
  ProviderConnectionsController_disconnect_v1: guarded(
    'ProviderConnectionsController_disconnect_v1',
    (request, p) =>
      keyed(request, () => {
        const c = find(p.organizationId, request.params.id);
        if (!c) return notFound();
        const body = bodyOf<RequestBody<'ProviderConnectionsController_disconnect_v1'>>(request);
        const set = changeSetOf(p.organizationId, c, { kind: 'disable' });
        if (isResponse(set)) return set;
        const stored = c.impactTokens.get(String(body.impactToken));
        if (
          !stored ||
          stored.rowVersion !== c.connection.rowVersion ||
          stored.expiresAt < Date.now() ||
          stored.changeSet !== JSON.stringify(set)
        )
          return apiError(
            409,
            'impact_changed',
            'The impact token is invalid or the change set changed; preview again',
          );
        applyChange(p.organizationId, c, { kind: 'disable' }, set, principalUser(request));
        return ok('ProviderConnectionsController_disconnect_v1', {
          connection: c.connection,
          providerCleanupSteps:
            c.connection.provider === 'microsoft_365'
              ? [
                  'Remove the outbound connector "Email security gateway outbound" and the internal-routing transport rules.',
                  'Remove the enterprise application of the gateway in Microsoft Entra (Enterprise applications).',
                ]
              : [
                  'Remove the outbound route or routing rule that points to the gateway.',
                  'Remove the gateway client from domain-wide delegation in the Admin console.',
                ],
          destinationsKept: true,
        });
      }),
  ),
  ProviderConnectionsController_wizard_v1: guarded(
    'ProviderConnectionsController_wizard_v1',
    (request, p) => {
      const c = find(p.organizationId, request.params.id);
      if (!c) return notFound();
      tick(p.organizationId, c);
      return ok('ProviderConnectionsController_wizard_v1', wizardOf(c));
    },
  ),
  ProviderGrantsController_create_v1: guarded('ProviderGrantsController_create_v1', (request, p) =>
    keyed(
      request,
      () => {
        const org = orgState(p.organizationId);
        const c = find(p.organizationId, request.params.id);
        if (!c) return notFound();
        const body = bodyOf<RequestBody<'ProviderGrantsController_create_v1'>>(request);
        const conn = c.connection;
        const gate = mailboxGate(body.profile, p.permissions);
        if (gate) return gate;
        if (
          body.profile !== PROFILE[conn.provider] &&
          body.profile !== MAILBOX_PROFILE[conn.provider]
        )
          return apiError(422, 'auth_method_not_allowed', 'Unknown profile');
        const method = body.authMethod ?? 'platform_app';
        if (!METHODS[conn.provider].includes(method))
          return apiError(422, 'auth_method_not_allowed', 'Method not allowed');
        if (conn.grants.some((g) => g.profile === body.profile && g.status !== 'revoked'))
          return apiError(409, 'grant_exists', 'A grant of this profile exists');
        const at = new Date().toISOString();
        conn.grants = conn.grants.filter((g) => g.profile !== body.profile);
        const grant = grantOf(
          conn.id,
          conn.provider,
          method,
          'pending_consent',
          at,
          String(body.profile),
        );
        conn.grants.push(grant);
        if (conn.status === 'draft') conn.status = 'connecting';
        touch(c);
        if (method === 'platform_app') {
          const stateValue = stableUuid(`${conn.id}:consent:${at}`)
            .replace(/-/g, '')
            .padEnd(43, 'A')
            .slice(0, 43);
          org.consentStates.set(stateValue, {
            connectionId: conn.id,
            profile: grant.profile,
            used: false,
          });
          return ok(
            'ProviderGrantsController_create_v1',
            {
              grant,
              next: 'consent',
              // Dev fixtures never leave the portal: "Microsoft" redirects straight back.
              consent: {
                consentUrl: `/integrations/providers/consent-callback?admin_consent=True&tenant=22222222-3333-4444-5555-666666666666&state=${stateValue}`,
                expiresAt: new Date(Date.now() + 10 * MINUTE).toISOString(),
              },
              delegation: null,
            },
            201,
          );
        }
        return ok(
          'ProviderGrantsController_create_v1',
          {
            grant,
            next: method === 'platform_service_account' ? 'delegation' : 'credentials',
            consent: null,
            delegation:
              method === 'platform_service_account'
                ? {
                    clientId: grant.clientId ?? '',
                    scopes: permissionsOf('google_workspace', String(body.profile)),
                    adminConsoleSteps: [
                      'Open the Google Admin console → Security → Access and data control → API controls → Manage domain-wide delegation.',
                      'Add new: enter the client ID and the two OAuth scopes below, then Authorize.',
                      'Enter a delegated administrator below and confirm.',
                    ],
                  }
                : null,
          },
          201,
        );
      },
      (response) => {
        const body = response.body as { consent?: { consentUrl: string | null } | null };
        return body.consent
          ? { ...response, body: { ...body, consent: { ...body.consent, consentUrl: null } } }
          : response;
      },
    ),
  ),
  ProviderGrantsController_completeConsent_v1: guarded(
    'ProviderGrantsController_completeConsent_v1',
    (request, p) =>
      keyed(request, () => {
        const org = orgState(p.organizationId);
        const body = bodyOf<RequestBody<'ProviderGrantsController_completeConsent_v1'>>(request);
        const entry = org.consentStates.get(String(body.state));
        if (!entry || entry.used)
          return apiError(
            404,
            'consent_state_invalid',
            'The consent state is invalid, expired or used',
          );
        entry.used = true;
        const c = find(p.organizationId, entry.connectionId);
        const grant = c?.connection.grants.find(
          (g) => g.profile === entry.profile && g.status === 'pending_consent',
        );
        if (!c || !grant)
          return apiError(404, 'consent_state_invalid', 'The consent state is invalid');
        const at = new Date().toISOString();
        if (body.error) {
          Object.assign(grant, {
            status: 'error',
            lastErrorCode: 'consent_declined',
            updatedAt: at,
          });
        } else {
          Object.assign(grant, {
            status: 'verifying',
            consentedAt: at,
            verifyRequestedAt: at,
            updatedAt: at,
          });
        }
        touch(c);
        return ok('ProviderGrantsController_completeConsent_v1', {
          connectionId: c.connection.id,
          grantId: grant.id,
          status: grant.status,
        });
      }),
  ),
  ProviderGrantsController_setCredentials_v1: guarded(
    'ProviderGrantsController_setCredentials_v1',
    (request, p) =>
      keyed(request, () => {
        const gate = mailboxGate(request.params.profile, p.permissions);
        if (gate) return gate;
        const c = find(p.organizationId, request.params.id);
        if (!c) return notFound();
        const grant = c.connection.grants.find(
          (g) => g.profile === request.params.profile && g.status !== 'revoked',
        );
        if (!grant) return apiError(404, 'grant_not_found', 'Grant not found');
        if (
          grant.authMethod !== 'customer_app_secret' &&
          grant.authMethod !== 'customer_service_account'
        )
          return apiError(
            422,
            'auth_method_not_allowed',
            'Credentials are only for customer methods',
          );
        const body = request.body as Record<string, unknown> | null;
        const valid =
          grant.authMethod === 'customer_app_secret'
            ? typeof body?.clientSecret === 'string' &&
              typeof body.clientId === 'string' &&
              typeof body.tenantId === 'string'
            : typeof body?.serviceAccountKey === 'object' && typeof body.subjectEmail === 'string';
        if (!valid) return apiError(422, 'credential_invalid', 'The credentials are incomplete');
        const at = new Date().toISOString();
        // Nothing of the credential is kept: only a fingerprint of the version.
        Object.assign(grant, {
          status: 'verifying',
          clientId: typeof body?.clientId === 'string' ? body.clientId : grant.clientId,
          subjectEmail:
            typeof body?.subjectEmail === 'string'
              ? `${body.subjectEmail.slice(0, 1)}•••@${body.subjectEmail.split('@')[1] ?? ''}`
              : grant.subjectEmail,
          credentialVersion: grant.credentialVersion + 1,
          credentialFingerprint: fingerprint(`${grant.id}:${grant.credentialVersion + 1}`),
          credentialSetAt: at,
          credentialExpiresAt: typeof body?.expiresAt === 'string' ? body.expiresAt : null,
          verifyRequestedAt: at,
          lastErrorCode: null,
          updatedAt: at,
        });
        touch(c);
        return ok('ProviderGrantsController_setCredentials_v1', grant);
      }),
  ),
  ProviderGrantsController_verify_v1: guarded('ProviderGrantsController_verify_v1', (request, p) =>
    keyed(request, () => {
      const gate = mailboxGate(request.params.profile, p.permissions);
      if (gate) return gate;
      const c = find(p.organizationId, request.params.id);
      if (!c) return notFound();
      const grant = c.connection.grants.find(
        (g) => g.profile === request.params.profile && g.status !== 'revoked',
      );
      if (!grant) return apiError(404, 'grant_not_found', 'Grant not found');
      const body = bodyOf<RequestBody<'ProviderGrantsController_verify_v1'>>(request);
      if (
        grant.authMethod === 'platform_service_account' &&
        !body.subjectEmail &&
        !grant.subjectEmail
      )
        return apiError(422, 'credential_invalid', 'subjectEmail is required');
      const at = new Date().toISOString();
      Object.assign(grant, {
        status: 'verifying',
        verifyRequestedAt: at,
        lastErrorCode: null,
        updatedAt: at,
        ...(body.subjectEmail
          ? {
              subjectEmail: `${body.subjectEmail.slice(0, 1)}•••@${body.subjectEmail.split('@')[1] ?? ''}`,
              consentedAt: at,
            }
          : {}),
      });
      touch(c);
      return ok('ProviderGrantsController_verify_v1', grant);
    }),
  ),
  ProviderGrantsController_revoke_v1: guarded('ProviderGrantsController_revoke_v1', (request, p) =>
    keyed(request, () => {
      const gate = mailboxGate(request.params.profile, p.permissions);
      if (gate) return gate;
      const c = find(p.organizationId, request.params.id);
      if (!c) return notFound();
      const grant = c.connection.grants.find(
        (g) => g.profile === request.params.profile && g.status !== 'revoked',
      );
      if (!grant) return apiError(404, 'grant_not_found', 'Grant not found');
      if (c.connection.outboundMode === 'active' && !isMailboxProfile(grant.profile))
        return apiError(409, 'outbound_active', 'Disable outbound routing first');
      Object.assign(grant, {
        status: 'revoked',
        credentialFingerprint: null,
        updatedAt: new Date().toISOString(),
      });
      touch(c);
      return ok('ProviderGrantsController_revoke_v1', {
        grant,
        providerRemovalSteps:
          c.connection.provider === 'microsoft_365'
            ? ['Microsoft Entra admin center → Enterprise applications → the gateway app → Delete.']
            : [
                'Admin console → Security → API controls → Domain-wide delegation → remove the gateway client.',
              ],
      });
    }),
  ),
  ProviderDomainsController_list_v1: guarded('ProviderDomainsController_list_v1', (request, p) => {
    const c = find(p.organizationId, request.params.id);
    if (!c) return notFound();
    tick(p.organizationId, c);
    return ok('ProviderDomainsController_list_v1', { data: linkedDomains(p.organizationId, c) });
  }),
  ProviderDomainsController_replace_v1: guarded(
    'ProviderDomainsController_replace_v1',
    (request, p) =>
      keyed(request, () => {
        const org = orgState(p.organizationId);
        const c = find(p.organizationId, request.params.id);
        if (!c) return notFound();
        const body = bodyOf<RequestBody<'ProviderDomainsController_replace_v1'>>(request);
        const ids = [...new Set(body.domainIds ?? [])];
        const all = domainsOf(p.organizationId);
        for (const id of ids) {
          const entry = all.find((e) => e.domain.id === id && !e.deleted);
          if (!entry) return apiError(404, 'domain_not_in_organization', 'Domain not found');
          if (entry.domain.status !== 'active')
            return apiError(422, 'domain_not_verified', `${entry.domain.name} is not verified`);
          if (
            org.connections.some(
              (o) =>
                o !== c &&
                o.connection.status !== 'disabled' &&
                o.links.some((l) => l.domainId === id),
            )
          )
            return apiError(
              409,
              'domain_linked_elsewhere',
              `${entry.domain.name} is linked to another connection`,
            );
        }
        c.links = ids.map(
          (id) =>
            c.links.find((l) => l.domainId === id) ?? {
              domainId: id,
              providerVerification: 'unknown',
              providerCheckedAt: null,
              providerMxHost: null,
              destination: CUSTOM_SERVERS,
              inboundAppliedAt: null,
            },
        );
        touch(c);
        tick(p.organizationId, c);
        return ok('ProviderDomainsController_replace_v1', {
          data: linkedDomains(p.organizationId, c),
        });
      }),
  ),
  ProviderMailFlowController_preview_v1: guarded(
    'ProviderMailFlowController_preview_v1',
    (request, p) => {
      const c = find(p.organizationId, request.params.id);
      if (!c) return notFound();
      const body = bodyOf<RequestBody<'ProviderMailFlowController_preview_v1'>>(request);
      if (!body.change) return apiError(400, 'validation_failed', ['change: Required']);
      const set = changeSetOf(p.organizationId, c, body.change);
      if (isResponse(set)) return set;
      const token = `${stableUuid(`${c.connection.id}:${Date.now()}:${Math.random()}`).replace(/-/g, '')}.${Math.floor(Date.now() / 1000) + 900}`;
      c.impactTokens.set(token, {
        changeSet: JSON.stringify(set),
        rowVersion: c.connection.rowVersion,
        expiresAt: Date.now() + 900_000,
      });
      const warnings: string[] = [];
      if (
        body.change.kind === 'inbound' &&
        set.domains.some(
          (d) =>
            c.links.find((l) => l.domainId === d.domainId)?.providerVerification !== 'verified',
        )
      )
        warnings.push('domain_not_provider_verified');
      return ok('ProviderMailFlowController_preview_v1', {
        change: body.change,
        changeSet: set,
        impactToken: token,
        expiresAt: new Date(Date.now() + 900_000).toISOString(),
        warnings,
      });
    },
  ),
  ProviderMailFlowController_apply_v1: guarded(
    'ProviderMailFlowController_apply_v1',
    (request, p) =>
      keyed(request, () => {
        const c = find(p.organizationId, request.params.id);
        if (!c) return notFound();
        const body = bodyOf<RequestBody<'ProviderMailFlowController_apply_v1'>>(request);
        if (body.confirm !== true || !body.change)
          return apiError(422, 'confirmation_required', 'confirm must be true');
        const set = changeSetOf(p.organizationId, c, body.change);
        if (isResponse(set)) return set;
        const stored = c.impactTokens.get(String(body.impactToken));
        if (
          !stored ||
          stored.rowVersion !== c.connection.rowVersion ||
          stored.expiresAt < Date.now() ||
          stored.changeSet !== JSON.stringify(set)
        )
          return apiError(
            409,
            'impact_changed',
            'The impact token is invalid or the change set changed; preview again',
          );
        applyChange(p.organizationId, c, body.change, set, principalUser(request));
        return ok('ProviderMailFlowController_apply_v1', {
          connection: c.connection,
          changeSet: set,
          appliedAt: new Date().toISOString(),
        });
      }),
  ),
  ProviderMailFlowController_get_v1: guarded('ProviderMailFlowController_get_v1', (request, p) => {
    const c = find(p.organizationId, request.params.id);
    if (!c) return notFound();
    const manage = p.permissions.includes('integration:manage');
    const conn = c.connection;
    return ok('ProviderMailFlowController_get_v1', {
      connectionId: conn.id,
      outboundMode: conn.outboundMode,
      internalRouting: conn.internalRouting,
      relayProof: conn.relayProof,
      relayProofIsDefault: conn.relayProofIsDefault,
      relayConnector: conn.relayConnectorId
        ? { id: conn.relayConnectorId, status: conn.outboundMode === 'off' ? 'disabled' : 'active' }
        : null,
      domains: linkedDomains(p.organizationId, c).map((d) => ({
        id: d.id,
        name: d.name,
        destinations: c.links.find((l) => l.domainId === d.id)?.destination ?? CUSTOM_SERVERS,
        inboundAppliedAt: d.inboundAppliedAt,
        dns: { mx: d.dns.mx, spf: d.dns.spf },
      })),
      relayActivity24h: {
        accepted: conn.outboundMode === 'active' ? 412 : 0,
        proofFailed: conn.outboundMode === 'active' ? 1 : 0,
        tempFailed: 0,
        probes: conn.outboundMode === 'off' ? 0 : 1,
        lastAcceptedAt: conn.outboundMode === 'active' ? isoAgo(4 * MINUTE) : null,
      },
      routeToken: {
        version: conn.routeTokenVersion,
        pendingVersion: conn.routeTokenPendingVersion,
        value: manage ? c.routeToken : null,
        masked: `••••${c.routeToken.slice(-4)}`,
      },
    });
  }),
  ProviderAttestationsController_record_v1: guarded(
    'ProviderAttestationsController_record_v1',
    (request, p) =>
      keyed(request, () => {
        const c = find(p.organizationId, request.params.id);
        if (!c) return notFound();
        const body = bodyOf<RequestBody<'ProviderAttestationsController_record_v1'>>(request);
        const def = ATTESTATIONS.find(
          (a) => a.code === body.code && a.provider === c.connection.provider,
        );
        if (!def) return apiError(422, 'attestation_unknown', 'Unknown attestation code');
        c.connection.attestations = c.connection.attestations.filter((a) => a.code !== def.code);
        if (body.attested)
          c.connection.attestations.push({
            code: def.code,
            userId: principalUser(request),
            at: new Date().toISOString(),
          });
        touch(c);
        return ok('ProviderAttestationsController_record_v1', {
          connectionId: c.connection.id,
          attestations: c.connection.attestations,
          rowVersion: c.connection.rowVersion,
        });
      }),
  ),
  ProviderValidationsController_create_v1: guarded(
    'ProviderValidationsController_create_v1',
    (request, p) =>
      keyed(
        request,
        () => {
          const c = find(p.organizationId, request.params.id);
          if (!c) return notFound();
          const body = bodyOf<RequestBody<'ProviderValidationsController_create_v1'>>(request);
          const kind = body.kind ?? 'full';
          const at = new Date().toISOString();
          const probe =
            (kind === 'full' || kind === 'outbound') && c.connection.outboundMode !== 'off';
          const token = stableUuid(`${c.connection.id}:probe:${at}`)
            .replace(/[^a-z2-7]/g, 'q')
            .slice(0, 26);
          const run: Run = {
            id: stableUuid(`${c.connection.id}:run:${at}`),
            kind,
            status: 'queued',
            requestedBy: { type: 'user', id: principalUser(request) },
            probeExpiresAt: probe ? new Date(Date.now() + DAY).toISOString() : null,
            summary: null,
            startedAt: null,
            completedAt: null,
            createdAt: at,
            results: [],
            probeObservations: [],
          };
          c.runs.unshift(run);
          const { results: _r, probeObservations: _o, ...view } = run;
          void _r;
          void _o;
          return ok(
            'ProviderValidationsController_create_v1',
            { ...view, probeAddress: probe ? `eg-probe-${token}@${PROBE_DOMAIN}` : null },
            201,
          );
        },
        (response) => ({ ...response, body: { ...(response.body as object), probeAddress: null } }),
      ),
  ),
  ProviderValidationsController_list_v1: guarded(
    'ProviderValidationsController_list_v1',
    (request, p) => {
      const c = find(p.organizationId, request.params.id);
      if (!c) return notFound();
      tick(p.organizationId, c);
      const kinds = request.query.get('kind')?.split(',').filter(Boolean) ?? [];
      const rows = c.runs
        .filter((r) => kinds.length === 0 || kinds.includes(r.kind))
        .map(({ results: _r, probeObservations: _o, ...view }) => view);
      return { status: 200, body: paginate(rows, request.query) };
    },
  ),
  ProviderValidationsController_get_v1: guarded(
    'ProviderValidationsController_get_v1',
    (request, p) => {
      const c = find(p.organizationId, request.params.id);
      if (!c) return notFound();
      tick(p.organizationId, c);
      const run = c.runs.find((r) => r.id === request.params.runId);
      return run
        ? ok('ProviderValidationsController_get_v1', run)
        : apiError(404, 'validation_run_not_found', 'Validation run not found');
    },
  ),
  ProviderHealthController_get_v1: guarded('ProviderHealthController_get_v1', (request, p) => {
    const c = find(p.organizationId, request.params.id);
    if (!c) return notFound();
    return ok('ProviderHealthController_get_v1', c.health);
  }),
  ProviderHealthController_checkNow_v1: guarded(
    'ProviderHealthController_checkNow_v1',
    (request, p) =>
      keyed(request, () => {
        const c = find(p.organizationId, request.params.id);
        if (!c) return notFound();
        const at = new Date().toISOString();
        c.connection.nextHealthCheckAt = at;
        if (c.connection.status === 'active') {
          c.health = {
            ...c.health,
            checkedAt: at,
            nextCheckAt: new Date(Date.now() + 15 * MINUTE).toISOString(),
            checks: healthChecks(c, 'pass'),
          };
        }
        return ok(
          'ProviderHealthController_checkNow_v1',
          { connectionId: c.connection.id, nextHealthCheckAt: at },
          202,
        );
      }),
  ),
  ProviderGuideController_get_v1: guarded('ProviderGuideController_get_v1', (request, p) => {
    const c = find(p.organizationId, request.params.id);
    if (!c) return notFound();
    const g = guide(c, p.organizationId);
    if (request.query.get('format') === 'markdown') {
      const slug = c.connection.displayName
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-|-$/g, '');
      return {
        status: 200,
        body: guideMarkdown(g),
        headers: {
          'content-type': 'text/markdown; charset=utf-8',
          'content-disposition': `attachment; filename="setup-${c.connection.provider.replace('_', '-')}-${slug}.md"`,
        },
      };
    }
    return ok('ProviderGuideController_get_v1', g);
  }),
};
