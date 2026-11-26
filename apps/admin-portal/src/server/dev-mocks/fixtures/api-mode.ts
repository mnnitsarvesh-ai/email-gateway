import 'server-only';
import type { OperationId, RequestBody, SuccessBody } from '@/lib/api/types';
import { SeededRandom, paginate, stableUuid } from '../generator';
import {
  apiError,
  ok,
  type FixtureHandlers,
  type FixtureRequest,
  type FixtureResponse,
} from '../types';
import {
  DAY,
  HOUR,
  MINUTE,
  findDomain,
  guarded,
  idempotent,
  isoAgo,
  refreshDomainModes,
} from './domains';
import {
  effectiveMode,
  entitledPlan,
  liveDomains,
  organizationModeView,
  planOf,
  setOrganizationMode,
} from './protection-modes';
import { MAILBOX_PROFILE, providerConnectionsOf } from './provider-connections';

export { DEV_MOCK_MARKER } from '../types';

/**
 * Dev fixtures of API-mode protection (step API-1 WP6, design D2, D10–D12): the organization and
 * domain protection modes (entitlement, MX conflict, inherit, unchanged = no change), and the 11
 * `/api-mode` operations over the 8.2 connections of the provider-connections fixture (grant
 * status from there), with mailboxes, detections, health checks, counters and the setup guide.
 * Synthetic only (`*.example.test`), per organization, deterministic, cursor pagination; never a
 * cursor, subscription id or client state in a view.
 */

export const API_MODE_OPERATIONS: readonly OperationId[] = [
  'ProtectionModeController_getOrganization_v1',
  'ProtectionModeController_putOrganization_v1',
  'ProtectionModeController_putDomain_v1',
  'ApiModeController_overview_v1',
  'ApiModeController_listConnections_v1',
  'ApiModeController_getConnection_v1',
  'ApiModeController_setupGuide_v1',
  'ApiModeController_updateSettings_v1',
  'ApiModeController_inventorySync_v1',
  'ApiModeController_listMailboxes_v1',
  'ApiModeController_getMailbox_v1',
  'ApiModeController_resyncMailbox_v1',
  'ApiModeController_listDetections_v1',
  'ApiModeController_getDetection_v1',
];

type ConnectionView = SuccessBody<'ApiModeController_getConnection_v1'>;
type ConnectionRow = SuccessBody<'ApiModeController_listConnections_v1'>['data'][number];
type Mailbox = SuccessBody<'ApiModeController_getMailbox_v1'>;
type Detection = SuccessBody<'ApiModeController_getDetection_v1'>;
type Health = ConnectionRow['health']['status'];

interface ApiConnectionState {
  apiConnectionId: string;
  feedsEnabled: boolean;
  feedMode: 'poll' | 'notify';
  feedsEnabledAt: string | null;
  inventoryStatus: ConnectionRow['inventoryStatus'];
  inventorySyncedAt: string | null;
  inventoryRequestedAt: string | null;
  health: Health;
  healthChangedAt: string | null;
  throttledUntil: string | null;
  rowVersion: number;
}

interface OrgApiState {
  connections: Map<string, ApiConnectionState>;
  mailboxes: Mailbox[];
  detections: Detection[];
}

interface ApiModeFixtureState {
  orgs: Map<string, OrgApiState>;
  idempotency: Map<string, FixtureResponse>;
}

const store = globalThis as typeof globalThis & { __egDevFixtureApiMode?: ApiModeFixtureState };
const state: ApiModeFixtureState = (store.__egDevFixtureApiMode ??= {
  orgs: new Map(),
  idempotency: new Map(),
});

export function resetApiModeFixtures(): void {
  state.orgs.clear();
  state.idempotency.clear();
}

const VERDICTS: Detection['verdict'][] = [
  'clean',
  'clean',
  'spam',
  'clean',
  'phishing',
  'clean',
  'malware',
  'suspicious',
  'clean',
  'bulk',
];

/** API-mode domains of the organization (effective api or hybrid, live). */
function apiDomains(organizationId: string) {
  return liveDomains(organizationId).filter(
    (d) => effectiveMode(organizationId, d.configured) !== 'inline',
  );
}

function seedOrg(organizationId: string): OrgApiState {
  const random = new SeededRandom(`${organizationId}:api-mode`);
  const connections = providerConnectionsOf(organizationId);
  const org: OrgApiState = { connections: new Map(), mailboxes: [], detections: [] };
  connections.forEach((c, index) => {
    const grant = c.grants.find((g) => g.profile === MAILBOX_PROFILE[c.provider]);
    const active = grant?.status === 'active';
    org.connections.set(c.id, {
      apiConnectionId: stableUuid(`${c.id}:api-mode`),
      feedsEnabled: active && index === 0,
      feedMode: 'poll',
      feedsEnabledAt: active && index === 0 ? isoAgo(5 * DAY) : null,
      inventoryStatus: active ? 'ok' : 'never',
      inventorySyncedAt: active ? isoAgo(2 * HOUR) : null,
      inventoryRequestedAt: null,
      health: active ? 'degraded' : 'unknown',
      healthChangedAt: active ? isoAgo(DAY) : null,
      throttledUntil: null,
      rowVersion: 3,
    });
  });
  const first = connections[0];
  const domains = apiDomains(organizationId);
  if (first && domains.length > 0) {
    const people = ['ana', 'ben', 'chen', 'dana', 'eli', 'fay', 'gus', 'hana', 'ivo', 'jo'];
    org.mailboxes = people.map((person, i) => {
      const domain = domains[i % domains.length]!;
      const coverage: Mailbox['coverage'] = i === 7 ? 'gap' : i === 9 ? 'out_of_scope' : 'covered';
      return {
        id: stableUuid(`${organizationId}:mailbox:${i}`),
        connectionId: first.id,
        address: `${person}@${domain.name}`,
        domain: { id: domain.id, name: domain.name },
        status: i === 9 ? 'disabled' : 'active',
        coverage,
        coverageChangedAt: isoAgo((i + 1) * HOUR),
        feedStatus: i === 7 ? 'error' : i === 9 ? 'off' : 'active',
        journalLastSeenAt: i % 3 === 0 ? isoAgo(i * 10 * MINUTE + MINUTE) : null,
        lastSyncAt: i === 9 ? null : isoAgo(3 * MINUTE),
        lastErrorCode: i === 7 ? 'rate_budget' : null,
        aliases: i === 0 ? [`a.${person}@${domain.name}`] : [],
        feedStartedAt: isoAgo(5 * DAY),
        notifications: { subscribed: false, expiresAt: null },
        lastChangeAt: isoAgo(20 * MINUTE),
        lastGapAt: null,
        consecutiveFailures: i === 7 ? 3 : 0,
        recentDetections: [],
      };
    });
    org.detections = Array.from({ length: 36 }, (_, i) => {
      const mailbox = org.mailboxes[i % 9]!;
      const receivedAt = isoAgo(i * 47 * MINUTE + random.int(1, 30) * MINUTE);
      const verdict = VERDICTS[i % VERDICTS.length] ?? 'clean';
      const lag = random.int(20, 900) * 1000;
      const source: Detection['source'] = i % 4 === 0 ? 'graph' : 'journal';
      return {
        id: stableUuid(`${organizationId}:detection:${i}`),
        mailboxId: mailbox.id,
        mailboxAddress: mailbox.address,
        connectionId: first.id,
        source,
        seenJournal: source === 'journal' || i % 8 === 0,
        seenApi: source === 'graph',
        status: i === 5 ? 'too_large' : 'scanned',
        verdict: i === 5 ? null : verdict,
        riskScore: i === 5 ? null : verdict === 'clean' ? random.int(0, 120) : random.int(400, 980),
        verdictAuthority: i % 11 === 0 ? 'inline' : 'copy',
        receivedAt,
        providerDeliveredAt: new Date(Date.parse(receivedAt) - lag / 2).toISOString(),
        verdictAt: i === 5 ? null : new Date(Date.parse(receivedAt) + lag / 2).toISOString(),
        lagMs: i === 5 ? null : lag,
        subject: null,
        subjectMasked: true,
        headerFrom: `s•••@sender-${i % 5}.example.test`,
        direction: 'inbound',
        deliveredBasis: source === 'graph' ? 'graph_received' : 'received_header',
        reasonCodes: verdict === 'clean' ? [] : ['url.reputation_malicious', 'auth.dmarc_fail'],
      };
    });
    for (const mailbox of org.mailboxes)
      mailbox.recentDetections = org.detections
        .filter((d) => d.mailboxId === mailbox.id)
        .slice(0, 20)
        .map(({ direction: _d, deliveredBasis: _b, reasonCodes: _r, ...rest }) => rest);
  }
  return org;
}

function orgState(organizationId: string): OrgApiState {
  let org = state.orgs.get(organizationId);
  if (!org) {
    org = seedOrg(organizationId);
    state.orgs.set(organizationId, org);
  }
  // Connections created after the seed get their defaults lazily (as the api does).
  for (const c of providerConnectionsOf(organizationId)) {
    if (!org.connections.has(c.id))
      org.connections.set(c.id, {
        apiConnectionId: stableUuid(`${c.id}:api-mode`),
        feedsEnabled: false,
        feedMode: 'poll',
        feedsEnabledAt: null,
        inventoryStatus: 'never',
        inventorySyncedAt: null,
        inventoryRequestedAt: null,
        health: 'unknown',
        healthChangedAt: null,
        throttledUntil: null,
        rowVersion: 1,
      });
  }
  return org;
}

function coverageOf(mailboxes: readonly Mailbox[], total: number | null) {
  const active = mailboxes.filter((m) => m.status === 'active');
  const covered = active.filter((m) => m.coverage === 'covered').length;
  const gap = active.filter((m) => m.coverage === 'gap').length;
  return {
    covered,
    gap,
    total,
    percent:
      total === null || covered + gap === 0
        ? null
        : Math.floor((covered / (covered + gap)) * 1000) / 10,
  };
}

function failingChecksOf(health: Health): string[] {
  return health === 'degraded'
    ? ['coverage.percent', 'feeds.errors']
    : health === 'failing'
      ? ['mailbox_access.grant']
      : [];
}

function rowOf(organizationId: string, connectionId: string): ConnectionRow | null {
  const connection = providerConnectionsOf(organizationId).find((c) => c.id === connectionId);
  if (!connection) return null;
  const s = orgState(organizationId).connections.get(connection.id)!;
  const grant = connection.grants.find(
    (g) => g.profile === MAILBOX_PROFILE[connection.provider] && g.status !== 'revoked',
  );
  const mailboxes = orgState(organizationId).mailboxes.filter(
    (m) => m.connectionId === connection.id,
  );
  return {
    id: connection.id,
    apiConnectionId: s.apiConnectionId,
    displayName: connection.displayName,
    provider: connection.provider,
    status: connection.status,
    bound: connection.tenantId !== null,
    feedsEnabled: s.feedsEnabled,
    feedMode: s.feedMode,
    feedsEnabledAt: s.feedsEnabledAt,
    inventoryStatus: s.inventoryStatus,
    inventorySyncedAt: s.inventorySyncedAt,
    inventoryRequestedAt: s.inventoryRequestedAt,
    mailboxesTotal:
      s.inventoryStatus === 'ok' ? mailboxes.filter((m) => m.status === 'active').length : null,
    health: { status: s.health, changedAt: s.healthChangedAt },
    throttledUntil: s.throttledUntil,
    lastErrorCode: null,
    grant: grant
      ? { profile: grant.profile, status: grant.status, authMethod: grant.authMethod }
      : null,
    journalSources:
      connection.provider === 'microsoft_365'
        ? [
            {
              id: stableUuid(`${connection.id}:journal-source`),
              displayName: 'Exchange journal rule (fixture)',
              kind: 'm365_journal',
              status: 'active',
              health: 'healthy',
              verified: true,
            },
          ]
        : [],
    rowVersion: s.rowVersion,
  };
}

function lagOf(seed: number) {
  return {
    p50Seconds1h: 45 + (seed % 3) * 15,
    p95Seconds1h: 240 + (seed % 5) * 60,
    p50Seconds24h: 60,
    p95Seconds24h: 420,
  };
}

function detailOf(organizationId: string, row: ConnectionRow): ConnectionView {
  const mailboxes = orgState(organizationId).mailboxes.filter((m) => m.connectionId === row.id);
  const grantActive = row.grant?.status === 'active';
  const journalOk = row.journalSources.some((j) => j.verified);
  const domains = apiDomains(organizationId).length > 0;
  const step = (
    name: ConnectionView['wizard']['steps'][number]['step'],
    status: ConnectionView['wizard']['steps'][number]['status'],
    blockers: string[] = [],
  ) => ({ step: name, status, blockers });
  const steps = [
    domains ? step('domains', 'done') : step('domains', 'not_started', ['no_api_mode_domain']),
    row.status === 'active' && row.bound
      ? step('connection', 'done')
      : step('connection', 'in_progress', [
          row.bound ? 'connection_not_active' : 'connection_not_bound',
        ]),
    journalOk
      ? step('journal', 'done')
      : step('journal', 'not_started', ['journal_source_missing']),
    grantActive
      ? step('mailbox_access', 'done')
      : step('mailbox_access', 'not_started', ['grant_missing']),
    !row.feedsEnabled
      ? step('feeds', 'skipped')
      : grantActive
        ? step('feeds', 'done')
        : step('feeds', 'blocked', ['mailbox_access']),
    row.health.status === 'healthy' || row.health.status === 'degraded'
      ? step('monitor', 'done')
      : step('monitor', 'in_progress', ['health_unknown']),
  ];
  const next = steps.find(
    (s) => s.status !== 'done' && s.status !== 'skipped' && s.status !== 'blocked',
  );
  const actions: Record<string, string> = {
    domains: 'set_domain_api_mode',
    connection: 'bind_connection',
    journal: 'configure_journal',
    mailbox_access: 'grant_mailbox_access',
    feeds: 'wait_for_feeds',
    monitor: 'review_health',
  };
  return {
    ...row,
    coverage: coverageOf(mailboxes, row.mailboxesTotal),
    wizard: {
      steps,
      nextAction: next ? { step: next.step, action: actions[next.step] ?? next.step } : null,
    },
    healthChecks:
      row.health.status === 'unknown'
        ? []
        : [
            { code: 'connection.active', status: 'pass', evidence: null },
            { code: 'intake.present', status: 'pass', evidence: 'journal source verified' },
            {
              code: 'coverage.percent',
              status: row.health.status === 'degraded' ? 'warn' : 'pass',
              evidence: 'covered 8 of 9 active mailboxes',
            },
            {
              code: 'feeds.errors',
              status: row.health.status === 'degraded' ? 'warn' : 'pass',
              evidence: '1 of 9 feed mailboxes in error',
            },
            { code: 'lag.p95_1h', status: 'pass', evidence: 'p95 300 s' },
          ],
    counters: Array.from({ length: 7 }, (_, i) => ({
      day: isoAgo(i * DAY).slice(0, 10),
      journalCopies: 40 + i * 3,
      feedCopies: row.feedsEnabled ? 12 + i : 0,
      duplicates: row.feedsEnabled ? 30 : 0,
      skippedInternal: 2,
      tooLarge: i === 0 ? 1 : 0,
      providerRequests: row.feedsEnabled ? 900 : 0,
      throttled429: i === 1 ? 2 : 0,
      throttled503: 0,
      providerErrors: 0,
      cursorResets: 0,
      lagCount: 50,
      lagP95Seconds: 300,
    })),
  };
}

const connectionNotFound = () =>
  apiError(404, 'api_mode_connection_not_found', 'API-mode connection not found');

function keyed(request: FixtureRequest, run: () => FixtureResponse): FixtureResponse {
  return idempotent(state.idempotency, request, run);
}

function reasonInvalid(reason: unknown): FixtureResponse | null {
  const text = typeof reason === 'string' ? reason.trim() : '';
  return text.length < 1 || text.length > 500
    ? apiError(400, 'validation_failed', ['reason: 1 to 500 characters'])
    : null;
}

const MODES = new Set(['inline', 'api', 'hybrid']);

function guideOf(row: ConnectionRow): SuccessBody<'ApiModeController_setupGuide_v1'> {
  const m365 = row.provider === 'microsoft_365';
  const permissions = m365
    ? ['Mail.ReadWrite', 'User.Read.All']
    : [
        'https://www.googleapis.com/auth/gmail.modify',
        'https://www.googleapis.com/auth/admin.directory.user.readonly',
      ];
  return {
    schema: 'api-mode-guide/1',
    provider: row.provider,
    connection: { id: row.id, displayName: row.displayName },
    notice:
      'Written for this connection (fixture). Nothing in this guide changes mail flow: the MX records stay with your provider.',
    sections: [
      {
        id: 'overview',
        number: 1,
        title: 'How API mode works',
        paragraphs: [
          'The gateway scans a copy of each delivered message: the journal copy, or the message read from the mailbox when no copy was seen.',
        ],
        steps: [],
      },
      {
        id: 'mailbox-access',
        number: 2,
        title: m365 ? 'Grant mailbox access' : 'Authorize domain-wide delegation',
        paragraphs: ['Grant exactly these permissions to the gateway mailbox app.'],
        steps: [
          {
            id: 'mailbox-access-grant',
            title: m365 ? 'Admin consent' : 'Delegation',
            paragraphs: ['Use the connection page’s mailbox access card.'],
            values: [{ label: 'Permissions', value: permissions.join(', ') }],
          },
        ],
      },
      {
        id: 'revoke',
        number: 3,
        title: 'Revoke',
        paragraphs: [
          'Revoke on the connection page, then remove the app or delegation at the provider.',
        ],
        steps: [],
      },
    ],
    attestations: [],
    permissions,
    generatedAt: new Date().toISOString(),
  };
}

function guideMarkdown(guide: SuccessBody<'ApiModeController_setupGuide_v1'>): string {
  return [
    `# API-mode setup: ${guide.connection.displayName}`,
    '',
    guide.notice,
    '',
    ...guide.sections.flatMap((s) => [`## ${s.number}. ${s.title}`, '', ...s.paragraphs, '']),
  ].join('\n');
}

function isPlatform(permissions: readonly string[]): boolean {
  return permissions.includes('platform:organizations');
}

export const fixtures: FixtureHandlers = {
  ProtectionModeController_getOrganization_v1: guarded(
    'ProtectionModeController_getOrganization_v1',
    (request, p) => {
      const id = request.params.id ?? '';
      if (id !== p.organizationId && !isPlatform(p.permissions))
        return apiError(404, 'organization_not_found', 'Organization not found');
      return ok(
        'ProtectionModeController_getOrganization_v1',
        organizationModeView(id, planOf(id)),
      );
    },
  ),
  ProtectionModeController_putOrganization_v1: guarded(
    'ProtectionModeController_putOrganization_v1',
    (request, p) =>
      keyed(request, () => {
        const id = request.params.id ?? '';
        if (id !== p.organizationId && !isPlatform(p.permissions))
          return apiError(404, 'organization_not_found', 'Organization not found');
        const body = (request.body ?? {}) as Partial<
          RequestBody<'ProtectionModeController_putOrganization_v1'>
        >;
        if (!body.mode || !MODES.has(body.mode))
          return apiError(400, 'validation_failed', ['mode: inline, api or hybrid']);
        const invalid = reasonInvalid(body.reason);
        if (invalid) return invalid;
        const mode = body.mode;
        if (mode !== 'inline' && !entitledPlan(planOf(id)))
          return apiError(403, 'api_mode_not_enabled', 'API-mode protection is not enabled');
        const inheriting = liveDomains(id).filter((d) => d.configured === null);
        const before = organizationModeView(id, planOf(id));
        if (mode === 'api' && before.mode !== 'api') {
          const conflicts = inheriting.filter((d) => d.mxPointsToGateway).slice(0, 20);
          if (conflicts.length > 0)
            return apiError(
              409,
              'protection_mode_mx_points_to_gateway',
              'The MX records of the domain still point to the gateway: choose hybrid, or move the MX records to the provider first',
              { domains: conflicts.map((d) => ({ id: d.id, name: d.name })) },
            );
        }
        const changed = before.mode !== mode;
        if (changed) {
          setOrganizationMode(id, mode);
          refreshDomainModes(id);
        }
        return ok('ProtectionModeController_putOrganization_v1', {
          ...organizationModeView(id, planOf(id)),
          organizationId: id,
          changed,
          inheritingDomains: inheriting.length,
        });
      }),
  ),
  ProtectionModeController_putDomain_v1: guarded(
    'ProtectionModeController_putDomain_v1',
    (request, p) =>
      keyed(request, () => {
        const entry = findDomain(p.organizationId, request.params.domainId);
        if (!entry) return apiError(404, 'domain_not_found', 'Domain not found');
        const body = (request.body ?? {}) as Partial<
          RequestBody<'ProtectionModeController_putDomain_v1'>
        >;
        if (!body.mode || (!MODES.has(body.mode) && body.mode !== 'inherit'))
          return apiError(400, 'validation_failed', ['mode: inline, api, hybrid or inherit']);
        const invalid = reasonInvalid(body.reason);
        if (invalid) return invalid;
        const configured = body.mode === 'inherit' ? null : body.mode;
        const before = entry.domain.protectionMode;
        const effective = effectiveMode(p.organizationId, configured);
        if (effective !== 'inline' && !entitledPlan(planOf(p.organizationId)))
          return apiError(403, 'api_mode_not_enabled', 'API-mode protection is not enabled');
        if (effective === 'api' && before.effective !== 'api' && entry.checks.mx === 'valid')
          return apiError(
            409,
            'protection_mode_mx_points_to_gateway',
            'The MX records of the domain still point to the gateway: choose hybrid, or move the MX records to the provider first',
            { domains: [{ id: entry.domain.id, name: entry.domain.name }] },
          );
        const changed = before.configured !== configured;
        if (changed) {
          entry.domain = {
            ...entry.domain,
            protectionMode: { ...before, configured, changedAt: new Date().toISOString() },
          };
          refreshDomainModes(p.organizationId);
        }
        const current = findDomain(p.organizationId, request.params.domainId) ?? entry;
        return ok('ProtectionModeController_putDomain_v1', {
          domainId: current.domain.id,
          name: current.domain.name,
          protectionMode: current.domain.protectionMode,
          changed,
        });
      }),
  ),
  ApiModeController_overview_v1: guarded('ApiModeController_overview_v1', (_request, p) => {
    const org = orgState(p.organizationId);
    const view = organizationModeView(p.organizationId, planOf(p.organizationId));
    const rows = providerConnectionsOf(p.organizationId)
      .map((c) => rowOf(p.organizationId, c.id))
      .filter((r): r is ConnectionRow => r !== null);
    const byHealth = { unknown: 0, healthy: 0, degraded: 0, failing: 0 };
    for (const r of rows) byHealth[r.health.status] += 1;
    const inventoried = rows.some((r) => r.inventoryStatus === 'ok');
    return ok('ApiModeController_overview_v1', {
      generatedAt: new Date().toISOString(),
      entitled: view.entitled,
      active: view.active,
      organizationMode: view.mode,
      domainsByEffectiveMode: view.domainsByEffectiveMode,
      coverage: coverageOf(
        org.mailboxes,
        inventoried ? org.mailboxes.filter((m) => m.status === 'active').length : null,
      ),
      connectionsByHealth: byHealth,
      lag: lagOf(0),
      throttling: { events1h: 0, events24h: 2 },
      copiesToday: org.detections.filter((d) => Date.parse(d.receivedAt) > Date.now() - DAY).length,
      connections: rows.map((r, i) => ({
        id: r.id,
        displayName: r.displayName,
        provider: r.provider,
        health: r.health.status,
        failingChecks: failingChecksOf(r.health.status),
        coverage: coverageOf(
          org.mailboxes.filter((m) => m.connectionId === r.id),
          r.mailboxesTotal,
        ),
        feedsEnabled: r.feedsEnabled,
        feedMode: r.feedMode,
        grantStatus: r.grant?.status ?? null,
        inventoryStatus: r.inventoryStatus,
        lag: lagOf(i),
        throttling: { events1h: 0, events24h: i === 0 ? 2 : 0 },
        copiesToday: i === 0 ? org.detections.length : 0,
        throttledUntil: r.throttledUntil,
      })),
    });
  }),
  ApiModeController_listConnections_v1: guarded(
    'ApiModeController_listConnections_v1',
    (_request, p) =>
      ok('ApiModeController_listConnections_v1', {
        data: providerConnectionsOf(p.organizationId)
          .map((c) => rowOf(p.organizationId, c.id))
          .filter((r): r is ConnectionRow => r !== null),
      }),
  ),
  ApiModeController_getConnection_v1: guarded(
    'ApiModeController_getConnection_v1',
    (request, p) => {
      const row = rowOf(p.organizationId, request.params.connectionId ?? '');
      return row
        ? ok('ApiModeController_getConnection_v1', detailOf(p.organizationId, row))
        : connectionNotFound();
    },
  ),
  ApiModeController_setupGuide_v1: guarded('ApiModeController_setupGuide_v1', (request, p) => {
    const row = rowOf(p.organizationId, request.params.connectionId ?? '');
    if (!row) return connectionNotFound();
    const guide = guideOf(row);
    const markdown =
      request.query.get('format') === 'markdown' ||
      (request.headers.get('accept') ?? '').includes('text/markdown');
    if (!markdown) return ok('ApiModeController_setupGuide_v1', guide);
    return {
      status: 200,
      body: guideMarkdown(guide),
      headers: {
        'content-type': 'text/markdown; charset=utf-8',
        'content-disposition': `attachment; filename="api-mode-${row.provider.replace('_', '-')}-fixture.md"`,
      },
    };
  }),
  ApiModeController_updateSettings_v1: guarded(
    'ApiModeController_updateSettings_v1',
    (request, p) =>
      keyed(request, () => {
        const row = rowOf(p.organizationId, request.params.connectionId ?? '');
        if (!row) return connectionNotFound();
        const s = orgState(p.organizationId).connections.get(row.id)!;
        const body = (request.body ?? {}) as Partial<
          RequestBody<'ApiModeController_updateSettings_v1'>
        >;
        if (typeof body.feedsEnabled !== 'boolean' || typeof body.expectedRowVersion !== 'number')
          return apiError(400, 'validation_failed', [
            'feedsEnabled and expectedRowVersion required',
          ]);
        if (body.expectedRowVersion !== s.rowVersion)
          return apiError(409, 'api_mode_connection_conflict', 'The settings changed', {
            currentRowVersion: s.rowVersion,
          });
        const mode = body.feedMode ?? s.feedMode;
        if (body.feedsEnabled && row.grant?.status !== 'active')
          return apiError(
            409,
            'api_mode_mailbox_access_required',
            'Feeds need the active mailbox access grant',
          );
        if (mode === 'notify' && row.provider !== 'microsoft_365')
          return apiError(
            422,
            'api_mode_notifications_unavailable',
            'Change notifications exist for Microsoft 365 only',
            { reason: 'provider' },
          );
        if (body.feedsEnabled && !s.feedsEnabled) s.feedsEnabledAt = new Date().toISOString();
        if (!body.feedsEnabled) s.feedsEnabledAt = null;
        s.feedsEnabled = body.feedsEnabled;
        s.feedMode = mode;
        s.rowVersion += 1;
        return ok('ApiModeController_updateSettings_v1', rowOf(p.organizationId, row.id)!);
      }),
  ),
  ApiModeController_inventorySync_v1: guarded('ApiModeController_inventorySync_v1', (request, p) =>
    keyed(request, () => {
      const row = rowOf(p.organizationId, request.params.connectionId ?? '');
      if (!row) return connectionNotFound();
      if (row.grant?.status !== 'active')
        return apiError(
          409,
          'api_mode_mailbox_access_required',
          'The inventory needs the active mailbox access grant',
        );
      const now = new Date().toISOString();
      orgState(p.organizationId).connections.get(row.id)!.inventoryRequestedAt = now;
      return ok(
        'ApiModeController_inventorySync_v1',
        { connectionId: row.id, inventoryRequestedAt: now, nextInventoryAt: now },
        202,
      );
    }),
  ),
  ApiModeController_listMailboxes_v1: guarded(
    'ApiModeController_listMailboxes_v1',
    (request, p) => {
      const q = request.query;
      const prefix = q.get('q')?.toLowerCase();
      const rows = orgState(p.organizationId)
        .mailboxes.filter(
          (m) =>
            (!q.get('connectionId') || m.connectionId === q.get('connectionId')) &&
            (!q.get('coverage') || m.coverage === q.get('coverage')) &&
            (!q.get('feedStatus') || m.feedStatus === q.get('feedStatus')) &&
            (!q.get('status') || m.status === q.get('status')) &&
            (!q.get('domainId') || m.domain?.id === q.get('domainId')) &&
            (!prefix || m.address.startsWith(prefix)),
        )
        .map(
          ({
            aliases: _a,
            feedStartedAt: _f,
            notifications: _n,
            lastChangeAt: _c,
            lastGapAt: _g,
            consecutiveFailures: _x,
            recentDetections: _r,
            ...row
          }) => row,
        );
      return { status: 200, body: paginate(rows, q) };
    },
  ),
  ApiModeController_getMailbox_v1: guarded('ApiModeController_getMailbox_v1', (request, p) => {
    const mailbox = orgState(p.organizationId).mailboxes.find(
      (m) => m.id === request.params.mailboxId,
    );
    return mailbox
      ? ok('ApiModeController_getMailbox_v1', mailbox)
      : apiError(404, 'api_mode_mailbox_not_found', 'Mailbox not found');
  }),
  ApiModeController_resyncMailbox_v1: guarded('ApiModeController_resyncMailbox_v1', (request, p) =>
    keyed(request, () => {
      const mailbox = orgState(p.organizationId).mailboxes.find(
        (m) => m.id === request.params.mailboxId,
      );
      if (!mailbox) return apiError(404, 'api_mode_mailbox_not_found', 'Mailbox not found');
      const row = rowOf(p.organizationId, mailbox.connectionId);
      if (row?.grant?.status !== 'active')
        return apiError(
          409,
          'api_mode_mailbox_access_required',
          'Resync needs the active mailbox access grant',
        );
      const now = new Date().toISOString();
      mailbox.feedStatus = 'pending';
      return ok(
        'ApiModeController_resyncMailbox_v1',
        { mailboxId: mailbox.id, syncRequestedAt: now },
        202,
      );
    }),
  ),
  ApiModeController_listDetections_v1: guarded(
    'ApiModeController_listDetections_v1',
    (request, p) => {
      const q = request.query;
      const from = q.get('from') ? Date.parse(q.get('from')!) : Date.now() - 7 * DAY;
      const to = q.get('to') ? Date.parse(q.get('to')!) : Date.now() + HOUR;
      if (to - from > 31 * DAY)
        return apiError(400, 'validation_failed', ['to: range longer than 31 days']);
      const rows = orgState(p.organizationId)
        .detections.filter((d) => {
          const at = Date.parse(d.receivedAt);
          return (
            at >= from &&
            at < to &&
            (!q.get('verdict') || d.verdict === q.get('verdict')) &&
            (!q.get('status') || d.status === q.get('status')) &&
            (!q.get('source') || d.source === q.get('source')) &&
            (!q.get('mailboxId') || d.mailboxId === q.get('mailboxId')) &&
            (!q.get('connectionId') || d.connectionId === q.get('connectionId'))
          );
        })
        .map(({ direction: _d, deliveredBasis: _b, reasonCodes: _r, ...row }) => row);
      return { status: 200, body: paginate(rows, q) };
    },
  ),
  ApiModeController_getDetection_v1: guarded('ApiModeController_getDetection_v1', (request, p) => {
    const detection = orgState(p.organizationId).detections.find(
      (d) => d.id === request.params.detectionId,
    );
    return detection
      ? ok('ApiModeController_getDetection_v1', detection)
      : apiError(404, 'api_mode_detection_not_found', 'Detection not found');
  }),
};
