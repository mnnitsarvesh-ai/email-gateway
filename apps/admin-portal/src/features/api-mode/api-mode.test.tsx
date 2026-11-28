import { screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { SuccessBody } from '@/lib/api/types';
import { visibleNavigation } from '@/lib/navigation';
import {
  ROLE_PERMISSIONS,
  TEST_ORG,
  apiErrorJson,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  mockApi,
  okJson,
  renderWithProviders,
} from '@/test';
import { DomainDetailPage } from '@/features/domains/domain-detail-page';
import { DomainsPage } from '@/features/domains/domains-page';
import {
  DomainOnboardingPage,
  STEPS_BY_MODE,
  nextStep,
  resumeStep,
  skippedSteps,
  stepCompletion,
} from '@/features/domains/onboarding-page';
import {
  DOMAIN_ID,
  PROVIDERS,
  destinations,
  dnsRecords,
  domainDetail,
  domainSummary,
  onboardingView,
  statusView,
  validation,
} from '@/features/domains/test-data';
import { ConnectionPage } from '@/features/integrations/providers/connection-page';
import { OrganizationDetail } from '@/features/organizations/organization-detail-page';
import { ApiModePage } from './api-mode-page';
import { mailboxQuery } from './mailboxes-tab';
import { coverageText, formatLagSeconds, protectionModeErrorText } from './model';
import { ApiError } from '@/lib/api/errors';

/**
 * Step API-1 WP6 (design D3, D14, §9.5): the wizard's protection-mode step (each option,
 * entitlement, skipped steps, mailbox step), the domain and organization mode panels and dialogs
 * (inherit, MX conflict, not entitled), the /api-mode tabs (tiles, connections table, feeds toggle,
 * mailboxes, detections, setup), the mailbox-access grant card and navigation gating. Synthetic
 * values only.
 */

const T = '2026-11-26T09:00:00.000Z';
const CONN = '0193f400-0000-7000-8000-000000000001';
const CONN_G = '0193f400-0000-7000-8000-000000000002';
const MAILBOX = '0193f700-0000-7000-8000-000000000001';
const SOURCE = '0193f800-0000-7000-8000-000000000001';

type OrgMode = SuccessBody<'ProtectionModeController_getOrganization_v1'>;
const orgMode = (over: Partial<OrgMode> = {}): OrgMode => ({
  mode: 'inline',
  changedAt: null,
  entitled: true,
  active: true,
  domainsByEffectiveMode: { inline: 2, api: 1, hybrid: 1 },
  ...over,
});

const API_DOMAIN = {
  configured: 'api' as const,
  effective: 'api' as const,
  inherited: false,
  changedAt: T,
};

type Row = SuccessBody<'ApiModeController_listConnections_v1'>['data'][number];
const row = (over: Partial<Row> = {}): Row => ({
  id: CONN,
  apiConnectionId: '0193f900-0000-7000-8000-000000000001',
  displayName: 'Contoso production',
  provider: 'microsoft_365',
  status: 'active',
  bound: true,
  feedsEnabled: false,
  feedMode: 'poll',
  feedsEnabledAt: null,
  inventoryStatus: 'ok',
  inventorySyncedAt: T,
  inventoryRequestedAt: null,
  mailboxesTotal: 10,
  health: { status: 'degraded', changedAt: T },
  throttledUntil: null,
  lastErrorCode: null,
  remediationPaused: false,
  remediationPausedAt: null,
  grant: { profile: 'm365.mailbox_remediation', status: 'active', authMethod: 'platform_app' },
  journalSources: [
    {
      id: SOURCE,
      displayName: 'Exchange journal rule',
      kind: 'm365_journal',
      status: 'active',
      health: 'healthy',
      verified: true,
    },
  ],
  rowVersion: 3,
  ...over,
});

type Overview = SuccessBody<'ApiModeController_overview_v1'>;
const remediationSummary = (
  over: Partial<Overview['remediation']> = {},
): Overview['remediation'] => ({
  policyMode: 'enforce',
  policySource: 'platform_default',
  paused: false,
  succeeded1h: 2,
  failed1h: 1,
  succeeded24h: 14,
  failed24h: 3,
  skipped24h: 4,
  simulated24h: 0,
  restores24h: 1,
  throttled24h: 2,
  backlog: { pending: 5, capped: false, oldestPendingAgeSeconds: 420 },
  latencyAvgSeconds24h: 6.5,
  latencyMaxSeconds24h: 41,
  ...over,
});
const overview = (over: Partial<Overview> = {}): Overview => ({
  generatedAt: T,
  entitled: true,
  active: true,
  organizationMode: 'inline',
  domainsByEffectiveMode: { inline: 2, api: 1, hybrid: 1 },
  coverage: { covered: 8, gap: 1, total: 9, percent: 88.8 },
  connectionsByHealth: { unknown: 1, healthy: 0, degraded: 1, failing: 0 },
  lag: { p50Seconds1h: 45, p95Seconds1h: 300, p50Seconds24h: 60, p95Seconds24h: 420 },
  throttling: { events1h: 0, events24h: 2 },
  copiesToday: 17,
  remediation: remediationSummary(),
  internal: { copies24h: 3, enabled: true },
  clawback: {
    active: 0,
    reviewRequired: 0,
    pendingApproval: 0,
    completed24h: 0,
    targetsSucceeded24h: 0,
    targetsFailed24h: 0,
    oldestActiveAgeSeconds: null,
  },
  reports: {
    pendingTriage: 0,
    inReview: 0,
    received24h: 0,
    resolved24h: 0,
    oldestPendingAgeSeconds: null,
    reportMailboxes: 0,
  },
  policy: { enabled: true, evaluated24h: 0, errors24h: 0 },
  outbound: { detections24h: 0, enabled: true },
  scope: { excluded: 0 },
  connections: [
    {
      id: CONN,
      displayName: 'Contoso production',
      provider: 'microsoft_365',
      health: 'degraded',
      failingChecks: ['coverage.percent', 'feeds.errors'],
      coverage: { covered: 8, gap: 1, total: 9, percent: 88.8 },
      feedsEnabled: false,
      feedMode: 'poll',
      grantStatus: 'active',
      inventoryStatus: 'ok',
      lag: { p50Seconds1h: 45, p95Seconds1h: 300, p50Seconds24h: 60, p95Seconds24h: 420 },
      throttling: { events1h: 0, events24h: 2 },
      copiesToday: 17,
      throttledUntil: null,
      remediation: remediationSummary(),
      internal: { copies24h: 3, enabled: true },
      clawback: { targetsQueued24h: 0, targetsSucceeded24h: 0, targetsFailed24h: 0 },
      reports: {
        pendingTriage: 0,
        inReview: 0,
        received24h: 0,
        resolved24h: 0,
        oldestPendingAgeSeconds: null,
        reportMailboxes: 0,
      },
    },
  ],
  ...over,
});

const mailbox = {
  id: MAILBOX,
  connectionId: CONN,
  address: 'ana@alpha.example.test',
  domain: { id: DOMAIN_ID, name: 'alpha.example.test' },
  status: 'active' as const,
  coverage: 'gap' as const,
  coverageChangedAt: T,
  feedStatus: 'active' as const,
  journalLastSeenAt: T,
  lastSyncAt: T,
  lastErrorCode: null,
};

const detection = {
  id: '0193fa00-0000-7000-8000-000000000001',
  mailboxId: MAILBOX,
  mailboxAddress: 'ana@alpha.example.test',
  connectionId: CONN,
  source: 'journal' as const,
  seenJournal: true,
  seenApi: false,
  status: 'scanned' as const,
  verdict: 'phishing' as const,
  riskScore: 870,
  verdictAuthority: 'copy' as const,
  receivedAt: T,
  providerDeliveredAt: T,
  verdictAt: T,
  lagMs: 90_000,
  subject: null,
  subjectMasked: true,
  headerFrom: 'evil‮sender@attacker.example.test',
  remediationState: 'none' as const,
  remediationAction: null,
  remediationId: null,
  quarantineEntryId: null,
  direction: 'inbound' as const,
  policyState: 'evaluated' as const,
  policyDisposition: 'allow' as const,
  policyTagged: false,
  dlpAction: null,
  verdictRevision: 0,
  clawbacks: [] as string[],
};

// ---- wizard ------------------------------------------------------------------------------------

describe('Domain onboarding: protection mode step (D3)', () => {
  it('API mode: inbound toggle hidden with the explanation, body with inboundEnabled false', async () => {
    let body: unknown = null;
    mockApi({
      ProtectionModeController_getOrganization_v1: () => okJson(orgMode()),
      DomainsController_create_v1: ({ body: b }) => (
        (body = b),
        okJson({ ...domainDetail({ protectionMode: API_DOMAIN }), dnsRecords: [] }, 201)
      ),
      DomainsController_get_v1: () => okJson(domainDetail({ protectionMode: API_DOMAIN })),
      DomainDestinationsController_get_v1: () =>
        okJson(destinations({ provider: null, servers: [] })),
      DomainRecipientsController_get_v1: () => okJson(validation()),
      DomainDnsController_dnsRecords_v1: () => okJson(dnsRecords()),
      ApiModeController_listConnections_v1: () => okJson({ data: [] }),
      ApiModeOnboardingController_domainOnboarding_v1: () => okJson(onboardingView()),
    });
    const { user, container } = renderWithProviders(<DomainOnboardingPage />, {
      route: '/domains/onboarding',
    });
    const api = await screen.findByRole('radio', { name: /API \(no MX change\)/ });
    expect(screen.getByText(/mail flow is never changed, delayed or bounced/)).toBeInTheDocument();
    expect(screen.getByText(/Inline filtering plus API post-delivery protection/)).toBeVisible();
    await user.click(api);
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('button', { name: 'Continue' }));
    await screen.findByLabelText('Domain name (required)');
    expect(screen.queryByText('Receive inbound mail for this domain')).not.toBeInTheDocument();
    expect(screen.getByRole('note')).toHaveTextContent(/stays off in API mode/);
    await user.type(screen.getByLabelText('Domain name (required)'), 'api.example.test');
    await user.click(screen.getByRole('button', { name: 'Add domain' }));
    await waitFor(() =>
      expect(body).toEqual({
        name: 'api.example.test',
        inboundEnabled: false,
        dkim: { ed25519: false },
        protectionMode: 'api',
      }),
    );
    expectRequestMatchesContract('DomainsController_create_v1', body);
  });

  it('Hybrid keeps the inbound toggle and posts the mode', async () => {
    let body: unknown = null;
    mockApi({
      ProtectionModeController_getOrganization_v1: () => okJson(orgMode()),
      DomainsController_create_v1: ({ body: b }) => (
        (body = b),
        okJson({ ...domainDetail(), dnsRecords: [] }, 201)
      ),
      DomainsController_get_v1: () => okJson(domainDetail({ status: 'pending_verification' })),
      DomainDestinationsController_get_v1: () =>
        okJson(destinations({ provider: null, servers: [] })),
      DomainRecipientsController_get_v1: () => okJson(validation()),
      DomainDnsController_dnsRecords_v1: () => okJson(dnsRecords()),
      ApiModeController_listConnections_v1: () => okJson({ data: [] }),
    });
    const { user } = renderWithProviders(<DomainOnboardingPage />, {
      route: '/domains/onboarding',
    });
    await user.click(await screen.findByRole('radio', { name: /^Hybrid/ }));
    await user.click(screen.getByRole('button', { name: 'Continue' }));
    expect(await screen.findByText('Receive inbound mail for this domain')).toBeInTheDocument();
    await user.type(screen.getByLabelText('Domain name (required)'), 'hybrid.example.test');
    await user.click(screen.getByRole('button', { name: 'Add domain' }));
    await waitFor(() =>
      expect(body).toMatchObject({ protectionMode: 'hybrid', inboundEnabled: true }),
    );
  });

  it('without the entitlement API and Hybrid are disabled with the reason', async () => {
    mockApi({
      ProtectionModeController_getOrganization_v1: () =>
        okJson(orgMode({ entitled: false, active: false })),
    });
    const { container } = renderWithProviders(<DomainOnboardingPage />, {
      route: '/domains/onboarding',
    });
    expect(await screen.findByRole('radio', { name: /API \(no MX change\)/ })).toBeDisabled();
    expect(screen.getByRole('radio', { name: /^Hybrid/ })).toBeDisabled();
    expect(screen.getByRole('radio', { name: /^Inline \(MX\)/ })).toBeEnabled();
    expect(screen.getByText(/need the API-mode protection feature/)).toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('step lists per mode (step API-4 B1): API lists no inline step, Hybrid both, Inline unchanged', () => {
    expect(STEPS_BY_MODE.inline).toEqual([
      'mode',
      'add',
      'dns',
      'verify',
      'destinations',
      'recipients',
      'mailbox',
      'activate',
      'done',
    ]);
    expect(STEPS_BY_MODE.api).toEqual([
      'mode',
      'add',
      'ownership',
      'connect',
      'intake',
      'mailboxes',
      'action',
      'review',
      'done',
    ]);
    expect(STEPS_BY_MODE.hybrid).toEqual([
      'mode',
      'add',
      'dns',
      'verify',
      'destinations',
      'recipients',
      'connect',
      'intake',
      'mailboxes',
      'action',
      'review',
      'done',
    ]);
    expect([...skippedSteps('api')]).toEqual([]);
    expect([...skippedSteps('inline')]).toEqual(['mailbox']);
    expect([...skippedSteps('hybrid')]).toEqual([]);
    expect(nextStep('ownership', 'api')).toBe('connect');
    expect(nextStep('recipients', 'hybrid')).toBe('connect');
    expect(nextStep('recipients', 'inline')).toBe('activate');
  });

  it('derives completion and the resume step from server state', () => {
    const api = domainDetail({ status: 'verified', protectionMode: API_DOMAIN });
    expect(resumeStep({ domain: api, hasDestinations: false, recipientMode: null })).toBe(
      'connect',
    );
    expect(
      resumeStep({
        domain: domainDetail({ status: 'pending_verification', protectionMode: API_DOMAIN }),
        hasDestinations: false,
        recipientMode: null,
      }),
    ).toBe('ownership');
    expect(
      resumeStep({
        domain: domainDetail({ status: 'verified' }),
        hasDestinations: false,
        recipientMode: null,
      }),
    ).toBe('destinations');
    expect(
      resumeStep({
        domain: domainDetail({ status: 'verified' }),
        hasDestinations: true,
        recipientMode: null,
      }),
    ).toBe('activate');
    const completion = stepCompletion({ domain: api, hasDestinations: false, recipientMode: null });
    expect(completion.mode).toBe(true);
    expect(completion.ownership).toBe(true);
    expect(completion.connect).toBe(false);
    expect(stepCompletion({ domain: null, hasDestinations: false, recipientMode: null }).mode).toBe(
      false,
    );
  });
});

// ---- domain and organization panels -------------------------------------------------------------

type DomainMode = SuccessBody<'DomainsController_get_v1'>['protectionMode'];

function mockDomainPage(protectionMode: DomainMode = API_DOMAIN, observedToGateway = true) {
  mockApi({
    DomainsController_get_v1: () => okJson(domainDetail({ protectionMode })),
    DomainDnsController_status_v1: () =>
      okJson(
        statusView(
          observedToGateway
            ? {}
            : {
                checks: {
                  ...statusView().checks,
                  mx: { ...statusView().checks.mx, observed: [] },
                },
              },
        ),
      ),
    DomainDnsController_dnsRecords_v1: () => okJson(dnsRecords()),
    DomainRecipientsController_get_v1: () => okJson(validation()),
    DomainDestinationsController_get_v1: () => okJson(destinations()),
    DestinationProvidersController_list_v1: () => okJson(PROVIDERS),
    ProtectionModeController_getOrganization_v1: () => okJson(orgMode({ mode: 'hybrid' })),
    ApiModeOnboardingController_domainOnboarding_v1: () =>
      okJson(onboardingView({ effectiveMode: protectionMode.effective })),
  });
}

describe('Domain protection mode panel (D2, D14)', () => {
  it('shows the effective mode and warns when an API-mode domain MX points to the gateway', async () => {
    mockDomainPage();
    const { container } = renderWithProviders(<DomainDetailPage domainId={DOMAIN_ID} />, {
      route: `/domains/${DOMAIN_ID}`,
    });
    expect(await screen.findByRole('heading', { name: 'Protection mode' })).toBeInTheDocument();
    expect(screen.getByText('This domain (API (no MX change))')).toBeInTheDocument();
    expect(await screen.findByText(/its MX record points to the gateway/)).toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('changes to inherit with a required reason (contract), and explains the MX conflict', async () => {
    mockDomainPage({ configured: 'hybrid', effective: 'hybrid', inherited: false, changedAt: T });
    const bodies: unknown[] = [];
    mockApi({
      ProtectionModeController_putDomain_v1: ({ body }) => {
        bodies.push(body);
        if (bodies.length === 1)
          return apiErrorJson(409, 'protection_mode_mx_points_to_gateway', 'MX conflict', {
            extra: { domains: [{ id: DOMAIN_ID, name: 'alpha.example.test' }] },
          });
        return okJson({
          domainId: DOMAIN_ID,
          name: 'alpha.example.test',
          protectionMode: { configured: null, effective: 'hybrid', inherited: true, changedAt: T },
          changed: true,
        });
      },
    });
    const { user } = renderWithProviders(<DomainDetailPage domainId={DOMAIN_ID} />, {
      route: `/domains/${DOMAIN_ID}`,
    });
    await user.click(await screen.findByRole('button', { name: 'Change mode' }));
    const dialog = await screen.findByRole('dialog');
    expect(
      within(dialog).getByRole('radio', { name: /Inherit from organization \(Hybrid\)/ }),
    ).toBeInTheDocument();
    await user.click(within(dialog).getByRole('radio', { name: /API \(no MX change\)/ }));
    await user.click(within(dialog).getByRole('button', { name: 'Change mode' }));
    expect(within(dialog).getByText('Enter a reason.')).toBeInTheDocument();
    expect(bodies).toEqual([]);
    await user.type(within(dialog).getByLabelText(/Reason/), 'Moving to API mode');
    await user.click(within(dialog).getByRole('button', { name: 'Change mode' }));
    expect(
      await within(dialog).findByText(/alpha.example.test: the MX record still points/),
    ).toBeInTheDocument();
    expect(within(dialog).getByText(/Choose Hybrid/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole('radio', { name: /Inherit from organization/ }));
    await user.click(within(dialog).getByRole('button', { name: 'Change mode' }));
    await waitFor(() => expect(bodies).toHaveLength(2));
    expect(bodies[1]).toEqual({ mode: 'inherit', reason: 'Moving to API mode' });
    expectRequestMatchesContract('ProtectionModeController_putDomain_v1', bodies[1]);
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  it('read-only users see the panel without the change control; the list shows the mode', async () => {
    mockDomainPage({ configured: null, effective: 'inline', inherited: true, changedAt: null });
    mockApi({
      DomainsController_list_v1: () =>
        okJson({
          data: [
            domainSummary(1, { protectionMode: API_DOMAIN }),
            domainSummary(2, {
              protectionMode: {
                configured: null,
                effective: 'hybrid',
                inherited: true,
                changedAt: null,
              },
            }),
          ],
          nextCursor: null,
        }),
    });
    const { unmount } = renderWithProviders(<DomainDetailPage domainId={DOMAIN_ID} />, {
      role: 'read_only_user',
      route: `/domains/${DOMAIN_ID}`,
    });
    expect(await screen.findByRole('heading', { name: 'Protection mode' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Change mode' })).not.toBeInTheDocument();
    unmount();
    renderWithProviders(<DomainsPage />, { route: '/domains' });
    const table = await screen.findByRole('table');
    expect(
      within(table).getByRole('columnheader', { name: /Protection mode/ }),
    ).toBeInTheDocument();
    expect(within(table).getByText('API')).toBeInTheDocument();
    expect(within(table).getByText('inherited')).toBeInTheDocument();
  });

  it('explains api_mode_not_enabled', () => {
    const error = new ApiError({ status: 403, code: 'api_mode_not_enabled', message: 'x' });
    expect(protectionModeErrorText(error)).toMatch(/not part of this organization’s plan/);
  });
});

const ORGANIZATION = {
  id: TEST_ORG.id,
  slug: 'alpha',
  name: 'Alpha Industries (example)',
  kind: 'customer' as const,
  status: 'active' as const,
  statusReason: null,
  statusChangedAt: null,
  plan: { code: 'enterprise', name: 'Enterprise' },
  serviceProfile: 'gateway' as const,
  deploymentMode: 'saas' as const,
  dataRegion: 'eu-west-1',
  deployments: [],
  deletion: null,
  protectionMode: orgMode(),
  createdAt: T,
  updatedAt: T,
};

describe('Organization protection mode panel (D2, D14)', () => {
  it('shows counts, states how many domains inherit and changes the mode with a reason', async () => {
    const bodies: unknown[] = [];
    mockApi({
      OrganizationsController_get_v1: () => okJson(ORGANIZATION),
      ProtectionModeController_getOrganization_v1: () => okJson(orgMode()),
      DomainsController_list_v1: () =>
        okJson({
          data: [
            domainSummary(1),
            domainSummary(2),
            domainSummary(3, { protectionMode: API_DOMAIN }),
          ],
          nextCursor: null,
        }),
      ProtectionModeController_putOrganization_v1: ({ body }) => {
        bodies.push(body);
        return okJson({
          ...orgMode({ mode: 'hybrid' }),
          organizationId: TEST_ORG.id,
          changed: true,
          inheritingDomains: 2,
        });
      },
    });
    const { user, container } = renderWithProviders(
      <OrganizationDetail organizationId={TEST_ORG.id} tenantView />,
      { route: '/settings?tab=organization' },
    );
    // Two queries (organization, then its mode) before the list renders: allow for a loaded runner.
    const counts = await screen.findByRole(
      'list',
      { name: 'Domains per effective mode' },
      { timeout: 5_000 },
    );
    expect(within(counts).getByText('Inline (MX)').nextSibling).toHaveTextContent('2');
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('button', { name: 'Change organization mode' }));
    const dialog = await screen.findByRole('dialog');
    expect(
      await within(dialog).findByText(/2 domains without a mode of their own inherit/),
    ).toBeInTheDocument();
    await user.click(within(dialog).getByRole('radio', { name: /^Hybrid/ }));
    await user.type(within(dialog).getByLabelText(/Reason/), 'Post-delivery protection');
    await user.click(within(dialog).getByRole('button', { name: 'Change organization mode' }));
    expect(
      await within(dialog).findByText(/Organization mode is now Hybrid; 2 domains inherit it/),
    ).toBeInTheDocument();
    expect(bodies[0]).toEqual({ mode: 'hybrid', reason: 'Post-delivery protection' });
    expectRequestMatchesContract('ProtectionModeController_putOrganization_v1', bodies[0]);
  });

  it('read-only users see the panel without the change control', async () => {
    mockApi({
      OrganizationsController_get_v1: () => okJson(ORGANIZATION),
      ProtectionModeController_getOrganization_v1: () =>
        okJson(orgMode({ entitled: false, active: false })),
    });
    renderWithProviders(<OrganizationDetail organizationId={TEST_ORG.id} tenantView />, {
      role: 'read_only_user',
      route: '/settings?tab=organization',
    });
    expect(await screen.findByText('Not included in the plan (Inline only)')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Change organization mode' })).toBeNull();
  });
});

// ---- /api-mode ------------------------------------------------------------------------------------

function mockApiModePage(rows: Row[] = [row()], over: Partial<Overview> = {}) {
  mockApi({
    ApiModeController_overview_v1: () => okJson(overview(over)),
    ApiModeController_listConnections_v1: () => okJson({ data: rows }),
  });
}

describe('/api-mode Mailbox protection (D14)', () => {
  it('Coverage: tiles, connection table with check titles and grant link (axe clean)', async () => {
    mockApiModePage([
      row(),
      row({
        id: CONN_G,
        displayName: 'Fabrikam Google',
        provider: 'google_workspace',
        grant: null,
        health: { status: 'unknown', changedAt: null },
        inventoryStatus: 'never',
        mailboxesTotal: null,
      }),
    ]);
    const { container } = renderWithProviders(<ApiModePage />, { route: '/api-mode' });
    const tiles = await screen.findByRole('list', { name: 'Mailbox protection summary' });
    expect(within(tiles).getByText('8 / 9')).toBeInTheDocument();
    expect(within(tiles).getByText('p95 5 min')).toBeInTheDocument();
    expect(within(tiles).getByText('0 healthy')).toBeInTheDocument();
    const table = screen.getByRole('table');
    expect(within(table).getByText('Mailbox coverage')).toBeInTheDocument();
    expect(within(table).getByText('Mailbox feed errors')).toBeInTheDocument();
    expect(within(table).getByText('Not granted')).toBeInTheDocument();
    expect(
      within(table).getByRole('link', { name: 'Grant mailbox access for Fabrikam Google' }),
    ).toHaveAttribute('href', `/integrations/providers/${CONN_G}?tab=settings#mailbox-access`);
    await expectNoAxeViolations(container);
  });

  it('Coverage without inventory shows "total unknown"', async () => {
    mockApiModePage([row()], { coverage: { covered: 3, gap: 0, total: null, percent: null } });
    renderWithProviders(<ApiModePage />, { route: '/api-mode' });
    expect(await screen.findByText('3 covered')).toBeInTheDocument();
    expect(screen.getByText(/Total unknown: connect mailbox access/)).toBeInTheDocument();
  });

  it('feeds toggle: PUT settings with the row version (CAS); mailbox access error explained', async () => {
    const bodies: unknown[] = [];
    mockApiModePage();
    mockApi({
      ApiModeController_updateSettings_v1: ({ body }) => {
        bodies.push(body);
        return bodies.length === 1
          ? apiErrorJson(409, 'api_mode_mailbox_access_required', 'Grant first')
          : okJson(row({ feedsEnabled: true, rowVersion: 4 }));
      },
    });
    const { user } = renderWithProviders(<ApiModePage />, { route: '/api-mode' });
    const toggle = await screen.findByRole('switch', {
      name: 'Mailbox feeds for Contoso production',
    });
    await user.click(toggle);
    expect(
      await screen.findByText(/Grant mailbox access for API mode on the connection first/),
    ).toBeInTheDocument();
    await user.click(toggle);
    await waitFor(() => expect(bodies).toHaveLength(2));
    expect(bodies[1]).toEqual({ feedsEnabled: true, feedMode: 'poll', expectedRowVersion: 3 });
    expectRequestMatchesContract('ApiModeController_updateSettings_v1', bodies[1]);
  });

  it('read-only users see every tab without write controls', async () => {
    mockApiModePage();
    renderWithProviders(<ApiModePage />, { role: 'read_only_user', route: '/api-mode' });
    await screen.findByRole('table');
    expect(screen.queryByRole('switch')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Sync inventory/ })).not.toBeInTheDocument();
    expect(screen.getByText('Off')).toBeInTheDocument();
    for (const tab of ['Coverage', 'Mailboxes', 'Detections', 'Setup'])
      expect(screen.getByRole('tab', { name: tab })).toBeInTheDocument();
  });

  it('Mailboxes: filtered cursor table and the resync action', async () => {
    const requests: URL[] = [];
    const resyncs: string[] = [];
    mockApi({
      ApiModeController_overview_v1: () => okJson(overview()),
      ApiModeController_listConnections_v1: () => okJson({ data: [row()] }),
      DomainsController_list_v1: () => okJson({ data: [domainSummary(1)], nextCursor: null }),
      ApiModeController_listMailboxes_v1: ({ url }) => {
        requests.push(url);
        return okJson({ data: [mailbox], nextCursor: null });
      },
      ApiModeController_resyncMailbox_v1: ({ params }) => {
        resyncs.push(String(params.mailboxId));
        return okJson({ mailboxId: MAILBOX, syncRequestedAt: T }, 202);
      },
    });
    const { user, container } = renderWithProviders(<ApiModePage />, {
      route: '/api-mode?tab=mailboxes&coverage=gap',
    });
    expect(await screen.findByText('ana@alpha.example.test')).toBeInTheDocument();
    expect(requests.at(-1)?.searchParams.get('coverage')).toBe('gap');
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('button', { name: /Actions for ana@alpha.example.test/ }));
    await user.click(await screen.findByRole('menuitem', { name: 'Resync feed' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Resync' }));
    await waitFor(() => expect(resyncs).toEqual([MAILBOX]));
    expect(mailboxQuery({ q: ' Ana', feedStatus: 'error' })).toEqual({
      q: 'ana',
      feedStatus: 'error',
    });
  });

  it('Detections: masked subject, sender as untrusted text, lag formatting', async () => {
    const requests: URL[] = [];
    mockApi({
      ApiModeController_overview_v1: () => okJson(overview()),
      ApiModeController_listConnections_v1: () => okJson({ data: [row()] }),
      ApiModeController_listDetections_v1: ({ url }) => {
        requests.push(url);
        return okJson({ data: [detection], nextCursor: null });
      },
    });
    const { container } = renderWithProviders(<ApiModePage />, {
      route: '/api-mode?tab=detections&verdict=phishing',
    });
    expect(await screen.findByText('Hidden (masked)')).toBeInTheDocument();
    expect(within(screen.getByRole('table')).getByText('Phishing')).toBeInTheDocument();
    expect(screen.getByText('2 min')).toBeInTheDocument();
    // Bidi override characters are neutralized; the value is never a link.
    const sender = screen.getByText(/attacker.example.test/);
    expect(sender.textContent).not.toContain('‮');
    expect(sender.closest('a')).toBeNull();
    expect(requests.at(-1)?.searchParams.get('verdict')).toBe('phishing');
    expect(requests.at(-1)?.searchParams.get('from')).toBeTruthy();
    await expectNoAxeViolations(container);
  });

  it('Setup: wizard steps, health checks and the guide with Markdown download', async () => {
    mockApi({
      ApiModeController_overview_v1: () => okJson(overview()),
      ApiModeController_listConnections_v1: () => okJson({ data: [row()] }),
      ApiModeController_getConnection_v1: () =>
        okJson({
          ...row(),
          coverage: { covered: 8, gap: 1, total: 9, percent: 88.8 },
          wizard: {
            steps: [
              { step: 'domains', status: 'done', blockers: [] },
              { step: 'connection', status: 'done', blockers: [] },
              { step: 'journal', status: 'done', blockers: [] },
              { step: 'mailbox_access', status: 'done', blockers: [] },
              { step: 'feeds', status: 'skipped', blockers: [] },
              { step: 'monitor', status: 'in_progress', blockers: ['health_unknown'] },
            ],
            nextAction: { step: 'monitor', action: 'review_health' },
          },
          healthChecks: [{ code: 'coverage.percent', status: 'warn', evidence: '8 of 9' }],
          counters: [],
        }),
      ApiModeController_setupGuide_v1: () =>
        okJson({
          schema: 'api-mode-guide/1',
          provider: 'microsoft_365',
          connection: { id: CONN, displayName: 'Contoso production' },
          notice: 'Written for this connection.',
          sections: [
            {
              id: 'mailbox-access',
              number: 1,
              title: 'Grant mailbox access',
              paragraphs: ['Grant exactly these permissions.'],
              steps: [
                {
                  id: 'consent',
                  title: 'Admin consent',
                  paragraphs: ['Use the connection page.'],
                  values: [{ label: 'Permissions', value: 'Mail.ReadWrite, User.Read.All' }],
                },
              ],
            },
          ],
          attestations: [],
          permissions: ['Mail.ReadWrite', 'User.Read.All'],
          generatedAt: T,
        }),
    });
    const { container } = renderWithProviders(<ApiModePage />, {
      route: `/api-mode?tab=setup&connection=${CONN}`,
    });
    const steps = await screen.findByRole('list', { name: 'API-mode setup steps' });
    expect(within(steps).getByText('Mailbox access granted')).toBeInTheDocument();
    expect(within(steps).getByText('health has not been evaluated yet')).toBeInTheDocument();
    expect(
      screen.getByText('Next: Healthy protection — Review the health checks'),
    ).toBeInTheDocument();
    expect(screen.getByText('8 of 9')).toBeInTheDocument();
    expect(
      await screen.findByRole('heading', { name: '1. Grant mailbox access' }),
    ).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Download Markdown' })).toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('formats coverage and lag', () => {
    expect(coverageText({ covered: 8, gap: 1, total: 9, percent: 88.8 })).toBe('8 of 9 (88.8 %)');
    expect(coverageText({ covered: 2, gap: 0, total: null, percent: null })).toBe(
      '2 covered, total unknown',
    );
    expect(formatLagSeconds(null)).toBe('No copies');
    expect(formatLagSeconds(45)).toBe('45 s');
  });
});

// ---- grant card and navigation ------------------------------------------------------------------

const providerGrant = (over: Record<string, unknown> = {}) => ({
  id: '0193f400-0000-7000-8000-0000000000a1',
  profile: 'm365.mail_flow',
  profileVersion: 1,
  authMethod: 'platform_app',
  status: 'active',
  clientId: '11111111-2222-3333-4444-555555555555',
  subjectEmail: null,
  credentialFingerprint: null,
  credentialVersion: 0,
  credentialSetAt: null,
  credentialExpiresAt: null,
  requestedPermissions: ['Organization.Read.All'],
  observedPermissions: ['Organization.Read.All'],
  missingPermissions: [],
  excessPermissions: [],
  consentedAt: T,
  verifyRequestedAt: T,
  verifiedAt: T,
  lastErrorCode: null,
  createdAt: T,
  updatedAt: T,
  ...over,
});

const providerConnection = (grants: unknown[]) => ({
  id: CONN,
  provider: 'microsoft_365',
  displayName: 'Contoso production',
  status: 'active',
  tenantName: 'Contoso Ltd',
  outboundMode: 'off',
  internalRouting: false,
  health: 'healthy',
  healthChangedAt: T,
  domainCount: 1,
  createdAt: T,
  tenantId: '11111111-2222-3333-4444-555555555555',
  tenantVerifiedAt: T,
  grants,
  domains: [{ id: DOMAIN_ID, name: 'alpha.example.test', providerVerification: 'verified' }],
  relayConnectorId: null,
  relayProof: { tenantHeader: 'required', dkimAligned: 'required' },
  relayProofIsDefault: true,
  attestations: [],
  routeTokenVersion: 1,
  routeTokenPendingVersion: null,
  healthCheckedAt: T,
  nextHealthCheckAt: T,
  disabledAt: null,
  rowVersion: 4,
  updatedAt: T,
});

const providerCatalog = {
  providers: [
    {
      provider: 'microsoft_365',
      displayName: 'Microsoft 365',
      profiles: [
        {
          key: 'm365.mailbox_remediation',
          version: 1,
          purpose: 'mailbox_remediation',
          title: 'Mailbox access for API mode',
          description: 'Reads new messages for scanning.',
          permissions: ['Mail.ReadWrite', 'User.Read.All'],
          readOnly: false,
          authMethods: ['platform_app', 'customer_app_secret'],
          availableAuthMethods: ['platform_app', 'customer_app_secret'],
        },
      ],
      attestations: [],
      egressSet: { version: 1, publishedAt: T, importedAt: T, rangeCount: 8 },
    },
  ],
  probeDomain: 'probe.gateway.example.test',
  gateway: { inboundHost: 'mx.gateway.example.test', outboundHost: 'out.gateway.example.test' },
};

describe('Mailbox access grant card (D4, D14)', () => {
  it('offers the 8.2 methods for the mailbox profile, states the permissions and creates the grant', async () => {
    const bodies: unknown[] = [];
    mockApi({
      ProviderConnectionsController_get_v1: () => okJson(providerConnection([providerGrant()])),
      ProviderCatalogController_get_v1: () => okJson(providerCatalog),
      ProviderGrantsController_create_v1: ({ body }) => {
        bodies.push(body);
        return okJson(
          {
            grant: providerGrant({
              profile: 'm365.mailbox_remediation',
              authMethod: 'customer_app_secret',
              status: 'pending_consent',
            }),
            next: 'credentials',
            consent: null,
            delegation: null,
          },
          201,
        );
      },
    });
    const { user, container } = renderWithProviders(<ConnectionPage connectionId={CONN} />, {
      route: `/integrations/providers/${CONN}?tab=settings`,
    });
    expect(
      await screen.findByRole('heading', { name: 'Mailbox access for API mode' }),
    ).toBeInTheDocument();
    expect(screen.getByText(/Mail.ReadWrite \(read new messages/)).toBeInTheDocument();
    expect(
      screen.getByText(/independent of the mail-flow access above and of account takeover/),
    ).toBeInTheDocument();
    expect(
      screen.getAllByText('Permissions requested (Mailbox access for API mode)')[0],
    ).toBeInTheDocument();
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('button', { name: 'Use your own app registration' }));
    await waitFor(() =>
      expect(bodies).toEqual([
        { profile: 'm365.mailbox_remediation', authMethod: 'customer_app_secret' },
      ]),
    );
    expectRequestMatchesContract('ProviderGrantsController_create_v1', bodies[0]);
  });

  it('active grant: revoke for remediation:write holders; others see why they cannot grant', async () => {
    const revokes: string[] = [];
    const active = providerGrant({ profile: 'm365.mailbox_remediation' });
    mockApi({
      ProviderConnectionsController_get_v1: () =>
        okJson(providerConnection([providerGrant(), active])),
      ProviderCatalogController_get_v1: () => okJson(providerCatalog),
      ProviderGrantsController_revoke_v1: ({ params }) => {
        revokes.push(String(params.profile));
        return okJson({
          grant: { ...active, status: 'revoked' },
          providerRemovalSteps: ['Remove the enterprise application.'],
        });
      },
    });
    const { user, unmount } = renderWithProviders(<ConnectionPage connectionId={CONN} />, {
      route: `/integrations/providers/${CONN}?tab=settings`,
    });
    await user.click(await screen.findByRole('button', { name: 'Revoke mailbox access' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Revoke mailbox access' }));
    expect(await screen.findByText('Remove the enterprise application.')).toBeInTheDocument();
    expect(revokes).toEqual(['m365.mailbox_remediation']);
    unmount();
    // domain_admin holds integration:manage but not remediation:write.
    renderWithProviders(<ConnectionPage connectionId={CONN} />, {
      role: 'domain_admin',
      route: `/integrations/providers/${CONN}?tab=settings`,
    });
    expect(
      await screen.findByText(/granting or revoking it needs the remediation write permission/),
    ).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Revoke mailbox access' })).toBeNull();
  });
});

describe('navigation gating of Mailbox protection', () => {
  const visible = (permissions: readonly string[], profile?: 'gateway' | 'archive_only') =>
    visibleNavigation(permissions, profile)
      .flatMap((section) => section.items)
      .some((item) => item.id === 'api-mode');

  it('needs remediation:read and the gateway profile', () => {
    expect(visible(ROLE_PERMISSIONS.read_only_user)).toBe(true);
    expect(visible(ROLE_PERMISSIONS.security_analyst)).toBe(true);
    expect(visible(ROLE_PERMISSIONS.quarantine_reviewer)).toBe(false);
    expect(visible(ROLE_PERMISSIONS.compliance_officer)).toBe(false);
    expect(visible(ROLE_PERMISSIONS.organization_admin, 'archive_only')).toBe(false);
    const security = visibleNavigation(ROLE_PERMISSIONS.organization_admin).find(
      (section) => section.id === 'security',
    );
    expect(security?.items.find((item) => item.id === 'api-mode')?.label).toBe(
      'Mailbox protection',
    );
  });

  it('refuses the page without remediation:read', () => {
    renderWithProviders(<ApiModePage />, { role: 'quarantine_reviewer', route: '/api-mode' });
    expect(screen.getByText('You do not have access to this page')).toBeInTheDocument();
  });
});
