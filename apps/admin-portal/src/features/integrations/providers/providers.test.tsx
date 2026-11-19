import { screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  apiErrorJson,
  currentTestUrl,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  mockApi,
  okJson,
  renderWithProviders,
} from '@/test';
import { ConnectorsTab } from '@/features/mail-servers/connectors-tab';
import { parseServiceAccountKey, m365CredentialsBody, m365CredentialsSchema } from './connect-step';
import { ConnectionPage } from './connection-page';
import { ConsentCallbackPage, consentBodyFrom } from './consent-callback-page';
import { guideFileName } from './guide-tab';
import { MailFlowDialog } from './mail-flow-dialog';
import { blockerText } from './model';
import { NewConnectionPage, newConnectionSchema } from './new-connection-page';
import { ProvidersSection } from './providers-section';
import type * as NavigateModule from './navigate';
import { initialStep } from './setup-tab';
import { groupResults } from './validations';

vi.mock('./navigate', async (importOriginal) => {
  const original = await importOriginal<typeof NavigateModule>();
  return { ...original, openConsentUrl: vi.fn() };
});

const { openConsentUrl } = await import('./navigate');

const T = '2026-11-19T09:00:00.000Z';
const ID = '0193f400-0000-7000-8000-000000000001';
const GRANT_ID = '0193f400-0000-7000-8000-0000000000a1';
const D1 = '0193f500-0000-7000-8000-000000000001';
const D2 = '0193f500-0000-7000-8000-000000000002';
// Synthetic, assembled at runtime: no secret-shaped literal in the source.
const SECRET = ['fixture', 'client', 'value', '0042'].join('-');
const STATE = 'A'.repeat(20) + 'b'.repeat(20) + '_-0';

const grant = (overrides: Record<string, unknown> = {}) => ({
  id: GRANT_ID,
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
  requestedPermissions: ['Organization.Read.All', 'Domain.Read.All'],
  observedPermissions: ['Organization.Read.All', 'Domain.Read.All'],
  missingPermissions: [],
  excessPermissions: [],
  consentedAt: T,
  verifyRequestedAt: T,
  verifiedAt: T,
  lastErrorCode: null,
  createdAt: T,
  updatedAt: T,
  ...overrides,
});

const connection = (overrides: Record<string, unknown> = {}) => ({
  id: ID,
  provider: 'microsoft_365',
  displayName: 'Contoso production',
  status: 'active',
  tenantName: 'Contoso Ltd',
  outboundMode: 'probe_only',
  internalRouting: false,
  health: 'healthy',
  healthChangedAt: T,
  domainCount: 2,
  createdAt: T,
  tenantId: '11111111-2222-3333-4444-555555555555',
  tenantVerifiedAt: T,
  grants: [grant()],
  domains: [
    { id: D1, name: 'alpha.example.test', providerVerification: 'verified' },
    { id: D2, name: 'bravo.example.test', providerVerification: 'verified' },
  ],
  relayConnectorId: '0193f600-0000-7000-8000-000000000001',
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
  ...overrides,
});

type Step = { step: string; status: string; blockers: string[] };
const wizard = (steps: Partial<Record<string, [string, string[]?]>> = {}, next = 'inbound') => {
  const order = ['connect', 'domains', 'inbound', 'outbound', 'validate', 'activate'];
  const defaults: Record<string, [string, string[]?]> = {
    connect: ['done'],
    domains: ['done'],
    inbound: ['in_progress', ['destinations_missing', 'attestations_missing']],
    outbound: ['done'],
    validate: ['blocked', ['inbound']],
    activate: ['blocked', ['validate']],
  };
  const all = { ...defaults, ...steps };
  return {
    connectionId: ID,
    provider: 'microsoft_365',
    connectionStatus: 'active',
    steps: order.map<Step>((step) => ({
      step,
      status: all[step]?.[0] ?? 'not_started',
      blockers: all[step]?.[1] ?? [],
    })),
    nextAction: { step: next, action: 'apply_inbound' },
    missingAttestations: ['m365.inbound_connector_created'],
  };
};

const linked = (overrides: Record<string, unknown> = {}) => [
  {
    id: D1,
    name: 'alpha.example.test',
    gatewayStatus: 'active',
    providerVerification: 'verified',
    providerCheckedAt: T,
    providerMxHost: 'alpha-example-test.mail.protection.outlook.com',
    destinationProvider: 'custom',
    inboundAppliedAt: null,
    dns: { mx: 'pass', spf: 'pass', dkim: 'pass' },
    ...overrides,
  },
  {
    id: D2,
    name: 'bravo.example.test',
    gatewayStatus: 'active',
    providerVerification: 'verified',
    providerCheckedAt: T,
    providerMxHost: null,
    destinationProvider: 'microsoft_365',
    inboundAppliedAt: T,
    dns: { mx: 'pass', spf: 'pass', dkim: 'pass' },
  },
];

const catalog = {
  providers: [
    {
      provider: 'microsoft_365',
      displayName: 'Microsoft 365',
      profiles: [
        {
          key: 'm365.mail_flow',
          version: 1,
          purpose: 'mail_flow',
          title: 'Mail flow (read-only)',
          description: 'Reads the tenant identity and domain verification.',
          permissions: ['Organization.Read.All', 'Domain.Read.All'],
          readOnly: true,
          authMethods: ['platform_app', 'customer_app_secret'],
          availableAuthMethods: ['platform_app', 'customer_app_secret'],
        },
      ],
      attestations: [
        {
          code: 'm365.inbound_connector_created',
          phase: 'inbound',
          statement: 'The inbound partner connector exists.',
          requiredFor: 'inbound',
        },
        {
          code: 'm365.outbound_connector_created',
          phase: 'outbound',
          statement: 'The outbound connector exists.',
          requiredFor: null,
        },
      ],
      egressSet: { version: 1, publishedAt: T, importedAt: T, rangeCount: 8 },
    },
    {
      provider: 'google_workspace',
      displayName: 'Google Workspace',
      profiles: [
        {
          key: 'google.mail_flow',
          version: 1,
          purpose: 'mail_flow',
          title: 'Mail flow (read-only)',
          description: 'Reads the customer and domains.',
          permissions: ['https://www.googleapis.com/auth/admin.directory.domain.readonly'],
          readOnly: true,
          authMethods: ['platform_service_account', 'customer_service_account'],
          availableAuthMethods: ['customer_service_account'],
        },
      ],
      attestations: [],
      egressSet: null,
    },
  ],
  probeDomain: 'probe.gateway.example.test',
  gateway: {
    mxHosts: ['mx1.gateway.example.test'],
    egressNetworks: ['192.0.2.10/32'],
    relayHosts: ['out.gateway.example.test'],
    relayTlsName: 'out.gateway.example.test',
    spfInclude: '_spf.gateway.example.test',
  },
};

const mailFlow = {
  connectionId: ID,
  outboundMode: 'probe_only',
  internalRouting: false,
  relayProof: { tenantHeader: 'required', dkimAligned: 'required' },
  relayProofIsDefault: true,
  relayConnector: { id: '0193f600-0000-7000-8000-000000000001', status: 'active' },
  domains: [],
  relayActivity24h: { accepted: 0, proofFailed: 0, tempFailed: 0, probes: 1, lastAcceptedAt: null },
  routeToken: { version: 1, pendingVersion: null, value: null, masked: '••••4567' },
};

const changeSet = (host = 'alpha-example-test.mail.protection.outlook.com') => ({
  kind: 'inbound',
  domains: [
    {
      domainId: D1,
      name: 'alpha.example.test',
      current: {
        provider: 'custom',
        servers: [{ host: 'mail.onprem.example.test', port: 25, priority: 10, tlsMode: 'may' }],
      },
      proposed: {
        provider: 'microsoft_365',
        servers: [{ host, port: 25, priority: 0, tlsMode: 'verify' }],
      },
      changed: true,
    },
  ],
  connector: { action: 'none', id: null },
  connection: [],
  grantsRevoked: 0,
});

function mockConnection(
  conn = connection(),
  extra: Parameters<typeof mockApi>[0] = {},
  wiz = wizard(),
) {
  mockApi({
    ProviderConnectionsController_get_v1: ({ params }) =>
      params.id === ID ? okJson(conn) : apiErrorJson(404, 'connection_not_found'),
    ProviderCatalogController_get_v1: () => okJson(catalog),
    ProviderConnectionsController_wizard_v1: () => okJson(wiz),
    ProviderDomainsController_list_v1: () => okJson({ data: linked() }),
    ProviderMailFlowController_get_v1: () => okJson(mailFlow),
    ProviderValidationsController_list_v1: () => okJson({ data: [], nextCursor: null }),
    ...extra,
  });
}

let setItem: ReturnType<typeof vi.spyOn>;
beforeEach(() => {
  vi.mocked(openConsentUrl).mockClear();
  setItem = vi.spyOn(Storage.prototype, 'setItem');
});
afterEach(() => {
  // Credentials and consent values never reach browser storage.
  for (const call of setItem.mock.calls) {
    expect(String(call[1])).not.toContain(SECRET);
    expect(String(call[1])).not.toContain(STATE);
  }
  setItem.mockRestore();
});

describe('pure helpers', () => {
  it('validates the new-connection form and the Microsoft credential form', () => {
    expect(
      newConnectionSchema.safeParse({ provider: 'microsoft_365', displayName: ' ' }).success,
    ).toBe(false);
    expect(
      newConnectionSchema.safeParse({ provider: 'google_workspace', displayName: 'Fabrikam' })
        .success,
    ).toBe(true);
    const parsed = m365CredentialsSchema.parse({
      tenantId: 'AAAAAAAA-2222-3333-4444-555555555555',
      clientId: '11111111-2222-3333-4444-555555555555',
      clientSecret: SECRET,
      expiresAt: '2027-01-31',
    });
    expect(m365CredentialsBody(parsed)).toEqual({
      tenantId: 'aaaaaaaa-2222-3333-4444-555555555555',
      clientId: '11111111-2222-3333-4444-555555555555',
      clientSecret: SECRET,
      expiresAt: '2027-01-31T00:00:00.000Z',
    });
    expect(
      m365CredentialsSchema.safeParse({ ...parsed, tenantId: 'contoso.onmicrosoft.com' }).success,
    ).toBe(false);
  });

  it('reads only service-account key files', () => {
    expect(() => parseServiceAccountKey('not json')).toThrow('not valid JSON');
    expect(() => parseServiceAccountKey('{"type":"authorized_user"}')).toThrow(
      'not a service account key',
    );
    expect(() =>
      parseServiceAccountKey('{"type":"service_account","client_email":"a@b.test"}'),
    ).toThrow('private_key');
  });

  it('builds the consent body from the redirect and refuses a missing or malformed state', () => {
    expect(consentBodyFrom(new URLSearchParams('tenant=x&admin_consent=True'))).toBeNull();
    expect(consentBodyFrom(new URLSearchParams('state=short'))).toBeNull();
    expect(
      consentBodyFrom(
        new URLSearchParams(
          `state=${STATE}&tenant=11111111-2222-3333-4444-555555555555&admin_consent=True`,
        ),
      ),
    ).toEqual({
      state: STATE,
      tenant: '11111111-2222-3333-4444-555555555555',
      adminConsent: true,
    });
    expect(
      consentBodyFrom(
        new URLSearchParams(`state=${STATE}&error=access_denied&error_description=declined`),
      ),
    ).toEqual({ state: STATE, error: 'access_denied', errorDescription: 'declined' });
  });

  it('picks the first step, words blockers, groups results and names the guide file', () => {
    expect(initialStep(wizard() as never)).toBe('inbound');
    expect(blockerText('attestations_missing')).toMatch(/Confirm the customer-side/);
    expect(blockerText('something_new')).toBe('Something new');
    expect(
      groupResults([
        { code: 'credentials.token', status: 'pass' },
        { code: 'inbound.smtp', status: 'fail' },
        { code: 'tenant.identity', status: 'pass' },
      ] as never).map(([area, list]) => [area, list.length]),
    ).toEqual([
      ['Access', 2],
      ['Inbound', 1],
    ]);
    expect(guideFileName({ provider: 'microsoft_365', displayName: 'Contoso Production!' })).toBe(
      'setup-microsoft-365-contoso-production.md',
    );
  });
});

describe('ProvidersSection on /integrations', () => {
  it('lists connections with links and badges; Connect only for managers (axe clean)', async () => {
    mockApi({
      ProviderConnectionsController_list_v1: () =>
        okJson({
          data: [
            {
              id: ID,
              provider: 'microsoft_365',
              displayName: 'Contoso production',
              status: 'active',
              tenantName: 'Contoso Ltd',
              outboundMode: 'active',
              internalRouting: true,
              health: 'critical',
              healthChangedAt: T,
              domainCount: 2,
              createdAt: T,
            },
          ],
          nextCursor: null,
        }),
    });
    const { container, unmount } = renderWithProviders(<ProvidersSection />);
    expect(await screen.findByRole('link', { name: 'Contoso production' })).toHaveAttribute(
      'href',
      `/integrations/providers/${ID}`,
    );
    expect(screen.getByText('Critical')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Connect' })).toHaveAttribute(
      'href',
      '/integrations/providers/new',
    );
    await expectNoAxeViolations(container);
    unmount();
    renderWithProviders(<ProvidersSection />, { role: 'security_analyst' });
    expect(await screen.findByRole('link', { name: 'Contoso production' })).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Connect' })).not.toBeInTheDocument();
  });
});

describe('NewConnectionPage', () => {
  it('creates a connection (contract, Idempotency-Key) and opens its Setup tab', async () => {
    const calls: { body: unknown; key: string | null }[] = [];
    mockApi({
      ProviderCatalogController_get_v1: () => okJson(catalog),
      ProviderConnectionsController_create_v1: ({ body, request }) => {
        calls.push({ body, key: request.headers.get('idempotency-key') });
        return okJson(connection({ status: 'draft', grants: [], domains: [] }), 201);
      },
    });
    const { user, container } = renderWithProviders(<NewConnectionPage />, {
      route: '/integrations/providers/new?provider=google_workspace',
    });
    expect(await screen.findByRole('radio', { name: /Google Workspace/ })).toBeChecked();
    await user.click(screen.getByRole('radio', { name: /Microsoft 365/ }));
    expect(screen.getByText('Organization.Read.All')).toBeInTheDocument();
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('button', { name: 'Create and continue' }));
    expect(await screen.findByText('Enter a name')).toBeInTheDocument();
    await user.type(screen.getByLabelText('Connection name (required)'), 'Contoso production');
    await user.click(screen.getByRole('button', { name: 'Create and continue' }));
    await waitFor(() => expect(currentTestUrl()).toBe(`/integrations/providers/${ID}?tab=setup`));
    expect(calls).toHaveLength(1);
    expectRequestMatchesContract('ProviderConnectionsController_create_v1', calls[0]?.body);
    expect(calls[0]?.body).toEqual({
      provider: 'microsoft_365',
      displayName: 'Contoso production',
    });
    expect(calls[0]?.key).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('is forbidden without integration:manage', () => {
    renderWithProviders(<NewConnectionPage />, { role: 'read_only_user' });
    expect(screen.getByText('You do not have access to this page')).toBeInTheDocument();
  });
});

describe('ConnectionPage', () => {
  it('shows the header, tabs and the server-computed wizard with blockers (axe clean)', async () => {
    mockConnection();
    const { container } = renderWithProviders(<ConnectionPage connectionId={ID} />, {
      route: `/integrations/providers/${ID}?tab=setup`,
    });
    expect(
      await screen.findByRole('heading', { name: 'Contoso production', level: 1 }),
    ).toBeVisible();
    expect(screen.getByText('Tenant Contoso Ltd')).toBeInTheDocument();
    for (const tab of ['Setup', 'Health', 'Validations', 'Setup guide', 'Settings'])
      expect(screen.getByRole('tab', { name: tab })).toBeInTheDocument();
    const steps = await screen.findByRole('navigation', { name: 'Setup steps' });
    expect(within(steps).getByRole('button', { name: /Inbound/ })).toHaveAttribute(
      'aria-current',
      'step',
    );
    expect(within(steps).getByRole('button', { name: /Validate.*blocked/i })).toBeInTheDocument();
    expect(
      screen.getByText('Not every linked domain delivers to the provider yet.'),
    ).toBeInTheDocument();
    expect(await screen.findByText('The inbound partner connector exists.')).toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('is a 404 for malformed and foreign ids', async () => {
    const { unmount } = renderWithProviders(<ConnectionPage connectionId="not-a-uuid" />);
    expect(screen.getByText(/Page not found/i)).toBeInTheDocument();
    unmount();
    mockConnection();
    renderWithProviders(<ConnectionPage connectionId="0193f400-0000-7000-8000-00000000ffff" />);
    expect(await screen.findByText(/Page not found/i)).toBeInTheDocument();
  });

  it('inbound: preview shows the change set; apply needs the effect and the typed name; impact_changed previews again', async () => {
    const previews: unknown[] = [];
    const applies: { body: unknown; key: string | null }[] = [];
    let applyCount = 0;
    mockConnection(connection(), {
      ProviderMailFlowController_preview_v1: ({ body }) => {
        previews.push(body);
        const host = previews.length === 1 ? undefined : 'alpha-new.mail.protection.outlook.com';
        return okJson({
          change: (body as { change: object }).change,
          changeSet: changeSet(host),
          impactToken: `token-${previews.length}.1999999999`,
          expiresAt: '2026-11-19T09:15:00.000Z',
          warnings: previews.length === 1 ? ['destination_differs_from_provider_mx'] : [],
        });
      },
      ProviderMailFlowController_apply_v1: ({ body, request }) => {
        applies.push({ body, key: request.headers.get('idempotency-key') });
        applyCount += 1;
        if (applyCount === 1) return apiErrorJson(409, 'impact_changed');
        return okJson({ connection: connection(), changeSet: changeSet(), appliedAt: T });
      },
    });
    const { user } = renderWithProviders(<ConnectionPage connectionId={ID} />, {
      route: `/integrations/providers/${ID}?tab=setup`,
    });
    const host = await screen.findByLabelText('Microsoft 365 host');
    expect(host).toHaveValue('alpha-example-test.mail.protection.outlook.com');
    await user.click(screen.getByRole('button', { name: 'Preview inbound change' }));
    const dialog = await screen.findByRole('dialog', { name: 'Apply inbound routing' });
    expect(await within(dialog).findByText('mail.onprem.example.test:25')).toBeInTheDocument();
    expect(
      within(dialog).getByText(
        'The destination host differs from the MX target the provider reports for the domain.',
      ),
    ).toBeInTheDocument();
    expectRequestMatchesContract('ProviderMailFlowController_preview_v1', previews[0]);
    expect(previews[0]).toEqual({
      change: {
        kind: 'inbound',
        domainIds: [D1],
        microsoftHosts: { [D1]: 'alpha-example-test.mail.protection.outlook.com' },
      },
    });
    const confirm = within(dialog).getByRole('button', { name: 'Apply inbound routing' });
    expect(confirm).toBeDisabled();
    await user.click(within(dialog).getByRole('checkbox', { name: /all inbound mail/ }));
    expect(confirm).toBeDisabled();
    await user.type(within(dialog).getByLabelText(/to confirm/), 'Contoso production');
    expect(confirm).toBeEnabled();
    await user.click(confirm);
    // 409 impact_changed: a new preview, a warning, and a fresh confirmation.
    expect(await within(dialog).findByRole('alert')).toHaveTextContent(
      'The configuration changed since your preview',
    );
    expect(
      await within(dialog).findByText('alpha-new.mail.protection.outlook.com:25'),
    ).toBeVisible();
    expect(within(dialog).getByLabelText(/to confirm/)).toHaveValue('');
    await user.click(within(dialog).getByRole('checkbox', { name: /all inbound mail/ }));
    await user.type(within(dialog).getByLabelText(/to confirm/), 'Contoso production');
    await user.click(within(dialog).getByRole('button', { name: 'Apply inbound routing' }));
    await waitFor(() =>
      expect(
        screen.queryByRole('dialog', { name: 'Apply inbound routing' }),
      ).not.toBeInTheDocument(),
    );
    expect(applies).toHaveLength(2);
    expectRequestMatchesContract('ProviderMailFlowController_apply_v1', applies[1]?.body);
    expect(applies[0]?.body).toMatchObject({ impactToken: 'token-1.1999999999', confirm: true });
    expect(applies[1]?.body).toMatchObject({ impactToken: 'token-2.1999999999', confirm: true });
    // A new intent (a different token) gets a new Idempotency-Key.
    expect(applies[0]?.key).not.toBe(applies[1]?.key);
  });

  it('hides apply actions from users without domain:routing_manage', async () => {
    mockConnection();
    renderWithProviders(<ConnectionPage connectionId={ID} />, {
      route: `/integrations/providers/${ID}?tab=setup`,
      role: 'security_analyst',
    });
    expect(await screen.findByLabelText(/alpha\.example\.test/)).toBeDisabled();
    expect(
      screen.queryByRole('button', { name: 'Preview inbound change' }),
    ).not.toBeInTheDocument();
    expect(screen.getByText(/Applying needs both/)).toBeInTheDocument();
  });
});

describe('Connect step', () => {
  const draft = connection({
    status: 'draft',
    tenantName: null,
    tenantId: null,
    grants: [],
    domains: [],
    outboundMode: 'off',
    relayConnectorId: null,
  });
  const connectWizard = wizard(
    { connect: ['not_started'], domains: ['blocked', ['connect']] },
    'connect',
  );

  it('admin consent: creates the grant and opens Microsoft’s consent URL in the same tab', async () => {
    const calls: unknown[] = [];
    mockConnection(
      draft,
      {
        ProviderGrantsController_create_v1: ({ body }) => {
          calls.push(body);
          return okJson(
            {
              grant: grant({ status: 'pending_consent' }),
              next: 'consent',
              consent: {
                consentUrl: `https://login.example.test/organizations/v2.0/adminconsent?state=${STATE}`,
                expiresAt: T,
              },
              delegation: null,
            },
            201,
          );
        },
      },
      connectWizard,
    );
    const { user } = renderWithProviders(<ConnectionPage connectionId={ID} />, {
      route: `/integrations/providers/${ID}?tab=setup`,
    });
    await user.click(
      await screen.findByRole('button', { name: 'Use admin consent to the gateway app' }),
    );
    await waitFor(() =>
      expect(openConsentUrl).toHaveBeenCalledWith(
        `https://login.example.test/organizations/v2.0/adminconsent?state=${STATE}`,
      ),
    );
    expectRequestMatchesContract('ProviderGrantsController_create_v1', calls[0]);
    expect(calls[0]).toEqual({ profile: 'm365.mail_flow', authMethod: 'platform_app' });
  });

  it('customer secret: never echoes the secret, clears it after upload and stores nothing', async () => {
    const uploads: unknown[] = [];
    mockConnection(
      connection({
        status: 'connecting',
        grants: [
          grant({ authMethod: 'customer_app_secret', status: 'pending_consent', clientId: null }),
        ],
      }),
      {
        ProviderGrantsController_setCredentials_v1: ({ body }) => {
          uploads.push(body);
          return okJson(grant({ authMethod: 'customer_app_secret', status: 'verifying' }));
        },
      },
      wizard({ connect: ['in_progress', ['consent_pending']] }, 'connect'),
    );
    const { user } = renderWithProviders(<ConnectionPage connectionId={ID} />, {
      route: `/integrations/providers/${ID}?tab=setup`,
    });
    const secret = await screen.findByLabelText('Client secret value');
    expect(secret).toHaveAttribute('type', 'password');
    expect(secret).toHaveAttribute('autocomplete', 'new-password');
    await user.type(
      screen.getByLabelText('Directory (tenant) ID'),
      '22222222-3333-4444-5555-666666666666',
    );
    await user.type(
      screen.getByLabelText('Application (client) ID'),
      '33333333-4444-5555-6666-777777777777',
    );
    await user.type(secret, SECRET);
    await user.click(screen.getByRole('button', { name: 'Upload and verify' }));
    await waitFor(() => expect(uploads).toHaveLength(1));
    expectRequestMatchesContract('ProviderGrantsController_setCredentials_v1', uploads[0]);
    expect(uploads[0]).toMatchObject({ clientSecret: SECRET });
    await waitFor(() => expect(screen.getByLabelText('Client secret value')).toHaveValue(''));
    expect(document.body.textContent).not.toContain(SECRET);
  });

  it('Google delegation: shows the client id and scopes and confirms with the delegated admin', async () => {
    const verifies: unknown[] = [];
    mockConnection(
      connection({
        provider: 'google_workspace',
        status: 'connecting',
        grants: [
          grant({
            profile: 'google.mail_flow',
            authMethod: 'platform_service_account',
            status: 'pending_consent',
            clientId: '100000000000000000001',
            requestedPermissions: [
              'https://www.googleapis.com/auth/admin.directory.domain.readonly',
            ],
          }),
        ],
      }),
      {
        ProviderGrantsController_verify_v1: ({ body }) => {
          verifies.push(body);
          return okJson(grant({ profile: 'google.mail_flow', status: 'verifying' }));
        },
      },
      {
        ...wizard({ connect: ['in_progress', ['consent_pending']] }, 'connect'),
        provider: 'google_workspace',
      },
    );
    const { user } = renderWithProviders(<ConnectionPage connectionId={ID} />, {
      route: `/integrations/providers/${ID}?tab=setup`,
    });
    expect(await screen.findByRole('button', { name: 'Copy client ID' })).toBeInTheDocument();
    expect(
      screen.getAllByText('https://www.googleapis.com/auth/admin.directory.domain.readonly').length,
    ).toBeGreaterThan(0);
    await user.click(screen.getByRole('button', { name: /I have authorized/ }));
    expect(await screen.findByRole('alert')).toHaveTextContent(/delegated administrator/);
    await user.type(
      screen.getAllByLabelText('Delegated administrator')[0]!,
      'admin@fabrikam.example',
    );
    await user.click(screen.getByRole('button', { name: /I have authorized/ }));
    await waitFor(() => expect(verifies).toEqual([{ subjectEmail: 'admin@fabrikam.example' }]));
  });
});

describe('Validation, health, guide and settings tabs', () => {
  it('validate: starts a full run and shows the probe address once with a copy button', async () => {
    const run = {
      id: '0193f700-0000-7000-8000-000000000001',
      kind: 'full',
      status: 'awaiting_probe',
      requestedBy: { type: 'user', id: null },
      probeExpiresAt: '2026-11-20T09:00:00.000Z',
      summary: null,
      startedAt: T,
      completedAt: null,
      createdAt: T,
    };
    mockConnection(
      connection(),
      {
        ProviderValidationsController_create_v1: () =>
          okJson(
            {
              ...run,
              probeAddress: 'eg-probe-abcdefghijklmnopqrstuvwxyz@probe.gateway.example.test',
            },
            201,
          ),
        ProviderValidationsController_get_v1: () =>
          okJson({
            ...run,
            results: [
              {
                code: 'inbound.smtp',
                subject: 'alpha.example.test',
                status: 'fail',
                severity: 'critical',
                evidence: { tlsVersion: 'TLSv1.3' },
                remediation: '#inbound-destination',
              },
            ],
            probeObservations: [],
          }),
      },
      wizard(
        { inbound: ['done'], validate: ['not_started'], activate: ['blocked', ['validate']] },
        'validate',
      ),
    );
    const { user } = renderWithProviders(<ConnectionPage connectionId={ID} />, {
      route: `/integrations/providers/${ID}?tab=setup`,
    });
    await user.click(await screen.findByRole('button', { name: 'Run full validation' }));
    expect(
      await screen.findByText('eg-probe-abcdefghijklmnopqrstuvwxyz@probe.gateway.example.test'),
    ).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Copy probe address' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'How to fix this (setup guide)' })).toHaveAttribute(
      'href',
      `/integrations/providers/${ID}?tab=guide#inbound-destination`,
    );
  });

  it('health: checks, transitions and Check now', async () => {
    const checks: unknown[] = [];
    mockConnection(connection(), {
      ProviderHealthController_get_v1: () =>
        okJson({
          connectionId: ID,
          status: 'critical',
          checkedAt: T,
          changedAt: T,
          nextCheckAt: T,
          checks: [
            {
              code: 'routing.loops',
              title: 'Mail loops',
              subject: '',
              status: 'fail',
              severity: 'critical',
              evidence: {},
              firstFailedAt: T,
              checkedAt: T,
            },
          ],
          transitions: [
            { from: 'healthy', to: 'critical', failingChecks: ['routing.loops'], at: T },
          ],
        }),
      ProviderHealthController_checkNow_v1: ({ request }) => {
        checks.push(request.headers.get('idempotency-key'));
        return okJson({ connectionId: ID, nextHealthCheckAt: T }, 202);
      },
    });
    const { user, container } = renderWithProviders(<ConnectionPage connectionId={ID} />, {
      route: `/integrations/providers/${ID}?tab=health`,
    });
    expect(await screen.findByText('Mail loops')).toBeInTheDocument();
    expect(screen.getByRole('list', { name: 'Health status changes' })).toHaveTextContent(
      'routing.loops',
    );
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('button', { name: 'Check now' }));
    await waitFor(() => expect(checks).toHaveLength(1));
  });

  it('guide: renders sections with copyable commands and downloads the Markdown', async () => {
    const markdownRequests: string[] = [];
    mockApi({});
    mockConnection(connection(), {
      ProviderGuideController_get_v1: ({ url }) => {
        if (url.searchParams.get('format') === 'markdown') {
          markdownRequests.push(url.search);
          return new Response('# Guide', {
            headers: {
              'content-type': 'text/markdown; charset=utf-8',
              'content-disposition':
                'attachment; filename="setup-microsoft-365-contoso-production.md"',
            },
          });
        }
        return okJson({
          schema: 'setup-guide/1',
          provider: 'microsoft_365',
          connection: {
            id: ID,
            displayName: 'Contoso production',
            tenantId: null,
            tenantName: null,
          },
          generatedAt: T,
          notice: 'Apply every step yourself.',
          sections: [
            {
              id: 'inbound',
              number: 4,
              title: 'Inbound',
              paragraphs: ['Point MX to the gateway.'],
              steps: [
                {
                  id: 'inbound-connector',
                  title: 'Inbound partner connector',
                  paragraphs: [],
                  commands: [
                    {
                      language: 'powershell',
                      code: 'New-InboundConnector -Name "Email security gateway"',
                    },
                  ],
                  attestation: {
                    code: 'm365.inbound_connector_created',
                    statement: 'The inbound partner connector exists.',
                    attested: false,
                    attestedAt: null,
                  },
                },
              ],
            },
          ],
        });
      },
    });
    const createObjectURL = vi.fn(() => 'blob:guide');
    const revokeObjectURL = vi.fn();
    Object.assign(URL, { createObjectURL, revokeObjectURL });
    const { user } = renderWithProviders(<ConnectionPage connectionId={ID} />, {
      route: `/integrations/providers/${ID}?tab=guide`,
    });
    expect(await screen.findByRole('heading', { name: '4. Inbound' })).toBeInTheDocument();
    expect(screen.getByText('New-InboundConnector -Name "Email security gateway"')).toBeVisible();
    expect(
      screen.getByRole('button', {
        name: /Copy the PowerShell commands of “Inbound partner connector”/,
      }),
    ).toBeInTheDocument();
    expect(screen.getByText('Not stated yet')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Download Markdown' }));
    await waitFor(() => expect(createObjectURL).toHaveBeenCalledTimes(1));
    expect(markdownRequests).toEqual(['?format=markdown']);
  });

  it('settings: disconnect requires the typed name and shows the provider cleanup steps', async () => {
    const disconnects: unknown[] = [];
    mockConnection(connection({ outboundMode: 'active' }), {
      ProviderMailFlowController_preview_v1: () =>
        okJson({
          change: { kind: 'disable' },
          changeSet: {
            kind: 'disable',
            domains: [],
            connector: { action: 'disable', id: '0193f600-0000-7000-8000-000000000001' },
            connection: [{ field: 'status', from: 'active', to: 'disabled' }],
            grantsRevoked: 1,
          },
          impactToken: 'token-d.1999999999',
          expiresAt: T,
          warnings: [],
        }),
      ProviderConnectionsController_disconnect_v1: ({ body }) => {
        disconnects.push(body);
        return okJson({
          connection: connection({ status: 'disabled', outboundMode: 'off' }),
          providerCleanupSteps: ['Remove the outbound connector in Exchange Online.'],
          destinationsKept: true,
        });
      },
    });
    const { user } = renderWithProviders(<ConnectionPage connectionId={ID} />, {
      route: `/integrations/providers/${ID}?tab=settings`,
    });
    await user.click(await screen.findByRole('button', { name: 'Disconnect…' }));
    const dialog = await screen.findByRole('dialog', { name: 'Disconnect Contoso production' });
    expect(await within(dialog).findByText(/Access grants revoked/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole('checkbox', { name: /stops relaying/ }));
    await user.type(within(dialog).getByLabelText(/to confirm/), 'Contoso');
    expect(within(dialog).getByRole('button', { name: 'Disconnect' })).toBeDisabled();
    await user.type(within(dialog).getByLabelText(/to confirm/), ' production');
    await user.click(within(dialog).getByRole('button', { name: 'Disconnect' }));
    expect(
      await screen.findByText('Remove the outbound connector in Exchange Online.'),
    ).toBeVisible();
    expectRequestMatchesContract('ProviderConnectionsController_disconnect_v1', disconnects[0]);
    expect(disconnects[0]).toEqual({ impactToken: 'token-d.1999999999', confirm: true });
  });
});

describe('MailFlowDialog', () => {
  it('retries a failed apply with the same Idempotency-Key', async () => {
    const keys: (string | null)[] = [];
    mockApi({
      ProviderMailFlowController_preview_v1: () =>
        okJson({
          change: { kind: 'outbound', mode: 'probe_only' },
          changeSet: {
            kind: 'outbound',
            domains: [],
            connector: { action: 'create', id: null },
            connection: [{ field: 'outboundMode', from: 'off', to: 'probe_only' }],
            grantsRevoked: 0,
          },
          impactToken: 'token-o.1999999999',
          expiresAt: T,
          warnings: [],
        }),
      ProviderMailFlowController_apply_v1: ({ request }) => {
        keys.push(request.headers.get('idempotency-key'));
        return keys.length === 1
          ? apiErrorJson(503, 'service_unavailable')
          : okJson({ connection: connection(), changeSet: changeSet(), appliedAt: T });
      },
    });
    const onOpenChange = vi.fn();
    const { user } = renderWithProviders(
      <MailFlowDialog
        open
        onOpenChange={onOpenChange}
        connectionId={ID}
        connectionName="Contoso production"
        change={{ kind: 'outbound', mode: 'probe_only' }}
        title="Enable probe mode"
        effect="I understand the effect."
        confirmLabel="Enable"
      />,
    );
    expect(await screen.findByText(/Outbound mode: Off/)).toBeInTheDocument();
    expect(screen.getByText(/Provider relay connector/)).toHaveTextContent('Create');
    await user.click(screen.getByRole('checkbox', { name: 'I understand the effect.' }));
    await user.type(screen.getByLabelText(/to confirm/), 'Contoso production');
    await user.click(screen.getByRole('button', { name: 'Enable' }));
    await user.click(await screen.findByRole('button', { name: 'Retry' }));
    await waitFor(() => expect(onOpenChange).toHaveBeenCalledWith(false));
    expect(keys).toHaveLength(2);
    expect(keys[0]).toBe(keys[1]);
  });
});

describe('ConsentCallbackPage', () => {
  const visit = (query: string) => {
    window.history.replaceState(null, '', `/integrations/providers/consent-callback?${query}`);
    return renderWithProviders(<ConsentCallbackPage />, {
      route: `/integrations/providers/consent-callback?${query}`,
    });
  };
  afterEach(() => window.history.replaceState(null, '', '/'));

  it('scrubs the query string before posting the JSON body, then opens the Setup tab', async () => {
    const posted: { body: unknown; search: string; locationAtPost: string }[] = [];
    mockApi({
      ProviderGrantsController_completeConsent_v1: ({ body, url }) => {
        posted.push({ body, search: url.search, locationAtPost: window.location.search });
        return okJson({ connectionId: ID, grantId: GRANT_ID, status: 'verifying' });
      },
    });
    visit(`admin_consent=True&tenant=11111111-2222-3333-4444-555555555555&state=${STATE}`);
    expect(window.location.search).toBe('');
    await waitFor(() => expect(currentTestUrl()).toBe(`/integrations/providers/${ID}?tab=setup`));
    expect(posted).toHaveLength(1);
    expect(posted[0]?.search).toBe('');
    expect(posted[0]?.locationAtPost).toBe('');
    expectRequestMatchesContract('ProviderGrantsController_completeConsent_v1', posted[0]?.body);
    expect(posted[0]?.body).toEqual({
      state: STATE,
      tenant: '11111111-2222-3333-4444-555555555555',
      adminConsent: true,
    });
  });

  it('shows the declined, invalid-state and missing-state cases', async () => {
    mockApi({
      ProviderGrantsController_completeConsent_v1: ({ body }) =>
        (body as { error?: string }).error
          ? okJson({ connectionId: ID, grantId: GRANT_ID, status: 'error' })
          : apiErrorJson(404, 'consent_state_invalid'),
    });
    const first = visit(`state=${STATE}&error=access_denied&error_description=The+admin+declined`);
    expect(await screen.findByRole('heading', { name: 'Consent was not granted' })).toBeVisible();
    expect(screen.getByRole('link', { name: 'Back to the connection' })).toHaveAttribute(
      'href',
      `/integrations/providers/${ID}?tab=setup`,
    );
    first.unmount();
    const second = visit(`state=${STATE}&admin_consent=True`);
    expect(
      await screen.findByRole('heading', { name: 'The consent could not be completed' }),
    ).toBeVisible();
    expect(screen.getByText(/The consent link expired, was already used/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Try again' })).not.toBeInTheDocument();
    second.unmount();
    visit('admin_consent=True');
    expect(screen.getByRole('heading', { name: 'This consent link cannot be used' })).toBeVisible();
  });
});

describe('Mail servers connectors tab (step 8.2)', () => {
  it('shows provider_relay connectors read-only with a link to their connection', async () => {
    mockApi({
      SmtpConnectorsController_list_v1: () =>
        okJson({
          data: [
            {
              id: '0193f600-0000-7000-8000-000000000001',
              name: 'Microsoft 365 relay: Contoso',
              authType: 'provider_relay',
              status: 'active',
              saslUsername: null,
              certificateFingerprintSha256: null,
              networks: [],
              requireTls: true,
              secretSetAt: null,
              providerConnectionId: ID,
              createdAt: T,
              updatedAt: T,
            },
          ],
          nextCursor: null,
        }),
    });
    const { user } = renderWithProviders(<ConnectorsTab />, {
      route: '/mail-servers?tab=connectors',
    });
    expect((await screen.findAllByText('Read-only')).length).toBeGreaterThan(0);
    expect(
      screen.getAllByRole('link', { name: 'Managed by its provider connection' })[0],
    ).toHaveAttribute('href', `/integrations/providers/${ID}`);
    await user.click(
      screen.getByRole('button', { name: 'Actions for Microsoft 365 relay: Contoso' }),
    );
    expect(screen.getByRole('menuitem', { name: 'Open provider connection' })).toBeInTheDocument();
    expect(screen.queryByRole('menuitem', { name: 'Delete' })).not.toBeInTheDocument();
    expect(screen.queryByRole('menuitem', { name: 'Edit' })).not.toBeInTheDocument();
  });
});
