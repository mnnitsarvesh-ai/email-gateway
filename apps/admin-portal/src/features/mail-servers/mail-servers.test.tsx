import { screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import {
  apiErrorJson,
  currentTestUrl,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  mockApi,
  noContentResponse,
  okJson,
  renderWithProviders,
} from '@/test';
import { destinations, domainSummary } from '@/features/domains/test-data';
import {
  connectorCreateBody,
  connectorCreateSchema,
  connectorUpdateBody,
  connectorUpdateSchema,
} from './connectors-tab';
import { MailServersPage } from './mail-servers-page';
import { suppressionCreateBody, suppressionCreateSchema } from './suppressions-tab';

const T = '2026-11-12T09:00:00.000Z';
const connector = (i: number, overrides: Record<string, unknown> = {}) => ({
  id: `0193b000-0000-7000-8000-${String(i).padStart(12, '0')}`,
  name: `Connector ${i}`,
  authType: 'sasl',
  status: 'active',
  saslUsername: `egc-test${i}`,
  certificateFingerprintSha256: null,
  networks: [],
  requireTls: true,
  secretSetAt: T,
  createdAt: T,
  updatedAt: T,
  ...overrides,
});
const suppression = (i: number, overrides: Record<string, unknown> = {}) => ({
  id: String(100 + i),
  address: `r${i}@partner.example.com`,
  reason: 'manual',
  source: 'portal',
  expiresAt: null,
  active: true,
  createdAt: T,
  createdBy: null,
  ...overrides,
});

describe('MailServersPage', () => {
  it('shows the tabs the role may use and refuses roles without any of them', () => {
    const { unmount } = renderWithProviders(<MailServersPage />, {
      role: 'mailbox_user',
      route: '/mail-servers',
    });
    expect(screen.getByText('You do not have access to this page')).toBeInTheDocument();
    unmount();
    mockApi({ DomainsController_list_v1: () => okJson({ data: [], nextCursor: null }) });
    renderWithProviders(<MailServersPage />, { role: 'domain_admin', route: '/mail-servers' });
    const tabs = screen.getAllByRole('tab').map((t) => t.textContent);
    expect(tabs).toEqual(['Destination servers', 'SMTP connectors', 'Suppressions', 'Deliveries']);
    expect(screen.getByText(/Delivery routes have no API/)).toBeInTheDocument();
  });

  it('destinations: lists domains with their destinations fetched per row (axe clean)', async () => {
    const requests: string[] = [];
    mockApi({
      DomainsController_list_v1: ({ url }) => (
        requests.push(url.search),
        okJson({ data: [domainSummary(1), domainSummary(2)], nextCursor: null })
      ),
      DomainDestinationsController_get_v1: ({ params }) =>
        params.id === domainSummary(1).id
          ? okJson(destinations())
          : okJson(destinations({ provider: null, servers: [] })),
    });
    const { container } = renderWithProviders(<MailServersPage />, {
      role: 'domain_admin',
      route: '/mail-servers?tab=destinations',
    });
    expect(await screen.findByText('mx1.alpha.example.test:25 (10)')).toBeInTheDocument();
    expect(await screen.findByText('None (mail is held)')).toBeInTheDocument();
    expect(
      screen.getByRole('link', { name: 'Edit destinations of d1.example.test' }),
    ).toHaveAttribute('href', `/domains/${domainSummary(1).id}?tab=destinations`);
    expect(requests[0]).toContain('limit=10');
    await expectNoAxeViolations(container);
  });

  it('destinations: read-only users get no edit links', async () => {
    mockApi({
      DomainsController_list_v1: () => okJson({ data: [domainSummary(1)], nextCursor: null }),
      DomainDestinationsController_get_v1: () => okJson(destinations()),
    });
    renderWithProviders(<MailServersPage />, { role: 'read_only_user', route: '/mail-servers' });
    await screen.findByText('mx1.alpha.example.test:25 (10)');
    expect(screen.queryByRole('link', { name: /Edit destinations/ })).not.toBeInTheDocument();
  });

  it('connectors: loading, error with request id, empty and filters in the URL', async () => {
    const requests: URL[] = [];
    let fail = true;
    mockApi({
      SmtpConnectorsController_list_v1: ({ url }) => {
        requests.push(url);
        if (fail) return apiErrorJson(500, 'internal_error', 'Boom', { requestId: 'req-c-1' });
        return okJson({ data: [], nextCursor: null });
      },
    });
    const { user } = renderWithProviders(<MailServersPage />, {
      role: 'domain_admin',
      route: '/mail-servers?tab=connectors',
    });
    expect(screen.getByText(/Loading SMTP connectors/)).toBeInTheDocument();
    expect(await screen.findByText('req-c-1')).toBeInTheDocument();
    fail = false;
    await user.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByText('No SMTP connectors')).toBeInTheDocument();
    await user.click(screen.getByRole('combobox', { name: 'Authentication' }));
    await user.click(await screen.findByRole('option', { name: 'Source IP' }));
    expect(currentTestUrl()).toBe('/mail-servers?tab=connectors&authType=source_ip');
    await waitFor(() => expect(requests.at(-1)?.searchParams.get('authType')).toBe('source_ip'));
  });

  it('connectors: creating a SASL connector shows the password once (contract)', async () => {
    let body: unknown = null;
    mockApi({
      SmtpConnectorsController_list_v1: () => okJson({ data: [connector(1)], nextCursor: null }),
      SmtpConnectorsController_create_v1: ({ body: b }) => (
        (body = b),
        okJson(
          {
            ...connector(2, { name: 'Exchange' }),
            credentials: { username: 'egc-new', password: 'dev-fixture-secret-123' },
          },
          201,
        )
      ),
    });
    const { user, container } = renderWithProviders(<MailServersPage />, {
      role: 'organization_admin',
      route: '/mail-servers?tab=connectors',
    });
    await screen.findByText('Connector 1');
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('button', { name: 'New connector' }));
    const dialog = await screen.findByRole('dialog', { name: 'New SMTP connector' });
    await user.type(within(dialog).getByLabelText('Name (required)'), 'Exchange');
    await user.click(within(dialog).getByRole('button', { name: 'Create connector' }));
    await waitFor(() => expect(body).toEqual({ name: 'Exchange', authType: 'sasl' }));
    expectRequestMatchesContract('SmtpConnectorsController_create_v1', body);
    const reveal = await screen.findByRole('dialog', { name: 'Connector credentials' });
    expect(within(reveal).getByText('dev-fixture-secret-123')).toBeInTheDocument();
    await user.click(within(reveal).getByRole('checkbox'));
    await user.click(within(reveal).getByRole('button', { name: 'Done' }));
    await waitFor(() =>
      expect(screen.queryByText('dev-fixture-secret-123')).not.toBeInTheDocument(),
    );
  });

  it('connectors: edit (contract), rotate (secret once) and delete; hidden for read-only', async () => {
    const calls: Record<string, unknown> = {};
    mockApi({
      SmtpConnectorsController_list_v1: () =>
        okJson({
          data: [
            connector(1),
            connector(2, {
              authType: 'source_ip',
              saslUsername: null,
              secretSetAt: null,
              networks: [{ cidr: '192.0.2.0/27', ipVersion: 4 }],
            }),
          ],
          nextCursor: null,
        }),
      SmtpConnectorsController_update_v1: ({ body }) => (
        (calls.update = body),
        okJson(connector(2))
      ),
      SmtpConnectorsController_rotateSecret_v1: () =>
        okJson({
          id: connector(1).id,
          credentials: { username: 'egc-test1', password: 'dev-fixture-rotated-9' },
          secretSetAt: T,
        }),
      SmtpConnectorsController_remove_v1: () => ((calls.remove = true), noContentResponse()),
    });
    const { user, unmount } = renderWithProviders(<MailServersPage />, {
      role: 'domain_admin',
      route: '/mail-servers?tab=connectors',
    });
    await user.click(await screen.findByRole('button', { name: 'Actions for Connector 2' }));
    await user.click(await screen.findByRole('menuitem', { name: 'Edit' }));
    const dialog = await screen.findByRole('dialog', { name: 'Edit Connector 2' });
    const networks = within(dialog).getByLabelText('Networks (required)');
    await user.clear(networks);
    await user.type(networks, '198.51.100.0/24');
    await user.click(within(dialog).getByRole('button', { name: 'Save connector' }));
    await waitFor(() =>
      expect(calls.update).toEqual({
        name: 'Connector 2',
        networks: ['198.51.100.0/24'],
        requireTls: true,
      }),
    );
    expectRequestMatchesContract('SmtpConnectorsController_update_v1', calls.update);

    await user.click(screen.getByRole('button', { name: 'Actions for Connector 1' }));
    await user.click(await screen.findByRole('menuitem', { name: 'Rotate password' }));
    await user.click(
      within(await screen.findByRole('alertdialog')).getByRole('button', {
        name: 'Rotate password',
      }),
    );
    const reveal = await screen.findByRole('dialog', { name: 'New connector password' });
    expect(within(reveal).getByText('dev-fixture-rotated-9')).toBeInTheDocument();
    await user.click(within(reveal).getByRole('checkbox'));
    await user.click(within(reveal).getByRole('button', { name: 'Done' }));
    await waitFor(() =>
      expect(screen.queryByText('dev-fixture-rotated-9')).not.toBeInTheDocument(),
    );

    await user.click(screen.getByRole('button', { name: 'Actions for Connector 1' }));
    await user.click(await screen.findByRole('menuitem', { name: 'Delete' }));
    await user.click(
      within(await screen.findByRole('alertdialog')).getByRole('button', {
        name: 'Delete connector',
      }),
    );
    await waitFor(() => expect(calls.remove).toBe(true));
    unmount();

    renderWithProviders(<MailServersPage />, {
      role: 'read_only_user',
      route: '/mail-servers?tab=connectors',
    });
    await screen.findByText('Connector 1');
    expect(screen.queryByRole('button', { name: 'New connector' })).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Actions for Connector 1' }),
    ).not.toBeInTheDocument();
  });

  it('suppressions: create needs an Idempotency-Key (contract) and explains suppression_exists', async () => {
    const keys: (string | null)[] = [];
    const bodies: unknown[] = [];
    mockApi({
      RecipientSuppressionsController_list_v1: () =>
        okJson({ data: [suppression(1)], nextCursor: null }),
      RecipientSuppressionsController_create_v1: ({ request, body }) => {
        keys.push(request.headers.get('idempotency-key'));
        bodies.push(body);
        return bodies.length === 1
          ? apiErrorJson(409, 'suppression_exists', 'The address is already suppressed', {
              extra: { id: '101' },
            })
          : okJson(suppression(2), 201);
      },
    });
    const { user, container } = renderWithProviders(<MailServersPage />, {
      role: 'domain_admin',
      route: '/mail-servers?tab=suppressions',
    });
    await screen.findByText('r1@partner.example.com');
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('button', { name: 'Suppress address' }));
    const dialog = await screen.findByRole('dialog', { name: 'Suppress an address' });
    await user.type(within(dialog).getByLabelText('Address (required)'), 'R1@Partner.example.com');
    await user.click(within(dialog).getByRole('button', { name: 'Suppress address' }));
    expect(
      await within(dialog).findByText('This address is already on the suppression list.'),
    ).toBeInTheDocument();
    expect(keys[0]).toMatch(/^[0-9a-f-]{36}$/);
    expect(bodies[0]).toEqual({ address: 'r1@partner.example.com', reason: 'manual' });
    expectRequestMatchesContract('RecipientSuppressionsController_create_v1', bodies[0]);
    await user.click(within(dialog).getByRole('button', { name: 'Show the existing entry' }));
    expect(currentTestUrl()).toBe(
      '/mail-servers?tab=suppressions&address=r1%40partner.example.com',
    );
  });

  it('suppressions: explains the limit, filters and sorts in the URL, removes with an Idempotency-Key', async () => {
    const requests: URL[] = [];
    let deleteKey: string | null = null;
    mockApi({
      RecipientSuppressionsController_list_v1: ({ url }) => (
        requests.push(url),
        okJson({
          data: [suppression(1, { reason: 'hard_bounce', source: 'postfix_log' })],
          nextCursor: null,
        })
      ),
      RecipientSuppressionsController_create_v1: () =>
        apiErrorJson(409, 'suppression_limit_reached', 'Limit reached'),
      RecipientSuppressionsController_delete_v1: ({ request }) => (
        (deleteKey = request.headers.get('idempotency-key')),
        noContentResponse()
      ),
    });
    const { user } = renderWithProviders(<MailServersPage />, {
      role: 'organization_admin',
      route: '/mail-servers?tab=suppressions',
    });
    await screen.findByText('r1@partner.example.com');
    await user.click(screen.getByRole('button', { name: 'Suppress address' }));
    const dialog = await screen.findByRole('dialog', { name: 'Suppress an address' });
    await user.type(within(dialog).getByLabelText('Address (required)'), 'x@example.com');
    await user.click(within(dialog).getByRole('button', { name: 'Suppress address' }));
    expect(
      await within(dialog).findByText(/reached its limit of manual suppressions/),
    ).toBeInTheDocument();
    await user.keyboard('{Escape}');

    await user.click(screen.getByRole('combobox', { name: 'Reason' }));
    await user.click(await screen.findByRole('option', { name: 'Hard bounce' }));
    await waitFor(() => expect(requests.at(-1)?.searchParams.get('reason')).toBe('hard_bounce'));
    await user.click(screen.getByRole('button', { name: /Added, change sort order/ }));
    await waitFor(() => expect(requests.at(-1)?.searchParams.get('sort')).toBe('-id'));
    expect(currentTestUrl()).toContain('sort=-id');

    await user.click(screen.getByRole('button', { name: 'Actions for r1@partner.example.com' }));
    await user.click(await screen.findByRole('menuitem', { name: 'Remove' }));
    const confirm = await screen.findByRole('alertdialog');
    expect(confirm).toHaveTextContent('hard bounce');
    await user.click(within(confirm).getByRole('button', { name: 'Remove' }));
    await waitFor(() => expect(deleteKey).toMatch(/^[0-9a-f-]{36}$/));
  });

  it('deliveries: sends the range and filters, links to the message', async () => {
    const requests: URL[] = [];
    mockApi({
      DeliveriesController_list_v1: ({ url }) => (
        requests.push(url),
        okJson({
          data: [
            {
              messageId: '0193c000-0000-7000-8000-000000000001',
              rcptSeq: 0,
              recipient: 'a@example.com',
              direction: 'outbound',
              status: 'deferred',
              attemptCount: 3,
              lastErrorClass: 'remote_4xx',
              statusChangedAt: T,
            },
          ],
          nextCursor: null,
        })
      ),
    });
    const { user, container } = renderWithProviders(<MailServersPage />, {
      role: 'read_only_user',
      route: '/mail-servers?tab=deliveries&range=24h',
    });
    expect(
      await screen.findByRole('link', { name: /Open message of the delivery to a@example.com/ }),
    ).toHaveAttribute('href', '/messages/0193c000-0000-7000-8000-000000000001');
    const first = requests[0]!;
    expect(
      Date.parse(first.searchParams.get('to')!) - Date.parse(first.searchParams.get('from')!),
    ).toBe(86_400_000);
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('combobox', { name: 'Delivery status' }));
    await user.click(await screen.findByRole('option', { name: 'Deferred' }));
    await waitFor(() => expect(requests.at(-1)?.searchParams.get('status')).toBe('deferred'));
    expect(currentTestUrl()).toContain('dstatus=deferred');
  });
});

describe('mail server forms', () => {
  it('mirror the request contracts', () => {
    const base = {
      name: 'Relay',
      networks: '',
      certificateFingerprintSha256: '',
      requireTls: true,
    };
    expectRequestMatchesContract(
      'SmtpConnectorsController_create_v1',
      connectorCreateBody(connectorCreateSchema.parse({ ...base, authType: 'sasl' })),
    );
    expectRequestMatchesContract(
      'SmtpConnectorsController_create_v1',
      connectorCreateBody(
        connectorCreateSchema.parse({
          ...base,
          authType: 'source_ip',
          networks: '192.0.2.0/27\n2001:db8::/48',
          requireTls: false,
        }),
      ),
    );
    expectRequestMatchesContract(
      'SmtpConnectorsController_create_v1',
      connectorCreateBody(
        connectorCreateSchema.parse({
          ...base,
          authType: 'client_certificate',
          certificateFingerprintSha256: 'AB:'.repeat(31) + 'AB',
        }),
      ),
    );
    expect(connectorCreateSchema.safeParse({ ...base, authType: 'source_ip' }).success).toBe(false);
    expectRequestMatchesContract(
      'SmtpConnectorsController_update_v1',
      connectorUpdateBody(
        { authType: 'sasl' },
        connectorUpdateSchema.parse({ name: 'X', networks: '', requireTls: true }),
      ),
    );
    expectRequestMatchesContract(
      'RecipientSuppressionsController_create_v1',
      suppressionCreateBody(
        suppressionCreateSchema.parse({
          address: 'a@b.example',
          reason: 'unsubscribe',
          expiresOn: new Date(Date.now() + 30 * 86_400_000).toISOString().slice(0, 10),
        }),
      ),
    );
  });
});
