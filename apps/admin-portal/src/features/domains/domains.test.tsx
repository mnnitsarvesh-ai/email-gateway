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
import { DomainDetailPage } from './domain-detail-page';
import { DomainsPage } from './domains-page';
import { destinationsBody, destinationsSchema } from './destinations-editor';
import { normalizeDomainName } from './model';
import {
  DOMAIN_ID,
  OTHER_DOMAIN_ID,
  PROVIDERS,
  destinations,
  dnsRecords,
  domainDetail,
  domainSummary,
  statusView,
  validation,
} from './test-data';
import {
  addRecipientsSchema,
  recipientValidationBody,
  recipientValidationSchema,
} from './recipients-panel';
import { domainStatusBody, domainStatusSchema } from './status-actions';
import { pollDelay } from './verification-panel';

function listHandler(total = 3, requests: URL[] = []) {
  const all = Array.from({ length: total }, (_, i) => domainSummary(i + 1));
  return ({ url }: { url: URL }) => {
    requests.push(url);
    const offset = Number(url.searchParams.get('cursor') ?? '0');
    const limit = Number(url.searchParams.get('limit') ?? '25');
    const status = url.searchParams.get('status');
    const rows = all.filter((d) => !status || d.status === status);
    const page = rows.slice(offset, offset + limit);
    return okJson({
      data: page,
      nextCursor: offset + limit < rows.length ? String(offset + limit) : null,
    });
  };
}

describe('DomainsPage', () => {
  it('shows skeleton rows while loading, then the domains (axe clean)', async () => {
    mockApi({ DomainsController_list_v1: listHandler(3) });
    const { container } = renderWithProviders(<DomainsPage />, { route: '/domains' });
    expect(screen.getByText(/Loading Domains/)).toBeInTheDocument();
    expect(await screen.findByRole('link', { name: 'd1.example.test' })).toHaveAttribute(
      'href',
      `/domains/${domainSummary(1).id}`,
    );
    expect(screen.getAllByText('Active').length).toBeGreaterThan(0);
    expect(screen.getByRole('link', { name: 'Add domain' })).toHaveAttribute(
      'href',
      '/domains/onboarding',
    );
    await expectNoAxeViolations(container);
  });

  it('shows the empty state with the primary action for managers', async () => {
    mockApi({ DomainsController_list_v1: () => okJson({ data: [], nextCursor: null }) });
    renderWithProviders(<DomainsPage />, { route: '/domains' });
    expect(await screen.findByText('No domains yet')).toBeInTheDocument();
    expect(screen.getAllByRole('link', { name: 'Add domain' })).toHaveLength(2);
  });

  it('shows the error with code and request id', async () => {
    mockApi({
      DomainsController_list_v1: () =>
        apiErrorJson(500, 'internal_error', 'Database unavailable', { requestId: 'req-d-1' }),
    });
    renderWithProviders(<DomainsPage />, { route: '/domains' });
    expect(await screen.findByText('internal_error')).toBeInTheDocument();
    expect(screen.getByText('req-d-1')).toBeInTheDocument();
  });

  it('writes filters to the URL and sends them, and pages with the cursor', async () => {
    const requests: URL[] = [];
    mockApi({ DomainsController_list_v1: listHandler(30, requests) });
    const { user } = renderWithProviders(<DomainsPage />, { route: '/domains' });
    await screen.findByRole('link', { name: 'd1.example.test' });
    await user.click(screen.getByRole('button', { name: 'Next' }));
    await waitFor(() => expect(requests.at(-1)?.searchParams.get('cursor')).toBe('25'));
    expect(await screen.findByText(/Page 2/)).toBeInTheDocument();

    await user.click(screen.getByRole('combobox', { name: 'Status' }));
    await user.click(await screen.findByRole('option', { name: 'Suspended' }));
    expect(currentTestUrl()).toBe('/domains?status=suspended');
    await waitFor(() => expect(requests.at(-1)?.searchParams.get('status')).toBe('suspended'));
    expect(requests.at(-1)?.searchParams.get('cursor')).toBeNull();
    expect(await screen.findByText('No results match these filters')).toBeInTheDocument();

    await user.type(screen.getByRole('searchbox', { name: /Search domains/ }), 'alp');
    await waitFor(() => expect(currentTestUrl()).toContain('q=alp'));
    await waitFor(() => expect(requests.at(-1)?.searchParams.get('q')).toBe('alp'));
  });

  it('hides "Add domain" from read-only users and refuses users without domain:read', async () => {
    mockApi({ DomainsController_list_v1: listHandler(1) });
    const { unmount } = renderWithProviders(<DomainsPage />, {
      role: 'read_only_user',
      route: '/domains',
    });
    await screen.findByRole('link', { name: 'd1.example.test' });
    expect(screen.queryByRole('link', { name: 'Add domain' })).not.toBeInTheDocument();
    unmount();
    renderWithProviders(<DomainsPage />, { role: 'domain_admin', route: '/domains' });
    expect(await screen.findByRole('link', { name: 'Add domain' })).toBeInTheDocument();
  });

  it('renders the 403 page for a role without domain:read', () => {
    renderWithProviders(<DomainsPage />, { role: 'mailbox_user', route: '/domains' });
    expect(screen.getByText('You do not have access to this page')).toBeInTheDocument();
  });
});

function mockDetail(overrides: Parameters<typeof mockApi>[0] = {}) {
  mockApi({
    DomainsController_get_v1: () => okJson(domainDetail()),
    DomainDnsController_status_v1: () => okJson(statusView()),
    DomainDnsController_dnsRecords_v1: () => okJson(dnsRecords()),
    DomainRecipientsController_get_v1: () => okJson(validation()),
    DomainRecipientsController_list_v1: () =>
      okJson({
        data: [{ localPart: 'sales', createdAt: '2026-11-12T08:00:00.000Z' }],
        nextCursor: null,
      }),
    DomainDestinationsController_get_v1: () => okJson(destinations()),
    DestinationProvidersController_list_v1: () => okJson(PROVIDERS),
    ...overrides,
  });
}

describe('DomainDetailPage', () => {
  it('shows the overview and verification checks (axe clean)', async () => {
    mockDetail();
    const { container } = renderWithProviders(<DomainDetailPage domainId={DOMAIN_ID} />, {
      route: `/domains/${DOMAIN_ID}`,
    });
    expect(
      await screen.findByRole('heading', { level: 1, name: 'alpha.example.test' }),
    ).toBeInTheDocument();
    expect(await screen.findByRole('list', { name: 'DNS checks' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Suspend' })).toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('renders the 404 page for a foreign or unknown id, and for a malformed id', async () => {
    mockApi({
      DomainsController_get_v1: () => apiErrorJson(404, 'domain_not_found', 'Domain not found'),
    });
    const { unmount } = renderWithProviders(<DomainDetailPage domainId={OTHER_DOMAIN_ID} />);
    expect(await screen.findByText('Page not found')).toBeInTheDocument();
    unmount();
    renderWithProviders(<DomainDetailPage domainId="not-a-uuid" />);
    expect(screen.getByText('Page not found')).toBeInTheDocument();
  });

  it('shows an error state with code and request id for other failures', async () => {
    mockApi({
      DomainsController_get_v1: () =>
        apiErrorJson(500, 'internal_error', 'Boom', { requestId: 'req-dd-1' }),
    });
    renderWithProviders(<DomainDetailPage domainId={DOMAIN_ID} />);
    expect(await screen.findByText('internal_error')).toBeInTheDocument();
    expect(screen.getByText('req-dd-1')).toBeInTheDocument();
  });

  it('hides every change action from read-only users', async () => {
    mockDetail();
    renderWithProviders(<DomainDetailPage domainId={DOMAIN_ID} />, {
      role: 'read_only_user',
      route: `/domains/${DOMAIN_ID}?tab=overview`,
    });
    await screen.findByRole('list', { name: 'DNS checks' });
    expect(screen.queryByRole('button', { name: 'Suspend' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Delete domain' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Verify now' })).not.toBeInTheDocument();
  });

  it('suspends with a required reason (contract) and refreshes', async () => {
    let body: unknown = null;
    mockDetail({
      DomainsController_changeStatus_v1: ({ body: b }) => (
        (body = b),
        okJson(domainDetail({ status: 'suspended', statusReason: 'Migration' }))
      ),
    });
    const { user } = renderWithProviders(<DomainDetailPage domainId={DOMAIN_ID} />);
    await user.click(await screen.findByRole('button', { name: 'Suspend' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Suspend domain' }));
    expect(
      await within(dialog).findByText('Enter a reason for suspending the domain'),
    ).toBeInTheDocument();
    await user.type(within(dialog).getByLabelText('Reason (required)'), 'Migration');
    await user.click(within(dialog).getByRole('button', { name: 'Suspend domain' }));
    await waitFor(() => expect(body).toEqual({ status: 'suspended', reason: 'Migration' }));
    expectRequestMatchesContract('DomainsController_changeStatus_v1', body);
  });

  it('deletes only after typing the domain name; an active domain must be suspended first', async () => {
    let deleted = false;
    mockDetail({
      DomainsController_get_v1: () => okJson(domainDetail({ status: 'suspended' })),
      DomainsController_remove_v1: () => ((deleted = true), noContentResponse()),
    });
    const { user, router } = renderWithProviders(<DomainDetailPage domainId={DOMAIN_ID} />);
    await user.click(await screen.findByRole('button', { name: 'Delete domain' }));
    const dialog = await screen.findByRole('alertdialog');
    const confirm = within(dialog).getByRole('button', { name: 'Delete domain' });
    expect(confirm).toBeDisabled();
    await user.type(within(dialog).getByRole('textbox'), 'alpha.example.test');
    expect(confirm).toBeEnabled();
    await user.click(confirm);
    await waitFor(() => expect(deleted).toBe(true));
    expect(router.push).toHaveBeenCalledWith('/domains');
  });

  it('runs "Verify now" and shows the fresh status', async () => {
    let verified = false;
    mockDetail({
      DomainsController_get_v1: () =>
        okJson(
          domainDetail({ status: 'pending_verification', verifiedAt: null, activatedAt: null }),
        ),
      DomainDnsController_status_v1: () =>
        okJson(statusView({ status: 'pending_verification', mailFlowReady: false })),
      DomainDnsController_verify_v1: () => (
        (verified = true),
        okJson(statusView({ status: 'verified', readyForActivation: true, mailFlowReady: false }))
      ),
    });
    const { user } = renderWithProviders(<DomainDetailPage domainId={DOMAIN_ID} />);
    expect(await screen.findByText(/Waiting for the ownership record/)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Verify now' }));
    await waitFor(() => expect(verified).toBe(true));
    expect(
      await screen.findByText('Ownership is proven: the domain can be activated.'),
    ).toBeInTheDocument();
  });

  it('lists DNS records with copy buttons and rotates DKIM with a warning', async () => {
    let rotateBody: unknown = null;
    mockDetail({
      DomainDnsController_rotate_v1: ({ body }) => {
        rotateBody = body;
        const record = dnsRecords().records[0]!;
        return okJson(
          {
            domainId: DOMAIN_ID,
            key: {
              ...domainDetail().dkimKeys[0]!,
              selector: 'eg2026b',
              status: 'pending',
              host: 'eg2026b._domainkey.alpha.example.test',
            },
            previous: domainDetail().dkimKeys[0]!,
            dnsRecord: {
              ...record,
              key: 'dkim:eg2026b',
              purpose: 'dkim',
              host: 'eg2026b._domainkey.alpha.example.test',
              value: 'v=DKIM1; p=NEWKEY',
            },
            overlapDays: 7,
          },
          201,
        );
      },
    });
    const { user, container } = renderWithProviders(<DomainDetailPage domainId={DOMAIN_ID} />, {
      route: `/domains/${DOMAIN_ID}?tab=dns`,
    });
    expect(
      await screen.findByRole('button', { name: 'Copy Ownership record value' }),
    ).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Copy all records' })).toBeInTheDocument();
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('button', { name: 'Rotate DKIM key' }));
    const dialog = await screen.findByRole('alertdialog');
    expect(dialog).toHaveTextContent('must publish');
    await user.click(within(dialog).getByRole('button', { name: 'Rotate key' }));
    await waitFor(() => expect(rotateBody).toEqual({ algorithm: 'rsa_2048' }));
    expectRequestMatchesContract('DomainDnsController_rotate_v1', rotateBody);
    expect(await screen.findByText('v=DKIM1; p=NEWKEY')).toBeInTheDocument();
  });

  it('saves recipient validation, adds and removes registry entries (contracts)', async () => {
    const bodies: Record<string, unknown> = {};
    mockDetail({
      DomainRecipientsController_set_v1: ({ body }) => (
        (bodies.set = body),
        okJson(validation({ mode: 'allow_list', enforcement: 'monitor' }))
      ),
      DomainRecipientsController_add_v1: ({ body }) => (
        (bodies.add = body),
        okJson({ added: 2, existing: 0 })
      ),
      DomainRecipientsController_remove_v1: ({ body }) => (
        (bodies.remove = body),
        okJson({ removed: 1 })
      ),
    });
    const { user, container } = renderWithProviders(<DomainDetailPage domainId={DOMAIN_ID} />, {
      route: `/domains/${DOMAIN_ID}?tab=recipients`,
    });
    await screen.findByText('sales');
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('radio', { name: /Allow list/ }));
    await user.click(screen.getByRole('radio', { name: /Monitor/ }));
    await user.click(screen.getByRole('button', { name: 'Save recipient validation' }));
    await waitFor(() => expect(bodies.set).toEqual({ mode: 'allow_list', enforcement: 'monitor' }));
    expectRequestMatchesContract('DomainRecipientsController_set_v1', bodies.set);

    await user.click(screen.getByRole('button', { name: 'Add recipients' }));
    const dialog = await screen.findByRole('dialog', { name: 'Add recipients' });
    await user.type(within(dialog).getByLabelText('Local parts (required)'), 'billing{enter}it');
    await user.click(within(dialog).getByRole('button', { name: 'Add' }));
    await waitFor(() => expect(bodies.add).toEqual({ localParts: ['billing', 'it'] }));
    expectRequestMatchesContract('DomainRecipientsController_add_v1', bodies.add);

    await user.click(screen.getByRole('button', { name: 'Actions for sales' }));
    await user.click(await screen.findByRole('menuitem', { name: 'Remove' }));
    await user.click(
      within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Remove' }),
    );
    await waitFor(() => expect(bodies.remove).toEqual({ localParts: ['sales'] }));
    expectRequestMatchesContract('DomainRecipientsController_remove_v1', bodies.remove);
  });

  it('replaces destinations (contract) and maps a 422 refusal to its field', async () => {
    const bodies: unknown[] = [];
    mockDetail({
      DomainDestinationsController_replace_v1: ({ body }) => {
        bodies.push(body);
        return bodies.length === 1
          ? apiErrorJson(422, 'unprocessable', 'Destination host is an internal name', {
              extra: { reason: 'internal_suffix', field: 'servers.0.host' },
            })
          : okJson(destinations());
      },
    });
    const { user, container } = renderWithProviders(<DomainDetailPage domainId={DOMAIN_ID} />, {
      route: `/domains/${DOMAIN_ID}?tab=destinations`,
    });
    await user.click(await screen.findByRole('button', { name: 'Edit destinations' }));
    const host = screen.getByLabelText('Host (required)');
    await user.clear(host);
    await user.type(host, 'mail.corp.internal');
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('button', { name: 'Save destinations' }));
    expect(await screen.findByText(/internal name \(internal_suffix\)/)).toBeInTheDocument();
    expectRequestMatchesContract('DomainDestinationsController_replace_v1', bodies[0]);
    await user.clear(host);
    await user.type(host, 'mx9.alpha.example.test');
    await user.click(screen.getByRole('button', { name: 'Save destinations' }));
    await waitFor(() => expect(bodies).toHaveLength(2));
    expect(bodies[1]).toEqual({
      provider: 'custom',
      servers: [{ host: 'mx9.alpha.example.test', port: 25, priority: 10, tlsMode: 'required' }],
    });
    expect(await screen.findByRole('button', { name: 'Edit destinations' })).toBeInTheDocument();
  });

  it('hides destination editing without domain:routing_manage', async () => {
    mockDetail();
    renderWithProviders(<DomainDetailPage domainId={DOMAIN_ID} />, {
      role: 'read_only_user',
      route: `/domains/${DOMAIN_ID}?tab=destinations`,
    });
    expect(await screen.findByText('mx1.alpha.example.test:25')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Edit destinations' })).not.toBeInTheDocument();
  });
});

describe('domain forms and helpers', () => {
  it('mirror the request contracts', () => {
    expectRequestMatchesContract(
      'DomainDestinationsController_replace_v1',
      destinationsBody(
        destinationsSchema.parse({
          provider: 'microsoft_365',
          host: 'a.mail.protection.outlook.com',
          servers: [],
        }),
      ),
    );
    expectRequestMatchesContract(
      'DomainDestinationsController_replace_v1',
      destinationsBody(
        destinationsSchema.parse({ provider: 'google_workspace', host: '', servers: [] }),
      ),
    );
    expectRequestMatchesContract(
      'DomainDestinationsController_replace_v1',
      destinationsBody(
        destinationsSchema.parse({
          provider: 'custom',
          host: '',
          servers: [
            {
              host: 'mx.example.org',
              port: '587',
              priority: '5',
              tlsMode: 'verify',
              tlsVerifyNames: 'nexthop:.example.org',
            },
          ],
        }),
      ),
    );
    expect(() => destinationsSchema.parse({ provider: 'custom', host: '', servers: [] })).toThrow();
    expectRequestMatchesContract(
      'DomainRecipientsController_set_v1',
      recipientValidationBody(
        recipientValidationSchema.parse({ mode: 'accept_all', enforcement: 'reject' }),
      ),
    );
    expectRequestMatchesContract(
      'DomainRecipientsController_add_v1',
      addRecipientsSchema.parse({ localParts: ['a', 'b.c'] }),
    );
    expect(addRecipientsSchema.safeParse({ localParts: ['a@b'] }).success).toBe(false);
    expectRequestMatchesContract(
      'DomainsController_changeStatus_v1',
      domainStatusBody(domainStatusSchema.parse({ status: 'active', reason: '' })),
    );
  });

  it('validates domain names like the api', () => {
    expect(normalizeDomainName(' Example.ORG. ')).toEqual({ ok: true, name: 'example.org' });
    expect(normalizeDomainName('bücher.example')).toEqual({ ok: true, name: 'bücher.example' });
    for (const bad of [
      'localhost',
      'example',
      '10.0.0.1',
      'a_b.example.org',
      '*.example.org',
      'x.local',
      '-a.example.org',
      'a..b.org',
      `${'a'.repeat(64)}.org`,
      `${'a.'.repeat(120)}org`,
    ]) {
      expect(normalizeDomainName(bad).ok, bad).toBe(false);
    }
  });

  it('backs off the status poll', () => {
    expect([1, 2, 3, 4, 5, 9].map(pollDelay)).toEqual([
      5_000, 10_000, 20_000, 40_000, 60_000, 60_000,
    ]);
  });
});
