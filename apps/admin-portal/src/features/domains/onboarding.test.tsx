import { screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import {
  apiErrorJson,
  currentTestUrl,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  mockApi,
  okJson,
  renderWithProviders,
} from '@/test';
import { DomainOnboardingPage, resumeStep } from './onboarding-page';
import { domainCreateBody, domainCreateSchema } from './onboarding-page';
import {
  DOMAIN_ID,
  PROVIDERS,
  destinations,
  dnsRecords,
  domainDetail,
  statusView,
  validation,
} from './test-data';

type DomainOverrides = Parameters<typeof domainDetail>[0];

function mockResume(
  domain: DomainOverrides,
  opts: { servers?: boolean; mode?: 'accept_all' | 'allow_list' } = {},
) {
  const detail = domainDetail(domain);
  const calls: Record<string, unknown[]> = {};
  mockApi({
    DomainsController_get_v1: () => okJson(detail),
    DomainDestinationsController_get_v1: () =>
      okJson(opts.servers ? destinations() : destinations({ provider: null, servers: [] })),
    DomainRecipientsController_get_v1: () =>
      okJson(validation({ mode: opts.mode ?? 'accept_all' })),
    DomainDnsController_dnsRecords_v1: () => okJson(dnsRecords()),
    DomainDnsController_status_v1: () =>
      okJson(
        statusView({ status: detail.status, readyForActivation: detail.status === 'verified' }),
      ),
    DestinationProvidersController_list_v1: () => okJson(PROVIDERS),
    DomainsController_changeStatus_v1: ({ body }) => (
      (calls.status = [...(calls.status ?? []), body]),
      okJson(domainDetail({ ...domain, status: 'active' }))
    ),
  });
  return calls;
}

const pending = { status: 'pending_verification' as const, verifiedAt: null, activatedAt: null };

describe('DomainOnboardingPage', () => {
  it('adds a domain with the mirrored name rules (contract) and continues to the DNS step', async () => {
    let body: unknown = null;
    mockResume({ ...pending, lastCheckedAt: null });
    mockApi({
      DomainsController_create_v1: ({ body: b }) => (
        (body = b),
        okJson({ ...domainDetail(pending), dnsRecords: dnsRecords().records }, 201)
      ),
    });
    const { user, container, router } = renderWithProviders(<DomainOnboardingPage />, {
      route: '/domains/onboarding',
    });
    await expectNoAxeViolations(container);
    const name = screen.getByLabelText('Domain name (required)');
    await user.type(name, 'bad_name.example.org');
    await user.click(screen.getByRole('button', { name: 'Add domain' }));
    expect(await screen.findByText(/letters, digits and hyphens only/)).toBeInTheDocument();
    expect(body).toBeNull();
    await user.clear(name);
    await user.type(name, ' Alpha.Example.Test. ');
    await user.click(screen.getByRole('button', { name: 'Add domain' }));
    await waitFor(() =>
      expect(body).toEqual({
        name: 'alpha.example.test',
        inboundEnabled: true,
        dkim: { ed25519: false },
      }),
    );
    expectRequestMatchesContract('DomainsController_create_v1', body);
    expect(router.replace).toHaveBeenCalledWith(
      `/domains/onboarding?domainId=${DOMAIN_ID}&step=dns`,
    );
    expect(
      await screen.findByRole('heading', { name: '2. Publish DNS records' }),
    ).toBeInTheDocument();
  });

  it('shows api conflicts at form level', async () => {
    mockApi({
      DomainsController_create_v1: () =>
        apiErrorJson(409, 'domain_exists', 'Domain already exists', { requestId: 'req-o-1' }),
    });
    const { user } = renderWithProviders(<DomainOnboardingPage />, {
      route: '/domains/onboarding',
    });
    await user.type(screen.getByLabelText('Domain name (required)'), 'alpha.example.test');
    await user.click(screen.getByRole('button', { name: 'Add domain' }));
    expect(await screen.findByText('Domain already exists')).toBeInTheDocument();
    expect(screen.getByText('req-o-1')).toBeInTheDocument();
  });

  it('resumes at "Publish DNS records" for a domain never checked', async () => {
    mockResume({ ...pending, lastCheckedAt: null });
    const { container } = renderWithProviders(<DomainOnboardingPage />, {
      route: `/domains/onboarding?domainId=${DOMAIN_ID}`,
    });
    expect(
      await screen.findByRole('heading', { name: '2. Publish DNS records' }),
    ).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Publish DNS records/ })).toHaveAttribute(
      'aria-current',
      'step',
    );
    await screen.findByRole('button', { name: 'Copy all records' });
    await expectNoAxeViolations(container);
  });

  it('resumes at "Verify" for a checked pending domain and keeps Continue disabled until verified', async () => {
    mockResume(pending);
    renderWithProviders(<DomainOnboardingPage />, {
      route: `/domains/onboarding?domainId=${DOMAIN_ID}`,
    });
    expect(await screen.findByRole('heading', { name: '3. Verify ownership' })).toBeInTheDocument();
    expect(screen.getByText(/propagate/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Continue' })).toBeDisabled();
  });

  it('resumes at the destination step for a verified domain without destinations', async () => {
    mockResume({ status: 'verified', activatedAt: null });
    renderWithProviders(<DomainOnboardingPage />, {
      route: `/domains/onboarding?domainId=${DOMAIN_ID}`,
    });
    expect(
      await screen.findByRole('heading', { name: '4. Destination mail server' }),
    ).toBeInTheDocument();
    expect(await screen.findByRole('button', { name: 'Save destinations' })).toBeInTheDocument();
  });

  it('opens the optional recipient step when asked', async () => {
    mockResume({ status: 'verified', activatedAt: null }, { servers: true });
    renderWithProviders(<DomainOnboardingPage />, {
      route: `/domains/onboarding?domainId=${DOMAIN_ID}&step=recipients`,
    });
    expect(
      await screen.findByRole('heading', { name: 'Recipient validation' }),
    ).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Skip for now' })).toBeInTheDocument();
  });

  it('resumes at "Activate" when only activation is left, and activates', async () => {
    const calls = mockResume({ status: 'verified', activatedAt: null }, { servers: true });
    const { user } = renderWithProviders(<DomainOnboardingPage />, {
      route: `/domains/onboarding?domainId=${DOMAIN_ID}`,
    });
    expect(await screen.findByRole('heading', { name: '6. Activate' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Activate domain' }));
    await user.click(
      within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Activate' }),
    );
    await waitFor(() => expect(calls.status).toEqual([{ status: 'active' }]));
    expectRequestMatchesContract('DomainsController_changeStatus_v1', calls.status?.[0]);
    await waitFor(() => expect(currentTestUrl()).toContain('step=done'));
  });

  it('resumes at "Done" for an active domain with destinations', async () => {
    mockResume({}, { servers: true });
    renderWithProviders(<DomainOnboardingPage />, {
      route: `/domains/onboarding?domainId=${DOMAIN_ID}`,
    });
    expect(await screen.findByRole('heading', { name: 'Onboarding complete' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Open alpha.example.test' })).toHaveAttribute(
      'href',
      `/domains/${DOMAIN_ID}`,
    );
  });

  it('renders the 404 page when resuming a foreign domain', async () => {
    mockApi({
      DomainsController_get_v1: () => apiErrorJson(404, 'domain_not_found', 'Domain not found'),
      DomainDestinationsController_get_v1: () =>
        apiErrorJson(404, 'domain_not_found', 'Domain not found'),
      DomainRecipientsController_get_v1: () =>
        apiErrorJson(404, 'domain_not_found', 'Domain not found'),
    });
    renderWithProviders(<DomainOnboardingPage />, {
      route: `/domains/onboarding?domainId=${DOMAIN_ID}`,
    });
    expect(await screen.findByText('Page not found')).toBeInTheDocument();
  });

  it('is refused without domain:manage', () => {
    renderWithProviders(<DomainOnboardingPage />, {
      role: 'read_only_user',
      route: '/domains/onboarding',
    });
    expect(screen.getByText('You do not have access to this page')).toBeInTheDocument();
  });

  it('derives the resume step from server state only', () => {
    const base = { hasDestinations: false, recipientMode: null };
    expect(resumeStep({ ...base, domain: null })).toBe('add');
    expect(resumeStep({ ...base, domain: domainDetail({ ...pending, lastCheckedAt: null }) })).toBe(
      'dns',
    );
    expect(resumeStep({ ...base, domain: domainDetail({ status: 'failed' }) })).toBe('verify');
    expect(resumeStep({ ...base, domain: domainDetail({ status: 'verified' }) })).toBe(
      'destinations',
    );
    expect(
      resumeStep({ ...base, hasDestinations: true, domain: domainDetail({ status: 'suspended' }) }),
    ).toBe('activate');
    expect(resumeStep({ ...base, hasDestinations: true, domain: domainDetail() })).toBe('done');
    expectRequestMatchesContract(
      'DomainsController_create_v1',
      domainCreateBody(
        domainCreateSchema.parse({
          name: 'x.example.org',
          inboundEnabled: false,
          dkim: { ed25519: true },
        }),
      ),
    );
  });
});
