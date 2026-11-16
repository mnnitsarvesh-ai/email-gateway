import { screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import {
  apiErrorJson,
  currentTestUrl,
  expectNoAxeViolations,
  mockApi,
  okJson,
  renderWithProviders,
} from '@/test';
import { PoliciesPage } from './policies-page';
import { PolicyBuilder, filterFields } from './policy-builder';
import {
  PLATFORM_RISK_PROFILE,
  POLICY_ID,
  POLICY_SETTINGS,
  REAL_CATALOG,
  execution,
  policyRow,
} from './test-data';

const MUTATION_LABELS = [
  /create/i,
  /publish/i,
  /activate/i,
  /^edit/i,
  /delete/i,
  /disable/i,
  /enable/i,
  /new policy/i,
];
function expectNoMutationButtons() {
  for (const label of MUTATION_LABELS) {
    expect(screen.queryByRole('button', { name: label })).not.toBeInTheDocument();
  }
}

describe('Policy management (/policies)', () => {
  it('lists email policies with filters in the URL; New policy only with create permission; axe', async () => {
    const seen: URLSearchParams[] = [];
    mockApi({
      PolicyManagementController_list_v1: ({ url }) => {
        seen.push(url.searchParams);
        return okJson({ data: [policyRow()], nextCursor: null, generation: '42' });
      },
    });
    const { user, container, unmount } = renderWithProviders(<PoliciesPage />, {
      role: 'security_analyst',
      route: '/policies',
    });
    expect(await screen.findByRole('link', { name: 'Inbound threats' })).toHaveAttribute(
      'href',
      `/policies/${POLICY_ID}`,
    );
    // Step 7.3 replaced the "arrives in step 7.3" banner with the builder.
    expect(screen.queryByText(/arrives in step 7\.3/)).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'New policy' })).toHaveAttribute(
      'href',
      '/policies/new',
    );
    expect(screen.getByRole('link', { name: 'Policy builder' })).toHaveAttribute(
      'href',
      '/policies/builder',
    );
    expect(screen.getByText(/Policy generation/)).toBeInTheDocument();
    await expectNoAxeViolations(container);
    await user.click(screen.getByLabelText('Status'));
    await user.click(await screen.findByRole('option', { name: 'Disabled' }));
    await waitFor(() => expect(currentTestUrl()).toContain('status=disabled'));
    await waitFor(() => expect(seen[seen.length - 1]?.get('status')).toBe('disabled'));
    unmount();
    renderWithProviders(<PoliciesPage />, { role: 'read_only_user', route: '/policies' });
    expect(await screen.findByRole('link', { name: 'Inbound threats' })).toBeInTheDocument();
    expectNoMutationButtons();
    expect(screen.queryByRole('link', { name: 'New policy' })).not.toBeInTheDocument();
  });

  it('the empty list points to New policy for users who may create policies', async () => {
    mockApi({
      PolicyManagementController_list_v1: () =>
        okJson({ data: [], nextCursor: null, generation: '1' }),
    });
    const { container } = renderWithProviders(<PoliciesPage />, {
      role: 'organization_admin',
      route: '/policies',
    });
    expect(await screen.findByText('No email policies yet')).toBeInTheDocument();
    expect(screen.getAllByRole('link', { name: 'New policy' })).toHaveLength(1);
    expect(screen.getByText(/Build your first policy with New policy/)).toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('shows DLP and BEC tabs only with their permissions; mailbox users are forbidden', async () => {
    mockApi({
      PolicyManagementController_list_v1: () =>
        okJson({ data: [], nextCursor: null, generation: '1' }),
    });
    const { unmount } = renderWithProviders(<PoliciesPage />, {
      role: 'security_analyst',
      route: '/policies',
    });
    expect(await screen.findByText('No email policies yet')).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'DLP' })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'BEC' })).toBeInTheDocument();
    unmount();
    const second = renderWithProviders(<PoliciesPage />, {
      role: 'read_only_user',
      route: '/policies',
    });
    await screen.findByText('No email policies yet');
    expect(screen.queryByRole('tab', { name: 'DLP' })).not.toBeInTheDocument();
    expect(screen.queryByRole('tab', { name: 'BEC' })).not.toBeInTheDocument();
    second.unmount();
    renderWithProviders(<PoliciesPage />, { role: 'mailbox_user', route: '/policies' });
    expect(await screen.findByText(/policy:read/)).toBeInTheDocument();
  });

  it('executions: bounded range and filters in the request, message links, errors with request id', async () => {
    const seen: URLSearchParams[] = [];
    mockApi({
      PolicyToolsController_history_v1: ({ url }) => {
        seen.push(url.searchParams);
        if (url.searchParams.get('disposition') === 'reject') {
          return apiErrorJson(400, 'validation_failed', ['to: too long'], {
            requestId: 'req-exec',
          });
        }
        return okJson({ data: [execution()], nextCursor: null });
      },
    });
    const { user, container } = renderWithProviders(<PoliciesPage />, {
      role: 'security_analyst',
      route: '/policies?tab=executions',
    });
    expect(await screen.findByRole('link', { name: 'Open message' })).toHaveAttribute(
      'href',
      '/messages/01933c3a-1b2c-7d4e-8f00-00000000a001',
    );
    const first = seen[0];
    expect(Date.parse(first?.get('to') ?? '') - Date.parse(first?.get('from') ?? '')).toBe(
      86_400_000,
    );
    await expectNoAxeViolations(container);
    await user.click(screen.getByLabelText('Disposition'));
    await user.click(await screen.findByRole('option', { name: 'Reject' }));
    const alert = await screen.findByRole('alert');
    expect(within(alert).getByText('req-exec')).toBeInTheDocument();
  });

  it('settings, risk and scanning tabs render the configuration read-only without the write permissions', async () => {
    mockApi({
      PolicySettingsController_get_v1: () => okJson(POLICY_SETTINGS),
      RiskProfilesController_profile_v1: () => okJson(PLATFORM_RISK_PROFILE),
      RiskProfilesController_listVersions_v1: () => okJson({ data: [], nextCursor: null }),
      ScanSettingsController_list_v1: () =>
        okJson({
          note: 'Changes apply after the cache TTL.',
          data: [
            {
              engine: 'rspamd',
              platform: {
                spamScore: 6,
                suspiciousScore: 4,
                scoreMin: 1,
                scoreMax: 20,
                phishingVerdict: 'malicious',
                dmarcRejectVerdict: 'suspicious',
                authFailureVerdict: 'reason_only',
              },
              bounds: {
                spamScore: { min: 3, max: 15 },
                suspiciousScore: { min: 2, max: 12 },
                phishingVerdict: ['malicious'],
                dmarcRejectVerdict: ['suspicious'],
                authFailureVerdict: ['reason_only'],
              },
              override: null,
              effective: {
                spamScore: 6,
                suspiciousScore: 4,
                phishingVerdict: 'malicious',
                dmarcRejectVerdict: 'suspicious',
                authFailureVerdict: 'reason_only',
              },
              required: true,
              tenantMayDisable: false,
              overrideApplied: false,
              violations: [],
              version: 0,
              updatedAt: null,
            },
          ],
        }),
    });
    const { container, unmount } = renderWithProviders(<PoliciesPage />, {
      role: 'security_analyst',
      route: '/policies?tab=settings',
    });
    expect(await screen.findByText('Recommendation overrides')).toBeInTheDocument();
    // security_analyst lacks policy:publish: the effective settings, no form.
    expect(screen.queryByRole('button', { name: 'Save settings' })).not.toBeInTheDocument();
    await expectNoAxeViolations(container);
    unmount();
    const risk = renderWithProviders(<PoliciesPage />, {
      role: 'read_only_user',
      route: '/policies?tab=risk',
    });
    expect(await screen.findByText(/Platform default \(rsk-default\/1\)/)).toBeInTheDocument();
    expect(screen.getByText('The platform default profile applies.')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'New draft' })).not.toBeInTheDocument();
    await expectNoAxeViolations(risk.container);
    risk.unmount();
    renderWithProviders(<PoliciesPage />, {
      role: 'security_analyst',
      route: '/policies?tab=scanning',
    });
    expect(await screen.findByRole('rowheader', { name: 'Rspamd' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Open scan settings' })).toHaveAttribute(
      'href',
      '/settings?tab=scanning',
    );
    expect(screen.getByText('Changes apply after the cache TTL.')).toBeInTheDocument();
    expectNoMutationButtons();
  });

  it('DLP sections switch through the URL; BEC lists render', async () => {
    mockApi({
      DlpPoliciesController_list_v1: () =>
        okJson({
          data: [
            {
              id: '01933c3a-1b2c-7d4e-8f00-0000000d0001',
              name: 'Payment cards outbound',
              description: null,
              enabled: true,
              mode: 'enforce',
              priority: 10,
              directions: ['outbound'],
              ruleCount: 2,
              version: 1,
              createdByUserId: null,
              updatedByUserId: null,
              createdAt: '2026-10-01T09:00:00.000Z',
              updatedAt: '2026-10-01T09:00:00.000Z',
            },
          ],
          nextCursor: null,
        }),
      DlpComplianceController_get_v1: () =>
        okJson({
          aadhaar: {
            enabled: false,
            active: false,
            basis: null,
            reference: null,
            attested: false,
            recordedByUserId: null,
            recordedAt: null,
            reviewDueAt: null,
          },
          version: 0,
          updatedAt: null,
        }),
      BecExecutivesController_list_v1: () =>
        okJson({
          data: [
            {
              id: '01933c3a-1b2c-7d4e-8f00-0000000be001',
              displayName: 'Dana Whitfield',
              normalizedName: 'dana whitfield',
              aliases: [],
              knownAddresses: ['ceo@alpha.example.test'],
              title: 'CEO',
              enabled: true,
              updatedByUserId: null,
              version: 1,
              createdByUserId: null,
              createdAt: '2026-10-01T09:00:00.000Z',
              updatedAt: '2026-10-01T09:00:00.000Z',
            },
          ],
          nextCursor: null,
        }),
    });
    const { user, container, unmount } = renderWithProviders(<PoliciesPage />, {
      role: 'security_analyst',
      route: '/policies?tab=dlp',
    });
    expect(await screen.findByText('Payment cards outbound')).toBeInTheDocument();
    await user.click(screen.getByRole('tab', { name: 'Compliance' }));
    await waitFor(() => expect(currentTestUrl()).toContain('section=compliance'));
    expect(await screen.findByText('Aadhaar detection')).toBeInTheDocument();
    await expectNoAxeViolations(container);
    unmount();
    renderWithProviders(<PoliciesPage />, { role: 'security_analyst', route: '/policies?tab=bec' });
    expect(await screen.findByText('Dana Whitfield')).toBeInTheDocument();
  });
});

describe('Policy builder (/policies/builder)', () => {
  it('offers New policy, test and dry run of the active set, and the searchable catalogue reference; axe', async () => {
    mockApi({ PolicyToolsController_catalog_v1: () => okJson(REAL_CATALOG) });
    const { user, container } = renderWithProviders(<PolicyBuilder />, {
      role: 'organization_admin',
      route: '/policies/builder',
    });
    expect(await screen.findByText('risk.score')).toBeInTheDocument();
    expect(screen.queryByText(/arrive in step 7\.3/)).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'New policy' })).toHaveAttribute(
      'href',
      '/policies/new',
    );
    expect(screen.getByRole('button', { name: 'Test with synthetic facts' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Dry run on stored messages' })).toBeInTheDocument();
    // Fields are grouped by the catalogue's groups and show their labels.
    expect(screen.getByRole('list', { name: 'Risk fields' })).toBeInTheDocument();
    expect(screen.getByText('Risk score')).toBeInTheDocument();
    await expectNoAxeViolations(container);
    await user.type(screen.getByLabelText('Search fields'), 'attachment');
    await waitFor(() => expect(screen.queryByText('risk.score')).not.toBeInTheDocument());
    expect(screen.getByText('attachment.type_family')).toBeInTheDocument();
    expect(currentTestUrl()).toContain('q=attachment');
    await user.click(screen.getByRole('button', { name: 'Hide the reference' }));
    expect(screen.queryByText('attachment.type_family')).not.toBeInTheDocument();
  });

  it('read-only users see the reference only (no New policy, no test or dry run)', async () => {
    mockApi({ PolicyToolsController_catalog_v1: () => okJson(REAL_CATALOG) });
    renderWithProviders(<PolicyBuilder />, { role: 'read_only_user', route: '/policies/builder' });
    expect(await screen.findByText('risk.score')).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'New policy' })).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: /synthetic facts|dry run/i }),
    ).not.toBeInTheDocument();
    expectNoMutationButtons();
  });

  it('filters fields by scope and text (labels included)', () => {
    expect(
      filterFields(REAL_CATALOG.fields, undefined, 'attachments').every(
        (f) => f.scope === 'attachments',
      ),
    ).toBe(true);
    const byLabel = filterFields(REAL_CATALOG.fields, 'DLP data categories', undefined);
    expect(byLabel.map((f) => f.name)).toContain('dlp.categories');
    expect(
      byLabel.every(
        (f) =>
          f.label.toLowerCase().includes('dlp data categories') ||
          f.description.toLowerCase().includes('dlp data categories'),
      ),
    ).toBe(true);
    expect(filterFields(REAL_CATALOG.fields, 'risk.score', undefined).map((f) => f.name)).toEqual([
      'risk.score',
    ]);
  });

  it('shows the error state with code and request id; is forbidden without policy:read', async () => {
    mockApi({
      PolicyToolsController_catalog_v1: () =>
        apiErrorJson(500, 'internal_error', 'Boom', { requestId: 'req-cat' }),
    });
    const { unmount } = renderWithProviders(<PolicyBuilder />, { role: 'security_analyst' });
    const alert = await screen.findByRole('alert');
    expect(within(alert).getByText('req-cat')).toBeInTheDocument();
    unmount();
    renderWithProviders(<PolicyBuilder />, { role: 'quarantine_reviewer' });
    expect(await screen.findByText(/policy:read/)).toBeInTheDocument();
  });

  it('a catalogue the builder cannot read is an error state, never a guess', async () => {
    mockApi({
      PolicyToolsController_catalog_v1: () =>
        okJson({ ...REAL_CATALOG, operatorDefinitions: 'missing' } as never),
    });
    renderWithProviders(<PolicyBuilder />, { role: 'organization_admin' });
    expect(
      await screen.findByText('The policy catalogue cannot drive the builder'),
    ).toBeInTheDocument();
    expect(screen.getByRole('list', { name: 'Catalogue problems' })).toHaveTextContent(
      'operatorDefinitions',
    );
  });
});
