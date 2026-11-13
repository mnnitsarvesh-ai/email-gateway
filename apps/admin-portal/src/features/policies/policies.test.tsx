import { screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { expectNoInjectedMarkup } from '@/features/messages/test-data';
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
import { PolicyDetail } from './policy-detail';
import {
  CATALOG,
  POLICY_ID,
  POLICY_SETTINGS,
  RISK_PROFILE,
  execution,
  policyDetail,
  policyRow,
  versionDetail,
  versionRow,
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
  it('lists email policies with filters in the URL; shows the 7.3 banner and no mutations; axe', async () => {
    const seen: URLSearchParams[] = [];
    mockApi({
      PolicyManagementController_list_v1: ({ url }) => {
        seen.push(url.searchParams);
        return okJson({ data: [policyRow()], nextCursor: null, generation: '42' });
      },
    });
    const { user, container } = renderWithProviders(<PoliciesPage />, {
      role: 'security_analyst',
      route: '/policies',
    });
    expect(await screen.findByRole('link', { name: 'Inbound threats' })).toHaveAttribute(
      'href',
      `/policies/${POLICY_ID}`,
    );
    expect(
      screen.getByText(/Creating, editing, publishing and activating policies arrives in step 7.3/),
    ).toBeInTheDocument();
    expect(screen.getByText(/Policy generation/)).toBeInTheDocument();
    expectNoMutationButtons();
    await expectNoAxeViolations(container);
    await user.click(screen.getByLabelText('Status'));
    await user.click(await screen.findByRole('option', { name: 'Disabled' }));
    await waitFor(() => expect(currentTestUrl()).toContain('status=disabled'));
    await waitFor(() => expect(seen[seen.length - 1]?.get('status')).toBe('disabled'));
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

  it('settings, risk and scanning tabs render the read-only configuration', async () => {
    mockApi({
      PolicySettingsController_get_v1: () => okJson(POLICY_SETTINGS),
      RiskProfilesController_profile_v1: () => okJson(RISK_PROFILE),
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
    await expectNoAxeViolations(container);
    unmount();
    const risk = renderWithProviders(<PoliciesPage />, {
      role: 'security_analyst',
      route: '/policies?tab=risk',
    });
    expect(await screen.findByText(/Platform default \(rsk-default\/1\)/)).toBeInTheDocument();
    expect(screen.getByText('The platform default profile applies.')).toBeInTheDocument();
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
    expectNoMutationButtons();
  });
});

describe('Policy detail (/policies/[policyId])', () => {
  it('shows the policy, versions and the active definition as text; selecting a version updates the URL', async () => {
    const versionsRequested: string[] = [];
    mockApi({
      PolicyManagementController_get_v1: () => okJson(policyDetail()),
      PolicyManagementController_listVersions_v1: () =>
        okJson({ data: [versionRow(3), versionRow(2), versionRow(1)], nextCursor: null }),
      PolicyManagementController_getVersion_v1: ({ params }) => {
        versionsRequested.push(params.versionNo ?? '');
        return okJson(
          versionDetail({
            versionNo: Number(params.versionNo),
            validation:
              params.versionNo === '1'
                ? {
                    valid: false,
                    violations: [
                      { path: 'rules[0]', code: 'field_unknown', message: 'Renamed field' },
                    ],
                  }
                : { valid: true, violations: [] },
          }),
        );
      },
    });
    const { user, container } = renderWithProviders(<PolicyDetail policyId={POLICY_ID} />, {
      role: 'read_only_user',
      route: `/policies/${POLICY_ID}`,
    });
    expect(
      await screen.findByRole('heading', { name: 'Inbound threats', level: 1 }),
    ).toBeInTheDocument();
    const definition = await screen.findByTestId('policy-definition');
    expect(definition.tagName).toBe('PRE');
    expect(definition.textContent).toContain('<script>window.__pwned=3</script>');
    expectNoInjectedMarkup(container);
    expect(versionsRequested).toEqual(['2']);
    expectNoMutationButtons();
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('button', { name: 'v1' }));
    await waitFor(() => expect(currentTestUrl()).toContain('version=1'));
    expect(await screen.findByText('Renamed field', { exact: false })).toBeInTheDocument();
  });

  it('renders not-found for unknown and foreign ids', async () => {
    mockApi({
      PolicyManagementController_get_v1: () =>
        apiErrorJson(404, 'policy_not_found', 'Not found', { requestId: 'req-pol' }),
    });
    renderWithProviders(<PolicyDetail policyId={POLICY_ID} />, { role: 'security_analyst' });
    expect(screen.getByText(/Loading the policy/)).toBeInTheDocument();
    const alert = await screen.findByRole('alert');
    expect(within(alert).getByText('policy_not_found')).toBeInTheDocument();
    expect(within(alert).getByText('req-pol')).toBeInTheDocument();
  });
});

describe('Policy builder (/policies/builder)', () => {
  it('shows the DSL catalogue as a searchable reference and the 7.3 state; axe', async () => {
    mockApi({ PolicyToolsController_catalog_v1: () => okJson(CATALOG) });
    const { user, container } = renderWithProviders(<PolicyBuilder />, {
      role: 'security_analyst',
      route: '/policies/builder',
    });
    expect(await screen.findByText('risk.score')).toBeInTheDocument();
    expect(
      screen.getByText(/The visual policy builder, test and dry-run arrive in step 7.3/),
    ).toBeInTheDocument();
    expect(screen.getAllByText('Terminal (decides the disposition)')).toHaveLength(2);
    expect(screen.getByText('not used by any field')).toBeInTheDocument();
    await expectNoAxeViolations(container);
    await user.type(screen.getByLabelText('Search fields'), 'attachment');
    await waitFor(() => expect(screen.queryByText('risk.score')).not.toBeInTheDocument());
    expect(screen.getByText('attachments.type_family')).toBeInTheDocument();
    expect(currentTestUrl()).toContain('q=attachment');
    expectNoMutationButtons();
  });

  it('filters fields by scope and text', () => {
    expect(filterFields(CATALOG.fields, undefined, 'attachments').map((f) => f.name)).toEqual([
      'attachments.type_family',
    ]);
    expect(filterFields(CATALOG.fields, 'between', undefined).map((f) => f.name)).toEqual([
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
});
