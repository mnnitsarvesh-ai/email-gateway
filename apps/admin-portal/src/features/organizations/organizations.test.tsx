import { screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { SuccessBody } from '@/lib/api/types';
import {
  TEST_ORG,
  apiErrorJson,
  currentTestUrl,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  mockApi,
  noContentResponse,
  okJson,
  renderWithProviders,
} from '@/test';
import { OrganizationDetailPage } from './organization-detail-page';
import { OrganizationsPage } from './organizations-page';
import {
  createOrganizationBody,
  createOrganizationSchema,
  profileBody,
  profileSchema,
} from './schemas';

type Organization = SuccessBody<'OrganizationsController_get_v1'>;

const org = (over: Partial<Organization> = {}): Organization => ({
  id: TEST_ORG.id,
  slug: 'alpha',
  name: 'Alpha Industries (example)',
  kind: 'customer',
  status: 'active',
  statusReason: null,
  statusChangedAt: null,
  plan: { code: 'business', name: 'Business' },
  deploymentMode: 'saas',
  dataRegion: 'eu-west-1',
  deployments: [
    {
      deploymentMode: 'saas',
      region: 'eu-west-1',
      environment: 'prod',
      status: 'active',
      endpointHostname: null,
      mxHostname: 'mx.gateway.example.test',
      releaseVersion: '1.4.0',
      provisionedAt: '2026-07-01T00:00:00.000Z',
      createdAt: '2026-07-01T00:00:00.000Z',
    },
  ],
  deletion: null,
  createdAt: '2026-07-01T00:00:00.000Z',
  updatedAt: '2026-11-01T00:00:00.000Z',
  ...over,
});

const settings: SuccessBody<'OrganizationConfigurationController_getSettings_v1'> = {
  organizationId: TEST_ORG.id,
  timezone: 'Europe/Berlin',
  locale: 'en-GB',
  quarantineRetentionDays: 30,
  quarantineRetentionMaxDays: 90,
  digestEnabled: true,
  digestSchedule: '0 8 * * 1-5',
  notificationEmail: 'security@example.com',
  mfaRequired: false,
  preferences: {},
  updatedAt: '2026-11-01T00:00:00.000Z',
};

describe('Organizations: platform catalogue', () => {
  it('lists organizations; search and filters write the URL and the request; pagination uses cursors', async () => {
    const seen: URLSearchParams[] = [];
    mockApi({
      OrganizationsController_list_v1: ({ url }) => {
        seen.push(url.searchParams);
        return url.searchParams.get('cursor') === 'n2'
          ? okJson({
              data: [
                org({
                  id: '01930000-0000-7000-8000-00000000b002',
                  slug: 'bravo',
                  name: 'Bravo Logistics (example)',
                }),
              ],
              nextCursor: null,
            })
          : okJson({ data: [org()], nextCursor: 'n2' });
      },
    });
    const { container, user } = renderWithProviders(<OrganizationsPage />, {
      route: '/organizations',
      role: 'platform_admin',
    });
    expect(await screen.findByRole('link', { name: 'Alpha Industries (example)' })).toHaveAttribute(
      'href',
      `/organizations/${TEST_ORG.id}`,
    );
    expect(screen.getByRole('button', { name: 'Create organization' })).toBeInTheDocument();
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('button', { name: 'Next' }));
    expect(await screen.findByText('Bravo Logistics (example)')).toBeInTheDocument();
    expect(seen.at(-1)?.get('cursor')).toBe('n2');
    await user.type(
      screen.getByRole('searchbox', { name: 'Search by name or slug prefix' }),
      'alp',
    );
    await waitFor(() => expect(currentTestUrl()).toContain('q=alp'));
    await waitFor(() => expect(seen.at(-1)?.get('q')).toBe('alp'));
    expect(seen.at(-1)?.has('cursor')).toBe(false);
    await user.click(screen.getByRole('combobox', { name: 'Status' }));
    await user.click(await screen.findByRole('option', { name: 'Suspended' }));
    await waitFor(() => expect(seen.at(-1)?.get('status')).toBe('suspended'));
  });

  it('shows empty and error states', async () => {
    mockApi({
      OrganizationsController_list_v1: () =>
        apiErrorJson(500, 'internal_error', 'Boom', { requestId: 'req-org-1' }),
    });
    renderWithProviders(<OrganizationsPage />, { route: '/organizations', role: 'platform_admin' });
    expect(await screen.findByText('req-org-1')).toBeInTheDocument();
    expect(screen.getByText('internal_error')).toBeInTheDocument();
  });

  it('creates an organization with a contract-conformant body and opens it', async () => {
    let body: unknown = null;
    mockApi({
      OrganizationsController_list_v1: () => okJson({ data: [], nextCursor: null }),
      OrganizationsController_create_v1: ({ body: b }) => {
        body = b;
        return okJson(
          {
            ...org({
              id: '01930000-0000-7000-8000-00000000c003',
              slug: 'charlie',
              name: 'Charlie Health',
            }),
            initialAdmin: {
              id: '01930000-0000-7000-8000-000000000999',
              email: 'admin@example.com',
              status: 'invited',
              invitationExpiresAt: '2026-11-20T00:00:00.000Z',
              invitationSent: true,
            },
          },
          201,
        );
      },
    });
    const { user, router } = renderWithProviders(<OrganizationsPage />, {
      route: '/organizations',
      role: 'platform_admin',
    });
    expect(await screen.findByText('No organizations yet')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Create organization' }));
    const dialog = await screen.findByRole('dialog', { name: 'Create organization' });
    await user.click(within(dialog).getByRole('button', { name: 'Create organization' }));
    expect(await within(dialog).findByText('Enter a name')).toBeInTheDocument();
    await user.type(
      within(dialog).getByLabelText(/^Name/, { selector: 'input' }),
      'Charlie Health',
    );
    await user.type(within(dialog).getByLabelText(/^Slug/), 'charlie');
    await user.type(within(dialog).getByLabelText(/^Plan code/), 'business');
    await user.type(within(dialog).getByLabelText(/^Data region/), 'ap-south-1');
    await user.type(within(dialog).getByLabelText(/^Administrator email/), 'admin@example.com');
    await user.type(within(dialog).getByLabelText(/^Administrator name/), 'First Admin');
    await user.click(within(dialog).getByRole('button', { name: 'Create organization' }));
    await waitFor(() =>
      expect(router.push).toHaveBeenCalledWith(
        '/organizations/01930000-0000-7000-8000-00000000c003',
      ),
    );
    expect(body).toEqual({
      name: 'Charlie Health',
      slug: 'charlie',
      planCode: 'business',
      deploymentMode: 'saas',
      dataRegion: 'ap-south-1',
      initialAdmin: { email: 'admin@example.com', displayName: 'First Admin' },
    });
    expectRequestMatchesContract('OrganizationsController_create_v1', body);
    expect(
      await screen.findByText(/An invitation was sent to admin@example.com/),
    ).toBeInTheDocument();
  });

  it('shows a duplicate slug (409) at form level and validates dedicated deployments', async () => {
    mockApi({
      OrganizationsController_list_v1: () => okJson({ data: [], nextCursor: null }),
      OrganizationsController_create_v1: () =>
        apiErrorJson(409, 'organization_slug_exists', 'An organization with this slug exists'),
    });
    const { user } = renderWithProviders(<OrganizationsPage />, {
      route: '/organizations',
      role: 'platform_admin',
    });
    await user.click(await screen.findByRole('button', { name: 'Create organization' }));
    const dialog = await screen.findByRole('dialog');
    await user.type(within(dialog).getByLabelText(/^Name/, { selector: 'input' }), 'Alpha');
    await user.type(within(dialog).getByLabelText(/^Slug/), 'alpha');
    await user.type(within(dialog).getByLabelText(/^Plan code/), 'business');
    await user.type(within(dialog).getByLabelText(/^Data region/), 'eu-west-1');
    await user.click(within(dialog).getByRole('radio', { name: 'Dedicated' }));
    await user.click(within(dialog).getByRole('button', { name: 'Create organization' }));
    expect(await within(dialog).findAllByText('A region such as ap-south-1')).toHaveLength(1);
    await user.type(within(dialog).getByLabelText(/^Deployment region/), 'eu-west-1');
    await user.type(within(dialog).getByLabelText(/^Deployment environment/), 'prod');
    await user.click(within(dialog).getByRole('button', { name: 'Create organization' }));
    expect(
      await within(dialog).findByText('An organization with this slug exists'),
    ).toBeInTheDocument();
  });

  it('form schemas produce contract-conformant bodies', () => {
    expectRequestMatchesContract(
      'OrganizationsController_create_v1',
      createOrganizationBody(
        createOrganizationSchema.parse({
          name: 'Delta',
          slug: 'delta-1',
          planCode: 'enterprise',
          deploymentMode: 'dedicated',
          dataRegion: 'ap-south-1',
          deploymentRegion: 'ap-south-1',
          deploymentEnvironment: 'prod',
          adminEmail: '',
          adminDisplayName: '',
        }),
      ),
    );
    expect(
      createOrganizationSchema.safeParse({
        name: 'X',
        slug: 'admin',
        planCode: 'b',
        deploymentMode: 'saas',
        dataRegion: 'eu-west-1',
        deploymentRegion: '',
        deploymentEnvironment: '',
        adminEmail: '',
        adminDisplayName: '',
      }).success,
    ).toBe(false);
    expectRequestMatchesContract(
      'OrganizationsController_update_v1',
      profileBody(profileSchema.parse({ name: 'New name', planCode: 'enterprise' }), {
        includePlan: true,
        currentPlan: 'business',
      }),
    );
  });

  it('users without organization:read or platform:organizations get the 403 page', () => {
    renderWithProviders(<OrganizationsPage />, { route: '/organizations', role: 'mailbox_user' });
    expect(
      screen.getByRole('heading', { name: 'You do not have access to this page' }),
    ).toBeInTheDocument();
  });
});

describe('Organizations: tenant view of the own organization', () => {
  it('shows the profile (id from /auth/me), edit form for organization:manage, no platform actions', async () => {
    let updateBody: unknown = null;
    mockApi({
      OrganizationsController_get_v1: ({ params }) =>
        params.id === TEST_ORG.id ? okJson(org()) : apiErrorJson(404, 'not_found', 'Not found'),
      OrganizationsController_update_v1: ({ body, request }) => {
        updateBody = body;
        expect(request.headers.get('idempotency-key')).toBeNull();
        return okJson(org({ name: 'Alpha Renamed' }));
      },
    });
    const { container, user } = renderWithProviders(<OrganizationsPage />, {
      route: '/organizations',
    });
    expect(
      await screen.findByRole('heading', { level: 1, name: 'Alpha Industries (example)' }),
    ).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Suspend' })).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Act in this organization' }),
    ).not.toBeInTheDocument();
    expect(screen.queryByRole('tab', { name: 'Deletion' })).not.toBeInTheDocument();
    expect(screen.getByText('Arrives in step 8.3')).toBeInTheDocument();
    expect(screen.queryByLabelText('Plan code')).not.toBeInTheDocument();
    await expectNoAxeViolations(container);
    const name = screen.getByLabelText(/^Name/);
    await user.clear(name);
    await user.type(name, 'Alpha Renamed');
    await user.click(screen.getByRole('button', { name: 'Save profile' }));
    await waitFor(() => expect(updateBody).toEqual({ name: 'Alpha Renamed' }));
    expectRequestMatchesContract('OrganizationsController_update_v1', updateBody);
    expect(await screen.findByText('Organization profile saved.')).toBeInTheDocument();
  });

  it('read-only users see the profile without the edit form; settings tab shows a summary', async () => {
    mockApi({
      OrganizationsController_get_v1: () => okJson(org()),
      OrganizationConfigurationController_getSettings_v1: () => okJson(settings),
    });
    const { user } = renderWithProviders(<OrganizationsPage />, {
      route: '/organizations',
      role: 'read_only_user',
    });
    await screen.findByRole('heading', { level: 1, name: 'Alpha Industries (example)' });
    expect(screen.queryByRole('button', { name: 'Save profile' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('tab', { name: 'Settings' }));
    expect(await screen.findByText('security@example.com')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Save settings' })).not.toBeInTheDocument();
  });

  it('usage tab and entitlements without override actions', async () => {
    mockApi({
      OrganizationsController_get_v1: () => okJson(org()),
      OrganizationsController_getUsage_v1: () =>
        okJson({
          organizationId: TEST_ORG.id,
          period: { from: '2026-10-14T00:00:00.000Z', to: '2026-11-13T00:00:00.000Z' },
          users: { total: 4, active: 3, invited: 1, disabled: 0, locked: 0 },
          domains: { total: 1, verified: 1, pendingVerification: 0, active: 1, suspended: 0 },
          messages: { total: 321, inbound: 300, outbound: 20, internal: 1, today: 9 },
          quarantine: { active: 2 },
          apiKeys: { active: 1 },
          sessions: { active: 3 },
          limits: [{ key: 'max_users', value: 50, source: 'plan', used: 4 }],
        }),
      OrganizationConfigurationController_listFeatures_v1: () =>
        okJson({
          organizationId: TEST_ORG.id,
          data: [
            {
              key: 'dlp',
              enabled: true,
              config: null,
              source: 'plan',
              updatedAt: '2026-11-01T00:00:00.000Z',
            },
          ],
        }),
      OrganizationConfigurationController_listLimits_v1: () =>
        okJson({
          organizationId: TEST_ORG.id,
          data: [
            { key: 'max_users', value: 50, source: 'plan', updatedAt: '2026-11-01T00:00:00.000Z' },
          ],
        }),
    });
    const { user } = renderWithProviders(<OrganizationsPage />, {
      route: '/organizations?tab=usage',
    });
    expect(await screen.findByText('321')).toBeInTheDocument();
    await user.click(screen.getByRole('tab', { name: 'Features and limits' }));
    expect(
      await screen.findByRole('table', { name: 'Features of this organization' }),
    ).toHaveTextContent('DLP');
    expect(screen.queryByRole('button', { name: /Override Max users/ })).not.toBeInTheDocument();
  });
});

describe('Organizations: platform detail', () => {
  it('suspends with a required reason (legacy Idempotency-Key) and shows Act in this organization', async () => {
    let body: unknown = null;
    let key: string | null = null;
    mockApi({
      OrganizationsController_get_v1: () => okJson(org()),
      OrganizationsController_changeStatus_v1: ({ body: b, request }) => {
        body = b;
        key = request.headers.get('idempotency-key');
        return okJson(org({ status: 'suspended', statusReason: 'Unpaid invoices ticket 7' }));
      },
    });
    const { user, container } = renderWithProviders(
      <OrganizationDetailPage organizationId={TEST_ORG.id} />,
      {
        route: `/organizations/${TEST_ORG.id}`,
        role: 'platform_admin',
      },
    );
    expect(
      await screen.findByRole('button', { name: 'Act in this organization' }),
    ).toBeInTheDocument();
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('button', { name: 'Suspend' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Suspend organization' }));
    expect(within(dialog).getByText('Enter a reason.')).toBeInTheDocument();
    await user.type(within(dialog).getByLabelText(/^Reason/), 'Unpaid invoices ticket 7');
    await user.click(within(dialog).getByRole('button', { name: 'Suspend organization' }));
    await waitFor(() =>
      expect(body).toEqual({ status: 'suspended', reason: 'Unpaid invoices ticket 7' }),
    );
    expect(key).toMatch(/^[0-9a-f-]{36}$/);
    expectRequestMatchesContract('OrganizationsController_changeStatus_v1', body);
    expect(await screen.findByText('Organization suspended.')).toBeInTheDocument();
  });

  it('opens the override dialog for the organization (tenant switch is only the audited override)', async () => {
    mockApi({ OrganizationsController_get_v1: () => okJson(org()) });
    const { user } = renderWithProviders(<OrganizationDetailPage organizationId={TEST_ORG.id} />, {
      route: `/organizations/${TEST_ORG.id}`,
      role: 'platform_admin',
    });
    await user.click(await screen.findByRole('button', { name: 'Act in this organization' }));
    const dialog = await screen.findByRole('dialog', { name: 'Act in Alpha Industries (example)' });
    await user.click(within(dialog).getByRole('button', { name: 'Start override' }));
    expect(await within(dialog).findByText(/at least 10 characters/)).toBeInTheDocument();
  });

  it('overrides and resets features and limits', async () => {
    const calls: string[] = [];
    let limitBody: unknown = null;
    mockApi({
      OrganizationsController_get_v1: () => okJson(org()),
      OrganizationConfigurationController_listFeatures_v1: () =>
        okJson({
          organizationId: TEST_ORG.id,
          data: [
            {
              key: 'attachment_sandbox',
              enabled: false,
              config: null,
              source: 'override',
              updatedAt: '2026-11-01T00:00:00.000Z',
            },
          ],
        }),
      OrganizationConfigurationController_listLimits_v1: () =>
        okJson({
          organizationId: TEST_ORG.id,
          data: [
            { key: 'max_users', value: 50, source: 'plan', updatedAt: '2026-11-01T00:00:00.000Z' },
          ],
        }),
      OrganizationConfigurationController_overrideFeature_v1: ({ body, params }) => {
        calls.push(`feature:${params.featureKey}:${JSON.stringify(body)}`);
        expectRequestMatchesContract(
          'OrganizationConfigurationController_overrideFeature_v1',
          body,
        );
        return okJson({
          key: 'attachment_sandbox',
          enabled: true,
          config: null,
          source: 'override',
          updatedAt: '2026-11-13T00:00:00.000Z',
        });
      },
      OrganizationConfigurationController_resetFeature_v1: ({ params }) => (
        calls.push(`reset:${params.featureKey}`),
        noContentResponse()
      ),
      OrganizationConfigurationController_overrideLimit_v1: ({ body }) => {
        limitBody = body;
        return okJson({
          key: 'max_users',
          value: 75,
          source: 'override',
          updatedAt: '2026-11-13T00:00:00.000Z',
        });
      },
    });
    const { user } = renderWithProviders(<OrganizationDetailPage organizationId={TEST_ORG.id} />, {
      route: `/organizations/${TEST_ORG.id}?tab=entitlements`,
      role: 'super_admin',
    });
    await user.click(
      await screen.findByRole('button', { name: 'Enable Attachment sandbox (override)' }),
    );
    await waitFor(() => expect(calls).toContain('feature:attachment_sandbox:{"enabled":true}'));
    await user.click(
      screen.getByRole('button', { name: 'Reset Attachment sandbox to the plan value' }),
    );
    await user.click(
      within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Reset to plan' }),
    );
    await waitFor(() => expect(calls).toContain('reset:attachment_sandbox'));
    await user.click(screen.getByRole('button', { name: 'Override Max users' }));
    const dialog = await screen.findByRole('dialog');
    const input = within(dialog).getByLabelText(/^Value/);
    await user.clear(input);
    await user.type(input, '75');
    await user.click(within(dialog).getByRole('button', { name: 'Save override' }));
    await waitFor(() => expect(limitBody).toEqual({ value: 75 }));
    expectRequestMatchesContract('OrganizationConfigurationController_overrideLimit_v1', limitBody);
  });

  it('deletion workflow: request with typed slug, four-eyes refusal on confirm explained', async () => {
    let state: 'none' | 'pending_deletion' = 'none';
    let requestBody: unknown = null;
    mockApi({
      OrganizationsController_get_v1: () => okJson(org()),
      OrganizationDeletionController_get_v1: () =>
        okJson({
          organizationId: TEST_ORG.id,
          status: state === 'none' ? 'active' : 'pending_deletion',
          state,
          requestedAt: state === 'none' ? null : '2026-11-13T09:00:00.000Z',
          requestedBy: state === 'none' ? null : '01930000-0000-7000-8000-000000000101',
          reason: state === 'none' ? null : 'Customer left, ticket 99',
          confirmationDeadline: state === 'none' ? null : '2026-11-14T09:00:00.000Z',
          confirmedAt: null,
          confirmedBy: null,
          purgeAfter: null,
          cancellable: state !== 'none',
        }),
      OrganizationDeletionController_request_v1: ({ body }) => {
        requestBody = body;
        state = 'pending_deletion';
        return okJson({
          organizationId: TEST_ORG.id,
          status: 'pending_deletion',
          state: 'pending_deletion',
          requestedAt: '2026-11-13T09:00:00.000Z',
          requestedBy: '01930000-0000-7000-8000-000000000101',
          reason: 'Customer left, ticket 99',
          confirmationDeadline: '2026-11-14T09:00:00.000Z',
          confirmedAt: null,
          confirmedBy: null,
          purgeAfter: null,
          cancellable: true,
        });
      },
      OrganizationDeletionController_confirm_v1: () =>
        apiErrorJson(
          403,
          'forbidden',
          'The deletion must be confirmed by a different platform user',
          { requestId: 'req-del-2' },
        ),
    });
    const { user } = renderWithProviders(<OrganizationDetailPage organizationId={TEST_ORG.id} />, {
      route: `/organizations/${TEST_ORG.id}?tab=deletion`,
      role: 'super_admin',
    });
    await user.click(await screen.findByRole('button', { name: 'Request deletion' }));
    let dialog = await screen.findByRole('alertdialog');
    await user.type(within(dialog).getByLabelText(/^Reason/), 'Customer left, ticket 99');
    expect(within(dialog).getByRole('button', { name: 'Request deletion' })).toBeDisabled();
    await user.type(within(dialog).getByLabelText(/Type alpha to confirm/), 'alpha');
    await user.click(within(dialog).getByRole('button', { name: 'Request deletion' }));
    await waitFor(() =>
      expect(requestBody).toEqual({ reason: 'Customer left, ticket 99', confirmSlug: 'alpha' }),
    );
    expectRequestMatchesContract('OrganizationDeletionController_request_v1', requestBody);
    await user.click(await screen.findByRole('button', { name: 'Confirm deletion' }));
    dialog = await screen.findByRole('alertdialog');
    await user.type(within(dialog).getByLabelText(/Type alpha to confirm/), 'alpha');
    await user.click(within(dialog).getByRole('button', { name: 'Confirm deletion' }));
    expect(await within(dialog).findByText(/Four-eyes rule/)).toBeInTheDocument();
    expect(within(dialog).getByText('req-del-2')).toBeInTheDocument();
  });
});
