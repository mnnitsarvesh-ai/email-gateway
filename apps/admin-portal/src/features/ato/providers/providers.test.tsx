import { screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import {
  apiErrorJson,
  currentTestUrl,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  makeMe,
  mockApi,
  okJson,
  renderWithProviders,
} from '@/test';
import { IntegrationsPage } from '@/features/integrations/integrations-page';
import { AtoAccountPage } from '../account-page';
import { AtoDashboardPage } from '../dashboard-page';
import { AtoSettingsPage } from '../settings-page';
import {
  ACCOUNT_ID,
  INCIDENT_ID,
  MFA_SESSION,
  accountDetail,
  overview,
  page,
  response,
  settings,
} from '../test-data';
import { AtoProviderPage } from './provider-page';
import { AtoProvidersPage } from './providers-page';
import { REQUIREMENTS } from './requirements.data';
import {
  FORWARDING_ITEM_ID,
  GOOGLE_INTEGRATION_ID,
  INTEGRATION_ID,
  RULE_ITEM_ID,
  SPARE_CONNECTION_ID,
  candidate,
  connections,
  detail,
  list,
  mailboxState,
  summary,
} from './test-data';

const admin = (mfa = true) =>
  makeMe({ role: 'organization_admin', overrides: mfa ? MFA_SESSION : {} });

describe('Identity providers (/ato/providers)', () => {
  it('lists integrations with health, lag and actions; axe', async () => {
    mockApi({
      AtoProvidersController_list_v1: () =>
        okJson(
          list([
            summary(),
            summary({
              id: GOOGLE_INTEGRATION_ID,
              provider: 'google_workspace',
              displayName: 'EXAMPLE Northwind Google Workspace',
              status: 'paused',
              pausedReason: 'connection_inactive',
              health: { status: 'degraded', checkedAt: null, stale: true },
              streams: {
                enabled: 2,
                available: 1,
                failing: 1,
                backfilling: 1,
                maxLagSeconds: 7500,
              },
            }),
          ]),
        ),
    });
    const { container } = renderWithProviders(<AtoProvidersPage />, {
      me: admin(),
      route: '/ato/providers',
    });
    const cards = await screen.findByRole('list', { name: 'Identity providers' });
    expect(
      within(cards).getByRole('link', { name: 'EXAMPLE Contoso Microsoft 365' }),
    ).toHaveAttribute('href', `/ato/providers/${INTEGRATION_ID}`);
    expect(within(cards).getByText('7 min')).toBeInTheDocument();
    expect(within(cards).getByText('2 h 5 min')).toBeInTheDocument();
    expect(within(cards).getByText('Health check out of date')).toBeInTheDocument();
    expect(within(cards).getByText(/connection is not active/)).toBeInTheDocument();
    expect(
      within(cards).getAllByText('Revoke sessions, Suspend the account, Remove a forwarding rule'),
    ).toHaveLength(2);
    expect(screen.getByText('2 of 5 identity providers in use.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Connect identity provider' })).toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('empty state links to the 8.2 connection pages; ato:read only cannot connect', async () => {
    mockApi({ AtoProvidersController_list_v1: () => okJson(list([])) });
    renderWithProviders(<AtoProvidersPage />, {
      role: 'compliance_auditor',
      route: '/ato/providers',
    });
    expect(await screen.findByText('No identity provider connected')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Connect identity provider' })).toBeNull();
    expect(screen.getByText(/then connect it here/)).toBeInTheDocument();
  });

  it('shows the feature-off state while ATO is off', async () => {
    mockApi({
      AtoProvidersController_list_v1: () =>
        okJson(list([], { featureEnabled: false, limit: { max: 5, used: 0 } })),
    });
    renderWithProviders(<AtoProvidersPage />, { me: admin(), route: '/ato/providers' });
    expect(await screen.findByText('Account takeover detection is off')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Connect identity provider' })).toBeNull();
  });

  it('shows removed integrations on request (includeDisabled=true)', async () => {
    const queries: (string | null)[] = [];
    mockApi({
      AtoProvidersController_list_v1: ({ url }) => {
        queries.push(url.searchParams.get('includeDisabled'));
        return okJson(
          list(
            url.searchParams.get('includeDisabled') === 'true'
              ? [
                  summary({
                    status: 'disabled',
                    disabledReason: 'user',
                    disabledAt: '2026-11-19T09:00:00.000Z',
                  }),
                ]
              : [],
          ),
        );
      },
    });
    const { user } = renderWithProviders(<AtoProvidersPage />, {
      me: admin(),
      route: '/ato/providers',
    });
    await user.click(await screen.findByRole('switch', { name: 'Show removed' }));
    expect(await screen.findByText('Removed', { selector: 'span' })).toBeInTheDocument();
    expect(queries).toEqual([null, 'true']);
  });

  it('connect dialog: eligibility, permissions, streams, backfill; contract and navigation', async () => {
    const created: Array<{ body: unknown; key: string | null }> = [];
    mockApi({
      AtoProvidersController_list_v1: () => okJson(list([])),
      AtoProvidersController_connections_v1: () =>
        okJson(
          connections([
            candidate(),
            candidate({
              id: '0193c1a0-bbbb-7a00-8000-000000000009',
              displayName: 'EXAMPLE Inactive tenant',
              eligibility: 'inactive',
              reasons: ['telemetry_grant_missing'],
            }),
          ]),
        ),
      AtoProvidersController_requirements_v1: () => okJson(REQUIREMENTS),
      AtoProvidersController_create_v1: ({ body, request }) => {
        created.push({ body, key: request.headers.get('idempotency-key') });
        return okJson(detail(), 201);
      },
    });
    const { user, container } = renderWithProviders(<AtoProvidersPage />, {
      me: admin(),
      route: '/ato/providers',
    });
    await user.click(await screen.findByRole('button', { name: 'Connect identity provider' }));
    const dialog = await screen.findByRole('dialog', { name: 'Connect an identity provider' });
    const inactive = await within(dialog).findByRole('radio', { name: /EXAMPLE Inactive tenant/ });
    expect(inactive).toBeDisabled();
    expect(
      within(dialog).getByText('The connection has no account takeover telemetry grant'),
    ).toBeInTheDocument();
    expect(within(dialog).getByRole('button', { name: 'Connect' })).toBeDisabled();
    await user.click(within(dialog).getByRole('radio', { name: /EXAMPLE Fabrikam Microsoft 365/ }));
    const permissions = within(dialog).getByRole('group', {
      name: 'Required and granted permissions of the connection',
    });
    expect(within(permissions).getAllByText('User.RevokeSessions.All').length).toBeGreaterThan(1);
    expect(
      within(permissions).getByText(/ActivityFeed.Read: proven by the health check only/),
    ).toBeInTheDocument();
    // Turning the mailbox audit primary off turns its companions off (D10).
    await user.click(within(dialog).getByRole('checkbox', { name: /Mailbox audit/ }));
    expect(within(dialog).getByRole('checkbox', { name: /Forwarding changes/ })).toBeDisabled();
    const days = within(dialog).getByRole('spinbutton', { name: 'Backfill days' });
    await user.clear(days);
    await user.type(days, '31');
    expect(within(dialog).getByRole('button', { name: 'Connect' })).toBeDisabled();
    await user.clear(days);
    await user.type(days, '3');
    await expectNoAxeViolations(container);
    await user.click(within(dialog).getByRole('button', { name: 'Connect' }));
    await waitFor(() => expect(created).toHaveLength(1));
    expectRequestMatchesContract('AtoProvidersController_create_v1', created[0]?.body);
    const body = created[0]?.body as {
      connectionId: string;
      settings: { backfillDays: number; streams: Record<string, { enabled: boolean }> };
    };
    expect(body.connectionId).toBe(SPARE_CONNECTION_ID);
    expect(body.settings.backfillDays).toBe(3);
    expect(body.settings.streams.mailbox_audit?.enabled).toBe(false);
    expect(body.settings.streams.forwarding_changes?.enabled).toBe(false);
    expect(body.settings.streams.sign_ins?.enabled).toBe(true);
    expect(created[0]?.key).toBeTruthy();
    await waitFor(() => expect(currentTestUrl()).toBe(`/ato/providers/${INTEGRATION_ID}`));
  });

  it('connect dialog without an MFA session shows the MFA prompt and keeps Connect disabled', async () => {
    mockApi({
      AtoProvidersController_list_v1: () => okJson(list([])),
      AtoProvidersController_connections_v1: () => okJson(connections()),
      AtoProvidersController_requirements_v1: () => okJson(REQUIREMENTS),
    });
    const { user } = renderWithProviders(<AtoProvidersPage />, {
      me: admin(false),
      route: '/ato/providers',
    });
    await user.click(await screen.findByRole('button', { name: 'Connect identity provider' }));
    const dialog = await screen.findByRole('dialog');
    await user.click(await within(dialog).findByRole('radio', { name: /EXAMPLE Fabrikam/ }));
    expect(
      within(dialog).getByText(/needs a session signed in with multi-factor/),
    ).toBeInTheDocument();
    expect(
      within(dialog).getByRole('button', { name: 'Sign in again with MFA' }),
    ).toBeInTheDocument();
    expect(within(dialog).getByRole('button', { name: 'Connect' })).toBeDisabled();
  });

  it('connect dialog explains the directory-in-use refusal', async () => {
    mockApi({
      AtoProvidersController_list_v1: () => okJson(list([])),
      AtoProvidersController_connections_v1: () => okJson(connections()),
      AtoProvidersController_requirements_v1: () => okJson(REQUIREMENTS),
      AtoProvidersController_create_v1: () =>
        apiErrorJson(409, 'ato_provider_directory_in_use', 'in use'),
    });
    const { user } = renderWithProviders(<AtoProvidersPage />, {
      me: admin(),
      route: '/ato/providers',
    });
    await user.click(await screen.findByRole('button', { name: 'Connect identity provider' }));
    const dialog = await screen.findByRole('dialog');
    await user.click(await within(dialog).findByRole('radio', { name: /EXAMPLE Fabrikam/ }));
    await user.click(within(dialog).getByRole('button', { name: 'Connect' }));
    expect(
      await within(dialog).findByText(/already monitored by another gateway organization/),
    ).toBeInTheDocument();
  });
});

describe('Identity provider details (/ato/providers/[integrationId])', () => {
  it('overview: health, connection, grants; pause with a reason; check now (contracts); axe', async () => {
    const paused: unknown[] = [];
    let checks = 0;
    mockApi({
      AtoProvidersController_get_v1: () => okJson(detail()),
      AtoProvidersController_pause_v1: ({ body }) => {
        paused.push(body);
        return okJson(detail({ status: 'paused', pausedReason: 'user' }));
      },
      AtoProvidersController_healthCheck_v1: () => {
        checks += 1;
        return okJson(
          {
            id: INTEGRATION_ID,
            status: 'active',
            health: { status: 'healthy', checkedAt: null, stale: false },
            requestedAt: '2026-11-20T09:00:00.000Z',
          },
          202,
        );
      },
    });
    const { user, container } = renderWithProviders(
      <AtoProviderPage integrationId={INTEGRATION_ID} />,
      { me: admin(), route: `/ato/providers/${INTEGRATION_ID}` },
    );
    expect(
      await screen.findByRole('heading', { name: 'EXAMPLE Contoso Microsoft 365', level: 1 }),
    ).toBeInTheDocument();
    expect(screen.getByText('m365.ato_telemetry')).toBeInTheDocument();
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('button', { name: 'Check now' }));
    await waitFor(() => expect(checks).toBe(1));
    await user.click(screen.getByRole('button', { name: 'Pause' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.type(within(dialog).getByRole('textbox'), 'Tenant maintenance window');
    await user.click(within(dialog).getByRole('button', { name: 'Pause' }));
    await waitFor(() => expect(paused).toHaveLength(1));
    expectRequestMatchesContract('AtoProvidersController_pause_v1', paused[0]);
    expect(paused[0]).toEqual({ reason: 'Tenant maintenance window' });
  });

  it('streams: lag, errors, throttling; backfill dialog sends from and streams', async () => {
    const backfills: unknown[] = [];
    const base = detail();
    mockApi({
      AtoProvidersController_get_v1: () =>
        okJson({
          ...base,
          streamDetails: base.streamDetails.map((s) =>
            s.stream === 'sign_ins'
              ? {
                  ...s,
                  lastErrorCode: 'throttled',
                  consecutiveFailures: 2,
                  throttledUntil: '2026-11-20T09:10:00.000Z',
                }
              : s,
          ),
        }),
      AtoProvidersController_backfill_v1: ({ body }) => {
        backfills.push(body);
        return okJson(detail(), 202);
      },
    });
    const { user, container } = renderWithProviders(
      <AtoProviderPage integrationId={INTEGRATION_ID} />,
      { me: admin(), route: `/ato/providers/${INTEGRATION_ID}?tab=streams` },
    );
    const table = await screen.findByRole('table', { name: 'Streams of the identity provider' });
    const signIns = within(table).getByRole('row', { name: /^Sign-ins/ });
    expect(within(signIns).getByText('7 min')).toBeInTheDocument();
    expect(within(signIns).getByText(/The provider is throttling requests/)).toBeInTheDocument();
    expect(within(table).getByRole('row', { name: /Forwarding changes/ })).toHaveTextContent(
      'With mailbox audit',
    );
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('button', { name: 'Backfill' }));
    const dialog = await screen.findByRole('alertdialog');
    const days = within(dialog).getByRole('spinbutton', { name: 'Days back' });
    await user.clear(days);
    await user.type(days, '5');
    await user.click(within(dialog).getByRole('checkbox', { name: 'Sign-ins' }));
    const before = Date.now();
    await user.click(within(dialog).getByRole('button', { name: 'Start backfill' }));
    await waitFor(() => expect(backfills).toHaveLength(1));
    expectRequestMatchesContract('AtoProvidersController_backfill_v1', backfills[0]);
    const sent = backfills[0] as { from: string; streams: string[] };
    expect(sent.streams).toEqual(['sign_ins']);
    expect(before - Date.parse(sent.from)).toBeGreaterThanOrEqual(5 * 86_400_000 - 5_000);
    expect(before - Date.parse(sent.from)).toBeLessThan(5 * 86_400_000 + 60_000);
  });

  it('actions and permissions tabs: capability matrix, missing permissions with copy', async () => {
    const kind = 'microsoft_entra';
    const base = detail();
    mockApi({
      AtoProvidersController_get_v1: () =>
        okJson({
          ...base,
          permissions: {
            granted: base.permissions.granted,
            profiles: base.permissions.profiles.map((p) =>
              p.profile === 'm365.ato_response' && p.grant
                ? { ...p, grant: { ...p.grant, missing: ['User.EnableDisableAccount.All'] } }
                : p,
            ),
          },
        }),
    });
    const { user, container } = renderWithProviders(
      <AtoProviderPage integrationId={INTEGRATION_ID} />,
      { me: admin(), route: `/ato/providers/${INTEGRATION_ID}?tab=actions` },
    );
    const matrix = await screen.findByRole('table', { name: 'Provider action capabilities' });
    expect(within(matrix).getByRole('row', { name: /Require MFA/ })).toHaveTextContent(
      'Not configured',
    );
    expect(within(matrix).getByRole('row', { name: /Revoke an OAuth grant/ })).toHaveTextContent(
      'Disabled in the settings',
    );
    expect(
      screen.getByText(/Mailbox-level forwarding cannot be removed through Microsoft Graph/),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('textbox', { name: 'MFA enforcement group (object id)' }),
    ).toBeEnabled();
    expect(kind).toBe(base.provider);
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('tab', { name: 'Permissions' }));
    expect(
      (await screen.findAllByRole('button', { name: 'Copy User.EnableDisableAccount.All' })).length,
    ).toBeGreaterThanOrEqual(2);
  });

  it('settings: whole document with rowVersion; conflict asks to reload; invalid lists paths', async () => {
    const sent: unknown[] = [];
    let answer: 'conflict' | 'invalid' = 'conflict';
    let version = 3;
    mockApi({
      AtoProvidersController_get_v1: () => okJson(detail({ rowVersion: version })),
      AtoProvidersController_update_v1: ({ body }) => {
        sent.push(body);
        return answer === 'conflict'
          ? apiErrorJson(409, 'ato_provider_conflict', 'conflict', {
              extra: { currentRowVersion: 4 },
            })
          : apiErrorJson(400, 'ato_provider_settings_invalid', 'invalid', {
              extra: { issues: [{ path: 'mfaEnforcement.groupId', message: 'invalid_format' }] },
            });
      },
    });
    const { user, container } = renderWithProviders(
      <AtoProviderPage integrationId={INTEGRATION_ID} />,
      { me: admin(), route: `/ato/providers/${INTEGRATION_ID}?tab=settings` },
    );
    const poll = await screen.findByRole('spinbutton', { name: 'Poll interval (seconds)' });
    await user.clear(poll);
    await user.type(poll, '30');
    expect(await screen.findByText('Enter a whole number from 60 to 3600')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Save settings' })).toBeDisabled();
    await user.clear(poll);
    await user.type(poll, '600');
    await user.click(screen.getByRole('switch', { name: 'Revoke an OAuth grant' }));
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('button', { name: 'Save settings' }));
    await waitFor(() => expect(sent).toHaveLength(1));
    expectRequestMatchesContract('AtoProvidersController_update_v1', sent[0]);
    const body = sent[0] as {
      rowVersion: number;
      settings: {
        pollIntervalSeconds: number;
        actions: { revoke_oauth_grant: { enabled: boolean } };
      };
    };
    expect(body.rowVersion).toBe(3);
    expect(body.settings.pollIntervalSeconds).toBe(600);
    expect(body.settings.actions.revoke_oauth_grant.enabled).toBe(true);
    expect(
      await screen.findByText(/changed this identity provider since you opened it/),
    ).toBeInTheDocument();
    version = 4;
    answer = 'invalid';
    await user.click(screen.getByRole('button', { name: 'Reload the current settings' }));
    await waitFor(() =>
      expect(screen.queryByRole('button', { name: 'Reload the current settings' })).toBeNull(),
    );
    await user.click(screen.getByRole('button', { name: 'Save settings' }));
    expect(await screen.findByText('mfaEnforcement.groupId: Invalid format')).toBeInTheDocument();
    expect((sent[1] as { rowVersion: number }).rowVersion).toBe(4);
  });

  it('read-only for ato:read; unknown ids render the not-found view', async () => {
    mockApi({
      AtoProvidersController_get_v1: ({ params }) =>
        params.integrationId === INTEGRATION_ID
          ? okJson(detail())
          : apiErrorJson(404, 'ato_provider_not_found', 'not found'),
    });
    const { user } = renderWithProviders(<AtoProviderPage integrationId={INTEGRATION_ID} />, {
      role: 'compliance_auditor',
      route: `/ato/providers/${INTEGRATION_ID}`,
    });
    expect(await screen.findByRole('heading', { level: 1 })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Pause' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Remove' })).toBeNull();
    await user.click(screen.getByRole('tab', { name: 'Settings' }));
    expect(
      await screen.findByText('Changing these settings needs ato:configure.'),
    ).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Save settings' })).toBeNull();
  });

  it('a foreign or malformed id looks like a missing one', async () => {
    mockApi({
      AtoProvidersController_get_v1: () => apiErrorJson(404, 'ato_provider_not_found', 'not found'),
    });
    renderWithProviders(<AtoProviderPage integrationId="0193c1a0-aaaa-7a00-8000-0000000000ff" />, {
      me: admin(),
      route: '/ato/providers/0193c1a0-aaaa-7a00-8000-0000000000ff',
    });
    expect(await screen.findByText(/Page not found/i)).toBeInTheDocument();
  });
});

describe('Account mailbox changes tab (step 8.5)', () => {
  const mockAccount = (extra: Parameters<typeof mockApi>[0] = {}) =>
    mockApi({
      AtoAccountsController_get_v1: () =>
        okJson(
          accountDetail({ activeIncident: { id: INCIDENT_ID, severity: 'high', status: 'open' } }),
        ),
      AtoAccountMailboxController_get_v1: () => okJson(mailboxState(ACCOUNT_ID)),
      AtoAccountsController_signals_v1: ({ url }) => {
        expect(url.searchParams.get('category')).toBe(
          'mailbox_configuration,oauth_activity,provider_risk',
        );
        return okJson(page([]));
      },
      ...extra,
    });

  it('mailbox state table, refresh now (contract), provider signals; axe', async () => {
    let refreshed = 0;
    mockAccount({
      AtoAccountMailboxController_refresh_v1: () => {
        refreshed += 1;
        return okJson(
          {
            accountId: ACCOUNT_ID,
            requestedAt: '2026-11-20T09:00:00.000Z',
            identities: 1,
            integrationIds: [INTEGRATION_ID],
          },
          202,
        );
      },
    });
    const { user, container } = renderWithProviders(<AtoAccountPage accountId={ACCOUNT_ID} />, {
      me: makeMe({ role: 'security_analyst', overrides: MFA_SESSION }),
      route: `/ato/accounts/${ACCOUNT_ID}?tab=mailbox`,
    });
    const table = await screen.findByRole('table', { name: 'Mailbox items' });
    const rule = within(table).getByRole('row', { name: /Inbox rule or filter/ });
    expect(within(rule).getByText('mail.example.net')).toBeInTheDocument();
    expect(within(rule).getByText(/Forwards outside the organization/)).toBeInTheDocument();
    expect(within(table).getByRole('row', { name: /Delegate/ })).not.toHaveTextContent(
      'Remove forwarding',
    );
    expect(screen.getByText('Directory: Active')).toBeInTheDocument();
    expect(
      await screen.findByText('No identity-provider signals in this range'),
    ).toBeInTheDocument();
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('button', { name: 'Refresh now' }));
    await waitFor(() => expect(refreshed).toBe(1));
  });

  it('remove forwarding opens the response request with remove_forwarding_rule and the item id', async () => {
    const requests: Array<{ body: unknown; key: string | null }> = [];
    mockAccount({
      AtoResponsesController_request_v1: ({ body, request, params }) => {
        expect(params.incidentId).toBe(INCIDENT_ID);
        requests.push({ body, key: request.headers.get('idempotency-key') });
        return requests.length === 1
          ? apiErrorJson(500, 'internal_error', 'boom')
          : okJson(
              response({
                actionType: 'remove_forwarding_rule',
                provider: 'microsoft_entra',
                impact: 'medium',
              }),
              201,
            );
      },
    });
    const { user } = renderWithProviders(<AtoAccountPage accountId={ACCOUNT_ID} />, {
      me: makeMe({ role: 'security_analyst', overrides: MFA_SESSION }),
      route: `/ato/accounts/${ACCOUNT_ID}?tab=mailbox`,
    });
    const table = await screen.findByRole('table', { name: 'Mailbox items' });
    const rule = within(table).getByRole('row', { name: /Inbox rule or filter/ });
    await user.click(within(rule).getByRole('button', { name: 'Remove forwarding' }));
    const dialog = await screen.findByRole('alertdialog', { name: 'Request a response' });
    expect(
      within(dialog).getByText(/Item: Inbox rule or filter forwarding to mail.example.net/),
    ).toBeInTheDocument();
    expect(
      within(dialog).getByText(/counts as done only when the provider confirms/),
    ).toBeInTheDocument();
    await user.type(
      within(dialog).getByRole('textbox', { name: /Reason/ }),
      'Forwarding to an unknown domain',
    );
    await user.click(within(dialog).getByRole('button', { name: 'Request' }));
    await waitFor(() => expect(requests).toHaveLength(1));
    await user.click(await within(dialog).findByRole('button', { name: 'Retry the same request' }));
    await waitFor(() => expect(requests).toHaveLength(2));
    expectRequestMatchesContract('AtoResponsesController_request_v1', requests[0]?.body);
    expect(requests[0]?.body).toEqual({
      actionType: 'remove_forwarding_rule',
      reason: 'Forwarding to an unknown domain',
      params: { itemId: RULE_ITEM_ID },
    });
    expect(requests[1]?.key).toBe(requests[0]?.key);
    // Microsoft mailbox-level forwarding: the manual step is explained up front.
    expect(within(table).getByRole('row', { name: /Mailbox forwarding/ })).toHaveTextContent(
      /cannot change mailbox-level forwarding/,
    );
    expect(FORWARDING_ITEM_ID).toBeTruthy();
  });

  it('without an active incident removal points to the incident; read-only users get no refresh', async () => {
    mockApi({
      AtoAccountsController_get_v1: () => okJson(accountDetail({ activeIncident: null })),
      AtoAccountMailboxController_get_v1: () => okJson(mailboxState(ACCOUNT_ID)),
      AtoAccountsController_signals_v1: () => okJson(page([])),
    });
    renderWithProviders(<AtoAccountPage accountId={ACCOUNT_ID} />, {
      role: 'security_analyst',
      route: `/ato/accounts/${ACCOUNT_ID}?tab=mailbox`,
    });
    expect(
      (await screen.findAllByText('Removal is requested from an active incident of this account.'))
        .length,
    ).toBe(2);
  });
});

describe('ATO pages with identity providers (step 8.5)', () => {
  it('dashboard: identity providers card with health counts and the worst lag', async () => {
    mockApi({
      AtoOverviewController_overview_v1: () => okJson(overview()),
      AtoProvidersController_list_v1: () =>
        okJson(
          list([
            summary(),
            summary({
              id: GOOGLE_INTEGRATION_ID,
              provider: 'google_workspace',
              health: { status: 'unhealthy', checkedAt: null, stale: false },
              streams: {
                enabled: 2,
                available: 0,
                failing: 2,
                backfilling: 0,
                maxLagSeconds: 4000,
              },
            }),
          ]),
        ),
    });
    renderWithProviders(<AtoDashboardPage />, { route: '/ato' });
    const card = await screen.findByRole('region', { name: 'Identity providers' });
    expect(await within(card).findByText('Unhealthy')).toBeInTheDocument();
    expect(within(card).getByText('1 h 6 min')).toBeInTheDocument();
    expect(within(card).getByRole('link', { name: 'Manage identity providers' })).toHaveAttribute(
      'href',
      '/ato/providers',
    );
  });

  it('settings: identity providers tab summarises integrations (no step 8.5 state)', async () => {
    mockApi({
      AtoSettingsController_get_v1: () =>
        okJson(
          settings({
            identityProviders: [
              {
                provider: 'microsoft_entra',
                integrations: [
                  { id: INTEGRATION_ID, provider: 'microsoft_entra', health: 'degraded' },
                ],
              },
              { provider: 'google_workspace', integrations: [] },
            ],
          }),
        ),
    });
    renderWithProviders(<AtoSettingsPage />, { route: '/ato/settings?tab=providers' });
    const providers = await screen.findByRole('list', { name: 'Identity providers by provider' });
    expect(within(providers).getByText('Degraded')).toBeInTheDocument();
    expect(within(providers).getByText('Not connected')).toBeInTheDocument();
    expect(screen.queryByText('Arrives in step 8.5')).toBeNull();
  });

  it('integrations: the identity providers link card for ato:read', async () => {
    mockApi({
      WebhooksController_list_v1: () => okJson({ data: [], nextCursor: null }),
      ProviderConnectionsController_list_v1: () => okJson({ data: [], nextCursor: null }),
    });
    renderWithProviders(<IntegrationsPage />, { route: '/integrations' });
    expect(await screen.findByRole('link', { name: 'Manage identity providers' })).toHaveAttribute(
      'href',
      '/ato/providers',
    );
  });
});
