import { screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import {
  apiErrorJson,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  makeMe,
  mockApi,
  okJson,
  renderWithProviders,
} from '@/test';
import { AtoResponsesPage } from './responses-page';
import { AtoSettingsPage } from './settings-page';
import {
  MFA_SESSION,
  RESPONSE_ID,
  RULES,
  page,
  response,
  restriction,
  settings,
  summaryOf,
} from './test-data';

const mfaAnalyst = () => makeMe({ role: 'security_analyst', overrides: MFA_SESSION });

describe('Responses (/ato/responses)', () => {
  it('pending approvals first; approve with MFA (contract, key); axe', async () => {
    const calls: Array<{ body: unknown; key: string | null }> = [];
    const statuses: (string | null)[] = [];
    mockApi({
      AtoResponsesController_list_v1: ({ url }) => {
        statuses.push(url.searchParams.get('status'));
        return okJson(page([summaryOf(response())]));
      },
      AtoResponsesController_approve_v1: ({ body, request }) => {
        calls.push({ body, key: request.headers.get('idempotency-key') });
        return okJson(
          response({ status: 'succeeded', providerStatus: 'applied', canDecide: false }),
        );
      },
    });
    const { user, container } = renderWithProviders(<AtoResponsesPage />, {
      me: mfaAnalyst(),
      route: '/ato/responses',
    });
    const table = await screen.findByRole('table', { name: 'Responses waiting for approval' });
    expect(statuses[0]).toBe('pending_approval');
    expect(within(table).getByText('Restrict SMTP sending')).toBeInTheDocument();
    await expectNoAxeViolations(container);
    await user.click(within(table).getByRole('button', { name: 'Approve: Restrict SMTP sending' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Approve' }));
    await waitFor(() => expect(calls).toHaveLength(1));
    expectRequestMatchesContract('AtoResponsesController_approve_v1', calls[0]?.body);
    expect(calls[0]?.body).toEqual({});
    expect(calls[0]?.key).toBeTruthy();
  });

  it('shows the MFA-required state without an MFA session; four eyes text for the requester', async () => {
    mockApi({
      AtoResponsesController_list_v1: () =>
        okJson(
          page([
            summaryOf(response()),
            summaryOf(response({ id: '01933c3a-1b2c-7d4e-8f00-0000000a7299', canDecide: false })),
          ]),
        ),
    });
    renderWithProviders(<AtoResponsesPage />, {
      role: 'security_analyst',
      route: '/ato/responses',
    });
    const approve = await screen.findByRole('button', { name: 'Approve: Restrict SMTP sending' });
    expect(approve).toBeDisabled();
    expect(screen.getByText(/Approving needs a session signed in with MFA/)).toBeInTheDocument();
    expect(screen.getByText(/the requester cannot approve their own request/)).toBeInTheDocument();
  });

  it('reject needs a reason of 10 characters; a 500 is retried with the same Idempotency-Key', async () => {
    const keys: (string | null)[] = [];
    let n = 0;
    mockApi({
      AtoResponsesController_list_v1: () => okJson(page([summaryOf(response())])),
      AtoResponsesController_reject_v1: ({ body, request }) => {
        expectRequestMatchesContract('AtoResponsesController_reject_v1', body);
        keys.push(request.headers.get('idempotency-key'));
        n += 1;
        return n === 1
          ? apiErrorJson(500, 'internal_error', 'boom')
          : okJson(response({ status: 'rejected' }));
      },
    });
    const { user } = renderWithProviders(<AtoResponsesPage />, { me: mfaAnalyst() });
    await user.click(await screen.findByRole('button', { name: 'Reject: Restrict SMTP sending' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.type(within(dialog).getByLabelText(/Reason/), 'short');
    await user.click(within(dialog).getByRole('button', { name: 'Reject' }));
    expect(await within(dialog).findByText(/at least 10 characters/)).toBeInTheDocument();
    await user.type(within(dialog).getByLabelText(/Reason/), ' but now long enough');
    await user.click(within(dialog).getByRole('button', { name: 'Reject' }));
    await user.click(await within(dialog).findByRole('button', { name: 'Retry the same request' }));
    await waitFor(() => expect(keys).toHaveLength(2));
    expect(keys[0]).toBe(keys[1]);
  });

  it('rolls back a succeeded restriction (MFA) and lists restrictions', async () => {
    const bodies: unknown[] = [];
    mockApi({
      AtoResponsesController_list_v1: () =>
        okJson(
          page([
            summaryOf(
              response({
                status: 'succeeded',
                providerStatus: 'applied',
                canDecide: false,
                canRollback: true,
              }),
            ),
          ]),
        ),
      AtoResponsesController_rollback_v1: ({ body, params }) => {
        expect(params.responseId).toBe(RESPONSE_ID);
        bodies.push(body);
        return okJson(response({ status: 'rolled_back' }));
      },
      AtoRestrictionsController_list_v1: ({ url }) => {
        expect(url.searchParams.get('status')).toBe('active');
        return okJson(page([restriction()]));
      },
    });
    const { user } = renderWithProviders(<AtoResponsesPage />, {
      me: mfaAnalyst(),
      route: '/ato/responses?tab=all',
    });
    expect(await screen.findByText('Applied by the gateway')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Roll back: Restrict SMTP sending' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.type(within(dialog).getByLabelText(/Reason/), 'False positive confirmed by phone');
    await user.click(within(dialog).getByRole('button', { name: 'Roll back' }));
    await waitFor(() => expect(bodies).toEqual([{ reason: 'False positive confirmed by phone' }]));
    expectRequestMatchesContract('AtoResponsesController_rollback_v1', bodies[0]);
    await user.click(screen.getByRole('tab', { name: 'Restrictions' }));
    const table = await screen.findByRole('table', { name: 'SMTP restrictions' });
    expect(within(table).getByText('finance@alpha.example.test')).toBeInTheDocument();
  });

  it('read-only roles see no decision controls', async () => {
    mockApi({ AtoResponsesController_list_v1: () => okJson(page([summaryOf(response())])) });
    renderWithProviders(<AtoResponsesPage />, { role: 'compliance_auditor' });
    expect(await screen.findByText('Restrict SMTP sending')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Approve/ })).not.toBeInTheDocument();
  });
});

describe('ATO settings (/ato/settings)', () => {
  it('edits a band and saves the whole draft with expectedRowVersion (contract); axe', async () => {
    const bodies: unknown[] = [];
    mockApi({
      AtoSettingsController_get_v1: () => okJson(settings()),
      AtoSettingsController_update_v1: ({ body }) => {
        bodies.push(body);
        return okJson(settings({ version: 3, rowVersion: 3 }));
      },
    });
    const { user, container } = renderWithProviders(<AtoSettingsPage />, {
      route: '/ato/settings',
    });
    const high = await screen.findByLabelText('High from');
    expect(high).toHaveAttribute('placeholder', '50');
    await expectNoAxeViolations(container);
    await user.type(high, '55');
    await user.click(screen.getByRole('button', { name: 'Save changes' }));
    await waitFor(() => expect(bodies).toHaveLength(1));
    expectRequestMatchesContract('AtoSettingsController_update_v1', bodies[0]);
    expect(bodies[0]).toEqual({
      expectedRowVersion: 2,
      settings: { mode: 'monitor', scoring: { bands: { medium: 30, high: 55 } } },
    });
  });

  it('explains a conflict with a reload, and lists invalid paths', async () => {
    let n = 0;
    mockApi({
      AtoSettingsController_get_v1: () => okJson(settings()),
      AtoSettingsController_update_v1: () => {
        n += 1;
        return n === 1
          ? apiErrorJson(409, 'ato_settings_conflict', 'Conflict', {
              extra: { currentRowVersion: 3 },
            })
          : apiErrorJson(400, 'ato_settings_invalid', 'Invalid', {
              extra: { issues: [{ path: 'scoring.bands', message: 'Bands must be ordered' }] },
            });
      },
    });
    const { user } = renderWithProviders(<AtoSettingsPage />);
    await user.type(await screen.findByLabelText('Critical from'), '40');
    await user.click(screen.getByRole('button', { name: 'Save changes' }));
    expect(await screen.findByText(/changed by someone else/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Reload the current settings' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Save changes' }));
    expect(await screen.findByText('scoring.bands: Bands must be ordered')).toBeInTheDocument();
  });

  it('rules, delivery policy and identity provider tabs; read-only without ato:configure', async () => {
    mockApi({
      AtoSettingsController_get_v1: () => okJson(settings()),
      AtoRulesController_list_v1: () => okJson(RULES),
    });
    const { user } = renderWithProviders(<AtoSettingsPage />, {
      role: 'security_analyst',
      route: '/ato/settings?tab=rules',
    });
    const rules = await screen.findByRole('list', { name: 'Detection rules' });
    expect(within(rules).getAllByText('Impossible travel').length).toBeGreaterThan(0);
    expect(within(rules).getByText('Unavailable')).toBeInTheDocument();
    expect(
      within(rules).getByRole('switch', { name: 'Repeated failed sign-ins enabled' }),
    ).toBeDisabled();
    expect(screen.getByText(/needs the ato:configure permission/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Save changes' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('tab', { name: 'Identity providers' }));
    expect(screen.getAllByText('Not connected')).toHaveLength(2);
    expect(screen.queryByText('Arrives in step 8.5')).toBeNull();
    await user.click(screen.getByRole('tab', { name: 'Delivery policy' }));
    expect(screen.getByText('None')).toBeInTheDocument();
  });

  it('the delivery policy tab links to the builder with the ATO test example', async () => {
    mockApi({
      AtoSettingsController_get_v1: () => okJson(settings({ policy: { atoFieldsInUse: true } })),
    });
    renderWithProviders(<AtoSettingsPage />, { route: '/ato/settings?tab=policy' });
    expect(await screen.findByText('In use')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Create a hold rule' })).toHaveAttribute(
      'href',
      '/policies/new?testPreset=outbound_high_risk_account',
    );
  });

  it('a rule toggle and weight are stored per rule code', async () => {
    const bodies: unknown[] = [];
    mockApi({
      AtoSettingsController_get_v1: () => okJson(settings({ stored: {} })),
      AtoRulesController_list_v1: () => okJson(RULES),
      AtoSettingsController_update_v1: ({ body }) => {
        bodies.push(body);
        return okJson(settings());
      },
    });
    const { user } = renderWithProviders(<AtoSettingsPage />, { route: '/ato/settings?tab=rules' });
    await user.click(
      await screen.findByRole('switch', { name: 'Repeated failed sign-ins enabled' }),
    );
    await user.type(
      screen.getByRole('spinbutton', { name: 'Repeated failed sign-ins weight' }),
      '35',
    );
    await user.click(screen.getByRole('button', { name: 'Save changes' }));
    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0]).toEqual({
      expectedRowVersion: 2,
      settings: { rules: { 'ato.auth.bruteforce': { enabled: false, weight: 35 } } },
    });
  });
});
