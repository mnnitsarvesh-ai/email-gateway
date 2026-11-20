import { screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import {
  apiErrorJson,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  mockApi,
  noContentResponse,
  okJson,
  renderWithProviders,
} from '@/test';
import { AtoAccountPage } from './account-page';
import { ACCOUNT_ID, CONTEXT_ID, RULES, accountDetail, authEvent, page, signal } from './test-data';

function mockAccount(extra: Parameters<typeof mockApi>[0] = {}) {
  mockApi({
    AtoAccountsController_get_v1: ({ params }) =>
      params.accountId === ACCOUNT_ID
        ? okJson(accountDetail())
        : apiErrorJson(404, 'ato_account_not_found', 'Not found'),
    AtoRulesController_list_v1: () => okJson(RULES),
    AtoAccountsController_signals_v1: () => okJson(page([signal()])),
    // Step 8.5: the mailbox changes tab reads the identity providers' mailbox state.
    AtoAccountMailboxController_get_v1: () =>
      okJson({
        accountId: ACCOUNT_ID,
        items: [],
        truncated: false,
        identities: [],
        integrations: [],
        refreshRequestedAt: null,
      }),
    AtoAccountsController_authEvents_v1: () => okJson(page([authEvent()])),
    AtoAccountsController_scoreHistory_v1: () =>
      okJson(
        page([
          {
            id: 'c1b2c3d4e5f6a7b8c9d0',
            computedAt: '2026-11-18T09:00:00.000Z',
            score: 90,
            level: 'critical',
            previousScore: 45,
            previousLevel: 'medium',
            trigger: 'signal',
            explanation: null,
            scorerVersion: 'ato-score/1',
            rulesVersion: 'ato-rules/1',
            settingsVersion: 2,
          },
        ]),
      ),
    AtoAccountsController_activity_v1: () =>
      okJson({
        account: ACCOUNT_ID,
        from: '2026-10-19T09:00:00.000Z',
        to: '2026-11-18T09:00:00.000Z',
        days: [
          {
            day: '2026-11-18T00:00:00.000Z',
            authSuccess: 2,
            authFailure: 0,
            messages: 420,
            recipients: 900,
            externalRecipients: 850,
            internalRecipients: 50,
            attachments: 3,
            findings: 12,
            maxHourMessages: 300,
            topRecipientDomains: [{ domain: 'partner.example', count: 30 }],
            content: {},
          },
        ],
      }),
    ...extra,
  });
}

describe('Account details (/ato/accounts/[accountId])', () => {
  it('overview: explanation with rule titles, controls; axe', async () => {
    mockAccount();
    const { container } = renderWithProviders(<AtoAccountPage accountId={ACCOUNT_ID} />, {
      route: `/ato/accounts/${ACCOUNT_ID}`,
    });
    expect(
      await screen.findByRole('heading', { name: 'finance@alpha.example.test', level: 1 }),
    ).toBeInTheDocument();
    const table = await screen.findByRole('table', { name: 'Top contributions to the score' });
    expect(await within(table).findByText('Phishing sent from the account')).toBeInTheDocument();
    expect(within(table).getByText('+45')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Active incident/ })).toHaveAttribute(
      'href',
      expect.stringContaining('/incidents/'),
    );
    expect(screen.getByRole('button', { name: 'Set override' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Protect account' })).toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('sets an override with a reason (contract body, Idempotency-Key)', async () => {
    const bodies: unknown[] = [];
    const keys: (string | null)[] = [];
    mockAccount({
      AtoAccountsController_setOverride_v1: ({ body, request }) => {
        bodies.push(body);
        keys.push(request.headers.get('idempotency-key'));
        return okJson(accountDetail());
      },
    });
    const { user } = renderWithProviders(<AtoAccountPage accountId={ACCOUNT_ID} />);
    await user.click(await screen.findByRole('button', { name: 'Set override' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('combobox', { name: 'Verdict' }));
    await user.click(await screen.findByRole('option', { name: 'Compromised' }));
    await user.click(within(dialog).getByRole('button', { name: 'Set override' }));
    expect(await within(dialog).findByText(/at least 10 characters/)).toBeInTheDocument();
    await user.type(within(dialog).getByLabelText(/Reason/), 'User confirmed the phishing run');
    await user.click(within(dialog).getByRole('button', { name: 'Set override' }));
    await waitFor(() => expect(bodies).toHaveLength(1));
    expectRequestMatchesContract('AtoAccountsController_setOverride_v1', bodies[0]);
    expect(bodies[0]).toEqual({
      verdict: 'compromised',
      reason: 'User confirmed the phishing run',
      expiresInHours: 72,
    });
    expect(keys[0]).toBeTruthy();
  });

  it('protects the account with the row version; a conflict is explained', async () => {
    const bodies: unknown[] = [];
    mockAccount({
      AtoAccountsController_update_v1: ({ body }) => {
        bodies.push(body);
        return apiErrorJson(409, 'ato_account_conflict', 'Changed');
      },
    });
    const { user } = renderWithProviders(<AtoAccountPage accountId={ACCOUNT_ID} />);
    await user.click(await screen.findByRole('button', { name: 'Protect account' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.type(within(dialog).getByLabelText(/Reason/), 'Executive mailbox');
    await user.click(within(dialog).getByRole('button', { name: 'Protect' }));
    await waitFor(() => expect(bodies).toHaveLength(1));
    expectRequestMatchesContract('AtoAccountsController_update_v1', bodies[0]);
    expect(bodies[0]).toEqual({
      protected: true,
      reason: 'Executive mailbox',
      expectedRowVersion: 3,
    });
    expect(await within(dialog).findByText(/Someone else changed it/)).toBeInTheDocument();
  });

  it('tabs: sign-ins, devices and IPs, outbound, mailbox, signals, history', async () => {
    mockAccount();
    const { user, container } = renderWithProviders(<AtoAccountPage accountId={ACCOUNT_ID} />, {
      route: `/ato/accounts/${ACCOUNT_ID}`,
    });
    await user.click(await screen.findByRole('tab', { name: 'Sign-ins' }));
    const signIns = await screen.findByRole('table', { name: 'Sign-ins of the account' });
    expect(within(signIns).getByText('203.0.113.77')).toBeInTheDocument();
    expect(within(signIns).getByText('Unavailable (no GeoIP database)')).toBeInTheDocument();
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('tab', { name: 'Devices and IPs' }));
    expect(await screen.findByText('198.51.100.0/24')).toBeInTheDocument();
    await user.click(screen.getByRole('tab', { name: 'Outbound activity' }));
    expect(await screen.findByRole('link', { name: 'Open in the email explorer' })).toHaveAttribute(
      'href',
      '/messages?sender=finance%40alpha.example.test&direction=outbound&range=30d',
    );
    expect(screen.getByRole('list', { name: 'Top recipient domains' })).toHaveTextContent(
      'partner.example',
    );
    await user.click(screen.getByRole('tab', { name: 'Mailbox changes' }));
    // Step 8.5: the mailbox state of the identity providers replaced the unavailable state.
    expect(await screen.findByText('No mailbox items reported')).toBeInTheDocument();
    await user.click(screen.getByRole('tab', { name: 'Detection reasons' }));
    expect(
      await screen.findByRole('table', { name: 'Risk signals of the account' }),
    ).toHaveTextContent('Phishing sent from the account');
    await user.click(screen.getByRole('tab', { name: 'Score history' }));
    expect(await screen.findByRole('table', { name: 'Score changes' })).toHaveTextContent('Signal');
  });

  it('trusted contexts: add (contract) and remove (DELETE)', async () => {
    const added: unknown[] = [];
    let removed = '';
    mockAccount({
      AtoAccountsController_addTrustedContext_v1: ({ body }) => {
        added.push(body);
        return okJson(accountDetail().trustedContexts[0], 201);
      },
      AtoAccountsController_removeTrustedContext_v1: ({ params }) => {
        removed = params.contextId ?? '';
        return noContentResponse();
      },
    });
    const { user } = renderWithProviders(<AtoAccountPage accountId={ACCOUNT_ID} />, {
      route: `/ato/accounts/${ACCOUNT_ID}?tab=trusted`,
    });
    await user.click(await screen.findByRole('button', { name: 'Add trusted context' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.type(within(dialog).getByLabelText('Value'), '192.0.2.0/24');
    await user.type(within(dialog).getByLabelText(/Reason/), 'Branch office');
    await user.click(within(dialog).getByRole('button', { name: 'Add' }));
    await waitFor(() => expect(added).toHaveLength(1));
    expectRequestMatchesContract('AtoAccountsController_addTrustedContext_v1', added[0]);
    expect(added[0]).toEqual({
      kind: 'ip_cidr',
      value: '192.0.2.0/24',
      reason: 'Branch office',
      expiresInDays: 90,
    });
    await user.click(
      screen.getByRole('button', { name: 'Remove trusted context 198.51.100.0/24' }),
    );
    const confirm = await screen.findByRole('alertdialog');
    await user.click(within(confirm).getByRole('button', { name: 'Remove' }));
    await waitFor(() => expect(removed).toBe(CONTEXT_ID));
  });

  it('a foreign or unknown account looks missing; read-only roles see no controls', async () => {
    mockAccount();
    renderWithProviders(<AtoAccountPage accountId="01933c3a-1b2c-7d4e-8f00-0000000affff" />);
    expect(await screen.findByText(/Page not found/i)).toBeInTheDocument();
  });

  it('a compliance auditor (ato:read only) sees no override, protection or trusted-context controls', async () => {
    mockAccount();
    const { user } = renderWithProviders(<AtoAccountPage accountId={ACCOUNT_ID} />, {
      role: 'compliance_auditor',
    });
    expect(await screen.findByRole('heading', { name: 'Risk' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Set override' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Protect account' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('tab', { name: 'Trusted contexts' }));
    expect(screen.queryByRole('button', { name: 'Add trusted context' })).not.toBeInTheDocument();
  });
});
