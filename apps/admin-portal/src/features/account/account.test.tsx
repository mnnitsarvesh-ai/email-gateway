import { screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import {
  apiErrorJson,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  makeMe,
  mockApi,
  noContentResponse,
  okJson,
  renderWithProviders,
} from '@/test';
import {
  ChangePasswordForm,
  MfaPanel,
  SessionsPanel,
  changePasswordBody,
  changePasswordSchema,
} from '.';
import { disableMfaSchema, regenerateSchema } from './mfa-panel';

describe('ChangePasswordForm', () => {
  it('submits a contract-conformant body and resets on success', async () => {
    let body: unknown = null;
    mockApi({
      AuthController_changePassword_v1: ({ body: b }) => ((body = b), noContentResponse()),
    });
    const { container, user } = renderWithProviders(<ChangePasswordForm />);
    await expectNoAxeViolations(container);
    await user.type(screen.getByLabelText('Current password'), 'old password value');
    await user.type(screen.getByLabelText('New password'), 'a brand new passphrase');
    await user.type(screen.getByLabelText('Repeat the new password'), 'a brand new passphrase');
    await user.click(screen.getByRole('button', { name: 'Change password' }));
    await waitFor(() =>
      expect(body).toEqual({
        currentPassword: 'old password value',
        newPassword: 'a brand new passphrase',
      }),
    );
    expectRequestMatchesContract('AuthController_changePassword_v1', body);
    await waitFor(() => expect(screen.getByLabelText('Current password')).toHaveValue(''));
  });

  it('explains a wrong current password (403) and api validation messages', async () => {
    mockApi({
      AuthController_changePassword_v1: () => apiErrorJson(403, 'forbidden', 'Forbidden'),
    });
    const { user } = renderWithProviders(<ChangePasswordForm />);
    await user.type(screen.getByLabelText('Current password'), 'old password value');
    await user.type(screen.getByLabelText('New password'), 'a brand new passphrase');
    await user.type(screen.getByLabelText('Repeat the new password'), 'a brand new passphrase');
    await user.click(screen.getByRole('button', { name: 'Change password' }));
    expect(await screen.findByText('The current password is not correct.')).toBeInTheDocument();
  });

  it('schemas match the request contracts', () => {
    expectRequestMatchesContract(
      'AuthController_changePassword_v1',
      changePasswordBody(
        changePasswordSchema.parse({
          currentPassword: 'x',
          newPassword: 'a long new passphrase',
          confirmPassword: 'a long new passphrase',
        }),
      ),
    );
    expectRequestMatchesContract(
      'MfaController_disable_v1',
      disableMfaSchema.parse({ password: 'x', code: '123456' }),
    );
    expectRequestMatchesContract(
      'MfaController_regenerate_v1',
      regenerateSchema.parse({ code: '123456' }),
    );
  });
});

describe('MfaPanel', () => {
  it('regenerates recovery codes and shows them once', async () => {
    mockApi({
      MfaController_regenerate_v1: () =>
        okJson({ recoveryCodes: Array.from({ length: 10 }, (_, i) => `rc${i}-xxxxx`) }),
    });
    const me = makeMe({ overrides: { mfaEnabled: true } });
    const { user } = renderWithProviders(<MfaPanel />, { me });
    expect(screen.getByText('Enabled')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Regenerate recovery codes' }));
    const dialog = await screen.findByRole('dialog', { name: 'Regenerate recovery codes' });
    await user.type(within(dialog).getByLabelText('Authentication code'), '123456');
    await user.click(within(dialog).getByRole('button', { name: 'Regenerate' }));
    const reveal = await screen.findByRole('dialog', { name: 'New recovery codes' });
    expect(reveal).toHaveTextContent('rc0-xxxxx');
    await user.click(within(reveal).getByRole('checkbox'));
    await user.click(within(reveal).getByRole('button', { name: 'Done' }));
    await waitFor(() => expect(screen.queryByText('rc0-xxxxx')).not.toBeInTheDocument());
  });

  it('offers setup when MFA is off', () => {
    renderWithProviders(<MfaPanel />, { me: makeMe({ overrides: { mfaEnabled: false } }) });
    expect(screen.getByRole('button', { name: 'Set up MFA' })).toBeInTheDocument();
  });
});

describe('SessionsPanel', () => {
  it('lists sessions and signs one out', async () => {
    let revoked = '';
    const sessions = [
      {
        id: 's1',
        current: true,
        authenticatedAt: '2026-11-13T08:00:00.000Z',
        lastUsedAt: '2026-11-13T09:00:00.000Z',
        expiresAt: '2026-11-20T08:00:00.000Z',
        ipAddress: '192.0.2.1',
        userAgent: 'Firefox',
        mfaAuthenticated: true,
      },
      {
        id: 's2',
        current: false,
        authenticatedAt: '2026-11-12T08:00:00.000Z',
        lastUsedAt: null,
        expiresAt: '2026-11-19T08:00:00.000Z',
        ipAddress: null,
        userAgent: null,
        mfaAuthenticated: false,
      },
    ];
    mockApi({
      SessionsController_list_v1: () => okJson({ data: sessions }),
      SessionsController_revoke_v1: ({ params }) => (
        (revoked = params.sessionId ?? ''),
        noContentResponse()
      ),
    });
    const { container, user } = renderWithProviders(<SessionsPanel />);
    expect(await screen.findByText('This session')).toBeInTheDocument();
    expect(screen.getByText('Unknown device')).toBeInTheDocument();
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('button', { name: 'Sign out' }));
    await user.click(await screen.findByRole('button', { name: 'Sign out session' }));
    await waitFor(() => expect(revoked).toBe('s2'));
  });
});
