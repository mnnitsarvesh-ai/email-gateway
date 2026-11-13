import { screen, waitFor } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  TEST_ORIGIN,
  apiErrorJson,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  makeMe,
  mockApi,
  noContentResponse,
  okJson,
  renderWithProviders,
  server,
} from '@/test';
import {
  AcceptInvitationForm,
  acceptInvitationBody,
  acceptInvitationSchema,
} from './accept-invitation-form';
import {
  ForgotPasswordForm,
  forgotPasswordBody,
  forgotPasswordSchema,
} from './forgot-password-form';
import { SESSION_QUERY_KEY } from '@/lib/auth/me';
import { LoginForm, loginBody, loginSchema } from './login-form';
import { MfaEnrollment, groupSecret } from './mfa-enrollment';
import { MfaForm } from './mfa-form';
import { ResetPasswordForm } from './reset-password-form';
import { safeNextPath } from './safe-next';
import { readAndClearHashToken } from './use-hash-token';
import { VerifyEmail } from './verify-email';

function onLogin(handler: (body: unknown) => Response) {
  let seen: unknown = null;
  server.use(
    http.post(`${TEST_ORIGIN}/bff/session/login`, async ({ request }) => {
      seen = await request.json();
      return handler(seen);
    }),
  );
  return () => seen;
}

afterEach(() => {
  window.history.replaceState(null, '', '/');
});

describe('safe next paths', () => {
  it.each([
    ['/dashboard', '/dashboard'],
    ['/users?status=active', '/users?status=active'],
    ['//evil.example', '/'],
    ['/\\evil.example', '/'],
    ['https://evil.example/x', '/'],
    ['javascript:alert(1)', '/'],
    ['/login?next=/x', '/'],
    ['/auth/reset-password', '/'],
    [null, '/'],
  ])('%s → %s', (input, expected) => {
    expect(safeNextPath(input)).toBe(expected);
  });
});

describe('/login', () => {
  it('signs in and continues to the validated next path', async () => {
    const seen = onLogin(() =>
      HttpResponse.json({ status: 'authenticated', mfaEnrollmentRequired: false }),
    );
    const { container, user, router } = renderWithProviders(<LoginForm />, {
      role: null,
      session: null,
      route: '/login?next=%2Fdomains',
    });
    await expectNoAxeViolations(container);
    await user.type(screen.getByLabelText('Email address'), 'admin@example.com');
    await user.type(screen.getByLabelText('Password'), 'correct horse');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));
    await waitFor(() => expect(router.replace).toHaveBeenCalledWith('/domains'));
    expect(seen()).toEqual({ email: 'admin@example.com', password: 'correct horse' });
    expectRequestMatchesContract('AuthController_login_v1', seen());
  });

  it('goes to the MFA step or the enrollment page', async () => {
    onLogin(() => HttpResponse.json({ status: 'mfa_required' }));
    const { user, router } = renderWithProviders(<LoginForm />, {
      role: null,
      session: null,
      route: '/login?next=%2Fusers',
    });
    await user.type(screen.getByLabelText('Email address'), 'a@example.com');
    await user.type(screen.getByLabelText('Password'), 'pw');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));
    await waitFor(() => expect(router.push).toHaveBeenCalledWith('/login/mfa?next=%2Fusers'));
  });

  it('sends enrollment-required users to /mfa/enroll', async () => {
    onLogin(() => HttpResponse.json({ status: 'authenticated', mfaEnrollmentRequired: true }));
    const { user, router } = renderWithProviders(<LoginForm />, {
      role: null,
      session: null,
      route: '/login',
    });
    await user.type(screen.getByLabelText('Email address'), 'a@example.com');
    await user.type(screen.getByLabelText('Password'), 'pw');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));
    await waitFor(() => expect(router.replace).toHaveBeenCalledWith('/mfa/enroll?next=%2F'));
  });

  it('shows a generic message for 401 and clears the password', async () => {
    onLogin(() => apiErrorJson(401, 'unauthorized', 'Invalid credentials'));
    const { user } = renderWithProviders(<LoginForm />, {
      role: null,
      session: null,
      route: '/login',
    });
    await user.type(screen.getByLabelText('Email address'), 'a@example.com');
    await user.type(screen.getByLabelText('Password'), 'wrong');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'The email address or password is incorrect.',
    );
    expect(screen.getByLabelText('Password')).toHaveValue('');
  });

  it('counts down Retry-After on 429 and disables the button', async () => {
    onLogin(() =>
      apiErrorJson(429, 'rate_limited', 'Too many requests', { headers: { 'retry-after': '30' } }),
    );
    const { user } = renderWithProviders(<LoginForm />, {
      role: null,
      session: null,
      route: '/login',
    });
    await user.type(screen.getByLabelText('Email address'), 'a@example.com');
    await user.type(screen.getByLabelText('Password'), 'pw');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(await screen.findByText(/Try again in 30 seconds/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Try again in \d+ s/ })).toBeDisabled();
  });

  it('validates input on the client and explains why the user was sent here', async () => {
    const { user } = renderWithProviders(<LoginForm />, {
      role: null,
      session: null,
      route: '/login?reason=expired',
    });
    expect(screen.getByRole('status')).toHaveTextContent('Your session ended');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(await screen.findByText('Enter your email address')).toBeInTheDocument();
  });

  it('builds contract-conformant bodies (organization optional)', () => {
    expectRequestMatchesContract(
      'AuthController_login_v1',
      loginBody(
        loginSchema.parse({ email: 'a@example.com', password: 'x', organization: 'alpha' }),
      ),
    );
    expectRequestMatchesContract(
      'AuthController_login_v1',
      loginBody(loginSchema.parse({ email: 'a@example.com', password: 'x', organization: '' })),
    );
  });
});

describe('/login/mfa', () => {
  it('verifies a TOTP code, or a recovery code', async () => {
    const bodies: unknown[] = [];
    server.use(
      http.post(`${TEST_ORIGIN}/bff/session/mfa`, async ({ request }) => {
        bodies.push(await request.json());
        return HttpResponse.json({ status: 'authenticated', mfaEnrollmentRequired: false });
      }),
    );
    const { container, user, router } = renderWithProviders(<MfaForm />, {
      role: null,
      session: null,
      route: '/login/mfa?next=%2Fquarantine',
    });
    await expectNoAxeViolations(container);
    await user.type(screen.getByLabelText('Authentication code'), '123456');
    await user.click(screen.getByRole('button', { name: 'Verify' }));
    await waitFor(() => expect(router.replace).toHaveBeenCalledWith('/quarantine'));
    await user.click(screen.getByRole('button', { name: 'Use a recovery code instead' }));
    await user.type(screen.getByLabelText('Recovery code'), 'abcde-fghij');
    await user.click(screen.getByRole('button', { name: 'Use recovery code' }));
    await waitFor(() =>
      expect(bodies).toEqual([{ code: '123456' }, { recoveryCode: 'abcde-fghij' }]),
    );
  });

  it('sends the user back to sign-in when the challenge expired', async () => {
    server.use(
      http.post(`${TEST_ORIGIN}/bff/session/mfa`, () =>
        apiErrorJson(401, 'mfa_challenge_expired', 'expired'),
      ),
    );
    const { user } = renderWithProviders(<MfaForm />, {
      role: null,
      session: null,
      route: '/login/mfa',
    });
    await user.type(screen.getByLabelText('Authentication code'), '123456');
    await user.click(screen.getByRole('button', { name: 'Verify' }));
    expect(await screen.findByRole('link', { name: 'Back to sign in' })).toHaveAttribute(
      'href',
      '/login?next=%2F',
    );
  });
});

describe('/forgot-password', () => {
  it('always shows the same confirmation', async () => {
    let body: unknown = null;
    mockApi({
      AuthController_forgotPassword_v1: ({ body: b }) => (
        (body = b),
        new HttpResponse(null, { status: 202 })
      ),
    });
    const { container, user } = renderWithProviders(<ForgotPasswordForm />, {
      role: null,
      session: null,
    });
    await expectNoAxeViolations(container);
    await user.type(screen.getByLabelText('Email address'), 'someone@example.com');
    await user.click(screen.getByRole('button', { name: 'Send reset link' }));
    expect(
      await screen.findByText(/If an account with a verified email address matches/),
    ).toBeInTheDocument();
    expect(body).toEqual({ email: 'someone@example.com' });
    expectRequestMatchesContract(
      'AuthController_forgotPassword_v1',
      forgotPasswordBody(
        forgotPasswordSchema.parse({ email: 'a@example.com', organization: 'alpha' }),
      ),
    );
  });

  it('shows the same confirmation on a server error (no account enumeration)', async () => {
    mockApi({ AuthController_forgotPassword_v1: () => apiErrorJson(500, 'internal_error') });
    const { user } = renderWithProviders(<ForgotPasswordForm />, { role: null, session: null });
    await user.type(screen.getByLabelText('Email address'), 'someone@example.com');
    await user.click(screen.getByRole('button', { name: 'Send reset link' }));
    expect(
      await screen.findByText(/If an account with a verified email address matches/),
    ).toBeInTheDocument();
  });
});

describe('emailed-link pages (#token=…)', () => {
  it('reads the token from the hash and clears it immediately', () => {
    window.history.replaceState(null, '', '/auth/reset-password?x=1#token=egt_abc');
    expect(readAndClearHashToken()).toBe('egt_abc');
    expect(window.location.hash).toBe('');
    expect(window.location.pathname + window.location.search).toBe('/auth/reset-password?x=1');
  });

  it('/auth/reset-password sets a new password with the token', async () => {
    window.history.replaceState(null, '', '/auth/reset-password#token=egt_reset_token');
    let body: unknown = null;
    mockApi({
      AuthController_resetPassword_v1: ({ body: b }) => ((body = b), noContentResponse()),
    });
    const { container, user } = renderWithProviders(<ResetPasswordForm />, {
      role: null,
      session: null,
    });
    expect(await screen.findByLabelText('New password')).toBeInTheDocument();
    expect(window.location.hash).toBe('');
    await expectNoAxeViolations(container);
    await user.type(screen.getByLabelText('New password'), 'short');
    await user.type(screen.getByLabelText('Repeat the new password'), 'short');
    await user.click(screen.getByRole('button', { name: 'Set new password' }));
    expect(await screen.findByText('Use at least 12 characters')).toBeInTheDocument();
    await user.clear(screen.getByLabelText('New password'));
    await user.clear(screen.getByLabelText('Repeat the new password'));
    await user.type(screen.getByLabelText('New password'), 'a long new passphrase');
    await user.type(screen.getByLabelText('Repeat the new password'), 'a long new passphrase');
    await user.click(screen.getByRole('button', { name: 'Set new password' }));
    expect(await screen.findByText(/Your password was changed/)).toBeInTheDocument();
    expect(body).toEqual({ token: 'egt_reset_token', newPassword: 'a long new passphrase' });
    expectRequestMatchesContract('AuthController_resetPassword_v1', body);
  });

  it('/auth/reset-password explains an invalid or missing link', async () => {
    renderWithProviders(<ResetPasswordForm />, { role: null, session: null });
    expect(
      await screen.findByText(/invalid, was already used, or has expired/),
    ).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Request a new link' })).toHaveAttribute(
      'href',
      '/forgot-password',
    );
  });

  it('/auth/accept-invitation inspects, then accepts with password and name', async () => {
    window.history.replaceState(null, '', '/auth/accept-invitation#token=egt_invite');
    const bodies: unknown[] = [];
    mockApi({
      AuthController_inspectInvitation_v1: ({ body }) => (
        bodies.push(body),
        okJson({
          email: 'new@example.com',
          organizationName: 'Alpha (example)',
          expiresAt: '2026-11-20T00:00:00.000Z',
        })
      ),
      AuthController_acceptInvitation_v1: ({ body }) => (bodies.push(body), noContentResponse()),
    });
    const { container, user } = renderWithProviders(<AcceptInvitationForm />, {
      role: null,
      session: null,
    });
    expect(await screen.findByText('Alpha (example)')).toBeInTheDocument();
    await expectNoAxeViolations(container);
    await user.type(screen.getByLabelText('Your name'), 'New User');
    await user.type(screen.getByLabelText('Password'), 'a long new passphrase');
    await user.type(screen.getByLabelText('Repeat the password'), 'a long new passphrase');
    await user.click(screen.getByRole('button', { name: 'Accept invitation' }));
    expect(await screen.findByText(/Your account is ready/)).toBeInTheDocument();
    expect(bodies).toEqual([
      { token: 'egt_invite' },
      { token: 'egt_invite', password: 'a long new passphrase', displayName: 'New User' },
    ]);
    expectRequestMatchesContract(
      'AuthController_acceptInvitation_v1',
      acceptInvitationBody(
        'egt_x',
        acceptInvitationSchema.parse({
          displayName: 'N',
          password: 'a long new passphrase',
          confirmPassword: 'a long new passphrase',
        }),
      ),
    );
  });

  it('/auth/verify-email verifies once', async () => {
    window.history.replaceState(null, '', '/auth/verify-email#token=egt_verify');
    const handler = vi.fn(() => noContentResponse());
    mockApi({ AuthController_verifyEmail_v1: handler });
    const { container } = renderWithProviders(<VerifyEmail />, { role: null, session: null });
    expect(await screen.findByText('Your email address is verified.')).toBeInTheDocument();
    expect(handler).toHaveBeenCalledTimes(1);
    await expectNoAxeViolations(container);
  });

  it('/auth/verify-email shows the invalid-link state on 400', async () => {
    window.history.replaceState(null, '', '/auth/verify-email#token=egt_bad');
    mockApi({
      AuthController_verifyEmail_v1: () =>
        apiErrorJson(400, 'validation_failed', 'Invalid or expired token'),
    });
    renderWithProviders(<VerifyEmail />, { role: null, session: null });
    expect(
      await screen.findByText(/invalid, was already used, or has expired/),
    ).toBeInTheDocument();
  });
});

describe('MFA enrollment', () => {
  it('shows the key and QR, enables with a code, shows recovery codes once, then refreshes with force', async () => {
    const refreshBodies: unknown[] = [];
    server.use(
      http.post(`${TEST_ORIGIN}/bff/session/refresh`, async ({ request }) => {
        refreshBodies.push(await request.json());
        return HttpResponse.json({ authenticated: true });
      }),
      http.get(`${TEST_ORIGIN}/bff/session`, () => HttpResponse.json({ authenticated: true })),
    );
    mockApi({
      MfaController_setup_v1: () =>
        okJson({
          secret: 'JBSWY3DPEHPK3PXP',
          otpauthUri: 'otpauth://totp/Test:a@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Test',
        }),
      MfaController_enable_v1: ({ body }) =>
        (body as { code: string }).code === '123456'
          ? okJson({ recoveryCodes: Array.from({ length: 10 }, (_, i) => `code${i}-abcde`) })
          : apiErrorJson(403, 'forbidden', 'Invalid code'),
      AuthController_me_v1: () => okJson(makeMe() as never),
    });
    const onComplete = vi.fn();
    const { container, user } = renderWithProviders(
      <MfaEnrollment account="a@example.com" onComplete={onComplete} />,
    );
    expect(await screen.findByText(groupSecret('JBSWY3DPEHPK3PXP'))).toBeInTheDocument();
    expect(
      screen.getByRole('img', { name: 'QR code with your authenticator key' }),
    ).toBeInTheDocument();
    await expectNoAxeViolations(container);
    await user.type(screen.getByLabelText('Authentication code'), '000000');
    await user.click(screen.getByRole('button', { name: 'Enable MFA' }));
    expect(await screen.findByText(/The code is not valid/)).toBeInTheDocument();
    await user.clear(screen.getByLabelText('Authentication code'));
    await user.type(screen.getByLabelText('Authentication code'), '123456');
    await user.click(screen.getByRole('button', { name: 'Enable MFA' }));
    expect(await screen.findByRole('list', { name: 'Recovery codes' })).toHaveTextContent(
      'code0-abcde',
    );
    expect(screen.getByRole('button', { name: 'Download as text' })).toBeInTheDocument();
    const cont = screen.getByRole('button', { name: 'Continue' });
    expect(cont).toBeDisabled();
    await user.click(screen.getByLabelText('I have stored my recovery codes in a safe place.'));
    await user.click(cont);
    await waitFor(() => expect(onComplete).toHaveBeenCalled());
    expect(refreshBodies).toEqual([{ force: true }]);
    expect(groupSecret('ABCDEFGH12')).toBe('ABCD EFGH 12');
  });

  it('writes the refreshed session into the cache before leaving (no bounce back to /mfa/enroll)', async () => {
    const refreshed = {
      authenticated: true,
      accessExpiresAt: '2026-11-13T12:01:00.000Z',
      refreshExpiresAt: '2026-11-20T12:00:00.000Z',
      mfaEnrollmentRequired: false,
      override: null,
      devFixtures: false,
    };
    server.use(http.post(`${TEST_ORIGIN}/bff/session/refresh`, () => HttpResponse.json(refreshed)));
    mockApi({
      MfaController_setup_v1: () =>
        okJson({
          secret: 'JBSWY3DPEHPK3PXP',
          otpauthUri: 'otpauth://totp/Test:a@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Test',
        }),
      MfaController_enable_v1: () =>
        okJson({ recoveryCodes: Array.from({ length: 10 }, (_, i) => `code${i}-abcde`) }),
      AuthController_me_v1: () => okJson(makeMe() as never),
    });
    let seenAtComplete: unknown;
    const { queryClient, user } = renderWithProviders(
      <MfaEnrollment
        account="a@example.com"
        onComplete={() => {
          seenAtComplete = queryClient.getQueryData(SESSION_QUERY_KEY);
        }}
      />,
      { session: { ...refreshed, mfaEnrollmentRequired: true } },
    );
    await screen.findByText(groupSecret('JBSWY3DPEHPK3PXP'));
    await user.type(screen.getByLabelText('Authentication code'), '123456');
    await user.click(screen.getByRole('button', { name: 'Enable MFA' }));
    await screen.findByRole('list', { name: 'Recovery codes' });
    await user.click(screen.getByLabelText('I have stored my recovery codes in a safe place.'));
    await user.click(screen.getByRole('button', { name: 'Continue' }));
    await waitFor(() => expect(seenAtComplete).toEqual(refreshed));
  });

  it('"already enabled" (409 on setup) also refreshes the session before continuing', async () => {
    const refreshBodies: unknown[] = [];
    server.use(
      http.post(`${TEST_ORIGIN}/bff/session/refresh`, async ({ request }) => {
        refreshBodies.push(await request.json());
        return HttpResponse.json({ authenticated: true, mfaEnrollmentRequired: false });
      }),
    );
    mockApi({
      MfaController_setup_v1: () => apiErrorJson(409, 'mfa_already_enabled', 'MFA is enabled'),
      AuthController_me_v1: () => okJson(makeMe() as never),
    });
    const onComplete = vi.fn();
    const { user } = renderWithProviders(
      <MfaEnrollment account="a@example.com" onComplete={onComplete} />,
    );
    await screen.findByText('Multi-factor authentication is already enabled for your account.');
    await user.click(screen.getByRole('button', { name: 'Continue' }));
    await waitFor(() => expect(onComplete).toHaveBeenCalled());
    expect(refreshBodies).toEqual([{ force: true }]);
  });
});
