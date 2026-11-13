import { screen, waitFor, within } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { describe, expect, it, vi } from 'vitest';
import {
  TEST_ORIGIN,
  apiErrorJson,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  makeMe,
  makeSession,
  mockApi,
  okJson,
  renderWithProviders,
  server,
} from '@/test';
import { AppShell } from './app-shell';
import { PlatformHealthCard } from './platform-health-card';
import { overrideFormSchema } from './tenant-switcher';

const page = <p>page content</p>;

describe('AppShell (design P11)', () => {
  it('shows the navigation the role permits, the tenant and the page', async () => {
    const { container } = renderWithProviders(<AppShell>{page}</AppShell>, {
      role: 'read_only_user',
      route: '/dashboard',
    });
    const nav = screen.getByRole('navigation', { name: 'Main' });
    expect(within(nav).getByRole('link', { name: 'Dashboard' })).toHaveAttribute(
      'aria-current',
      'page',
    );
    expect(within(nav).queryByRole('link', { name: 'Audit logs' })).not.toBeInTheDocument();
    expect(within(nav).getByRole('link', { name: 'Settings' })).toBeInTheDocument();
    expect(screen.getByText('Alpha Industries (example)')).toBeInTheDocument();
    expect(screen.getByText('page content')).toBeInTheDocument();
    expect(screen.getByRole('main')).toHaveAttribute('id', 'main');
    expect(screen.queryByText('DEV FIXTURES')).not.toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('guards a route the role may not open with the 403 view', () => {
    renderWithProviders(<AppShell>{page}</AppShell>, {
      role: 'mailbox_user',
      route: '/audit-logs',
    });
    expect(
      screen.getByRole('heading', { name: 'You do not have access to this page' }),
    ).toBeInTheDocument();
    expect(screen.queryByText('page content')).not.toBeInTheDocument();
  });

  it('shows the DEV FIXTURES badge when the BFF runs fixtures', () => {
    renderWithProviders(<AppShell>{page}</AppShell>, {
      session: makeSession({ devFixtures: true }),
      route: '/settings',
    });
    expect(screen.getByText('DEV FIXTURES')).toBeInTheDocument();
  });

  it('sends users who must enroll in MFA to /mfa/enroll and logged-out users to /login', async () => {
    const first = renderWithProviders(<AppShell>{page}</AppShell>, {
      session: makeSession({ mfaEnrollmentRequired: true }),
      route: '/dashboard',
    });
    await waitFor(() => expect(first.router.replace).toHaveBeenCalledWith('/mfa/enroll'));
    expect(screen.queryByText('page content')).not.toBeInTheDocument();
    first.unmount();
    const second = renderWithProviders(<AppShell>{page}</AppShell>, {
      session: makeSession({ authenticated: false }),
      route: '/users',
    });
    await waitFor(() => expect(second.router.replace).toHaveBeenCalledWith('/login?next=%2Fusers'));
  });

  it('opens a focus-trapped drawer on mobile that closes on navigation', async () => {
    vi.spyOn(window, 'matchMedia').mockImplementation(
      (query: string) =>
        ({
          matches: query.includes('max-width: 767px'),
          media: query,
          addEventListener: () => undefined,
          removeEventListener: () => undefined,
          addListener: () => undefined,
          removeListener: () => undefined,
        }) as unknown as MediaQueryList,
    );
    const { user } = renderWithProviders(<AppShell>{page}</AppShell>, { route: '/dashboard' });
    expect(screen.queryByRole('navigation', { name: 'Main' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Open navigation' }));
    const dialog = await screen.findByRole('dialog');
    await user.click(within(dialog).getByRole('link', { name: 'Users' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  it('returns focus to the menu button when the drawer closes with Escape', async () => {
    vi.spyOn(window, 'matchMedia').mockImplementation(
      (query: string) =>
        ({
          matches: query.includes('max-width: 767px'),
          media: query,
          addEventListener: () => undefined,
          removeEventListener: () => undefined,
          addListener: () => undefined,
          removeListener: () => undefined,
        }) as unknown as MediaQueryList,
    );
    const { user } = renderWithProviders(<AppShell>{page}</AppShell>, { route: '/dashboard' });
    const menu = screen.getByRole('button', { name: 'Open navigation' });
    await user.click(menu);
    await screen.findByRole('dialog');
    await user.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(menu).toHaveFocus();
  });

  it('collapses the desktop sidebar and remembers it', async () => {
    vi.spyOn(window, 'matchMedia').mockImplementation(
      (query: string) =>
        ({
          matches: query.includes('min-width: 1280px') && !query.includes('max-width'),
          media: query,
          addEventListener: () => undefined,
          removeEventListener: () => undefined,
          addListener: () => undefined,
          removeListener: () => undefined,
        }) as unknown as MediaQueryList,
    );
    const { user } = renderWithProviders(<AppShell>{page}</AppShell>, { route: '/dashboard' });
    // Full width on load without a width animation (the breakpoint resolves after the first
    // effect; animating that change made the sidebar slide open on every desktop page load).
    const sidebar = screen.getByRole('complementary', { name: 'Sidebar' });
    expect(sidebar).toHaveClass('w-64');
    expect(sidebar.className).not.toContain('transition-[width]');
    await user.click(screen.getByRole('button', { name: 'Collapse sidebar' }));
    expect(sidebar).toHaveClass('w-16');
    expect(sidebar.className).toContain('transition-[width]');
    expect(localStorage.getItem('eg:sidebar:collapsed')).toBe('true');
    expect(screen.getByRole('button', { name: 'Expand sidebar' })).toHaveAttribute(
      'aria-expanded',
      'false',
    );
  });

  it('offers the tenant switcher to platform operators and starts an override', async () => {
    const orgId = '01930000-0000-7000-8000-0000000000e1';
    mockApi({
      OrganizationsController_list_v1: () =>
        okJson({
          data: [{ id: orgId, name: 'Beta Logistics (example)', slug: 'beta' }],
          nextCursor: null,
        } as never),
    });
    let body: unknown = null;
    server.use(
      http.post(`${TEST_ORIGIN}/bff/session/override`, async ({ request }) => {
        body = await request.json();
        return HttpResponse.json(
          {
            id: 'ovr-1',
            organizationId: orgId,
            organizationName: 'Beta Logistics (example)',
            expiresAt: new Date(Date.now() + 1_800_000).toISOString(),
          },
          { status: 201 },
        );
      }),
    );
    mockApi({ AuthController_me_v1: () => okJson(makeMe({ role: 'platform_admin' }) as never) });
    server.use(http.get(`${TEST_ORIGIN}/bff/session`, () => HttpResponse.json(makeSession())));
    const { user } = renderWithProviders(<AppShell>{page}</AppShell>, {
      role: 'platform_admin',
      route: '/organizations',
    });
    await user.click(screen.getByRole('button', { name: 'Switch tenant' }));
    const dialog = await screen.findByRole('dialog', { name: 'Act in a customer organization' });
    await user.click(await within(dialog).findByText('Beta Logistics (example)'));
    await user.type(within(dialog).getByLabelText(/Reason/), 'Ticket OPS-1234 mail flow check');
    await user.click(within(dialog).getByRole('button', { name: 'Start override' }));
    await waitFor(() =>
      expect(body).toEqual({
        organizationId: orgId,
        reason: 'Ticket OPS-1234 mail flow check',
        durationMinutes: 30,
      }),
    );
    expectRequestMatchesContract('PlatformOverrideController_start_v1', body);
  });

  it('explains 403 mfa_required in the tenant switcher', async () => {
    const orgId = '01930000-0000-7000-8000-0000000000e1';
    mockApi({
      OrganizationsController_list_v1: () =>
        okJson({ data: [{ id: orgId, name: 'Beta', slug: 'beta' }], nextCursor: null } as never),
    });
    server.use(
      http.post(`${TEST_ORIGIN}/bff/session/override`, () =>
        apiErrorJson(403, 'mfa_required', 'MFA required'),
      ),
    );
    const { user } = renderWithProviders(<AppShell>{page}</AppShell>, {
      role: 'platform_admin',
      route: '/organizations',
    });
    await user.click(screen.getByRole('button', { name: 'Switch tenant' }));
    const dialog = await screen.findByRole('dialog');
    await user.click(await within(dialog).findByText('Beta'));
    await user.type(within(dialog).getByLabelText(/Reason/), 'Ticket OPS-99 check');
    await user.click(within(dialog).getByRole('button', { name: 'Start override' }));
    expect(await within(dialog).findByText(/needs an MFA session/)).toBeInTheDocument();
  });

  it('hides the switcher from tenant users and shows the override banner with End now', async () => {
    renderWithProviders(<AppShell>{page}</AppShell>, {
      role: 'organization_admin',
      route: '/dashboard',
    });
    expect(screen.queryByRole('button', { name: 'Switch tenant' })).not.toBeInTheDocument();
    let ended = false;
    server.use(
      http.delete(
        `${TEST_ORIGIN}/bff/session/override`,
        () => ((ended = true), new HttpResponse(null, { status: 204 })),
      ),
    );
    server.use(http.get(`${TEST_ORIGIN}/bff/session`, () => HttpResponse.json(makeSession())));
    mockApi({ AuthController_me_v1: () => okJson(makeMe({ role: 'platform_admin' }) as never) });
    const session = makeSession({
      override: {
        id: 'ovr-1',
        organizationId: 'org-b',
        organizationName: 'Beta Logistics (example)',
        expiresAt: '2026-11-13T12:00:00.000Z',
      },
    });
    const me = makeMe({
      role: 'platform_admin',
      overrides: {
        override: {
          id: 'ovr-1',
          reason: 'Ticket OPS-1',
          organizationId: 'org-b',
          expiresAt: '2026-11-13T12:00:00.000Z',
        },
      },
    });
    const { user } = renderWithProviders(<AppShell>{page}</AppShell>, {
      me,
      session,
      route: '/dashboard',
    });
    const banner = screen.getByRole('region', { name: 'Tenant override' });
    expect(banner).toHaveTextContent('Acting in Beta Logistics (example) as Test User');
    expect(banner).toHaveTextContent('reason: Ticket OPS-1');
    await user.click(within(banner).getByRole('button', { name: 'End now' }));
    await waitFor(() => expect(ended).toBe(true));
  });

  it('the user menu signs out and links to account security', async () => {
    let loggedOut = false;
    server.use(
      http.post(
        `${TEST_ORIGIN}/bff/session/logout`,
        () => ((loggedOut = true), new HttpResponse(null, { status: 204 })),
      ),
    );
    // After sign-out the cache is cleared; the still-mounted shell refetches its user and session.
    server.use(
      http.get(`${TEST_ORIGIN}/bff/session`, () =>
        HttpResponse.json(makeSession({ authenticated: false })),
      ),
    );
    mockApi({ AuthController_me_v1: () => okJson(makeMe() as never) });
    const { user, router } = renderWithProviders(<AppShell>{page}</AppShell>, {
      route: '/dashboard',
    });
    const accountButton = screen.getByRole('button', { name: 'Account menu for Test User' });
    // WCAG 2.5.3 (label in name): the avatar initials are decorative, so the visible text of the
    // button ("Test User") is part of its accessible name (axe label-content-name-mismatch).
    expect(accountButton.querySelector('[data-slot="avatar"]')).toHaveAttribute(
      'aria-hidden',
      'true',
    );
    await user.click(accountButton);
    expect(await screen.findByRole('menuitem', { name: /Account security/ })).toHaveAttribute(
      'href',
      '/settings?tab=security',
    );
    await user.click(screen.getByRole('menuitem', { name: /^Sign out$/ }));
    await waitFor(() => expect(loggedOut).toBe(true));
    await waitFor(() => expect(router.replace).toHaveBeenCalledWith('/login'));
  });

  it('says so when sign-out could not end the server session (502 logout_incomplete)', async () => {
    server.use(
      http.post(`${TEST_ORIGIN}/bff/session/logout`, () =>
        HttpResponse.json(
          {
            statusCode: 502,
            error: 'BAD_GATEWAY',
            code: 'logout_incomplete',
            message: 'Signed out of this browser, but the server session could not be ended',
          },
          { status: 502 },
        ),
      ),
      http.get(`${TEST_ORIGIN}/bff/session`, () =>
        HttpResponse.json(makeSession({ authenticated: false })),
      ),
    );
    mockApi({ AuthController_me_v1: () => okJson(makeMe() as never) });
    const { user, router } = renderWithProviders(<AppShell>{page}</AppShell>, {
      route: '/dashboard',
    });
    await user.click(screen.getByRole('button', { name: 'Account menu for Test User' }));
    await user.click(await screen.findByRole('menuitem', { name: /^Sign out$/ }));
    expect(
      await screen.findByText(
        /signed out of this browser, but the server session could not be ended/,
      ),
    ).toBeInTheDocument();
    await waitFor(() => expect(router.replace).toHaveBeenCalledWith('/login'));
  });
});

describe('PlatformHealthCard', () => {
  it('renders only for platform:operations, through /bff/platform/health', async () => {
    server.use(
      http.get(`${TEST_ORIGIN}/bff/platform/health`, () =>
        HttpResponse.json({
          reachable: true,
          status: 'ok',
          version: '1.0.0',
          checks: [{ name: 'mysql', status: 'ok', latencyMs: 3 }],
        }),
      ),
    );
    const { container } = renderWithProviders(<PlatformHealthCard />, { role: 'platform_admin' });
    expect(await screen.findByText('mysql')).toBeInTheDocument();
    expect(screen.getByText('Operational')).toBeInTheDocument();
    await expectNoAxeViolations(container);
    renderWithProviders(<PlatformHealthCard />, { role: 'organization_admin' });
    expect(screen.getAllByText('Platform dependencies')).toHaveLength(1);
  });
});

describe('override form contract', () => {
  it('produces a body that matches POST /platform/overrides', () => {
    const parsed = overrideFormSchema.parse({
      organizationId: '01930000-0000-7000-8000-0000000000e1',
      reason: ' Ticket OPS-1234 ',
      durationMinutes: '45',
    });
    expectRequestMatchesContract('PlatformOverrideController_start_v1', parsed);
    expect(() =>
      overrideFormSchema.parse({ organizationId: 'x', reason: 'short', durationMinutes: 1 }),
    ).toThrow();
  });
});
