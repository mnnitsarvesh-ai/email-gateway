/**
 * Authentication through the browser (design §9): password login and logout, MFA enrollment in
 * Settings → Security with the displayed key (RFC 6238 helper), TOTP and recovery-code logins,
 * the forced enrollment of a platform operator, silent refresh after the access token expired
 * (the api runs with AUTH_ACCESS_TOKEN_TTL_SECONDS=60 for this suite), parallel requests at
 * expiry, and sign-out everywhere from a second browser.
 */
import type { BrowserContext, Page } from '@playwright/test';
import {
  accountMenu,
  completeEnrollment,
  fillLogin,
  signIn,
  signOut,
  submitTotp,
  user,
} from '../support/auth';
import {
  assertGuardClean,
  clientIp,
  expect,
  newGuard,
  protectContext,
  test,
} from '../support/fixtures';
import { updateUser } from '../support/state';

test.describe.configure({ mode: 'serial' });

interface SessionState {
  authenticated: boolean;
  accessExpiresAt: string | null;
}

async function session(page: Page): Promise<SessionState> {
  const res = await page.request.get('/bff/session');
  return (await res.json()) as SessionState;
}

/** Waits until the access token of the session has expired (TTL 60 s), without any page open. */
async function idlePastExpiry(context: BrowserContext, page: Page): Promise<void> {
  const before = await session(page);
  expect(before.authenticated).toBe(true);
  const expiresAt = Date.parse(before.accessExpiresAt!);
  // TTL of the e2e api (60 s): an access token never lives longer.
  expect(expiresAt - Date.now()).toBeLessThanOrEqual(61_000);
  await page.close();
  const wait = Math.max(0, expiresAt - Date.now()) + 3_000;
  await new Promise((r) => setTimeout(r, wait));
  expect(context.pages()).toHaveLength(0);
}

test('password login, shell, logout and the login redirect', async ({ page }) => {
  await page.goto('/dashboard');
  await expect(page).toHaveURL(/\/login\?next=%2Fdashboard/);
  await signIn(page, 'alphaAdmin', { next: '/dashboard' });
  await expect(page).toHaveURL(/\/dashboard/);
  await expect(page.getByText('E2E Portal Alpha', { exact: true })).toBeVisible();
  await signOut(page);
  expect((await session(page)).authenticated).toBe(false);
  await page.goto('/users');
  await expect(page).toHaveURL(/\/login\?next=%2Fusers/);
});

test('a wrong password is refused with the api message', async ({ page }) => {
  const u = user('alphaReadOnly');
  await page.goto('/login');
  await page.getByLabel('Email address').fill(u.email);
  await page.getByLabel('Password', { exact: true }).fill(`${u.password}-wrong`);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.getByRole('alert').first()).toBeVisible();
  await expect(page).toHaveURL(/\/login$/);
});

test('MFA: enable in Settings → Security, then sign in with TOTP and with a recovery code', async ({
  page,
}) => {
  await signIn(page, 'alphaMfaAdmin', { next: '/settings?tab=security' });
  const card = page
    .locator('[data-slot="card"]')
    .filter({ hasText: 'Multi-factor authentication' });
  await expect(card.getByText('Not enabled')).toBeVisible();
  await card.getByRole('button', { name: 'Set up MFA' }).click();
  const codes = await completeEnrollment(page, 'alphaMfaAdmin');
  await card.getByRole('button', { name: 'Continue' }).click();
  await expect(card.getByText('Enabled', { exact: true })).toBeVisible();
  // The codes were shown once: they are gone from the page after Continue.
  await expect(page.getByText(codes[0]!, { exact: true })).toHaveCount(0);
  await signOut(page);

  // TOTP at the next 30 s step (the enable call used the current one).
  await fillLogin(page, 'alphaMfaAdmin');
  await page.waitForURL((url) => url.pathname === '/login/mfa');
  await submitTotp(page, 'alphaMfaAdmin');
  await expect(accountMenu(page)).toBeVisible({ timeout: 30_000 });
  await signOut(page);

  // A recovery code works once.
  const [recovery, ...rest] = user('alphaMfaAdmin').recoveryCodes!;
  await fillLogin(page, 'alphaMfaAdmin');
  await page.waitForURL((url) => url.pathname === '/login/mfa');
  await page.getByRole('button', { name: 'Use a recovery code instead' }).click();
  await page.getByLabel('Recovery code').fill(recovery!);
  await page.getByRole('button', { name: 'Use recovery code' }).click();
  await expect(accountMenu(page)).toBeVisible({ timeout: 30_000 });
  updateUser('alphaMfaAdmin', { recoveryCodes: rest });
  await signOut(page);
});

test('platform admin: first login is forced to /mfa/enroll', async ({ page }) => {
  await signIn(page, 'platformAdmin', { stopAtEnrollment: true });
  await expect(page).toHaveURL(/\/mfa\/enroll/);
  // Console routes redirect to the enrollment while it is pending.
  await page.goto('/dashboard');
  await expect(page).toHaveURL(/\/mfa\/enroll/);
  await completeEnrollment(page, 'platformAdmin');
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.waitForURL((url) => url.pathname !== '/mfa/enroll');
  await expect(accountMenu(page)).toBeVisible();
  await expect(page.getByText('Platform', { exact: true }).first()).toBeVisible();
});

test('idle past the access-token expiry: navigation refreshes silently', async ({
  context,
  page,
}) => {
  test.setTimeout(240_000);
  await signIn(page, 'alphaAnalyst', { next: '/dashboard' });
  const before = await session(page);
  await idlePastExpiry(context, page);
  const next = await context.newPage();
  await next.goto('/messages');
  await expect(next).toHaveURL(/\/messages/);
  await expect(next.getByRole('heading', { level: 1, name: /email explorer/i })).toBeVisible();
  await expect(next.getByRole('table').first()).toBeVisible();
  const after = await session(next);
  expect(after.authenticated).toBe(true);
  expect(Date.parse(after.accessExpiresAt!)).toBeGreaterThan(Date.parse(before.accessExpiresAt!));
});

test('parallel requests and two tabs at expiry do not end the session', async ({
  context,
  page,
}) => {
  test.setTimeout(240_000);
  await signIn(page, 'alphaAdmin', { next: '/users' });
  await idlePastExpiry(context, page);
  // Two tabs open at once; the dashboard fires five report queries and `me` in parallel.
  const [a, b] = await Promise.all([context.newPage(), context.newPage()]);
  await Promise.all([a.goto('/dashboard?range=7d'), b.goto('/reports')]);
  for (const tab of [a, b]) {
    await expect(tab).not.toHaveURL(/\/login/);
    await expect(accountMenu(tab)).toBeVisible();
  }
  await expect(a.getByRole('heading', { level: 3, name: 'Total emails processed' })).toBeVisible();
  await expect(a.getByText(/request id/i)).toHaveCount(0);
  // The session survived: a reload stays signed in and the BFF reports it authenticated.
  await a.reload();
  await expect(accountMenu(a)).toBeVisible();
  expect((await session(a)).authenticated).toBe(true);
});

test('sign out everywhere from a second browser sends the first one to /login', async ({
  browser,
  page,
}) => {
  test.setTimeout(180_000);
  await signIn(page, 'alphaDomainAdmin', { next: '/domains' });
  const guard = newGuard();
  const other = await browser.newContext({ locale: 'en-US', timezoneId: 'UTC' });
  await protectContext(other, guard, clientIp('logout-all-second-browser'));
  const second = await other.newPage();
  await signIn(second, 'alphaDomainAdmin', { next: '/domains' });
  await accountMenu(second).click();
  await second.getByRole('menuitem', { name: 'Sign out everywhere' }).click();
  await second
    .getByRole('alertdialog')
    .getByRole('button', { name: 'Sign out everywhere' })
    .click();
  await second.waitForURL((url) => url.pathname === '/login');
  await other.close();
  assertGuardClean(guard);

  // The first browser's refresh token was revoked; its next navigation ends at /login (at the
  // latest when its 60 s access token expires and the refresh is refused).
  await expect(async () => {
    await page.goto('/domains');
    await expect(page).toHaveURL(/\/login/, { timeout: 5_000 });
  }).toPass({ timeout: 90_000, intervals: [2_000, 5_000, 10_000] });
});
