/**
 * Sign-in through the real login pages (password → TOTP or enrollment), as a user would. TOTP
 * secrets come from the seed (approver) or from enrollment through the UI (platform admin,
 * mfa-admin) and are kept in the git-ignored state file.
 */
import { expect, type Page } from '@playwright/test';
import { readState, reloadState, updateUser, type UserKey } from './state';
import { freshTotp } from './totp';

export function user(key: UserKey) {
  return reloadState().users[key];
}

export async function fillLogin(page: Page, key: UserKey, next?: string): Promise<void> {
  const u = readState().users[key];
  await page.goto(next ? `/login?next=${encodeURIComponent(next)}` : '/login');
  await page.getByLabel('Email address').fill(u.email);
  await page.getByLabel('Password', { exact: true }).fill(u.password);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
}

/** A fresh TOTP code for the user (each 30 s step is accepted once by the api). */
export async function nextTotp(key: UserKey): Promise<string> {
  const u = user(key);
  if (!u.totpSecret) throw new Error(`${key} has no TOTP secret yet`);
  const { code, step } = await freshTotp(u.totpSecret, u.lastTotpStep);
  updateUser(key, { lastTotpStep: step });
  return code;
}

export async function submitTotp(page: Page, key: UserKey): Promise<void> {
  await page.getByLabel('Authentication code').fill(await nextTotp(key));
  await page.getByRole('button', { name: 'Verify' }).click();
}

/** Completes `/mfa/enroll` (or the Settings enrollment card) and stores secret and codes. */
export async function completeEnrollment(page: Page, key: UserKey): Promise<string[]> {
  const secretNode = page.locator('code[data-secret]').first();
  await expect(secretNode).toBeVisible();
  const secret = ((await secretNode.textContent()) ?? '').replace(/\s+/g, '');
  expect(secret).toMatch(/^[A-Z2-7]{16,}$/);
  updateUser(key, { totpSecret: secret, lastTotpStep: undefined, recoveryCodes: [] });
  await page.getByLabel('Authentication code').fill(await nextTotp(key));
  await page.getByRole('button', { name: 'Enable MFA' }).click();
  const list = page.getByRole('list', { name: 'Recovery codes' });
  await expect(list).toBeVisible();
  const codes = (await list.getByRole('listitem').allTextContents()).map((c) => c.trim());
  expect(codes.length).toBeGreaterThanOrEqual(8);
  updateUser(key, { recoveryCodes: codes });
  await page.getByLabel('I have stored my recovery codes in a safe place.').check();
  return codes;
}

/**
 * Signs in and lands on a console page. Handles the MFA challenge (stored secret) and a forced
 * enrollment (enrolls through the UI) unless `stopAtEnrollment` is set.
 */
export async function signIn(
  page: Page,
  key: UserKey,
  options: { next?: string; stopAtEnrollment?: boolean } = {},
): Promise<void> {
  await fillLogin(page, key, options.next);
  await page.waitForURL((url) => url.pathname !== '/login', { timeout: 30_000 });
  if (new URL(page.url()).pathname === '/login/mfa') {
    await submitTotp(page, key);
    await page.waitForURL((url) => url.pathname !== '/login/mfa', { timeout: 30_000 });
  }
  if (new URL(page.url()).pathname === '/mfa/enroll') {
    if (options.stopAtEnrollment) return;
    await completeEnrollment(page, key);
    await page.getByRole('button', { name: 'Continue' }).click();
    await page.waitForURL((url) => url.pathname !== '/mfa/enroll', { timeout: 30_000 });
  }
  await expect(accountMenu(page)).toBeVisible({ timeout: 30_000 });
}

export function accountMenu(page: Page) {
  return page.getByRole('button', { name: /^Account menu for / });
}

/** Signs out through the account menu. */
export async function signOut(page: Page): Promise<void> {
  await accountMenu(page).click();
  await page.getByRole('menuitem', { name: 'Sign out', exact: true }).click();
  await page.waitForURL((url) => url.pathname === '/login');
}
