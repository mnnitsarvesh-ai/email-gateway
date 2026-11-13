/**
 * Permission-aware navigation (design P11, §9): for five roles the visible navigation equals the
 * entries whose gate operations the user may call, evaluated from the OpenAPI snapshot's
 * `x-eg-permissions` and the user's `GET /auth/me` permissions (not from the portal's code);
 * `/` lands on the first permitted entry; direct URLs of hidden pages show the 403 page; actions
 * the role cannot perform are not offered.
 */
import type { Page } from '@playwright/test';
import { signIn } from '../support/auth';
import { NAV_GATES, expectedNav, me } from '../support/contract';
import { expect, test } from '../support/fixtures';
import type { UserKey } from '../support/state';

async function visibleNav(page: Page): Promise<string[]> {
  const nav = page.getByRole('navigation', { name: 'Main' });
  await expect(nav.getByRole('link').first()).toBeVisible();
  return (await nav.getByRole('link').allTextContents()).map((t) => t.trim());
}

async function expectForbidden(page: Page, href: string): Promise<void> {
  await page.goto(href);
  await expect(
    page.getByRole('heading', { level: 1, name: 'You do not have access to this page' }),
  ).toBeVisible();
}

const ROLES: Array<{ key: UserKey; role: string; minVisible: number }> = [
  { key: 'alphaAdmin', role: 'organization_admin', minVisible: 15 },
  { key: 'alphaAnalyst', role: 'security_analyst', minVisible: 10 },
  { key: 'alphaReadOnly', role: 'read_only_user', minVisible: 10 },
  { key: 'alphaMailbox', role: 'mailbox_user', minVisible: 2 },
  { key: 'platformAdmin', role: 'platform_admin', minVisible: 10 },
];

for (const { key, role, minVisible } of ROLES) {
  test(`${role}: navigation matches the permissions; hidden pages are 403`, async ({ page }) => {
    await signIn(page, key);
    const profile = await me(page);
    expect(profile.roles).toContain(role);
    const expected = expectedNav(profile.permissions);
    expect(expected.length).toBeGreaterThanOrEqual(minVisible);
    expect(await visibleNav(page)).toEqual(expected);

    // `/` lands on the first permitted entry.
    await page.goto('/');
    const first = NAV_GATES.find((item) => item.label === expected[0])!;
    await expect(page).toHaveURL(new RegExp(`${first.href.replace('/', '\\/')}(\\?|$)`));

    for (const hidden of NAV_GATES.filter((item) => !expected.includes(item.label))) {
      await expectForbidden(page, hidden.href);
    }
  });
}

test('hidden actions: invite, add domain, new webhook and tenant switch follow the role', async ({
  page,
  context,
}) => {
  // Organization admin: every action offered.
  await signIn(page, 'alphaAdmin', { next: '/users' });
  await expect(page.getByRole('button', { name: 'Invite user' }).first()).toBeVisible();
  await page.goto('/domains');
  await expect(page.getByRole('link', { name: 'Add domain' }).first()).toBeVisible();
  await page.goto('/integrations');
  await expect(page.getByRole('button', { name: 'New webhook' }).first()).toBeVisible();
  await expect(page.getByRole('button', { name: 'Switch tenant' })).toHaveCount(0);
  await context.clearCookies();

  // Read-only user: can list users and domains, cannot change them.
  await signIn(page, 'alphaReadOnly', { next: '/users' });
  await expect(page.getByRole('heading', { level: 1, name: 'Users' })).toBeVisible();
  await expect(page.getByRole('table').first()).toBeVisible();
  await expect(page.getByRole('button', { name: 'Invite user' })).toHaveCount(0);
  await page.goto('/domains');
  await expect(page.getByRole('table').first()).toBeVisible();
  await expect(page.getByRole('link', { name: 'Add domain' })).toHaveCount(0);
  await context.clearCookies();

  // Security analyst: reads webhooks, cannot create them; no domain management.
  await signIn(page, 'alphaAnalyst', { next: '/integrations' });
  await expect(page.getByRole('heading', { level: 1, name: /integrations/i })).toBeVisible();
  await expect(page.getByRole('button', { name: 'New webhook' })).toHaveCount(0);
  await page.goto('/domains');
  await expect(page.getByRole('table').first()).toBeVisible();
  await expect(page.getByRole('link', { name: 'Add domain' })).toHaveCount(0);
  await context.clearCookies();

  // Mailbox user: only the self-service quarantine.
  await signIn(page, 'alphaMailbox', { next: '/quarantine' });
  await expect(page.getByRole('heading', { level: 1, name: /my quarantine/i })).toBeVisible();
  await expect(page.getByRole('tab', { name: /^entries$/i })).toHaveCount(0);
  await context.clearCookies();

  // Platform admin: the tenant switcher.
  await signIn(page, 'platformAdmin');
  await expect(page.getByRole('button', { name: 'Switch tenant' })).toBeVisible();
});
