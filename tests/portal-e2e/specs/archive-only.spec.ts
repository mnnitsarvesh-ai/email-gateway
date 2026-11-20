/**
 * Step 8.6 (D13, ADR-0090; §9.5): an organization on the archive-only plan (seeded `gamma`)
 * sees no gateway pages. Its admin (organization admin + compliance officer) lands on Archive
 * search; Dashboard, Reports, Email explorer, Quarantine, Mail servers, the Security section and
 * the SMTP connectors card are hidden, and their URLs show "Not available for this plan".
 */
import { signIn } from '../support/auth';
import { expectedNav, me } from '../support/contract';
import { expect, test } from '../support/fixtures';
import { expectNoSeriousA11yViolations } from '../support/pages';

test.describe.configure({ timeout: 180_000 });

const HIDDEN = [
  'Dashboard',
  'Reports',
  'Email explorer',
  'Quarantine',
  'Mail servers',
  'Incidents',
  'Policy management',
  'Policy builder',
  'Threat intelligence',
  'URL protection',
  'Attachment analysis',
];

test('archive-only organization: archive start page, no gateway navigation', async ({ page }) => {
  await signIn(page, 'gammaAdmin');
  const profile = await me(page);
  expect(profile.organization.serviceProfile).toBe('archive_only');
  await expect(page).toHaveURL(/\/archive(\?|$)/);
  const nav = page.getByRole('navigation', { name: 'Main' });
  await expect(nav.getByRole('link').first()).toBeVisible();
  const labels = (await nav.locator('[data-nav-label]').allTextContents()).map((t) => t.trim());
  expect(labels).toEqual(expectedNav(profile.permissions, 'archive_only'));
  for (const hidden of HIDDEN) expect(labels).not.toContain(hidden);
  expect(labels).toContain('Search');
  expect(labels).toContain('Settings');
  await expect(nav.getByText('Security', { exact: true })).toHaveCount(0);
  await expectNoSeriousA11yViolations(page, 'archive-only start page');
});

test('archive-only organization: gateway URLs say "not available for this plan"', async ({
  page,
}) => {
  await signIn(page, 'gammaAdmin', { next: '/settings?tab=journaling' });
  await expect(page.getByRole('form', { name: 'Journaling settings' })).toBeVisible();
  for (const href of [
    '/dashboard',
    '/messages',
    '/quarantine',
    '/policies/builder',
    '/mail-servers',
  ]) {
    await page.goto(href);
    await expect(
      page.getByRole('heading', { level: 1, name: 'Not available for this plan' }),
    ).toBeVisible();
  }
  await expectNoSeriousA11yViolations(page, 'not available for this plan');
  await page.goto('/integrations');
  await expect(page.getByRole('heading', { level: 1, name: 'Integrations' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Manage SMTP connectors' })).toHaveCount(0);
  await expect(page.getByRole('link', { name: 'Journaling settings' })).toBeVisible();
});
