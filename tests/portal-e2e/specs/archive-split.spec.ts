/**
 * Step 8.6 (D12, D14, ADR-0089; §9.5): the Journaling / Archive permission split through the
 * browser against the real api.
 *
 * - a new organization admin (no archive role): manages journaling, sees Retention and lock
 *   (configuration, `archive:read`), but no Search, Legal holds, eDiscovery or Access audit, and
 *   the api refuses archived records; without an MFA session the Compliance Officer role cannot
 *   be assigned (step 8.6 review fix); an organization admin signed in with MFA assigns it to
 *   another user after a confirmation (audited `rbac.archive_access_granted` / `_revoked`) and
 *   cannot assign it to themselves;
 * - a compliance officer: the whole Archive section, record search, read-only journaling, and the
 *   Access audit page listing the role assignment of the first test.
 */
import type { Page } from '@playwright/test';
import { signIn, signOut } from '../support/auth';
import { NAV_GATES, expectedNav, me } from '../support/contract';
import { expect, test } from '../support/fixtures';
import { auditRows } from '../support/journaling';
import { bff } from '../support/messages';
import { expectNoSeriousA11yViolations } from '../support/pages';
import { readState } from '../support/state';

test.describe.configure({ mode: 'serial', timeout: 180_000 });

const ARCHIVE_ITEMS = ['Search', 'Retention and lock', 'Legal holds', 'eDiscovery', 'Access audit'];

async function navLabels(page: Page): Promise<string[]> {
  const nav = page.getByRole('navigation', { name: 'Main' });
  await expect(nav.getByRole('link').first()).toBeVisible();
  return (await nav.locator('[data-nav-label]').allTextContents()).map((t) => t.trim());
}

const range = () =>
  `from=${encodeURIComponent(new Date(Date.now() - 7 * 86_400_000).toISOString())}&to=${encodeURIComponent(new Date(Date.now() + 60_000).toISOString())}`;

test('organization admin without an archive role: journaling yes, archived mail no', async ({
  page,
}) => {
  await signIn(page, 'alphaAdmin', { next: '/settings?tab=journaling' });
  const profile = await me(page);
  expect(profile.roles).toEqual(['organization_admin']);
  expect(profile.permissions).toContain('journal:manage');
  expect(profile.permissions).not.toContain('archive:search');
  const labels = await navLabels(page);
  expect(labels).toEqual(expectedNav(profile.permissions));
  expect(labels).toContain('Retention and lock');
  for (const hidden of ['Search', 'Legal holds', 'eDiscovery', 'Access audit'])
    expect(labels).not.toContain(hidden);
  await expect(page.getByRole('form', { name: 'Journaling settings' })).toBeVisible();

  // Direct URLs and the api refuse archived records.
  for (const href of ['/archive', '/legal-holds', '/ediscovery', '/archive/access-audit']) {
    await page.goto(href);
    await expect(
      page.getByRole('heading', { level: 1, name: 'You do not have access to this page' }),
    ).toBeVisible();
  }
  expect((await bff(page, 'GET', `/archive/messages?${range()}`)).status).toBe(403);
  // Configuration stays readable (archive:read); archive paths of the settings are refused.
  const settings = await bff(page, 'GET', '/archive/settings');
  expect(settings.status).toBe(200);

  // Without an MFA session the archive role cannot be delegated (the api's rule, step 8.6).
  await page.goto(`/users/${readState().alpha.memberUserId}`);
  await expect(page.getByRole('heading', { level: 1, name: 'Alpha Member 01' })).toBeVisible();
  await expect(page.getByRole('checkbox', { name: /Compliance Officer/ })).toBeDisabled();
  await expect(page.getByText(/only from a session signed in with multi-factor/)).toBeVisible();
  await signOut(page);
});

test('organization admin with MFA: assigns Compliance Officer to another user, never to themselves', async ({
  page,
}) => {
  await signIn(page, 'alphaAccessAdmin', { next: '/settings?tab=journaling' });
  const profile = await me(page);
  expect(profile.roles).toEqual(['organization_admin']);
  expect(profile.session.mfaAuthenticated).toBe(true);
  expect(profile.permissions).not.toContain('archive:search');

  // Assigning the archive role asks for confirmation and is audited.
  const since = new Date(Date.now() - 5_000);
  await page.goto(`/users/${readState().alpha.memberUserId}`);
  await expect(page.getByRole('heading', { level: 1, name: 'Alpha Member 01' })).toBeVisible();
  const officer = page.getByRole('checkbox', { name: /Compliance Officer/ });
  await expect(officer).toBeEnabled();
  await officer.click();
  await page.getByRole('button', { name: 'Save roles' }).click();
  const dialog = page.getByRole('alertdialog', { name: 'Grant access to archived mail?' });
  await expect(dialog).toBeVisible();
  await expectNoSeriousA11yViolations(page, 'archive access confirmation');
  await dialog.getByRole('button', { name: 'Grant archive access' }).click();
  await expect(page.getByText('Roles saved.')).toBeVisible();
  await expect
    .poll(async () => (await auditRows('alpha', 'rbac.archive_access_granted', since)).length)
    .toBeGreaterThanOrEqual(1);
  // And removed again (audited as revoked).
  await page.getByRole('checkbox', { name: /Compliance Officer/ }).click();
  await page.getByRole('button', { name: 'Save roles' }).click();
  await expect(page.getByText('Roles saved.').first()).toBeVisible();
  await expect
    .poll(async () => (await auditRows('alpha', 'rbac.archive_access_revoked', since)).length)
    .toBeGreaterThanOrEqual(1);

  // Never to themselves: the portal disables it and the api refuses it.
  await page.goto(`/users/${profile.user.id}`);
  await expect(page.getByRole('checkbox', { name: /Compliance Officer/ })).toBeDisabled();
  await expect(page.getByText(/cannot give yourself access to archived mail/)).toBeVisible();
  const self = await bff(page, 'PUT', `/users/${profile.user.id}/roles`, {
    roleKeys: ['organization_admin', 'compliance_officer'],
  });
  expect(self.status).toBe(403);
  expect((await me(page)).roles).toEqual(['organization_admin']);
  await signOut(page);
});

test('compliance officer: the Archive section, record search and the access audit', async ({
  page,
}) => {
  await signIn(page, 'alphaCompliance', { next: '/archive?range=7d' });
  const profile = await me(page);
  expect(profile.roles).toEqual(['compliance_officer']);
  const labels = await navLabels(page);
  expect(labels).toEqual(expectedNav(profile.permissions));
  for (const item of ARCHIVE_ITEMS) expect(labels).toContain(item);
  expect(labels).not.toContain('Email explorer');
  await expect(page.getByRole('heading', { level: 1, name: 'Archive' })).toBeVisible();
  expect((await bff(page, 'GET', `/archive/messages?${range()}`)).status).toBe(200);

  // Journaling is read-only for the archive role (journal:read).
  await page.goto('/settings?tab=journaling');
  await expect(
    page.getByText(/changing journaling needs the journal:manage permission/),
  ).toBeVisible();
  await expect(page.getByRole('form', { name: 'Journaling settings' })).toHaveCount(0);

  // Access audit: the role assignment of the previous test, one category per view.
  await page.goto('/archive/access-audit?range=7d&category=granted');
  await expect(page.getByRole('heading', { level: 1, name: 'Access audit' })).toBeVisible();
  await expect(
    page.getByRole('button', { name: /Details of rbac\.archive_access_granted/ }).first(),
  ).toBeVisible({ timeout: 20_000 });
  await expectNoSeriousA11yViolations(page, '/archive/access-audit');
  // The default category (archive.*) is not written to the URL.
  await page.getByRole('radio', { name: 'Archive use' }).click();
  await expect(page).not.toHaveURL(/category=/);
  await expect(page.getByText('archive.*', { exact: true })).toBeVisible();
  // The access audit link is part of the navigation contract.
  expect(NAV_GATES.find((g) => g.label === 'Access audit')?.requires).toEqual(['archive:search']);
  await signOut(page);
});
