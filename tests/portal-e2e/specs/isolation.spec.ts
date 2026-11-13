/**
 * Tenant isolation through the browser (design §9, §8): an alpha administrator opening beta's
 * domain, message, webhook, quarantine entry and approval URLs gets the same 404 page as for a
 * missing id; alpha's lists carry no beta data; the shell names the tenant. The platform
 * override is the only way to act in another tenant: started with a reason, a banner while it
 * is active, the target's data, ended, and its audit row in the platform audit trail.
 */
import { randomUUID } from 'node:crypto';
import type { Page } from '@playwright/test';
import { signIn } from '../support/auth';
import { expect, test } from '../support/fixtures';
import { readState } from '../support/state';

/**
 * The not-found state of a detail route: the shared "Page not found" page, or the page's error
 * state for an api `404` (title "Not found", a `*_not_found` code). The foreign id must look
 * exactly like an id that exists nowhere (design P8): same heading, same code.
 */
async function notFoundSignature(page: Page, path: string): Promise<string> {
  await page.goto(path);
  const pageNotFound = page.getByRole('heading', { level: 1, name: 'Page not found' });
  const errorTitle = page.getByText('Not found', { exact: true });
  await expect(pageNotFound.or(errorTitle).first()).toBeVisible();
  if (await pageNotFound.isVisible()) return 'page-not-found';
  const code = await page
    .locator('main')
    .getByText(/^[a-z_]+_not_found$/)
    .first()
    .textContent();
  return `error-state:${code}`;
}

async function expectNotFound(page: Page, route: string, foreignId: string): Promise<void> {
  const foreign = await notFoundSignature(page, `${route}/${foreignId}`);
  const missing = await notFoundSignature(page, `${route}/${randomUUID()}`);
  expect(foreign, `${route}: a foreign id looks like a missing one`).toBe(missing);
}

test('alpha admin: beta ids are 404, lists hold alpha data only', async ({ page }) => {
  const s = readState();
  await signIn(page, 'alphaAdmin', { next: '/domains' });
  // Tenant indicator in the top bar.
  await expect(page.getByText(s.orgs.alpha.name, { exact: true })).toBeVisible();

  await expectNotFound(page, '/domains', s.beta.domainId);
  await expectNotFound(page, '/messages', s.beta.messageId);
  await expectNotFound(page, '/webhooks', s.beta.webhookId);
  await expectNotFound(page, '/quarantine', s.beta.entryId);
  await expectNotFound(page, '/quarantine/approvals', s.beta.approvalId);

  const lists: Array<[string, string]> = [
    ['/domains', s.alpha.domainName],
    ['/messages?range=7d', 'Alpha'],
    ['/quarantine?tab=entries', s.alpha.domainName],
    ['/users', `@${s.alpha.domainName}`],
    ['/audit-logs?range=7d&action=user.invited', 'user.invited'],
  ];
  for (const [path, alphaMarker] of lists) {
    await page.goto(path);
    await expect(page.getByRole('table').first()).toContainText(alphaMarker);
    const text = await page.locator('main').innerText();
    expect(text, `${path} shows no beta data`).not.toContain(s.beta.marker);
    expect(text, `${path} shows no beta domain`).not.toContain(s.beta.domainName);
    expect(text, `${path} shows no beta audit rows`).not.toContain('e2e_beta.marker_event');
  }
});

test('platform override: reason, banner, target data, end, audit row', async ({ page }) => {
  const s = readState();
  await signIn(page, 'platformAdmin', { next: '/organizations' });
  await page.getByRole('button', { name: 'Switch tenant' }).click();
  const dialog = page.getByRole('dialog', { name: 'Act in a customer organization' });
  await dialog.getByRole('combobox', { name: 'Search organizations' }).fill(s.orgs.beta.slug);
  await dialog.getByRole('option', { name: new RegExp(s.orgs.beta.name) }).click();
  const reason = 'E2E isolation check of the beta tenant (synthetic data)';
  await dialog.getByLabel('Reason').fill(reason);
  await dialog.getByLabel('Duration (minutes)').fill('10');
  await dialog
    .getByRole('button', { name: /start|act/i })
    .last()
    .click();

  const banner = page.getByRole('region', { name: 'Tenant override' });
  await expect(banner).toBeVisible();
  await expect(banner).toContainText(`Acting in ${s.orgs.beta.name}`);
  await expect(banner).toContainText(reason.slice(0, 40));

  // The target's data, through the override token.
  await page.goto('/domains');
  await expect(page.getByRole('table').first()).toContainText(s.beta.domainName);
  await page.goto('/messages?range=7d');
  await expect(page.getByRole('table').first()).toContainText(s.beta.marker);
  await expect(page.locator('main')).not.toContainText('Alpha spam message');

  await banner.getByRole('button', { name: 'End now' }).click();
  await expect(banner).toHaveCount(0);

  // The start is audited in the target organization's trail (platform audit tab, MFA session).
  await page.goto(
    `/audit-logs?tab=platform&organizationId=${s.orgs.beta.id}&action=platform.override_started`,
  );
  const table = page.getByRole('table', { name: /platform audit log entries/i });
  await expect(table).toContainText('platform.override_started');
});
