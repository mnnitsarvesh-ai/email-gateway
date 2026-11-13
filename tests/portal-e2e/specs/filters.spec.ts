/**
 * Filters write the URL and narrow the api results (design P8): domains (q, status), quarantine
 * entries (state, reason; a filter change resets the cursor stack to page 1), audit logs (exact
 * action, action prefix) and the email explorer (direction, verdict).
 */
import type { Locator, Page } from '@playwright/test';
import { signIn } from '../support/auth';
import { expect, test } from '../support/fixtures';
import { readState } from '../support/state';

function table(page: Page): Locator {
  return page.locator('main table').first();
}

async function choose(page: Page, label: string, option: string): Promise<void> {
  await page
    .getByRole('combobox', { name: new RegExp(`^${label}`) })
    .first()
    .click();
  await page.getByRole('option', { name: option, exact: true }).click();
}

/** Every body row of the main table contains `text` (and there is at least one row). */
async function everyRowContains(page: Page, text: string | RegExp): Promise<void> {
  const rows = table(page).locator('tbody tr');
  await expect(rows.first()).toBeVisible();
  await expect
    .poll(async () => {
      const texts = await rows.allInnerTexts();
      return (
        texts.length > 0 &&
        texts.every((t) => (typeof text === 'string' ? t.includes(text) : text.test(t)))
      );
    })
    .toBe(true);
}

test('domains: name prefix and status', async ({ page }) => {
  const s = readState();
  await signIn(page, 'alphaDomainAdmin', { next: '/domains' });
  await expect(table(page)).toContainText(s.alpha.domainName);

  const search = page
    .getByRole('searchbox', { name: 'Search domains by name prefix' })
    .or(page.getByLabel('Search domains by name prefix'));
  await search.first().fill('nomatch-e2e');
  await expect(page).toHaveURL(/[?&]q=nomatch-e2e/);
  await expect(page.locator('main')).toContainText(/no domains|nothing|no results|no match/i);
  await search.first().fill('alpha');
  await expect(page).toHaveURL(/[?&]q=alpha/);
  await expect(table(page)).toContainText(s.alpha.domainName);

  await choose(page, 'Status', 'Active');
  await expect(page).toHaveURL(/[?&]status=active/);
  await everyRowContains(page, 'Active');
  await choose(page, 'Status', 'Suspended');
  await expect(page).toHaveURL(/[?&]status=suspended/);
  await expect(table(page).locator('tbody tr').filter({ hasText: s.alpha.domainName })).toHaveCount(
    0,
  );
});

test('quarantine: state and reason filters; a filter change resets the cursor', async ({
  page,
}) => {
  await signIn(page, 'alphaReviewer', { next: '/quarantine?tab=entries' });
  const pager = page.getByRole('navigation', { name: /pagination$/ }).first();
  await expect(pager).toContainText('Page 1 ·');
  // Page 2 exists (≥ 51 entries in the last 7 days).
  await pager.getByRole('button', { name: 'Next' }).click();
  await expect(pager).toContainText('Page 2 ·');

  await choose(page, 'State', 'Held');
  await expect(page).toHaveURL(/[?&]state=held/);
  await expect(pager).toContainText('Page 1 ·');
  await everyRowContains(page, 'Held');

  await choose(page, 'Reason', 'Phishing');
  await expect(page).toHaveURL(/[?&]reason=phishing/);
  await everyRowContains(page, 'Phishing');
  await expect(table(page)).not.toContainText('Spam');
});

test('audit logs: exact action and action prefix', async ({ page }) => {
  await signIn(page, 'alphaAdmin', { next: '/audit-logs?range=7d' });
  await expect(table(page).locator('tbody tr').first()).toBeVisible();

  const exact = page.getByLabel('Action (exact)');
  await exact.fill('user.invited');
  await exact.press('Enter');
  await expect(page).toHaveURL(/[?&]action=user\.invited/);
  await everyRowContains(page, 'user.invited');

  await exact.fill('');
  await exact.press('Enter');
  const prefix = page.getByLabel('Action prefix');
  await prefix.fill('policy.');
  await prefix.press('Enter');
  await expect(page).toHaveURL(/[?&]actionPrefix=policy\./);
  await everyRowContains(page, /policy\./);
  await expect(table(page)).not.toContainText('user.invited');
});

test('email explorer: direction and verdict', async ({ page }) => {
  await signIn(page, 'alphaAnalyst', { next: '/messages?range=7d' });
  await expect(table(page)).toContainText('Alpha clean message 000');

  await choose(page, 'Direction', 'Outbound');
  await expect(page).toHaveURL(/[?&]direction=outbound/);
  await everyRowContains(page, 'Outbound');

  await choose(page, 'Direction', 'Inbound');
  await page.getByRole('button', { name: /^Verdict/ }).click();
  await page.getByRole('menuitemcheckbox', { name: 'Phishing' }).click();
  await page.keyboard.press('Escape');
  await expect(page).toHaveURL(/[?&]verdict=phishing/);
  await everyRowContains(page, 'Phishing');
  await expect(table(page)).not.toContainText('Alpha clean message');
});
