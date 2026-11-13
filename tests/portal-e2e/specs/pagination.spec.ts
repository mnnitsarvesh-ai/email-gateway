/**
 * Cursor pagination (design P8): forward keyset pages with a cursor stack (Next / Previous), no
 * totals ("Page N · R rows"). Users (25 per page, ≥ 40 seeded), messages (50 per page, 142 in
 * the last 7 days) and audit logs (25 per page, ≥ 70 seeded).
 */
import type { Page } from '@playwright/test';
import { signIn } from '../support/auth';
import { expect, test } from '../support/fixtures';
import { readState } from '../support/state';

async function rowKeys(page: Page): Promise<string[]> {
  const rows = page.locator('main table').first().locator('tbody tr');
  await expect(rows.first()).toBeVisible();
  // Text without relative times ("5 minutes ago" changes while the test runs) plus the labelled
  // controls of the row (audit rows can share their visible text; the "Details of <action> at
  // <time>" button tells them apart).
  return rows.evaluateAll((trs) =>
    trs.map((tr) =>
      [
        (tr as HTMLElement).innerText
          .replace(/\b(an?|\d+) (second|minute|hour|day|month|year)s? ago\b/g, '')
          .replace(/\s+/g, ' ')
          .trim(),
        ...[...tr.querySelectorAll('[aria-label]')].map((e) => e.getAttribute('aria-label')),
      ].join(' | '),
    ),
  );
}

async function walk(page: Page, pageSize: number, minimumRows: number): Promise<void> {
  const pager = page.getByRole('navigation', { name: /pagination$/ }).first();
  await expect(pager).toContainText(`Page 1 · ${pageSize} rows`);
  const first = await rowKeys(page);
  expect(first).toHaveLength(pageSize);
  await expect(pager.getByRole('button', { name: 'Previous' })).toBeDisabled();

  const seen = new Set(first);
  let pageNo = 1;
  let rows = first;
  while (seen.size < minimumRows) {
    const next = pager.getByRole('button', { name: 'Next' });
    await expect(next).toBeEnabled();
    const before = rows[0];
    await next.click();
    pageNo += 1;
    await expect(pager).toContainText(`Page ${pageNo} ·`);
    // The previous page stays visible while the next one loads.
    await expect.poll(async () => (await rowKeys(page))[0]).not.toBe(before);
    const current = await rowKeys(page);
    expect(current.length).toBeGreaterThan(0);
    // Keyset pages never repeat a row.
    for (const key of current) expect(seen.has(key), `row repeated on page ${pageNo}`).toBe(false);
    for (const key of current) seen.add(key);
    rows = current;
  }
  expect(rows.length).toBeGreaterThan(0);
  // Previous pops the cursor stack back to page 1 with the same rows.
  while (pageNo > 1) {
    await pager.getByRole('button', { name: 'Previous' }).click();
    pageNo -= 1;
    await expect(pager).toContainText(`Page ${pageNo} ·`);
  }
  await expect.poll(() => rowKeys(page)).toEqual(first);
}

test('users: more than one page of 25', async ({ page }) => {
  const s = readState();
  await signIn(page, 'alphaAdmin', { next: '/users' });
  await walk(page, 25, s.alpha.userCount);
  // The last page is short and has no Next.
  const pager = page.getByRole('navigation', { name: /pagination$/ }).first();
  await pager.getByRole('button', { name: 'Next' }).click();
  await expect(pager).toContainText('Page 2 ·');
  await expect(pager.getByRole('button', { name: 'Next' })).toBeDisabled();
});

test('messages: pages of 50 over the last 7 days', async ({ page }) => {
  await signIn(page, 'alphaAnalyst', { next: '/messages?range=7d' });
  await expect(page.getByText('Alpha clean message 000').first()).toBeVisible();
  await walk(page, 50, 120);
});

test('audit logs: pages of 25', async ({ page }) => {
  const s = readState();
  await signIn(page, 'alphaAdmin', { next: '/audit-logs?range=7d&actionPrefix=user.' });
  // Without a filter: every seeded row plus the run's own activity.
  await page.goto('/audit-logs?range=7d');
  await walk(page, 25, s.alpha.auditRows);
});
