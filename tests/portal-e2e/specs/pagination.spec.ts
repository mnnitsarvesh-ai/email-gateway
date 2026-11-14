/**
 * Cursor pagination (design P8): forward keyset pages with a cursor stack (Next / Previous), no
 * totals ("Page N · R rows"). Users (25 per page, ≥ 41 seeded), messages (50 per page, about
 * 150 in the last 7 days) and audit logs (25 per page, ≥ 70 seeded).
 */
import type { Page, Response } from '@playwright/test';
import { signIn } from '../support/auth';
import { expect, test } from '../support/fixtures';
import { readState } from '../support/state';

async function rowKeys(page: Page): Promise<string[]> {
  const rows = page.locator('main table').first().locator('tbody tr');
  await expect(rows.first()).toBeVisible();
  // Text without relative times ("5 minutes ago" changes while the test runs) plus the labelled
  // controls of the row: what the user sees, compared when Previous restores page 1.
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

/**
 * Walks forward until `minimumRows` distinct rows were seen, then back to page 1. Row identity is
 * the api's id from the list responses (`data[].id`): two audit rows of one actor, action and
 * second look identical on screen (the run itself writes such rows, e.g. `quarantine.searched`),
 * so the visible text alone cannot prove that keyset pages never repeat a row.
 */
async function walk(
  page: Page,
  listPath: string,
  pageSize: number,
  minimumRows: number,
): Promise<void> {
  // Bodies are read as they arrive (a body of a response the page navigated away from is gone).
  const responses: Array<{ cursor: boolean; ids: string[] }> = [];
  const listener = (res: Response) => {
    const url = new URL(res.url());
    if (url.pathname !== listPath || res.request().method() !== 'GET' || !res.ok()) return;
    void res
      .json()
      .then((body: { data: Array<{ id: string }> }) =>
        responses.push({ cursor: url.searchParams.has('cursor'), ids: body.data.map((r) => r.id) }),
      )
      .catch(() => undefined);
  };
  page.on('response', listener);
  const pageIds = async (action: () => Promise<unknown>, cursor: boolean): Promise<string[]> => {
    const before = responses.length;
    await action();
    await expect
      .poll(() => responses.slice(before).filter((r) => r.cursor === cursor).length)
      .toBeGreaterThan(0);
    return responses
      .slice(before)
      .filter((r) => r.cursor === cursor)
      .at(-1)!.ids;
  };
  const pager = page.getByRole('navigation', { name: /pagination$/ }).first();
  const firstIds = await pageIds(() => page.reload(), false);
  expect(firstIds).toHaveLength(pageSize);
  await expect(pager).toContainText(`Page 1 · ${pageSize} rows`);
  const first = await rowKeys(page);
  expect(first).toHaveLength(pageSize);
  await expect(pager.getByRole('button', { name: 'Previous' })).toBeDisabled();

  const seen = new Set(firstIds);
  let pageNo = 1;
  while (seen.size < minimumRows) {
    const next = pager.getByRole('button', { name: 'Next' });
    await expect(next).toBeEnabled();
    const ids = await pageIds(() => next.click(), true);
    pageNo += 1;
    await expect(pager).toContainText(`Page ${pageNo} · ${ids.length} row`);
    expect(ids.length).toBeGreaterThan(0);
    // Keyset pages never repeat a row.
    for (const id of ids) expect(seen.has(id), `row ${id} repeated on page ${pageNo}`).toBe(false);
    for (const id of ids) seen.add(id);
    expect(await rowKeys(page)).toHaveLength(ids.length);
  }
  // Previous pops the cursor stack back to page 1 with the same rows.
  while (pageNo > 1) {
    await pager.getByRole('button', { name: 'Previous' }).click();
    pageNo -= 1;
    await expect(pager).toContainText(`Page ${pageNo} ·`);
  }
  await expect.poll(() => rowKeys(page)).toEqual(first);
  page.off('response', listener);
}

test('users: more than one page of 25', async ({ page }) => {
  const s = readState();
  await signIn(page, 'alphaAdmin', { next: '/users' });
  await walk(page, '/bff/api/v1/users', 25, s.alpha.userCount);
  // The last page is short and has no Next.
  const pager = page.getByRole('navigation', { name: /pagination$/ }).first();
  await pager.getByRole('button', { name: 'Next' }).click();
  await expect(pager).toContainText('Page 2 ·');
  await expect(pager.getByRole('button', { name: 'Next' })).toBeDisabled();
});

test('messages: pages of 50 over the last 7 days', async ({ page }) => {
  await signIn(page, 'alphaAnalyst', { next: '/messages?range=7d' });
  // Subjects are masked since step 7.2: the rows differ by sender, verdict and risk score.
  await expect(page.locator('main table tbody').getByText('Hidden').first()).toBeVisible();
  await walk(page, '/bff/api/v1/messages', 50, 120);
});

test('audit logs: pages of 25', async ({ page }) => {
  const s = readState();
  await signIn(page, 'alphaAdmin', { next: '/audit-logs?range=7d&actionPrefix=user.' });
  // Without a filter: every seeded row plus the run's own activity.
  await page.goto('/audit-logs?range=7d');
  await walk(page, '/bff/api/v1/audit/logs', 25, s.alpha.auditRows);
});
