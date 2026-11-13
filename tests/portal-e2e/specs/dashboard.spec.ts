/**
 * Dashboard (design §1.4): the 12 widgets show the figures computed independently from the
 * seeded rows (seed/plan.ts `expectDashboard`) for the default range (last 7 days).
 */
import type { Page } from '@playwright/test';
import { signIn } from '../support/auth';
import { expect, test } from '../support/fixtures';
import { readState } from '../support/state';

const nf = new Intl.NumberFormat('en-US');

function tile(page: Page, label: string) {
  return page
    .getByRole('heading', { level: 3, name: label, exact: true })
    .locator('xpath=ancestor::*[@data-slot="card"][1]');
}

test('the 12 widgets show the seeded figures for the last 7 days', async ({ page }) => {
  const state = readState();
  const want = state.expected.dashboard7d;
  await signIn(page, 'alphaAdmin', { next: '/dashboard?range=7d' });
  await expect(page).toHaveURL(/\/dashboard/);
  await expect(page.getByRole('heading', { level: 1, name: 'Dashboard' })).toBeVisible();

  const expectTile = async (label: string, value: string) => {
    await expect(tile(page, label)).toContainText(value);
  };
  // 1–4 traffic, 5–8 threats.
  await expectTile('Total emails processed', nf.format(want.total));
  await expectTile('Inbound emails', nf.format(want.inbound));
  await expectTile('Outbound emails', nf.format(want.outbound));
  await expectTile('Internal emails', nf.format(want.internal));
  await expectTile('Spam blocked', nf.format(want.spamBlocked));
  await expectTile('Malware detected', nf.format(want.malware));
  await expectTile('Phishing detected', nf.format(want.phishing));
  await expectTile('Quarantined emails', nf.format(want.quarantinedMessages));
  await expectTile(
    'Quarantined emails',
    `${nf.format(want.quarantineEntries)} quarantine ${want.quarantineEntries === 1 ? 'entry' : 'entries'}`,
  );
  // 9: delivery success rate (one decimal place, percent).
  expect(want.successRate).not.toBeNull();
  await expectTile('Delivery success rate', `${(want.successRate! * 100).toFixed(1)} %`);
  await expectTile(
    'Delivery success rate',
    `${nf.format(want.delivered)} delivered of ${nf.format(want.deliveries)} deliveries`,
  );
  // 10: time to verdict p95 as a histogram upper bound, average in the subtitle.
  expect(want.p95UpperBoundMs).not.toBeNull();
  const seconds = want.p95UpperBoundMs! / 1000;
  await expectTile(
    'Time to verdict (p95)',
    `≤ ${seconds < 10 ? seconds.toFixed(1) : seconds.toFixed(0)} s`,
  );
  await expectTile(
    'Time to verdict (p95)',
    `Average ${(want.averageMs! / 1000).toFixed(want.averageMs! < 10_000 ? 1 : 0)} s`,
  );

  // 11: threat trends, through the chart's table view (sum of each verdict column).
  const trendsFigure = page.getByRole('region', { name: 'Threat trends' }).getByRole('figure');
  await expect(
    trendsFigure.getByRole('img', { name: /^Threat verdicts over time\. / }),
  ).toBeVisible();
  await trendsFigure.getByRole('button', { name: 'View data as table' }).click();
  const table = trendsFigure.getByRole('table', { name: /data table/ });
  await expect(table).toBeVisible();
  const headers = (await table.locator('thead th').allTextContents()).map((h) => h.trim());
  const rows = await table.locator('tbody tr').all();
  for (const [verdict, label] of [
    ['spam', 'Spam'],
    ['phishing', 'Phishing'],
    ['malware', 'Malware'],
    ['bec', 'BEC'],
    ['suspicious', 'Suspicious'],
  ] as const) {
    const column = headers.findIndex((h) => h.toLowerCase() === label.toLowerCase());
    expect(column, `column ${label} in ${headers.join('|')}`).toBeGreaterThan(0);
    let sum = 0;
    for (const row of rows) {
      const cell = row.locator('th, td').nth(column);
      sum += Number(((await cell.textContent()) ?? '0').replace(/[^\d]/g, '') || 0);
    }
    expect(sum, `threat trend total of ${verdict}`).toBe(want.threatVerdicts[verdict] ?? 0);
  }

  // 12: top attacked domains (table), deleted domain marked, unattributed note.
  const top = page.getByRole('table', { name: 'Top attacked domains' });
  await expect(top.locator('tbody tr')).toHaveCount(want.topDomains.length);
  for (const [index, domain] of want.topDomains.entries()) {
    const row = top.locator('tbody tr').nth(index);
    await expect(row.locator('th')).toContainText(domain.name);
    await expect(row.locator('td').nth(0)).toHaveText(nf.format(domain.threats));
    await expect(row.locator('td').nth(1)).toHaveText(nf.format(domain.inbound));
    if (domain.deleted) await expect(row).toContainText('Deleted');
  }
  await expect(page.getByRole('note').filter({ hasText: 'could not be attributed' })).toContainText(
    `${nf.format(want.unattributed.inbound)} inbound messages (${nf.format(want.unattributed.threats)} with a threat verdict)`,
  );
  // Widgets never show an error state.
  await expect(page.getByText(/request id/i)).toHaveCount(0);
});
