/**
 * Email Explorer (step 7.2 §2 E10, §9) against the real api and the seeded data (seed/plan.ts
 * `planExplorerAlpha`): search by every field, every filter with its exact expected rows in a
 * custom time window, sort, pagination, column visibility kept across a reload, saved views
 * (create, apply, rename, delete, server-side), the audited subject reveal (one bulk call per
 * page, `message.revealed` rows on the writer), the masked view of a read-only user and the
 * debounced search (one request while typing).
 */
import type { Page } from '@playwright/test';
import { signIn, user } from '../support/auth';
import { expect, test } from '../support/fixtures';
import {
  bff,
  expectListAfter,
  expectRows,
  isListRequest,
  messageAuditRows,
  messageOf,
  pager,
  spy,
  userPublicId,
  writerDb,
} from '../support/messages';
import { expectNoSeriousA11yViolations, expectSettled } from '../support/pages';
import { readState } from '../support/state';
import { EXPLORER_WINDOW, MINUTE } from '../seed/plan';

test.describe.configure({ timeout: 240_000 });

/** `YYYY-MM-DDTHH:mm` (UTC: the browser runs with `timezoneId: 'UTC'`). */
const localMinute = (ms: number) => new Date(ms).toISOString().slice(0, 16);

/** The explorer test window (whole minutes, see seed/plan.ts EXPLORER_WINDOW). */
function windowOf(): { from: string; to: string; fromMs: number; toMs: number } {
  const seeded = Date.parse(readState().seededAt);
  const fromMs = Math.floor((seeded - EXPLORER_WINDOW.fromMinutesAgo * MINUTE) / MINUTE) * MINUTE;
  const toMs = Math.floor((seeded - EXPLORER_WINDOW.toMinutesAgo * MINUTE) / MINUTE) * MINUTE;
  return { from: localMinute(fromMs), to: localMinute(toMs), fromMs, toMs };
}

async function chooseField(page: Page, label: string): Promise<void> {
  await page.getByRole('combobox', { name: 'Search field' }).click();
  await page.getByRole('option', { name: label, exact: true }).click();
}

/** Selects a search field, types the value and commits it with Enter. */
async function search(page: Page, field: string, value: string): Promise<void> {
  await chooseField(page, field);
  const input = page.getByRole('searchbox', { name: `Search by ${field}` });
  await input.fill(value);
  await input.press('Enter');
}

async function removeChip(page: Page, field: string): Promise<void> {
  await page.getByRole('button', { name: `Remove search ${field}` }).click();
}

async function chooseSelect(page: Page, label: string, option: string): Promise<void> {
  await page
    .getByRole('combobox', { name: new RegExp(`^${label}`) })
    .first()
    .click();
  await page.getByRole('option', { name: option, exact: true }).click();
}

async function toggleMulti(page: Page, label: string, option: string): Promise<void> {
  await page.getByRole('button', { name: new RegExp(`^${label}`) }).click();
  await page.getByRole('menuitemcheckbox', { name: option, exact: true }).click();
  await page.keyboard.press('Escape');
}

test('search by every field; sort; Message-ID with brackets; beta twin never listed', async ({
  page,
}) => {
  const s = readState();
  await signIn(page, 'alphaAnalyst', { next: '/messages' });
  await expect(page.getByRole('heading', { level: 1, name: 'Email explorer' })).toBeVisible();
  await expectSettled(page, '/messages');
  await expectNoSeriousA11yViolations(page, '/messages');

  // [field label, typed value, URL key (§3.6), fragment of the GET /messages query, rows]
  const cases: Array<[field: string, value: string, key: string, param: string, rows: number]> = [
    ['Sender (envelope)', 'invoices@vendor-one.e2e-portal.test', 'sender', 'sender=', 2],
    ['Sender (From header)', 'security@vendor-two.e2e-portal.test', 'headerFrom', 'headerFrom=', 1],
    ['Recipient', 'CFO@customer-two.e2e-portal.test', 'recipient', 'recipient=cfo@', 1],
    ['Subject', 'RE: invoice 4471 for october', 'subject', 'subject=', 1],
    ['Subject starts with', 'Invoice 44', 'subjectPrefix', 'subjectPrefix=', 2],
    ['Message ID', 'inv-4472.e2e@vendor-one.e2e-portal.test', 'messageId', 'internetMessageId=', 1],
    ['Sender domain', 'vendor-one.e2e-portal.test', 'senderDomain', 'senderDomain=', 2],
    [
      'Recipient domain',
      '@customer-two.e2e-portal.test',
      'recipientDomain',
      'recipientDomain=customer-two',
      1,
    ],
    [
      'Recipient domain',
      'partner-three.e2e-portal.test',
      'recipientDomain',
      'recipientDomain=partner-three',
      1,
    ],
  ];
  for (const [field, value, key, param, rows] of cases) {
    await expectListAfter(page, () => search(page, field, value), rows, param);
    await expect(page).toHaveURL(new RegExp(`[?&]${key}=`));
    await expect(page.getByRole('list', { name: 'Active searches' })).toContainText(field);
    // The beta twin (same sender and Message-ID) and no other tenant's data appear.
    await expect(page.locator('main')).not.toContainText(s.beta.domainName);
    // Removing the chip restores the default 24-hour list (a full first page; served from the
    // query cache, so no new request is awaited).
    await removeChip(page, field);
    await expect(page.getByRole('list', { name: 'Active searches' })).toHaveCount(0);
    await expectRows(page, 50);
  }

  // Message-ID in angle brackets: the same message (brackets optional, §2 E2).
  await expectListAfter(
    page,
    () => search(page, 'Message ID', '<inv-4471.e2e@vendor-one.e2e-portal.test>'),
    1,
    'internetMessageId=<inv-4471',
  );
  await page.locator('main table tbody tr').first().getByRole('link').click();
  await expect(page).toHaveURL(new RegExp(`/messages/${messageOf('alpha-search-1')}`));
  await page.goBack();

  // Sort: newest first by default; the header toggles to oldest first (`sort=receivedAt`).
  await page.goto('/messages?senderDomain=vendor-one.e2e-portal.test');
  await expectRows(page, 2);
  // The two messages differ by risk score (110 for search 1, 480 for search 2).
  const firstRisk = async () => {
    const text = await page.locator('main table tbody tr').first().innerText();
    return /\b110\b/.test(text) ? '110' : /\b480\b/.test(text) ? '480' : text;
  };
  await expect.poll(firstRisk).toBe('110');
  await expectListAfter(
    page,
    () => page.getByRole('button', { name: /^Received\s*, change sort order/ }).click(),
    2,
    'sort=receivedAt',
  );
  await expect(page).toHaveURL(/[?&]sort=receivedAt/);
  await expect.poll(firstRisk).toBe('480');
  await expect(
    page.locator('main thead th').filter({ has: page.getByRole('button', { name: /^Received/ }) }),
  ).toHaveAttribute('aria-sort', 'ascending');
});

test('every filter returns exactly the seeded rows of a custom time window', async ({ page }) => {
  const w = windowOf();
  await signIn(page, 'alphaAnalyst', { next: '/messages' });

  // Custom range through the picker (minute precision, browser time zone = UTC).
  await page.getByRole('button', { name: 'Choose a custom time range' }).click();
  await page.getByLabel('From', { exact: true }).fill(w.from);
  await page.getByLabel('To', { exact: true }).fill(w.to);
  const expected = readState().alpha.recentReceivedAt.filter((iso) => {
    const t = Date.parse(iso);
    return t >= w.fromMs && t < w.toMs;
  }).length;
  // Search 1–4, details phish and outbound, generated message 1 (seed/plan.ts).
  expect(expected).toBe(7);
  await expectListAfter(
    page,
    () => page.getByRole('button', { name: 'Apply', exact: true }).click(),
    expected,
  );
  await expect(page).toHaveURL(/[?&]range=custom/);
  const base = new URL(page.url());
  await expectNoSeriousA11yViolations(page, '/messages (custom range)');

  const reset = async () => {
    await page.goto(`/messages${base.search}`);
    await expectRows(page, expected);
  };

  await expectListAfter(page, () => toggleMulti(page, 'Direction', 'Outbound'), 2, 'direction=');
  await reset();
  await expectListAfter(page, () => toggleMulti(page, 'Verdict', 'Phishing'), 2, 'verdict=');
  await reset();
  await expectListAfter(page, () => toggleMulti(page, 'Action', 'Tag'), 2, 'action=');
  await reset();
  await expectListAfter(page, () => toggleMulti(page, 'Status', 'Quarantined'), 2, 'status=');
  await reset();
  await expectListAfter(
    page,
    () => chooseSelect(page, 'Risk score band', '800–1000'),
    2,
    'riskScore.gte=800',
  );
  await reset();
  await page.getByLabel('Risk from').fill('500');
  await expectListAfter(page, () => page.getByLabel('Risk from').press('Enter'), 3, 'riskScore');
  await reset();
  await expectListAfter(
    page,
    () => chooseSelect(page, 'Attachments', 'With attachments'),
    3,
    'hasAttachments=true',
  );
  await reset();
  await expectListAfter(
    page,
    () => chooseSelect(page, 'Delivery status', 'Bounced'),
    2,
    'deliveryStatus=bounced',
  );
  await reset();
  await expectListAfter(
    page,
    () => chooseSelect(page, 'Delivery status', 'Deferred'),
    1,
    'deliveryStatus=deferred',
  );
  await reset();
  await expectListAfter(
    page,
    () => chooseSelect(page, 'Delivery status', 'Delivered'),
    4,
    'deliveryStatus=delivered',
  );
  await reset();
  await expectListAfter(
    page,
    () => chooseSelect(page, 'Quarantine status', 'Held'),
    2,
    'quarantineStatus=held',
  );
  await reset();
  await expectListAfter(
    page,
    () => chooseSelect(page, 'Domain', readState().alpha.domainName),
    expected - 1,
    'domainId=',
  );
  await reset();
  await expectListAfter(page, () => toggleMulti(page, 'Direction', 'Internal'), 0, 'direction=');
  // "Clear filters" restores the window (the cached first query: no new request awaited).
  await page.getByRole('button', { name: 'Clear filters' }).first().click();
  await expect(page).not.toHaveURL(/[?&]direction=/);
  await expectRows(page, expected);
});

test('pagination, column visibility kept across a reload', async ({ page }) => {
  await signIn(page, 'alphaAnalyst', { next: '/messages?range=7d' });
  await expectRows(page, 50);
  const nav = pager(page);
  await nav.getByRole('button', { name: 'Next' }).click();
  await expect(nav).toContainText('Page 2 ·');
  await nav.getByRole('button', { name: 'Previous' }).click();
  await expect(nav).toContainText('Page 1 · 50 rows');

  await page.getByRole('button', { name: 'Columns' }).click();
  await page.getByRole('menuitemcheckbox', { name: 'Size', exact: true }).click();
  await page.keyboard.press('Escape');
  await expect(page.getByRole('columnheader', { name: 'Size' })).toHaveCount(0);
  await page.reload();
  await expectRows(page, 50);
  await expect(page.getByRole('columnheader', { name: 'Size' })).toHaveCount(0);
  await expect(page.getByRole('columnheader', { name: 'Risk' })).toBeVisible();
  await page.getByRole('button', { name: 'Columns' }).click();
  await page.getByRole('menuitemcheckbox', { name: 'Size', exact: true }).click();
  await page.keyboard.press('Escape');
  await expect(page.getByRole('columnheader', { name: 'Size' })).toBeVisible();
});

test('saved views: create, apply, rename, delete (stored server-side)', async ({ page }) => {
  const analyst = user('alphaAnalyst');
  const owner = await writerDb().user.findFirstOrThrow({
    where: { email: analyst.email },
    select: { id: true },
  });
  const countViews = () => writerDb().savedView.count({ where: { userId: owner.id } });
  const before = await countViews();

  await signIn(page, 'alphaAnalyst', { next: '/messages' });
  await expectListAfter(
    page,
    () => search(page, 'Sender (envelope)', 'invoices@vendor-one.e2e-portal.test'),
    2,
    'sender=',
  );
  await page.getByRole('button', { name: /^Views/ }).click();
  await page.getByRole('menuitem', { name: /Save as new view/ }).click();
  const dialog = page.getByRole('dialog', { name: 'Save as new view' });
  await dialog.getByLabel('Name (required)').fill('E2E vendor invoices');
  await expectNoSeriousA11yViolations(page, 'save view dialog');
  await dialog.getByRole('button', { name: 'Save view' }).click();
  await expect(dialog).toHaveCount(0);
  await expect(page.getByRole('button', { name: /^Views: E2E vendor invoices/ })).toBeVisible();
  await expect.poll(countViews).toBe(before + 1);

  // Apply from a clean explorer: the URL and the rows come back.
  await page.goto('/messages');
  await expectRows(page, 50);
  await page.getByRole('button', { name: /^Views/ }).click();
  await expectListAfter(
    page,
    () => page.getByRole('menuitemradio', { name: 'E2E vendor invoices' }).click(),
    2,
    'sender=',
  );
  await expect(page).toHaveURL(/[?&]sender=invoices%40vendor-one\.e2e-portal\.test/);
  await expect(page).toHaveURL(/[?&]view=/);

  // Rename.
  await page.getByRole('button', { name: /^Views/ }).click();
  await page.getByRole('menuitem', { name: /^Rename/ }).click();
  const rename = page.getByRole('dialog', { name: 'Rename view' });
  await rename.getByLabel('Name (required)').fill('E2E vendor invoices (renamed)');
  await rename.getByRole('button', { name: 'Rename' }).click();
  await expect(rename).toHaveCount(0);
  await expect(
    page.getByRole('button', { name: /^Views: E2E vendor invoices \(renamed\)/ }),
  ).toBeVisible();
  await expect
    .poll(async () =>
      (
        await writerDb().savedView.findMany({ where: { userId: owner.id }, select: { name: true } })
      ).map((v) => v.name),
    )
    .toContain('E2E vendor invoices (renamed)');

  // Delete with confirmation.
  await page.getByRole('button', { name: /^Views/ }).click();
  await page.getByRole('menuitem', { name: /^Delete/ }).click();
  const confirm = page.getByRole('alertdialog', { name: 'Delete saved view' });
  await confirm.getByRole('button', { name: 'Delete view' }).click();
  await expect(confirm).toHaveCount(0);
  await expect.poll(countViews).toBe(before);
  await page.getByRole('button', { name: /^Views/ }).click();
  await expect(page.getByRole('menuitem', { name: 'No saved views yet' })).toBeVisible();
  await page.keyboard.press('Escape');
});

test('subject reveal: one audited bulk call per page, rows on the writer, forgotten when off', async ({
  page,
}) => {
  const started = new Date(Date.now() - 1_000);
  await signIn(page, 'alphaAnalyst', { next: '/messages?senderDomain=vendor-one.e2e-portal.test' });
  await expectRows(page, 2);
  await expect(page.locator('main table tbody')).toContainText('Hidden');
  await expect(page.locator('main')).not.toContainText('Invoice 4471');

  const reveals = spy(
    page,
    (request) =>
      request.method() === 'POST' &&
      new URL(request.url()).pathname === '/bff/api/v1/messages/reveal',
  );
  await page.getByRole('switch', { name: 'Show subjects' }).click();
  const table = page.locator('main table tbody');
  await expect(table).toContainText('RE: Invoice 4471 for October');
  await expect(table).toContainText('Fwd: Invoice 4472 for November');
  await expect(table.getByText('Revealed').first()).toBeVisible();
  const ids = [messageOf('alpha-search-1'), messageOf('alpha-search-2')];
  // One call for the page, with exactly the page's ids (a CSRF-protected POST).
  expect(reveals.seen).toHaveLength(1);
  expect(reveals.seen[0]!.headers['x-csrf-token']).toBeTruthy();
  expect(
    (JSON.parse(reveals.seen[0]!.body ?? '{}') as { messageIds: string[] }).messageIds.sort(),
  ).toEqual([...ids].sort());

  const actor = await userPublicId(user('alphaAnalyst').email);
  await expect
    .poll(async () => (await messageAuditRows('message.revealed', ids, started)).length)
    .toBe(2);
  for (const row of await messageAuditRows('message.revealed', ids, started)) {
    expect(row.actorId).toBe(actor);
    expect(row.metadata).toMatchObject({ fields: ['subject'], bulk: true });
    // Never the value itself.
    expect(JSON.stringify(row.metadata)).not.toContain('Invoice');
  }

  // Off: the values are forgotten; on again re-reveals the page (a new audited call).
  await page.getByRole('switch', { name: 'Show subjects' }).click();
  await expect(page.locator('main')).not.toContainText('Invoice 4471');
  reveals.stop();
  await expectNoSeriousA11yViolations(page, '/messages (subjects revealed and hidden)');
});

test('read-only user: masked subjects, no subject or recipient search, no reveal, no saved-view leak', async ({
  page,
}) => {
  await signIn(page, 'alphaReadOnly', { next: '/messages?range=7d' });
  await expectRows(page, 50);
  await expect(page.locator('main table tbody')).toContainText('Hidden');
  await expect(page.getByRole('switch', { name: 'Show subjects' })).toHaveCount(0);
  await page.getByRole('combobox', { name: 'Search field' }).click();
  const options = (await page.getByRole('option').allTextContents()).map((o) => o.trim());
  expect(options).toEqual(
    expect.arrayContaining([
      'Sender (envelope)',
      'Recipient domain',
      'Message ID',
      'Sender domain',
    ]),
  );
  expect(options).not.toContain('Subject');
  expect(options).not.toContain('Subject starts with');
  // The exact recipient would confirm a masked address (ADR-0062, §13 closer).
  expect(options).not.toContain('Recipient');
  await page.keyboard.press('Escape');
  // A shared link with a subject search is not applied (and says so).
  await page.goto('/messages?subject=Invoice%204471%20for%20October');
  await expect(page.getByRole('status').filter({ hasText: 'need permissions' })).toBeVisible();
  await expectRows(page, 50);
  // Neither is an exact recipient; the api refuses it for this role too.
  await page.goto('/messages?range=7d&recipient=cfo%40customer-two.e2e-portal.test');
  await expect(
    page
      .getByRole('status')
      .filter({ hasText: 'need permissions' })
      .filter({ hasText: 'Recipient' }),
  ).toBeVisible();
  await expectRows(page, 50);
  const refused = await bff(page, 'GET', '/messages?recipient=cfo%40customer-two.e2e-portal.test');
  expect(refused.status).toBe(403);
  expect(refused.body).toMatchObject({
    code: 'message_filter_forbidden',
    filter: 'recipient',
    permission: 'message:reveal',
  });
  await expectNoSeriousA11yViolations(page, '/messages (read-only user)');
});

test('debounced search: one list request while typing a value', async ({ page }) => {
  await signIn(page, 'alphaAnalyst', { next: '/messages' });
  await expectRows(page, 50);
  await chooseField(page, 'Sender (envelope)');
  const lists = spy(page, (request) => request.method() === 'GET' && isListRequest(request.url()));
  const input = page.getByRole('searchbox', { name: 'Search by Sender (envelope)' });
  const committed = page.waitForResponse(
    (res) => isListRequest(res.url()) && res.url().includes('sender='),
  );
  await input.pressSequentially('invoices@vendor-one.e2e-portal.test', { delay: 40 });
  await committed;
  await expectRows(page, 2);
  // Idle well past the 600 ms commit delay: nothing more is sent.
  await page.waitForTimeout(1_500);
  lists.stop();
  expect(lists.seen.map((r) => decodeURIComponent(r.url))).toHaveLength(1);
  expect(decodeURIComponent(lists.seen[0]!.url)).toContain(
    'sender=invoices@vendor-one.e2e-portal.test',
  );
});
