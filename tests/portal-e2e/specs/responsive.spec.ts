/**
 * Responsive layout (design P11, P14) in the three projects: desktop 1440×900 (expanded
 * sidebar, collapsible), tablet 834×1112 (icon rail, expandable) and mobile 390×844 (drawer from
 * the top bar, focus-trapped, closes on navigation). No top-level page scrolls horizontally;
 * data tables stay usable (stacked cards on mobile, a scrolling table otherwise). Step 7.2: the
 * Email Explorer and every Email Details section fit each viewport; the section navigation is
 * vertical tabs (desktop), a horizontal tab list (tablet) or a labelled select (mobile). Step 7.3:
 * the policy builder (summary beside the editor from 1280 px, above it below; stacked condition
 * rows and full-screen panel sheets below 640 px), the policy pages and the DLP/BEC editor sheets
 * fit every viewport. Step 8.4: the account takeover and incident pages fit every viewport.
 */
import type { Page, TestInfo } from '@playwright/test';
import { signIn } from '../support/auth';
import { NAV_GATES } from '../support/contract';
import { expect, test } from '../support/fixtures';
import { atoAccount } from '../support/ato';
import { messageOf } from '../support/messages';
import { expectNoSeriousA11yViolations } from '../support/pages';
import { readState } from '../support/state';

test.use({ actionTimeout: 20_000 });

type Layout = 'desktop' | 'tablet' | 'mobile';

function layoutOf(testInfo: TestInfo): Layout {
  const name = testInfo.project.name;
  return name === 'mobile' ? 'mobile' : name === 'tablet' ? 'tablet' : 'desktop';
}

async function horizontalOverflow(page: Page): Promise<number> {
  return page.evaluate(() => {
    const root = document.documentElement;
    return Math.max(root.scrollWidth, document.body.scrollWidth) - root.clientWidth;
  });
}

test('navigation: sidebar, rail or drawer', async ({ page }, testInfo) => {
  const layout = layoutOf(testInfo);
  await signIn(page, 'alphaAdmin', { next: '/dashboard' });
  const sidebar = page.getByRole('complementary', { name: 'Sidebar' });
  const nav = page.getByRole('navigation', { name: 'Main' });

  if (layout === 'desktop') {
    await expect(sidebar).toBeVisible();
    await expect(nav.getByRole('link', { name: 'Users' })).toBeVisible();
    expect((await sidebar.boundingBox())!.width).toBeGreaterThan(200);
    // Collapsible to the rail and back (state kept per viewer).
    await page.getByRole('button', { name: 'Collapse sidebar' }).click();
    await expect.poll(async () => (await sidebar.boundingBox())!.width).toBeLessThan(80);
    await page.getByRole('button', { name: 'Expand sidebar' }).click();
    await expect.poll(async () => (await sidebar.boundingBox())!.width).toBeGreaterThan(200);
    await expect(page.getByRole('button', { name: 'Open navigation' })).toHaveCount(0);
  } else if (layout === 'tablet') {
    // Icon rail: the links are there, their text is visually hidden; expandable.
    await expect(sidebar).toBeVisible();
    expect((await sidebar.boundingBox())!.width).toBeLessThan(80);
    await expect(nav.getByRole('link', { name: 'Users' })).toBeAttached();
    await page.getByRole('button', { name: 'Expand sidebar' }).click();
    await expect.poll(async () => (await sidebar.boundingBox())!.width).toBeGreaterThan(200);
    await page.getByRole('button', { name: 'Collapse sidebar' }).click();
    await expect.poll(async () => (await sidebar.boundingBox())!.width).toBeLessThan(80);
    await nav.getByRole('link', { name: 'Users' }).click();
    await expect(page).toHaveURL(/\/users/);
  } else {
    // Drawer: no sidebar; the menu button opens a modal dialog that traps focus.
    await expect(sidebar).toHaveCount(0);
    const open = page.getByRole('button', { name: 'Open navigation' });
    await open.click();
    const drawer = page.getByRole('dialog', { name: 'Navigation' });
    await expect(drawer).toBeVisible();
    for (let i = 0; i < 40; i++) {
      await page.keyboard.press('Tab');
      const inside = await page.evaluate(() => {
        const dialog = document.querySelector('[role="dialog"]');
        return Boolean(dialog && document.activeElement && dialog.contains(document.activeElement));
      });
      expect(inside, `focus stays in the drawer (Tab ${i + 1})`).toBe(true);
    }
    await page.keyboard.press('Escape');
    await expect(drawer).toHaveCount(0);
    await expect(open).toBeFocused();
    // Closes on navigation.
    await open.click();
    await drawer.getByRole('link', { name: 'Users' }).click();
    await expect(page).toHaveURL(/\/users/);
    await expect(drawer).toHaveCount(0);
  }
});

test('no horizontal page overflow on any top-level page', async ({ page }, testInfo) => {
  test.setTimeout(300_000);
  await signIn(page, 'alphaAdmin', { next: '/dashboard' });
  const offenders: string[] = [];
  for (const item of NAV_GATES) {
    const path =
      item.href === '/messages' || item.href === '/audit-logs'
        ? `${item.href}?range=7d`
        : item.href;
    await page.goto(path);
    await expect(page.locator('main h1').first()).toBeVisible({ timeout: 20_000 });
    await expect(page.locator('main [aria-busy="true"]')).toHaveCount(0, { timeout: 20_000 });
    const overflow = await horizontalOverflow(page);
    if (overflow > 1) offenders.push(`${path}: ${overflow}px`);
  }
  expect(offenders, `pages wider than the ${layoutOf(testInfo)} viewport`).toEqual([]);
});

test('data tables: cards on mobile, a scrolling table otherwise', async ({ page }, testInfo) => {
  const layout = layoutOf(testInfo);
  await signIn(page, 'alphaAdmin', { next: '/users' });
  const region = page.getByRole('region', { name: /users/i }).first();
  if (layout === 'mobile') {
    const cards = page.getByTestId('data-table-cards');
    await expect(cards).toBeVisible();
    await expect(cards.getByRole('listitem').first()).toContainText('@alpha.e2e-portal.test');
    await expect(page.locator('main table')).toHaveCount(0);
    // Row actions and paging stay reachable.
    await expect(page.getByRole('navigation', { name: /pagination$/ }).first()).toBeVisible();
  } else {
    const table = page.locator('main table').first();
    await expect(table).toBeVisible();
    await expect(table.locator('tbody tr').first()).toContainText('@alpha.e2e-portal.test');
    // The table scrolls inside its container, never the page.
    expect(await horizontalOverflow(page)).toBeLessThanOrEqual(1);
  }
  await expect(region.or(page.locator('main')).first()).toBeVisible();
});

test('email explorer and details fit the viewport; section navigation per layout', async ({
  page,
}, testInfo) => {
  test.setTimeout(300_000);
  const layout = layoutOf(testInfo);
  await signIn(page, 'alphaAnalyst', { next: '/messages?range=7d' });
  await expect(page.locator('main [aria-busy="true"]')).toHaveCount(0, { timeout: 20_000 });
  if (layout === 'mobile') {
    await expect(page.getByTestId('data-table-cards')).toBeVisible();
  } else {
    await expect(page.locator('main table').first()).toBeVisible();
  }
  // Search bar, chips and the reveal switch stay inside the viewport.
  await page.getByRole('switch', { name: 'Show subjects' }).click();
  await page.goto('/messages?senderDomain=vendor-one.e2e-portal.test&direction=inbound');
  await expect(page.getByRole('list', { name: 'Active searches' })).toBeVisible();
  expect(
    await horizontalOverflow(page),
    `explorer wider than the ${layout} viewport`,
  ).toBeLessThanOrEqual(1);
  await expectNoSeriousA11yViolations(page, `/messages (${layout})`);

  const phish = messageOf('alpha-detail-phish');
  await page.goto(`/messages/${phish}`);
  await expect(page.getByRole('heading', { level: 1, name: 'Email details' })).toBeVisible();
  if (layout === 'mobile') {
    await expect(page.getByLabel('Section', { exact: true })).toBeVisible();
    await expect(page.getByRole('tablist', { name: 'Message sections' })).toHaveCount(0);
  } else {
    const tabs = page.getByRole('tablist', { name: 'Message sections' });
    await expect(tabs).toBeVisible();
    await expect(tabs).toHaveAttribute(
      'aria-orientation',
      layout === 'desktop' ? 'vertical' : 'horizontal',
    );
  }
  const offenders: string[] = [];
  for (const section of [
    'summary',
    'people',
    'headers',
    'authentication',
    'spam',
    'phishing',
    'urls',
    'attachments',
    'dlp',
    'risk',
    'policy',
    'delivery',
    'quarantine',
    'audit',
  ]) {
    await page.goto(`/messages/${phish}?section=${section}`);
    await expect(page.locator('main h2').first()).toBeVisible({ timeout: 20_000 });
    await expect(page.locator('main [aria-busy="true"]')).toHaveCount(0, { timeout: 20_000 });
    const overflow = await horizontalOverflow(page);
    if (overflow > 1) offenders.push(`${section}: ${overflow}px`);
    // Each section at each width (tables that scroll on a phone must be keyboard-scrollable).
    await expectNoSeriousA11yViolations(page, `/messages/[id]?section=${section} (${layout})`);
  }
  expect(offenders, `details sections wider than the ${layout} viewport`).toEqual([]);
  if (layout === 'mobile') {
    // The select navigates between sections.
    await page.getByLabel('Section', { exact: true }).selectOption({ label: 'Email headers' });
    await expect(page).toHaveURL(/[?&]section=headers/);
  }
  await expectNoSeriousA11yViolations(page, `/messages/[id] (${layout})`);
});

test('policy builder: summary placement, stacked conditions, panels as sheets', async ({
  page,
}, testInfo) => {
  test.setTimeout(300_000);
  const layout = layoutOf(testInfo);
  const { policies } = readState();
  await signIn(page, 'alphaAdmin', { next: `/policies/${policies.policyId}/versions/3` });
  await expect(page.getByRole('heading', { level: 1 })).toHaveText(`${policies.policyName} · v3`);
  await expect(page.locator('main [aria-busy="true"]')).toHaveCount(0, { timeout: 20_000 });
  const viewport = page.viewportSize()!;
  const summary = page.getByRole('complementary', { name: 'Readable summary of the policy' });
  const rules = page.getByRole('region', { name: /^Rules \(/ });
  const summaryBox = (await summary.boundingBox())!;
  const rulesBox = (await rules.boundingBox())!;
  if (layout === 'desktop') {
    // ≥ 1280 px: editor and summary side by side.
    expect(summaryBox.x).toBeGreaterThan(rulesBox.x + rulesBox.width - 1);
  } else {
    // Below 1280 px: the summary comes first, above the editor.
    expect(summaryBox.y + summaryBox.height).toBeLessThanOrEqual(rulesBox.y + 1);
  }
  const condition = page
    .getByRole('group', { name: /^Condition 1 of \d+ in all of the following \(AND\), level 1$/ })
    .first();
  const field = (await condition.getByRole('combobox', { name: /^Field / }).boundingBox())!;
  const operator = (await condition.getByRole('combobox', { name: 'Operator' }).boundingBox())!;
  if (layout === 'mobile') {
    // < 640 px: field, operator and value each on their own line.
    expect(operator.y).toBeGreaterThanOrEqual(field.y + field.height - 1);
  } else {
    expect(Math.abs(operator.y - field.y)).toBeLessThan(4);
  }
  expect(
    await horizontalOverflow(page),
    `builder wider than the ${layout} viewport`,
  ).toBeLessThanOrEqual(1);
  await expectNoSeriousA11yViolations(page, `/policies/[id]/versions/3 (${layout})`);

  // The test panel: a side panel on desktop, a full-screen sheet on a phone.
  await page
    .getByRole('group', { name: 'Version actions' })
    .getByRole('button', { name: 'Test' })
    .click();
  const panel = page.getByRole('dialog', { name: 'Test with synthetic facts' });
  await expect(panel).toBeVisible();
  const panelBox = (await panel.boundingBox())!;
  if (layout === 'mobile') {
    expect(panelBox.width).toBeGreaterThanOrEqual(viewport.width - 1);
  } else {
    expect(panelBox.width).toBeLessThan(viewport.width);
  }
  await expectNoSeriousA11yViolations(page, `test panel (${layout})`);
  await panel.getByRole('button', { name: 'Close' }).last().click();

  const offenders: string[] = [];
  for (const path of [
    '/policies/new',
    `/policies/${policies.policyId}`,
    `/policies/${policies.policyId}?tab=versions`,
    `/policies/${policies.policyId}/compare?from=1&to=2`,
    '/policies?tab=settings',
    '/policies?tab=risk',
    '/policies?tab=dlp',
    '/policies?tab=bec',
  ]) {
    await page.goto(path);
    await expect(page.locator('main h1').first()).toBeVisible({ timeout: 20_000 });
    await expect(page.locator('main [aria-busy="true"]')).toHaveCount(0, { timeout: 20_000 });
    const overflow = await horizontalOverflow(page);
    if (overflow > 1) offenders.push(`${path}: ${overflow}px`);
    await expectNoSeriousA11yViolations(page, `${path} (${layout})`);
  }
  expect(offenders, `policy pages wider than the ${layout} viewport`).toEqual([]);
});

test('DLP and BEC editor sheets fit the viewport', async ({ page }, testInfo) => {
  const layout = layoutOf(testInfo);
  await signIn(page, 'alphaAnalyst', { next: '/policies?tab=dlp' });
  for (const [tab, section, button, title] of [
    ['dlp', 'Patterns', 'New pattern', 'New custom pattern'],
    ['dlp', 'Exceptions', 'New exception', 'New DLP exception'],
    ['bec', 'Executives', 'New executive', 'New executive'],
  ] as const) {
    await page.goto(`/policies?tab=${tab}`);
    await page.getByRole('tab', { name: section, exact: true }).click();
    await page.getByRole('button', { name: button }).click();
    const sheet = page.getByRole('dialog', { name: title });
    await expect(sheet).toBeVisible();
    const box = (await sheet.boundingBox())!;
    const viewport = page.viewportSize()!;
    if (layout === 'mobile') expect(box.width).toBeGreaterThanOrEqual(viewport.width - 1);
    expect(box.x).toBeGreaterThanOrEqual(-1);
    expect(box.x + box.width).toBeLessThanOrEqual(viewport.width + 1);
    expect(await horizontalOverflow(page), `${title} (${layout})`).toBeLessThanOrEqual(1);
    await expectNoSeriousA11yViolations(page, `${title} sheet (${layout})`);
    await sheet.getByRole('button', { name: 'Cancel' }).click();
    await expect(sheet).toHaveCount(0);
  }
});

test('account takeover and incident pages fit the viewport (step 8.4)', async ({
  page,
}, testInfo) => {
  test.setTimeout(240_000);
  const layout = layoutOf(testInfo);
  const victim = atoAccount('victim');
  await signIn(page, 'alphaAdmin', { next: '/ato' });
  const offenders: string[] = [];
  for (const path of [
    '/ato?range=7d',
    '/ato/accounts',
    `/ato/accounts/${victim.accountId}`,
    `/ato/accounts/${victim.accountId}?tab=sign-ins`,
    '/ato/responses?tab=all',
    '/ato/settings?tab=automation',
    '/incidents',
    `/incidents/${victim.incidentId}`,
    `/incidents/${victim.incidentId}/report`,
  ]) {
    await page.goto(path);
    await expect(page.locator('main h1').first()).toBeVisible({ timeout: 20_000 });
    await expect(page.locator('main [aria-busy="true"]')).toHaveCount(0, { timeout: 20_000 });
    const overflow = await horizontalOverflow(page);
    if (overflow > 1) offenders.push(`${path}: ${overflow}px`);
    await expectNoSeriousA11yViolations(page, `${path} (${layout})`);
  }
  expect(offenders, `account takeover pages wider than the ${layout} viewport`).toEqual([]);
});

test('API-mode onboarding pages fit the viewport (step API-4)', async ({ page }, testInfo) => {
  test.setTimeout(240_000);
  const layout = layoutOf(testInfo);
  const s = readState().onboarding;
  await signIn(page, 'etaAdmin', { next: '/protection-by-mode' });
  const offenders: string[] = [];
  const wizard = `/domains/onboarding?domainId=${s.domains.bound}`;
  for (const path of [
    '/protection-by-mode',
    `/domains/${s.domains.bound}`,
    `/domains/${s.domains.inline}`,
    `${wizard}&step=ownership`,
    `${wizard}&step=connect`,
    `${wizard}&step=intake`,
    `${wizard}&step=mailboxes`,
    `${wizard}&step=action`,
    `${wizard}&step=review`,
    '/api-mode?tab=remediation',
    '/api-mode?tab=detections',
  ]) {
    await page.goto(path);
    await expect(page.locator('main h1').first()).toBeVisible({ timeout: 20_000 });
    await expect(page.locator('main [aria-busy="true"]')).toHaveCount(0, { timeout: 20_000 });
    const overflow = await horizontalOverflow(page);
    if (overflow > 1) offenders.push(`${path}: ${overflow}px`);
    await expectNoSeriousA11yViolations(page, `${path} (${layout})`);
  }
  expect(offenders, `onboarding pages wider than the ${layout} viewport`).toEqual([]);
});
