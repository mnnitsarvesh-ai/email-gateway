/**
 * Responsive layout (design P11, P14) in the three projects: desktop 1440×900 (expanded
 * sidebar, collapsible), tablet 834×1112 (icon rail, expandable) and mobile 390×844 (drawer from
 * the top bar, focus-trapped, closes on navigation). No top-level page scrolls horizontally;
 * data tables stay usable (stacked cards on mobile, a scrolling table otherwise).
 */
import type { Page, TestInfo } from '@playwright/test';
import { signIn } from '../support/auth';
import { NAV_GATES } from '../support/contract';
import { expect, test } from '../support/fixtures';

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
