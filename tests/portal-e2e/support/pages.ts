/**
 * Page checks shared by the specs: a page rendered real data (a marker from the seeded rows),
 * shows no error state, has finished loading, and has no serious or critical axe violation
 * (WCAG 2.2 A/AA rules of axe-core 4.14, via @axe-core/playwright).
 */
import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';

export async function expectNoSeriousA11yViolations(page: Page, label: string): Promise<void> {
  const results = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'])
    .analyze();
  const serious = results.violations
    .filter((v) => v.impact === 'serious' || v.impact === 'critical')
    .map(
      (v) =>
        `${v.id} (${v.impact}): ${v.nodes
          .slice(0, 3)
          .map((n) => n.target.join(' '))
          .join(' | ')}`,
    );
  expect.soft(serious, `axe serious/critical violations on ${label}`).toEqual([]);
}

/** No error state (the ErrorState is an alert with "Code"), no busy skeleton left. */
export async function expectSettled(page: Page, label: string): Promise<void> {
  const main = page.locator('main');
  await expect
    .soft(main.locator('[aria-busy="true"]'), `${label} finished loading`)
    .toHaveCount(0, { timeout: 20_000 });
  await expect
    .soft(
      main.getByRole('alert').filter({ has: page.getByText('Code', { exact: true }) }),
      `${label} has no error state`,
    )
    .toHaveCount(0);
}

export interface PageCheck {
  path: string;
  /** Level-1 heading of the page. */
  heading: string | RegExp;
  /** Text from the seeded data that must appear. */
  markers?: Array<string | RegExp>;
  /** Steps whose "Arrives in step N" state must be present. */
  unavailable?: string[];
  /** "Not offered" states (no step delivers them). */
  notOffered?: number;
}

export async function checkPage(page: Page, check: PageCheck): Promise<void> {
  await page.goto(check.path);
  await expect
    .soft(
      page.getByRole('heading', { level: 1, name: check.heading }).first(),
      `${check.path} heading`,
    )
    .toBeVisible({ timeout: 20_000 });
  const main = page.locator('main');
  for (const marker of check.markers ?? []) {
    await expect
      .soft(main.getByText(marker).first(), `${check.path} shows ${String(marker)}`)
      .toBeVisible({ timeout: 20_000 });
  }
  for (const step of check.unavailable ?? []) {
    await expect
      .soft(main.getByText(`Arrives in step ${step}`).first(), `${check.path} step ${step}`)
      .toBeVisible();
  }
  if (check.notOffered) {
    await expect
      .soft(main.getByText('Not offered', { exact: true }), `${check.path} not offered`)
      .toHaveCount(check.notOffered);
  }
  await expectSettled(page, check.path);
  await expectNoSeriousA11yViolations(page, check.path);
}
