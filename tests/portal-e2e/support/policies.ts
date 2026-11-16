/**
 * Helpers of the step 7.3 specs (policy builder, policy management, DLP/BEC configuration):
 * driving the builder's catalogue-driven controls (field picker, operator and value selects,
 * list inputs, action menu), the version toolbar, horizontal overflow, and reading rows the api
 * wrote (audit) on the writer. Locators use roles and accessible names only, as a user (or an
 * assistive technology) finds the controls.
 */
import { expect, type Locator, type Page } from '@playwright/test';
import { readState } from './state';
import { writerDb } from './messages';

/** Picks `label` in the condition's searchable field picker (labels come from the catalogue). */
export async function pickField(page: Page, condition: Locator, label: string): Promise<void> {
  await condition.getByRole('combobox', { name: /^Field / }).click();
  await page.getByRole('combobox', { name: 'Search fields' }).fill(label);
  await page
    .getByRole('option', { name: new RegExp(`^${escape(label)} `) })
    .first()
    .click();
  await expect(condition.getByRole('combobox', { name: `Field ${label}` })).toBeVisible();
}

/** Chooses an option of a design-system select (Radix: a combobox opening a listbox). */
export async function chooseOption(page: Page, combobox: Locator, option: string): Promise<void> {
  await combobox.click();
  await page.getByRole('listbox').getByRole('option', { name: option, exact: true }).click();
  await expect(page.getByRole('listbox')).toHaveCount(0);
}

export async function chooseOperator(page: Page, condition: Locator, label: string): Promise<void> {
  await chooseOption(page, condition.getByRole('combobox', { name: 'Operator' }), label);
}

/** Types one item into a list value ("Add domain", "Add pattern", …) and presses Enter. */
export async function addListItem(scope: Locator, noun: string, value: string): Promise<void> {
  const input = scope.getByRole('textbox', { name: `Add ${noun}` });
  await input.fill(value);
  await input.press('Enter');
}

/** Adds an action through the "Add action" menu of a rule. */
export async function addAction(page: Page, rule: Locator, label: string): Promise<void> {
  await rule.getByRole('button', { name: 'Add action' }).click();
  await page.getByRole('menuitem', { name: label, exact: true }).click();
}

/** A condition row by its 1-based position in a group of `joiner` at `level`. */
export function conditionIn(
  scope: Locator,
  position: number,
  joiner: 'AND' | 'OR',
  level: number,
): Locator {
  const words =
    joiner === 'AND' ? 'all of the following \\(AND\\)' : 'any of the following \\(OR\\)';
  return scope.getByRole('group', {
    name: new RegExp(`^Condition ${position} of \\d+ in ${words}, level ${level}$`),
  });
}

export function versionActions(page: Page): Locator {
  return page.getByRole('group', { name: 'Version actions' });
}

/** The text of a description-list value in `scope` (`<dt>term</dt><dd>value</dd>`). */
export async function definitionOf(scope: Locator, term: string): Promise<string> {
  const value = scope
    .getByRole('term')
    .filter({ hasText: new RegExp(`^${escape(term)}$`) })
    .first()
    .locator('xpath=following-sibling::dd[1]');
  return ((await value.textContent()) ?? '').trim();
}

/** Horizontal page overflow in CSS pixels (≤ 1 means none). */
export async function horizontalOverflow(page: Page): Promise<number> {
  return page.evaluate(() => {
    const root = document.documentElement;
    return Math.max(root.scrollWidth, document.body.scrollWidth) - root.clientWidth;
  });
}

/** "require_approval" → "Require approval" (the portal's disposition labels). */
export function humanize(code: string): string {
  const text = code.replace(/_/g, ' ');
  return text.charAt(0).toUpperCase() + text.slice(1);
}

/** Audit rows of a policy (both resource types) written since `since`, on the writer. */
export async function policyAuditRows(
  policyId: string,
  since: Date,
): Promise<Array<{ action: string; resourceType: string; metadata: unknown }>> {
  const org = await writerDb().organization.findUniqueOrThrow({
    where: { publicId: readState().orgs.alpha.id },
    select: { id: true },
  });
  return writerDb().auditLog.findMany({
    where: {
      organizationId: org.id,
      resourceType: { in: ['email_policy', 'policy_version'] },
      resourceId: policyId,
      createdAt: { gte: since },
    },
    select: { action: true, resourceType: true, metadata: true },
    orderBy: { createdAt: 'asc' },
  });
}

/** The policy id of a builder URL (`/policies/<id>/versions/<n>`). */
export function policyIdOf(url: string): string {
  const match = /\/policies\/([0-9a-f-]{36})\//.exec(new URL(url).pathname + '/');
  if (!match) throw new Error(`not a policy URL: ${url}`);
  return match[1]!;
}

function escape(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
