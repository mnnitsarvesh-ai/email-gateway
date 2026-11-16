/**
 * DLP and BEC configuration editing (step 7.3 design §2 B13, product-owner decision of
 * 2026-11-16, WP5) against the real api: a security analyst creates a custom pattern after the
 * server-side "Test pattern" (the UI shows what the api answers for the same body; the browser
 * never evaluates a pattern), creates/edits/deletes a dictionary and an exception, adds a rule to
 * a DLP policy, adds/edits/deletes a BEC executive, a vendor and a trusted sender and lifts a
 * seeded suppression; a role with `dlp:read`/`bec:read` but no manage permission sees no editing
 * control; the Aadhaar compliance basis needs `dlp:compliance_manage` and an MFA session (the
 * seeded MFA organization admin records and withdraws it; an admin without MFA sees the
 * MFA-required state); beta's rows are never visible to alpha. Every write is checked on the api.
 */
import type { Locator, Page } from '@playwright/test';
import { signIn } from '../support/auth';
import { me } from '../support/contract';
import {
  assertGuardClean,
  clientIp,
  expect,
  newGuard,
  protectContext,
  test,
} from '../support/fixtures';
import { bff, spy } from '../support/messages';
import { expectNoSeriousA11yViolations, expectSettled } from '../support/pages';
import { readState } from '../support/state';

test.describe.configure({ timeout: 300_000 });
test.use({ actionTimeout: 20_000 });

const RUN = Date.now().toString(36);

function main(page: Page) {
  return page.locator('main');
}

async function openSection(page: Page, tab: 'dlp' | 'bec', section: string): Promise<Locator> {
  await page.goto(`/policies?tab=${tab}`);
  await page
    .getByRole('tablist', { name: tab === 'dlp' ? 'DLP sections' : 'BEC sections' })
    .getByRole('tab', { name: section, exact: true })
    .click();
  const panel = page.getByRole('tabpanel', { name: section, exact: true });
  await expect(panel).toBeVisible();
  await expectSettled(page, `${tab} ${section}`);
  return panel;
}

/** Opens a row's action menu (rows are named by their entry) and picks `item`. */
async function rowAction(page: Page, scope: Locator, entry: string, item: string): Promise<void> {
  await scope
    .getByRole('button', { name: new RegExp(`^Actions for (.+ )?${escape(entry)}`) })
    .click();
  await page.getByRole('menuitem', { name: item, exact: true }).click();
}

/** Confirms the open confirmation dialog with `button`. */
async function confirm(page: Page, button: string | RegExp): Promise<void> {
  const dialog = page.getByRole('alertdialog').or(page.getByRole('dialog')).last();
  await dialog.getByRole('button', { name: button }).click();
  await expect(dialog).toHaveCount(0);
}

function escape(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

test('security analyst: patterns with the server test, dictionaries, exceptions, DLP rules', async ({
  page,
}) => {
  const { policies } = readState();
  await signIn(page, 'alphaAnalyst', { next: '/policies?tab=dlp' });
  await expect(main(page).getByText('View only')).toHaveCount(0);

  // Custom pattern: the server tests it before it is created.
  let panel = await openSection(page, 'dlp', 'Patterns');
  await panel.getByRole('button', { name: 'New pattern' }).click();
  let sheet = page.getByRole('dialog', { name: 'New custom pattern' });
  const patternName = `E2E order id ${RUN}`;
  await sheet.getByRole('textbox', { name: 'Name (required)' }).fill(patternName);
  await sheet.getByRole('textbox', { name: 'Pattern (required)' }).fill('ORD-[0-9]{6}');
  await sheet
    .getByRole('textbox', { name: 'Synthetic sample text' })
    .fill('Order ORD-123456 shipped; ORD-12 is too short.');
  const tests = spy(page, (r) => r.url().endsWith('/bff/api/v1/dlp/patterns/test'));
  await sheet.getByRole('button', { name: 'Test pattern' }).click();
  const region = sheet.getByRole('region', { name: 'Test pattern' });
  await expect.poll(() => tests.seen.length).toBe(1);
  const testBody = JSON.parse(tests.seen[0]!.body ?? '{}') as Record<string, unknown>;
  expect(testBody).toMatchObject({ pattern: 'ORD-[0-9]{6}' });
  const direct = await bff(page, 'POST', '/dlp/patterns/test', testBody);
  expect(direct.status).toBe(200);
  expect(direct.body?.valid).toBe(true);
  const matches = (direct.body?.matches ?? []) as Array<{ masked?: string; value?: string }>;
  expect(matches.length).toBe(1);
  const masked = matches[0]!.masked ?? matches[0]!.value ?? '';
  expect(masked).not.toContain('123456');
  await expect(region).toContainText(masked);
  await expectNoSeriousA11yViolations(page, 'new pattern sheet with a test result');
  await sheet.getByRole('button', { name: 'Create pattern' }).click();
  await expect(sheet).toHaveCount(0);
  await expect(panel.getByRole('row').filter({ hasText: patternName })).toBeVisible();

  // Dictionary: create, edit the terms, delete.
  panel = await openSection(page, 'dlp', 'Dictionaries');
  await panel.getByRole('button', { name: 'New dictionary' }).click();
  sheet = page.getByRole('dialog', { name: 'New keyword dictionary' });
  const dictionary = `E2E project names ${RUN}`;
  await sheet.getByRole('textbox', { name: 'Name (required)' }).fill(dictionary);
  await sheet
    .getByRole('textbox', { name: 'Terms (required)', exact: true })
    .fill('project falcon\nproject osprey');
  await sheet.getByRole('button', { name: 'Create dictionary' }).click();
  await expect(sheet).toHaveCount(0);
  await expect(panel.getByRole('row').filter({ hasText: dictionary })).toBeVisible();
  await rowAction(page, panel, dictionary, 'Edit');
  sheet = page.getByRole('dialog').last();
  const terms = sheet.getByRole('textbox', { name: 'Terms (required)', exact: true });
  await expect(terms).toHaveValue(/project falcon/);
  await terms.fill('project falcon\nproject osprey\nproject heron');
  const patches = spy(
    page,
    (r) => r.method() === 'PATCH' && r.url().includes('/bff/api/v1/dlp/dictionaries/'),
  );
  await sheet.getByRole('button', { name: /^Save/ }).click();
  await expect(sheet).toHaveCount(0);
  expect(JSON.parse(patches.seen[0]!.body ?? '{}')).toMatchObject({
    terms: ['project falcon', 'project osprey', 'project heron'],
  });
  await rowAction(page, panel, dictionary, 'Delete');
  await confirm(page, /^Delete/);
  await expect(panel.getByRole('row').filter({ hasText: dictionary })).toHaveCount(0);

  // Exception: create, edit the reason, delete.
  panel = await openSection(page, 'dlp', 'Exceptions');
  await panel.getByRole('button', { name: 'New exception' }).click();
  sheet = page.getByRole('dialog', { name: 'New DLP exception' });
  const domain = `partner-${RUN}.e2e-portal.test`;
  await sheet.getByRole('textbox', { name: 'Domain (required)' }).fill(domain);
  await sheet.getByRole('textbox', { name: 'Reason (required)' }).fill('Contracted partner (e2e)');
  await sheet.getByRole('button', { name: 'Add exception' }).click();
  await expect(sheet).toHaveCount(0);
  await expect(panel.getByRole('row').filter({ hasText: domain })).toBeVisible();
  await rowAction(page, panel, domain, 'Edit');
  sheet = page.getByRole('dialog').last();
  await sheet.getByRole('textbox', { name: 'Reason (required)' }).fill('Contract renewed (e2e)');
  await sheet.getByRole('button', { name: /^Save/ }).click();
  await expect(sheet).toHaveCount(0);
  await expect(panel.getByRole('row').filter({ hasText: domain })).toContainText(
    'Contract renewed',
  );
  await rowAction(page, panel, domain, 'Delete');
  await confirm(page, /^(Delete|Remove)/);
  await expect(panel.getByRole('row').filter({ hasText: domain })).toHaveCount(0);

  // A rule in the seeded DLP policy.
  panel = await openSection(page, 'dlp', 'Policies');
  await rowAction(page, panel, policies.dlpPolicyName, 'Rules');
  const rules = page.getByRole('dialog', { name: `Rules of ${policies.dlpPolicyName}` });
  await rules.getByRole('button', { name: 'Add rule' }).first().click();
  sheet = page.getByRole('dialog', { name: `New rule in ${policies.dlpPolicyName}` });
  await sheet.getByRole('textbox', { name: 'Name (required)' }).fill('Card numbers (e2e)');
  await sheet
    .getByRole('combobox', { name: 'Action (required)' })
    .selectOption({ label: 'Quarantine' });
  await sheet.getByRole('checkbox', { name: 'Payment cards' }).check();
  await expectNoSeriousA11yViolations(page, 'new DLP rule sheet');
  const ruleWrites = spy(
    page,
    (r) => r.method() === 'POST' && r.url().endsWith(`/dlp/policies/${policies.dlpPolicyId}/rules`),
  );
  await sheet.getByRole('button', { name: 'Add rule' }).click();
  await expect(sheet).toHaveCount(0);
  expect(JSON.parse(ruleWrites.seen[0]!.body ?? '{}')).toMatchObject({
    name: 'Card numbers (e2e)',
    action: 'quarantine',
    conditions: { selectors: { categories: ['payment_card'] } },
  });
  await expect(rules.getByRole('row').filter({ hasText: 'Card numbers (e2e)' })).toBeVisible();
  const policy = await bff(page, 'GET', `/dlp/policies/${policies.dlpPolicyId}`);
  expect((policy.body?.rules as unknown[]).length).toBe(1);
});

test('security analyst: BEC executives, vendors, trusted senders and a suppression', async ({
  page,
}) => {
  const { policies } = readState();
  await signIn(page, 'alphaAnalyst', { next: '/policies?tab=bec' });

  // Executive: create, edit the title, delete.
  let panel = await openSection(page, 'bec', 'Executives');
  await panel.getByRole('button', { name: 'New executive' }).click();
  let sheet = page.getByRole('dialog', { name: 'New executive' });
  const executive = `Erin Example ${RUN}`;
  await sheet.getByRole('textbox', { name: 'Display name (required)' }).fill(executive);
  await sheet
    .getByRole('textbox', { name: 'Job title (optional)' })
    .fill('Chief Financial Officer');
  await sheet
    .getByRole('textbox', { name: 'Known addresses (optional)' })
    .fill('erin@alpha.e2e-portal.test');
  await expectNoSeriousA11yViolations(page, 'new executive sheet');
  await sheet.getByRole('button', { name: 'Add executive' }).click();
  await expect(sheet).toHaveCount(0);
  await expect(panel.getByRole('row').filter({ hasText: executive })).toBeVisible();
  await rowAction(page, panel, executive, 'Edit');
  sheet = page.getByRole('dialog').last();
  await sheet
    .getByRole('textbox', { name: 'Job title (optional)' })
    .fill('Chief Executive Officer');
  await sheet.getByRole('button', { name: /^Save/ }).click();
  await expect(sheet).toHaveCount(0);
  await expect(panel.getByRole('row').filter({ hasText: executive })).toContainText(
    'Chief Executive Officer',
  );
  await rowAction(page, panel, executive, 'Delete');
  await confirm(page, /^(Delete|Remove)/);
  await expect(panel.getByRole('row').filter({ hasText: executive })).toHaveCount(0);

  // Vendor: create, edit, delete.
  panel = await openSection(page, 'bec', 'Vendors');
  await panel.getByRole('button', { name: 'New vendor' }).click();
  sheet = page.getByRole('dialog', { name: 'New vendor' });
  const vendor = `Example Supplies ${RUN}`;
  await sheet.getByRole('textbox', { name: 'Vendor name (required)' }).fill(vendor);
  await sheet
    .getByRole('textbox', { name: 'Domains (required)' })
    .fill(`supplies-${RUN}.e2e-portal.test`);
  await sheet.getByRole('button', { name: 'Add vendor' }).click();
  await expect(sheet).toHaveCount(0);
  await expect(panel.getByRole('row').filter({ hasText: vendor })).toBeVisible();
  await rowAction(page, panel, vendor, 'Edit');
  sheet = page.getByRole('dialog').last();
  await sheet.getByRole('textbox', { name: 'Aliases (optional)' }).fill('Example Supplies Ltd');
  await sheet.getByRole('button', { name: /^Save/ }).click();
  await expect(sheet).toHaveCount(0);
  await rowAction(page, panel, vendor, 'Delete');
  await confirm(page, /^(Delete|Remove)/);
  await expect(panel.getByRole('row').filter({ hasText: vendor })).toHaveCount(0);

  // Trusted sender: create, edit the reason, delete.
  panel = await openSection(page, 'bec', 'Trusted senders');
  await panel.getByRole('button', { name: 'New trusted sender' }).click();
  sheet = page.getByRole('dialog', { name: 'New trusted sender' });
  const trusted = `payroll-${RUN}.test`;
  await sheet.getByRole('textbox', { name: 'Registrable domain (required)' }).fill(trusted);
  await sheet.getByRole('textbox', { name: 'Reason (required)' }).fill('Payroll provider (e2e)');
  await sheet.getByRole('button', { name: 'Add trusted sender' }).click();
  await expect(sheet).toHaveCount(0);
  await expect(panel.getByRole('row').filter({ hasText: trusted })).toBeVisible();
  await rowAction(page, panel, trusted, 'Edit');
  sheet = page.getByRole('dialog').last();
  await sheet
    .getByRole('textbox', { name: 'Reason (required)' })
    .fill('Payroll provider, renewed (e2e)');
  await sheet.getByRole('button', { name: /^Save/ }).click();
  await expect(sheet).toHaveCount(0);
  await expect(panel.getByRole('row').filter({ hasText: trusted })).toContainText('renewed');
  await rowAction(page, panel, trusted, 'Delete');
  await confirm(page, /^(Delete|Remove)/);
  await expect(panel.getByRole('row').filter({ hasText: trusted })).toHaveCount(0);

  // Lift the seeded suppression.
  panel = await openSection(page, 'bec', 'Suppressions');
  const row = panel.getByRole('row').filter({ hasText: 'vendor-one.e2e-portal.test' });
  await expect(row).toContainText('bec.content.urgency');
  await row.getByRole('button', { name: /^Actions for/ }).click();
  await page.getByRole('menuitem', { name: /^Lift/ }).click();
  await expectNoSeriousA11yViolations(page, 'lift suppression confirmation');
  await confirm(page, /^Lift/);
  await expect(
    panel.getByRole('row').filter({ hasText: 'vendor-one.e2e-portal.test' }),
  ).toHaveCount(0);
  const gone = await bff(page, 'DELETE', `/bec/suppressions/${policies.suppressionId}`);
  expect(gone.status).toBe(404);
});

test('read permission without manage: no editing controls', async ({ page }) => {
  await signIn(page, 'alphaAuditor', { next: '/policies?tab=dlp' });
  const granted = new Set((await me(page)).permissions);
  expect(granted.has('dlp:read') && granted.has('bec:read')).toBe(true);
  expect(granted.has('dlp:manage') || granted.has('bec:manage')).toBe(false);
  await expect(main(page).getByText('View only').first()).toBeVisible();
  for (const [tab, section, button] of [
    ['dlp', 'Policies', 'New DLP policy'],
    ['dlp', 'Patterns', 'New pattern'],
    ['dlp', 'Dictionaries', 'New dictionary'],
    ['dlp', 'Exceptions', 'New exception'],
    ['bec', 'Executives', 'New executive'],
    ['bec', 'Vendors', 'New vendor'],
    ['bec', 'Trusted senders', 'New trusted sender'],
  ] as const) {
    const panel = await openSection(page, tab, section);
    await expect(panel.getByRole('button', { name: button })).toHaveCount(0);
  }
  // Rules stay viewable, without editing controls; suppressions cannot be lifted.
  const { policies } = readState();
  const panel = await openSection(page, 'dlp', 'Policies');
  await rowAction(page, panel, policies.dlpPolicyName, 'Rules');
  const rules = page.getByRole('dialog', { name: `Rules of ${policies.dlpPolicyName}` });
  await expect(rules.getByRole('button', { name: 'Add rule' })).toHaveCount(0);
  await page.keyboard.press('Escape');
  const compliance = await openSection(page, 'dlp', 'Compliance');
  await expect(compliance.getByRole('button', { name: /basis/i })).toHaveCount(0);
  const suppressions = await openSection(page, 'bec', 'Suppressions');
  await expect(suppressions.getByRole('button', { name: /^Actions for/ })).toHaveCount(0);
  await expectNoSeriousA11yViolations(page, 'BEC suppressions (view only)');
});

test('Aadhaar compliance basis: MFA-required state, then record and withdraw with MFA', async ({
  page,
  browser,
}) => {
  // An organization admin without an MFA session sees the MFA-required state.
  await signIn(page, 'alphaAdmin', { next: '/policies?tab=dlp' });
  let panel = await openSection(page, 'dlp', 'Compliance');
  await expect(panel.getByText('mfa_required')).toBeVisible();
  await expect(panel.getByRole('button', { name: /^(Record|Update) basis/ })).toHaveCount(0);
  await expectNoSeriousA11yViolations(page, 'DLP compliance (MFA required)');

  // The seeded MFA organization admin records the basis and withdraws it.
  const context = await browser.newContext({
    baseURL: 'http://localhost:3001',
    locale: 'en-US',
    timezoneId: 'UTC',
  });
  const guard = newGuard();
  await protectContext(context, guard, clientIp(`aadhaar:${RUN}`));
  const mfa = await context.newPage();
  try {
    await signIn(mfa, 'alphaApprover', { next: '/policies?tab=dlp' });
    panel = await openSection(mfa, 'dlp', 'Compliance');
    await panel.getByRole('button', { name: 'Record basis' }).click();
    const sheet = mfa.getByRole('dialog', { name: 'Record the Aadhaar detection basis' });
    await sheet.getByRole('combobox', { name: 'Basis (required)' }).selectOption({ index: 1 });
    await sheet
      .getByRole('textbox', { name: 'Document or approval reference (required)' })
      .fill(`E2E-REF-${RUN}`);
    const review = new Date(Date.now() + 180 * 86_400_000).toISOString().slice(0, 10);
    await sheet.getByLabel(/^Review date/).fill(review);
    await sheet.getByRole('checkbox', { name: /^I attest/ }).check();
    await expectNoSeriousA11yViolations(mfa, 'record Aadhaar basis sheet');
    const writes = spy(
      mfa,
      (r) => r.method() === 'PUT' && r.url().endsWith('/dlp/compliance/aadhaar'),
    );
    await sheet.getByRole('button', { name: 'Record basis' }).click();
    const sure = mfa
      .getByRole('alertdialog', { name: 'Record the Aadhaar detection basis?' })
      .or(mfa.getByRole('dialog', { name: 'Record the Aadhaar detection basis?' }));
    await sure.getByRole('button', { name: 'Record basis' }).click();
    await expect.poll(() => writes.seen.length).toBe(1);
    expect(writes.seen[0]!.headers['idempotency-key']).toMatch(/^[0-9a-f-]{36}$/);
    await expect(panel).toContainText(`E2E-REF-${RUN}`);
    await expectNoSeriousA11yViolations(mfa, 'DLP compliance (recorded)');
    await panel.getByRole('button', { name: 'Withdraw basis' }).click();
    await confirm(mfa, 'Withdraw basis');
    await expect(panel).not.toContainText(`E2E-REF-${RUN}`);
    const state = await bff(mfa, 'GET', '/dlp/compliance');
    expect(JSON.stringify(state.body)).not.toContain(`E2E-REF-${RUN}`);
  } finally {
    await context.close();
    assertGuardClean(guard);
  }
});

test('cross-tenant: beta DLP and BEC rows are never visible to alpha', async ({ page }) => {
  const { policies } = readState();
  await signIn(page, 'alphaAdmin', { next: '/policies?tab=dlp' });
  const patterns = await openSection(page, 'dlp', 'Patterns');
  await expect(patterns.getByText('BETA-ONLY')).toHaveCount(0);
  const executives = await openSection(page, 'bec', 'Executives');
  await expect(executives.getByText('BETA-ONLY')).toHaveCount(0);
  const suppressions = await openSection(page, 'bec', 'Suppressions');
  await expect(suppressions.getByText('beta-only-vendor.e2e-portal.test')).toHaveCount(0);

  const pattern = await bff(page, 'GET', `/dlp/patterns/${policies.beta.patternId}`);
  expect(pattern.status).toBe(404);
  const executive = await bff(page, 'GET', `/bec/executives/${policies.beta.executiveId}`);
  expect(executive.status).toBe(404);
  const lift = await bff(page, 'DELETE', `/bec/suppressions/${policies.beta.suppressionId}`);
  expect(lift.status).toBe(404);
  for (const path of ['/dlp/patterns', '/bec/executives', '/bec/suppressions']) {
    const list = await bff(page, 'GET', `${path}?limit=100`);
    expect(list.status).toBe(200);
    expect(JSON.stringify(list.body)).not.toMatch(/BETA-ONLY|beta-only-vendor/);
  }
});
