/**
 * Visual policy builder (step 7.3 design §9.4, ADR-0063) against the real api: an organization
 * administrator builds a policy with nested AND/OR groups (two levels), a NOT, three actions with
 * parameters and a rule exception from the catalogue's controls, reads the live summary, saves
 * the draft, sees the server's violation on an invalid regular expression and fixes it, runs Test
 * with a preset and Dry run on recent messages (the UI shows what a direct api call with the same
 * body returns), publishes and activates (generation, audit rows), creates v2 from v1, changes and
 * publishes it, compares v1/v2, rolls back to v1 (active marker, `policy.version_activated` with
 * `previousVersionNo` in the audit tab), disables and enables the policy. The browser never
 * evaluates policy logic: every verdict on screen is the server's.
 */
import type { Page } from '@playwright/test';
import { signIn } from '../support/auth';
import { expect, test } from '../support/fixtures';
import { bff, spy } from '../support/messages';
import { expectNoSeriousA11yViolations, expectSettled } from '../support/pages';
import {
  addAction,
  addListItem,
  chooseOperator,
  chooseOption,
  conditionIn,
  definitionOf,
  humanize,
  pickField,
  policyAuditRows,
  policyIdOf,
  versionActions,
} from '../support/policies';
import { readState } from '../support/state';

test.describe.configure({ timeout: 300_000 });
test.use({ actionTimeout: 20_000 });

const RULE_ID = 'e2e-hold';
const POLICY_NAME = `E2E built policy ${Date.now().toString(36)}`;

function main(page: Page) {
  return page.locator('main');
}

function summary(page: Page) {
  return page.getByRole('complementary', { name: 'Readable summary of the policy' });
}

/** Builds the policy of §9.4 on `/policies/new` with the catalogue-driven controls. */
async function buildPolicy(page: Page): Promise<void> {
  await page.getByRole('textbox', { name: 'Name (required)' }).fill(POLICY_NAME);
  await page
    .getByRole('form', { name: 'New policy' })
    .getByRole('textbox', { name: 'Description' })
    .fill('Built by the portal e2e suite');
  await page.getByRole('textbox', { name: 'Change note' }).fill('First version');
  await chooseOption(page, page.getByRole('combobox', { name: 'Policy direction' }), 'Outbound');

  const rule = page.getByRole('region', { name: 'Rule rule-1', exact: true });
  await rule.getByRole('textbox', { name: 'Rule id' }).fill(RULE_ID);
  const r = page.getByRole('region', { name: `Rule ${RULE_ID}`, exact: true });
  await r
    .getByRole('textbox', { name: 'Description (optional)' })
    .fill('Hold outbound confidential data');

  // Level 1 (AND): DLP data categories contain any of Confidential.
  const top = r.getByRole('group', {
    name: `Conditions of rule ${RULE_ID}, all of the following (AND), level 1`,
    exact: true,
  });
  const c1 = conditionIn(top, 1, 'AND', 1);
  await pickField(page, c1, 'DLP data categories');
  await chooseOperator(page, c1, 'contains any of');
  await c1.getByRole('checkbox', { name: 'Confidential' }).check();

  // Level 2 (OR): Number of recipients > 10, NOT (Scan verdict is Malicious).
  await top.getByRole('button', { name: 'Add group' }).last().click();
  const group = r.getByRole('group', {
    name: 'Group 2, any of the following (OR), level 2',
    exact: true,
  });
  await expect(group.getByRole('button', { name: 'Any (OR)' })).toHaveAttribute(
    'aria-pressed',
    'true',
  );
  const g1 = conditionIn(group, 1, 'OR', 2);
  await pickField(page, g1, 'Number of recipients');
  await chooseOperator(page, g1, '>');
  await g1.getByRole('spinbutton').first().fill('10');
  await group.getByRole('button', { name: 'Add condition' }).last().click();
  const g2 = conditionIn(group, 2, 'OR', 2);
  await pickField(page, g2, 'Scan verdict');
  await chooseOperator(page, g2, 'is');
  await chooseOption(page, g2.getByRole('combobox', { name: 'Value' }), 'Malicious');
  await g2.getByRole('button', { name: /^NOT: negate condition 2/ }).click();

  // Rule exception: every recipient in the trusted partner domain.
  await r.getByRole('button', { name: 'Add exception' }).click();
  const exception = r.getByRole('group', { name: `Exception 1 of rule ${RULE_ID}`, exact: true });
  await pickField(page, exception, 'Recipient domain');
  await chooseOperator(page, exception, 'is one of');
  await addListItem(exception, 'value', 'trusted-partner.e2e-portal.test');

  // Actions: QUARANTINE + ALERT (severity) + TAG (label, subject prefix).
  await addAction(page, r, 'Quarantine');
  await addAction(page, r, 'Alert administrators');
  await addAction(page, r, 'Tag');
  const actions = r.getByRole('region', { name: `Actions (THEN) of rule ${RULE_ID}` });
  await chooseOption(
    page,
    actions.getByRole('combobox', { name: 'Severity (required)' }),
    'Warning',
  );
  await actions.getByRole('textbox', { name: 'Tag label (required)' }).fill('e2e-hold');
  await actions.getByRole('textbox', { name: 'Subject prefix' }).fill('[HOLD]');
}

test('build, save, validate, test, dry run, publish, version, compare, roll back', async ({
  page,
}) => {
  const started = new Date(Date.now() - 1_000);
  await signIn(page, 'alphaAdmin', { next: '/policies/builder' });
  await expect(page.getByRole('heading', { level: 1, name: 'Policy builder' })).toBeVisible();
  await expectSettled(page, '/policies/builder');
  await expectNoSeriousA11yViolations(page, '/policies/builder');
  await main(page).getByRole('link', { name: 'New policy' }).first().click();
  await expect(page).toHaveURL(/\/policies\/new$/);
  await expect(page.getByRole('heading', { level: 1, name: 'New policy' })).toBeVisible();

  await buildPolicy(page);

  // The live summary renders the document with the catalogue's labels (presentation only).
  const article = summary(page).getByRole('article', { name: new RegExp(`^Rule ${RULE_ID} `) });
  const ifLines = article.getByRole('list', { name: `Conditions of rule ${RULE_ID}` });
  await expect(ifLines.getByRole('listitem')).toHaveText([
    'Email direction is Outbound',
    'AND DLP data categories contain any of Confidential',
    'AND any of:',
    'Number of recipients is greater than 10',
    'OR NOT: Scan verdict is Malicious',
  ]);
  await expect(article.getByRole('list', { name: `Exceptions of rule ${RULE_ID}` })).toContainText(
    'trusted-partner.e2e-portal.test',
  );
  await expect(
    article.getByRole('list', { name: `Actions of rule ${RULE_ID}` }).getByRole('listitem'),
  ).toHaveText([
    'Quarantine',
    'AND Alert administrators (severity: warning)',
    /^AND Tag \(tag label: "e2e-hold", subject prefix: "\[HOLD\]"\)$/,
  ]);
  await expectNoSeriousA11yViolations(page, '/policies/new (built)');

  // Save the draft → version 1 of the new policy.
  const creates = spy(
    page,
    (r) => r.method() === 'POST' && r.url().endsWith('/bff/api/v1/policies'),
  );
  await page.getByRole('button', { name: 'Save draft' }).click();
  await page.waitForURL(/\/policies\/[0-9a-f-]{36}\/versions\/1$/);
  const policyId = policyIdOf(page.url());
  const sent = JSON.parse(creates.seen[0]!.body ?? '{}') as {
    name: string;
    definition: { rules: Array<Record<string, unknown>> };
  };
  expect(sent.name).toBe(POLICY_NAME);
  expect(sent.definition.rules[0]).toMatchObject({
    id: RULE_ID,
    when: {
      all: [
        { field: 'dlp.categories', op: 'contains_any', value: ['confidential'] },
        {
          any: [
            { field: 'recipients.count', op: 'gt', value: 10 },
            { not: { field: 'scan.verdict', op: 'equals', value: 'malicious' } },
          ],
        },
      ],
    },
    actions: [
      { type: 'QUARANTINE' },
      { type: 'ALERT', severity: 'warning' },
      { type: 'TAG', label: 'e2e-hold', subjectPrefix: '[HOLD]' },
    ],
  });
  await expect(page.getByRole('heading', { level: 1 })).toHaveText(`${POLICY_NAME} · v1`);
  await expectSettled(page, 'version 1');
  await expectNoSeriousA11yViolations(page, '/policies/[id]/versions/1 (draft)');

  // An invalid regular expression: the server's violation is shown on that condition.
  const r = page.getByRole('region', { name: `Rule ${RULE_ID}`, exact: true });
  const group = r.getByRole('group', {
    name: 'Group 2, any of the following (OR), level 2',
    exact: true,
  });
  await group.getByRole('button', { name: 'Add condition' }).last().click();
  const g3 = conditionIn(group, 3, 'OR', 2);
  await pickField(page, g3, 'Attachment file name');
  await chooseOperator(page, g3, 'matches regular expression');
  await addListItem(g3, 'pattern', 'invoice-(unclosed');
  const validations = spy(page, (q) => q.url().endsWith('/bff/api/v1/policies/validate'));
  await versionActions(page).getByRole('button', { name: 'Validate' }).click();
  const problems = g3.getByRole('list', { name: 'Problems reported by the server' });
  await expect(problems).toBeVisible();
  await expect(problems).toContainText(/regex|regular expression|pattern/i);
  expect(validations.seen.length).toBeGreaterThanOrEqual(1);
  // The error summary links the violation to its node.
  await expect(main(page).getByRole('heading', { name: /The server reported/ })).toBeVisible();
  await expectNoSeriousA11yViolations(page, 'builder with a server violation');

  // Fix it, validate again, save.
  await g3.getByRole('button', { name: /^Remove .*invoice-\(unclosed/ }).click();
  await addListItem(g3, 'pattern', '^invoice-[0-9]+\\.pdf$');
  await versionActions(page).getByRole('button', { name: 'Validate' }).click();
  await expect(g3.getByRole('list', { name: 'Problems reported by the server' })).toHaveCount(0);
  await expect(main(page).getByText('The server accepts this document.')).toBeVisible();
  const saves = spy(
    page,
    (q) => q.method() === 'PUT' && q.url().includes(`/policies/${policyId}/versions/1`),
  );
  await versionActions(page).getByRole('button', { name: 'Save' }).click();
  await expect.poll(() => saves.seen.length).toBe(1);
  expect(JSON.parse(saves.seen[0]!.body ?? '{}')).toMatchObject({ expectedRowVersion: 1 });
  await expect(versionActions(page).getByRole('button', { name: 'Save' })).toBeDisabled();

  // Test with a preset: the UI shows what the api answers for the same body.
  await versionActions(page).getByRole('button', { name: 'Test' }).click();
  const testDialog = page.getByRole('dialog', { name: 'Test with synthetic facts' });
  await expect(testDialog.getByRole('radio', { name: 'This draft' })).toBeChecked();
  await chooseOption(
    page,
    testDialog.getByRole('combobox', { name: 'Start from an example' }),
    'Outbound confidential data',
  );
  const tests = spy(page, (q) => q.url().endsWith('/bff/api/v1/policies/test'));
  await testDialog.getByRole('button', { name: 'Run test' }).click();
  const result = testDialog.getByRole('region', { name: 'Test result (evaluated by the server)' });
  await expect(result).toBeVisible();
  const testBody = JSON.parse(tests.seen[0]!.body ?? '{}') as Record<string, unknown>;
  expect(testBody.target).toEqual({ policyId, versionNo: 1 });
  const direct = await bff(page, 'POST', '/policies/test', testBody);
  expect(direct.status).toBe(200);
  const expected = direct.body!.result as {
    disposition: string;
    decisive: { source: string; ruleId: string | null; policyPublicId: string | null };
  };
  expect(expected.disposition).toBe('quarantine');
  expect(expected.decisive.ruleId).toBe(RULE_ID);
  expect(expected.decisive.policyPublicId).toBe(policyId);
  expect(await definitionOf(result, 'Disposition')).toBe(humanize(expected.disposition));
  expect(await definitionOf(result, 'Decided by')).toContain(RULE_ID);
  await expect(result.getByRole('region', { name: 'Matched rules' })).toContainText(RULE_ID);
  await expectNoSeriousA11yViolations(page, 'test panel with a result');
  await testDialog.getByRole('button', { name: 'Close' }).last().click();

  // Dry run on recent messages: the rows equal a direct api call with the same body.
  await versionActions(page).getByRole('button', { name: 'Dry run' }).click();
  const dryDialog = page.getByRole('dialog', { name: 'Dry run against stored messages' });
  const dryRuns = spy(page, (q) => q.url().endsWith('/bff/api/v1/policies/dry-run'));
  await dryDialog.getByRole('button', { name: 'Run dry run' }).click();
  const dryResult = dryDialog.getByRole('region', {
    name: 'Dry run result (computed by the server)',
  });
  await expect(dryResult).toBeVisible();
  const dryBody = JSON.parse(dryRuns.seen[0]!.body ?? '{}') as Record<string, unknown>;
  expect(dryBody.target).toEqual({ policyId, versionNo: 1 });
  const dry = await bff(page, 'POST', '/policies/dry-run', dryBody);
  expect(dry.status).toBe(200);
  const items = dry.body!.items as Array<{
    messageId: string | null;
    stored: { disposition: string };
    dryRun: { disposition: string } | null;
  }>;
  expect(items.length).toBeGreaterThan(0);
  const rows = dryResult
    .getByRole('table', { name: 'Stored and dry-run decisions per message' })
    .getByRole('row');
  await expect(rows).toHaveCount(items.length + 1);
  for (const item of items) {
    const row = rows.filter({ hasText: item.messageId ?? '' });
    await expect(row).toHaveCount(1);
    await expect(row).toContainText(humanize(item.stored.disposition));
    if (item.dryRun) await expect(row).toContainText(humanize(item.dryRun.disposition));
  }
  await expect(dryResult).toContainText(
    `${String(dry.body!.evaluated)} evaluated, ${String(dry.body!.skipped)} skipped`,
  );
  // Never a beta message (the sample reads only the caller's organization).
  expect(JSON.stringify(dry.body)).not.toContain(readState().beta.twinMessageId);
  await expectNoSeriousA11yViolations(page, 'dry-run panel with a result');
  await dryDialog.getByRole('button', { name: 'Close' }).last().click();

  // Publish with activate: generation and the next-evaluation note.
  await versionActions(page).getByRole('button', { name: 'Publish…' }).click();
  const publish = page.getByRole('dialog', { name: 'Publish version 1' });
  await expect(publish.getByRole('switch', { name: 'Activate now' })).toBeChecked();
  await expect(publish.getByRole('status').filter({ hasText: 'The server accepts' })).toBeVisible();
  await expectNoSeriousA11yViolations(page, 'publish dialog');
  const publishes = spy(page, (q) => q.url().endsWith(`/policies/${policyId}/versions/1/publish`));
  await publish.getByRole('button', { name: 'Publish and activate' }).click();
  const published = page.getByRole('dialog', { name: 'Version 1 published' });
  await expect(published).toContainText('published and active');
  await expect(published).toContainText(/policy generation is now \d+/);
  expect(publishes.seen[0]!.headers['idempotency-key']).toMatch(/^[0-9a-f-]{36}$/);
  await published.getByRole('button', { name: 'Done' }).click();
  await expect(
    page
      .getByRole('paragraph')
      .filter({ hasText: /^Published/ })
      .first(),
  ).toBeVisible();

  // v2 from v1: change the alert severity, save, publish.
  await versionActions(page).getByRole('button', { name: 'New draft from this version' }).click();
  await page.waitForURL(new RegExp(`/policies/${policyId}/versions/2$`));
  await expect(page.getByRole('heading', { level: 1 })).toHaveText(`${POLICY_NAME} · v2`);
  const actions2 = page.getByRole('region', { name: `Actions (THEN) of rule ${RULE_ID}` });
  await chooseOption(
    page,
    actions2.getByRole('combobox', { name: 'Severity (required)' }),
    'Critical',
  );
  await versionActions(page).getByRole('button', { name: 'Save' }).click();
  await expect(versionActions(page).getByRole('button', { name: 'Save' })).toBeDisabled();
  await versionActions(page).getByRole('button', { name: 'Publish…' }).click();
  await page
    .getByRole('dialog', { name: 'Publish version 2' })
    .getByRole('button', { name: 'Publish and activate' })
    .click();
  await page
    .getByRole('dialog', { name: 'Version 2 published' })
    .getByRole('button', { name: 'Done' })
    .click();

  // Compare v1 and v2: the diff shows the changed action.
  await page.goto(`/policies/${policyId}/compare?from=1&to=2`);
  await expect(page.getByRole('heading', { level: 1 })).toContainText('Compare');
  await expectSettled(page, 'compare');
  await expect(main(page)).toContainText('severity: warning');
  await expect(main(page)).toContainText('severity: critical');
  await expectNoSeriousA11yViolations(page, '/policies/[id]/compare');

  // Roll back to v1: the active marker moves; the rollback is audited with previousVersionNo.
  await page.goto(`/policies/${policyId}/versions/1`);
  await versionActions(page).getByRole('button', { name: 'Roll back to v1' }).click();
  const rollback = page.getByRole('dialog', { name: 'Roll back to v1?' });
  await expect(rollback).toContainText('re-activates an earlier published version');
  await expectNoSeriousA11yViolations(page, 'rollback dialog');
  await rollback.getByRole('button', { name: 'Roll back to v1' }).click();
  const activeDialog = page.getByRole('dialog', { name: 'Version 1 is active' });
  await expect(activeDialog).toContainText('The policy now evaluates version 1.');
  await activeDialog.getByRole('button', { name: 'Done' }).click();

  await page.goto(`/policies/${policyId}?tab=versions`);
  const versions = page.getByRole('table', { name: 'Policy versions' });
  await expect(versions.getByRole('row', { name: /^Select version 1 v1 Active/ })).toBeVisible();
  await expect(versions.getByRole('row', { name: /^Select version 2 v2 Published/ })).toBeVisible();
  await expectNoSeriousA11yViolations(page, '/policies/[id]?tab=versions');

  await page.getByRole('tab', { name: 'Audit' }).click();
  const audit = page.getByRole('table', { name: 'Audit trail of the policy' });
  const rollbackRow = audit
    .getByRole('row')
    .filter({ hasText: 'policy.version_activated' })
    .filter({ hasText: /Previous version\s*2/ });
  await expect(rollbackRow.first()).toBeVisible();
  await expect(audit.getByRole('row').filter({ hasText: 'policy.version_published' })).toHaveCount(
    2,
  );
  await expectNoSeriousA11yViolations(page, '/policies/[id]?tab=audit');
  const auditRows = await policyAuditRows(policyId, started);
  const activations = auditRows.filter((row) => row.action === 'policy.version_activated');
  expect(activations.at(-1)!.metadata).toMatchObject({ versionNo: 1, previousVersionNo: 2 });

  // Disable and enable (switch with a confirmation).
  await page.getByRole('tab', { name: 'Overview' }).click();
  const enabled = page.getByRole('switch', { name: 'Enabled' });
  await expect(enabled).toBeChecked();
  await enabled.click();
  const disable = page
    .getByRole('alertdialog', { name: 'Disable this policy?' })
    .or(page.getByRole('dialog', { name: 'Disable this policy?' }));
  await disable.getByRole('button', { name: 'Disable', exact: true }).click();
  await expect(enabled).not.toBeChecked();
  await expect(
    main(page)
      .getByRole('definition')
      .filter({ hasText: /^Disabled$/ }),
  ).toBeVisible();
  await enabled.click();
  const enable = page
    .getByRole('alertdialog', { name: 'Enable this policy?' })
    .or(page.getByRole('dialog', { name: 'Enable this policy?' }));
  await enable.getByRole('button', { name: 'Enable', exact: true }).click();
  await expect(enabled).toBeChecked();
  const statusRows = await policyAuditRows(policyId, started);
  expect(statusRows.map((row) => row.action)).toEqual(
    expect.arrayContaining(['policy.disabled', 'policy.enabled']),
  );
});

/**
 * Step 8.4 (D23, §10.6): the account takeover fields reach the builder only through the catalogue
 * (group "Account takeover"); they are offered in a hold rule's conditions, never in exceptions
 * or in a rule that allows mail (the server refuses that with `field_strict_only`); the test
 * panel's ATO example runs against the unsaved policy; the policy is published, then disabled
 * again so the tenant's delivery is unchanged for later specs.
 */
test('account takeover fields: hold rule only, strict-only refusal, ATO test example, publish', async ({
  page,
}) => {
  const name = `E2E ATO hold ${Date.now().toString(36)}`;
  const ruleId = 'ato-hold';
  await signIn(page, 'alphaAdmin', { next: '/policies/new' });
  await expect(page.getByRole('heading', { level: 1, name: 'New policy' })).toBeVisible();
  await page.getByRole('textbox', { name: 'Name (required)' }).fill(name);
  await chooseOption(page, page.getByRole('combobox', { name: 'Policy direction' }), 'Outbound');
  await page
    .getByRole('region', { name: 'Rule rule-1', exact: true })
    .getByRole('textbox', { name: 'Rule id' })
    .fill(ruleId);
  const r = page.getByRole('region', { name: `Rule ${ruleId}`, exact: true });
  await addAction(page, r, 'Quarantine');
  const top = r.getByRole('group', {
    name: `Conditions of rule ${ruleId}, all of the following (AND), level 1`,
    exact: true,
  });
  const c1 = conditionIn(top, 1, 'AND', 1);
  await pickField(page, c1, 'Sender account takeover risk level');
  await chooseOperator(page, c1, '≥');
  await chooseOption(page, c1.getByRole('combobox', { name: 'Value' }), 'High');
  const article = summary(page).getByRole('article', { name: new RegExp(`^Rule ${ruleId} `) });
  await expect(article.getByRole('list', { name: `Conditions of rule ${ruleId}` })).toContainText(
    'Sender account takeover risk level is at least High',
  );

  // Not offered in an exception.
  await r.getByRole('button', { name: 'Add exception' }).click();
  const exception = r.getByRole('group', { name: `Exception 1 of rule ${ruleId}`, exact: true });
  await exception.getByRole('combobox', { name: /^Field / }).click();
  await page.getByRole('combobox', { name: 'Search fields' }).fill('account takeover');
  await expect(page.getByText('No field matches.')).toBeVisible();
  await page.keyboard.press('Escape');
  await exception
    .getByRole('button', { name: /^Remove / })
    .first()
    .click();
  await expect(exception).toHaveCount(0);

  // An ALLOW rule over an ATO field: warned in the builder, refused by the server (the action
  // menu offers ALLOW only when no holding action is present, so the QUARANTINE goes first).
  await r.getByRole('button', { name: 'Remove action Quarantine' }).click();
  await addAction(page, r, 'Allow');
  await expect(c1).toContainText(/is not accepted in a rule with Allow/);
  await page.getByRole('button', { name: 'Validate' }).first().click();
  await expect(main(page)).toContainText(
    'Account takeover fields may only make a decision stricter',
  );
  await r.getByRole('button', { name: 'Remove action Allow' }).click();
  await addAction(page, r, 'Quarantine');
  await page.getByRole('button', { name: 'Validate' }).first().click();
  await expect(main(page).getByText('The server accepts this document.')).toBeVisible();
  await expectNoSeriousA11yViolations(page, 'builder with an ATO hold rule');

  // Test the unsaved policy with the ATO example: the server holds the message.
  await page.getByRole('button', { name: 'Test' }).first().click();
  const testDialog = page.getByRole('dialog', { name: 'Test with synthetic facts' });
  await chooseOption(
    page,
    testDialog.getByRole('combobox', { name: 'Start from an example' }),
    'Outbound from a high-risk account',
  );
  await expect(testDialog.getByRole('group', { name: 'Account takeover' })).toBeVisible();
  const tests = spy(page, (q) => q.url().endsWith('/bff/api/v1/policies/test'));
  await testDialog.getByRole('button', { name: 'Run test' }).click();
  const result = testDialog.getByRole('region', { name: 'Test result (evaluated by the server)' });
  await expect(result).toBeVisible();
  const body = JSON.parse(tests.seen[0]!.body ?? '{}') as { facts: { ato?: unknown } };
  expect(body.facts.ato).toEqual({ riskScore: 65, riskLevel: 'high' });
  expect(await definitionOf(result, 'Disposition')).toBe('Quarantine');
  expect(await definitionOf(result, 'Decided by')).toContain(ruleId);
  await testDialog.getByRole('button', { name: 'Close' }).last().click();

  // Save, publish and activate; then disable the policy again (later specs see no ATO hold).
  await page.getByRole('button', { name: 'Save draft' }).click();
  await page.waitForURL(/\/policies\/[0-9a-f-]{36}\/versions\/1$/);
  const policyId = policyIdOf(page.url());
  await versionActions(page).getByRole('button', { name: 'Publish…' }).click();
  await page
    .getByRole('dialog', { name: 'Publish version 1' })
    .getByRole('button', { name: 'Publish and activate' })
    .click();
  await page
    .getByRole('dialog', { name: 'Version 1 published' })
    .getByRole('button', { name: 'Done' })
    .click();
  await page.goto(`/policies/${policyId}`);
  const enabled = page.getByRole('switch', { name: 'Enabled' });
  await expect(enabled).toBeChecked();
  await enabled.click();
  await page
    .getByRole('alertdialog', { name: 'Disable this policy?' })
    .or(page.getByRole('dialog', { name: 'Disable this policy?' }))
    .getByRole('button', { name: 'Disable', exact: true })
    .click();
  await expect(enabled).not.toBeChecked();
});
