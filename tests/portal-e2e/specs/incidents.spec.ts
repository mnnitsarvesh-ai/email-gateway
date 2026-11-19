/**
 * Security incidents (step 8.4 §6, §10.6, D24) against the real api over incidents opened by the
 * ATO store's incident policy (seed/ato.ts): the generic list with the category filter limited to
 * readable categories, the incident workflow on `/incidents/[id]` (assign, note, investigate,
 * confirm, request `restrict_smtp_sending`, approval by a second analyst with MFA, the applied
 * restriction, roll back), a false-positive resolution with feedback (signals dismissed, a trusted
 * context added, the account rescored), a manual incident, the print report (audited), the
 * auditor's read-only view, and axe on every view. Beta incidents never appear.
 */
import { activeRestrictions, atoAccount, auditActions } from '../support/ato';
import { signIn } from '../support/auth';
import { expect, test } from '../support/fixtures';
import { checkPage, expectNoSeriousA11yViolations, expectSettled } from '../support/pages';
import { chooseOption } from '../support/policies';

test.describe.configure({ timeout: 240_000 });

test('incident list: readable categories, filters in the URL, never a beta incident; axe', async ({
  page,
}) => {
  const victim = atoAccount('victim');
  const traveller = atoAccount('traveller');
  const beta = atoAccount('beta-victim', 'beta');
  await signIn(page, 'alphaAnalyst', { next: '/incidents?category=account_takeover' });
  await expect(page.getByRole('heading', { level: 1, name: 'Incidents' })).toBeVisible();
  const table = page.getByRole('table', { name: 'Security incidents' });
  await expect(table.getByRole('link', { name: victim.address })).toBeVisible();
  await expect(table.getByRole('link', { name: traveller.address })).toBeVisible();
  await expect(table.getByRole('link', { name: beta.address })).toHaveCount(0);
  // The category filter offers only readable categories (8.4: account takeover).
  await page.getByRole('combobox', { name: 'Category' }).click();
  await expect(page.getByRole('option')).toHaveText([
    'Every category you can read',
    'Account takeover',
  ]);
  await page.keyboard.press('Escape');
  await expectNoSeriousA11yViolations(page, '/incidents');

  await page.goto('/incidents?severity=critical');
  await expect(table.getByRole('link', { name: victim.address })).toBeVisible();
  await expect(table.getByRole('link', { name: traveller.address })).toHaveCount(0);
  // Most severe first (the suite's own sign-ins may add incidents of portal users too).
  await page.goto('/incidents?sort=-severity');
  await expect(table.getByRole('row').nth(1)).toContainText('Critical');
  await expect(table.getByRole('link', { name: victim.address })).toBeVisible();
});

test('workflow: assign, note, investigate, confirm, request a restriction, second-analyst approval, roll back', async ({
  page,
  context,
}) => {
  const started = new Date(Date.now() - 1_000);
  const victim = atoAccount('victim');
  await signIn(page, 'alphaAnalyst', { next: `/incidents/${victim.incidentId}` });
  await expect(
    page.getByRole('heading', { level: 1, name: `Account takeover: ${victim.address}` }),
  ).toBeVisible();
  await expectSettled(page, '/incidents/[id]');
  await expectNoSeriousA11yViolations(page, '/incidents/[id]');

  // Assign to me.
  await page.getByRole('button', { name: 'Assign to me' }).click();
  await page.getByRole('alertdialog').getByRole('button', { name: 'Assign to me' }).click();
  await expect(
    page
      .getByRole('term')
      .filter({ hasText: /^Assignee$/ })
      .locator('xpath=following-sibling::dd[1]'),
  ).toHaveText('You');

  // A note.
  await page.getByLabel('Investigation note').fill('Phishing reported by two recipients (e2e).');
  await page.getByRole('button', { name: 'Add note' }).click();
  const timeline = page.getByRole('list', { name: 'Incident timeline' });
  await expect(timeline).toContainText('Phishing reported by two recipients (e2e).');

  // Investigate, then confirm with a note.
  await page.getByRole('button', { name: 'Start investigating' }).click();
  await page.getByRole('alertdialog').getByRole('button', { name: 'Start investigating' }).click();
  await expect(page.getByRole('button', { name: 'Confirm compromise' })).toBeVisible();
  await page.getByRole('button', { name: 'Confirm compromise' }).click();
  const confirm = page.getByRole('alertdialog');
  await confirm.getByLabel(/Note/).fill('The user confirmed the phishing run.');
  await confirm.getByRole('button', { name: 'Confirm compromise' }).click();
  await expect(timeline).toContainText('Investigating → Confirmed');

  // Request restrict_smtp_sending from the recommendation: high impact → pending approval.
  const recommendations = page.getByRole('list', { name: 'Recommendations' });
  await recommendations
    .getByRole('listitem')
    .filter({ hasText: 'Restrict SMTP sending' })
    .getByRole('button', { name: 'Request' })
    .click();
  const request = page.getByRole('alertdialog', { name: 'Request a response' });
  await expect(request.getByRole('combobox', { name: 'Response' })).toContainText(
    'Restrict SMTP sending',
  );
  await chooseOption(page, request.getByRole('combobox', { name: 'Duration' }), '1 hour');
  await request.getByLabel(/Reason/).fill('Stop the ongoing phishing run (e2e).');
  await expectNoSeriousA11yViolations(page, 'request response dialog');
  await request.getByRole('button', { name: 'Request' }).click();
  const responses = page.getByRole('table', { name: 'Responses of the incident' });
  await expect(responses).toContainText('Pending approval');
  // Four eyes: the requester cannot approve.
  await expect(responses.getByRole('button', { name: /^Approve/ })).toHaveCount(0);
  await expect(responses).toContainText('the requester cannot approve their own request');
  await context.clearCookies();

  // A second analyst with an MFA session approves; the gateway restriction is applied.
  await signIn(page, 'alphaApprover', { next: '/ato/responses' });
  const pending = page.getByRole('table', { name: 'Responses waiting for approval' });
  await pending.getByRole('button', { name: 'Approve: Restrict SMTP sending' }).click();
  await page.getByRole('alertdialog').getByRole('button', { name: 'Approve' }).click();
  await expect(pending.getByRole('button', { name: 'Approve: Restrict SMTP sending' })).toHaveCount(
    0,
  );
  await expect.poll(async () => (await activeRestrictions()).length).toBe(1);
  expect((await activeRestrictions())[0]).toMatchObject({ kind: 'send_block', scope: 'mailbox' });
  await page.goto('/ato/responses?tab=restrictions');
  const restrictions = page.getByRole('table', { name: 'SMTP restrictions' });
  await expect(restrictions).toContainText(victim.address);
  await expect(restrictions).toContainText('Sending restricted');
  await expectNoSeriousA11yViolations(page, '/ato/responses?tab=restrictions');

  // Applied state on the incident; roll back (MFA, reason) lifts the restriction.
  await page.goto(`/incidents/${victim.incidentId}`);
  const incidentResponses = page.getByRole('table', { name: 'Responses of the incident' });
  await expect(incidentResponses).toContainText('Applied by the gateway');
  await incidentResponses.getByRole('button', { name: 'Roll back: Restrict SMTP sending' }).click();
  const rollback = page.getByRole('alertdialog');
  await rollback.getByLabel(/Reason/).fill('The account owner reset the password (e2e).');
  await rollback.getByRole('button', { name: 'Roll back' }).click();
  await expect(incidentResponses).toContainText('Rolled back');
  await expect.poll(async () => (await activeRestrictions()).length).toBe(0);

  const actions = await auditActions(started);
  expect(actions).toEqual(
    expect.arrayContaining([
      'security_incident.assigned',
      'security_incident.note_added',
      'security_incident.status_changed',
    ]),
  );
});

test('false-positive resolution with feedback dismisses the signals and trusts the context', async ({
  page,
}) => {
  const traveller = atoAccount('traveller');
  await signIn(page, 'alphaAnalyst', { next: `/incidents/${traveller.incidentId}` });
  await expect(
    page.getByRole('heading', { level: 1, name: `Account takeover: ${traveller.address}` }),
  ).toBeVisible();
  await page.getByRole('button', { name: 'Resolve as false positive' }).click();
  const dialog = page.getByRole('alertdialog');
  await chooseOption(page, dialog.getByRole('combobox', { name: 'Resolution' }), 'Benign activity');
  await expect(
    dialog.getByRole('checkbox', { name: /Dismiss the incident’s active signals/ }),
  ).toBeChecked();
  await dialog.getByLabel('Value').fill('203.0.113.0/24');
  await dialog.getByRole('button', { name: 'Add trusted context' }).click();
  await expect(dialog.getByRole('list', { name: 'Trusted contexts to add' })).toContainText(
    '203.0.113.0/24',
  );
  await dialog
    .getByLabel(/Resolution note/)
    .fill('The user travelled and sent a real newsletter (e2e).');
  await expectNoSeriousA11yViolations(page, 'false-positive dialog');
  await dialog.getByRole('button', { name: 'Resolve as false positive' }).click();
  await expect(
    page
      .getByRole('term')
      .filter({ hasText: /^Status$/ })
      .first()
      .locator('xpath=following-sibling::dd[1]'),
  ).toHaveText('False positive');
  await expect(page.getByRole('button', { name: 'Start investigating' })).toHaveCount(0);

  // The account was rescored (signals dismissed) and trusts the network.
  await page.goto(`/ato/accounts/${traveller.accountId}?tab=trusted`);
  await expect(page.getByRole('list', { name: 'Trusted contexts' })).toContainText(
    'false-positive feedback',
  );
  await page.goto(`/ato/accounts/${traveller.accountId}`);
  await expect(page.getByRole('meter', { name: /risk score 0 of 100, Low/ }).first()).toBeVisible();
  await page.goto(`/ato/accounts/${traveller.accountId}?tab=signals`);
  await expect(page.getByRole('table', { name: 'Risk signals of the account' })).toContainText(
    'Dismissed',
  );
});

test('a manual incident for an account, resolved again; the report is audited; axe', async ({
  page,
}) => {
  const started = new Date(Date.now() - 1_000);
  const quiet = atoAccount('quiet');
  const victim = atoAccount('victim');
  await signIn(page, 'alphaAnalyst', { next: '/incidents' });
  await page.getByRole('button', { name: 'New incident' }).click();
  const dialog = page.getByRole('alertdialog', { name: 'Open an incident' });
  await dialog.getByLabel('Account (address starts with)').fill('ato-quiet');
  await dialog.getByRole('button', { name: new RegExp(quiet.address.replace('.', '\\.')) }).click();
  await dialog.getByLabel(/Why/).fill('The user reported an unexpected MFA prompt (e2e).');
  await expectNoSeriousA11yViolations(page, 'new incident dialog');
  await dialog.getByRole('button', { name: 'Open incident' }).click();
  await page.waitForURL(/\/incidents\/[0-9a-f-]{36}$/);
  await expect(
    page.getByRole('heading', { level: 1, name: `Account takeover: ${quiet.address}` }),
  ).toBeVisible();
  await expect(page.locator('main')).toContainText('Opened manually');
  await page.getByRole('button', { name: 'Resolve', exact: true }).click();
  const resolve = page.getByRole('alertdialog');
  await chooseOption(page, resolve.getByRole('combobox', { name: 'Resolution' }), 'Duplicate');
  await resolve.getByLabel(/Resolution note/).fill('Same report as the earlier ticket (e2e).');
  await resolve.getByRole('button', { name: 'Resolve' }).click();
  await expect(
    page
      .getByRole('term')
      .filter({ hasText: /^Status$/ })
      .first()
      .locator('xpath=following-sibling::dd[1]'),
  ).toHaveText('Resolved');

  await checkPage(page, {
    path: `/incidents/${victim.incidentId}/report`,
    heading: 'Security incident report: Account takeover',
    markers: ['Detection reason', 'Signals', 'Timeline'],
  });
  await expect(page.getByRole('button', { name: 'Print or save as PDF' })).toBeVisible();
  expect(await auditActions(started)).toEqual(
    expect.arrayContaining(['security_incident.created', 'security_incident.report_exported']),
  );
});

test('compliance auditor: reads incidents and the report, no triage controls', async ({ page }) => {
  const victim = atoAccount('victim');
  await signIn(page, 'alphaAuditor', { next: `/incidents/${victim.incidentId}` });
  await expect(
    page.getByRole('heading', { level: 1, name: `Account takeover: ${victim.address}` }),
  ).toBeVisible();
  await expect(page.getByText(/triage needs the category’s manage permission/)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Start investigating' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Request a response' })).toHaveCount(0);
  await page.goto('/incidents');
  await expect(page.getByRole('button', { name: 'New incident' })).toHaveCount(0);
  await expectNoSeriousA11yViolations(page, '/incidents (auditor)');
});
