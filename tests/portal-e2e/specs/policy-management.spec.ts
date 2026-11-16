/**
 * Policy management (step 7.3 design §9.4, B9–B13) against the real api and the seeded policy
 * "E2E outbound data guard" (v1 published, v2 active with nested groups and an exception, v3
 * draft): page 13 and the detail views with axe; the seeded versions and their comparison; the
 * permission sets — a security analyst edits and tests drafts but has no publish controls (and a
 * direct publish call is `403`), a read-only user sees the builder in view mode only; cross-tenant
 * isolation (beta's policy and version URLs are the 404 state; the sample dry-run never lists a
 * beta message); risk-profile drafts (create → edit a threshold → save → publish → a second
 * version → roll back); the settings toggle with its confirmation.
 */
import type { Page } from '@playwright/test';
import { signIn } from '../support/auth';
import { expect, test } from '../support/fixtures';
import { bff } from '../support/messages';
import { expectNoSeriousA11yViolations, expectSettled } from '../support/pages';
import { chooseOption, versionActions } from '../support/policies';
import { readState } from '../support/state';

test.describe.configure({ timeout: 300_000 });
test.use({ actionTimeout: 20_000 });

function main(page: Page) {
  return page.locator('main');
}

const NOT_FOUND = /not found|does not exist|no longer exists/i;

test('page 13 and the seeded policy: list, detail, versions, compare', async ({ page }) => {
  const { policies } = readState();
  await signIn(page, 'alphaAdmin', { next: '/policies' });
  await expect(page.getByRole('heading', { level: 1, name: 'Policy management' })).toBeVisible();
  await expect(main(page).getByText(policies.policyName)).toBeVisible();
  await expect(main(page).getByText(policies.beta.policyName)).toHaveCount(0);
  await expect(main(page).getByRole('link', { name: 'New policy' }).first()).toBeVisible();
  await expect(main(page).getByText('Arrives in step 7.3')).toHaveCount(0);
  await expectSettled(page, '/policies');
  await expectNoSeriousA11yViolations(page, '/policies');

  await page.goto(`/policies/${policies.policyId}?tab=versions`);
  const versions = page.getByRole('table', { name: 'Policy versions' });
  await expect(versions.getByRole('row', { name: /^Select version 3 v3 Draft/ })).toBeVisible();
  await expect(
    versions.getByRole('row', { name: /^Select version 2 v2 Active Published/ }),
  ).toBeVisible();
  await expect(versions.getByRole('row', { name: /^Select version 1 v1 Published/ })).toBeVisible();
  // Two selected rows → Compare.
  await versions.getByRole('checkbox', { name: 'Select version 1' }).check();
  await versions.getByRole('checkbox', { name: 'Select version 2' }).check();
  await main(page)
    .getByRole('link', { name: /^Compare/ })
    .or(main(page).getByRole('button', { name: /^Compare/ }))
    .first()
    .click();
  await expect(page).toHaveURL(/\/compare\?/);
  await expectSettled(page, 'compare v1/v2');
  // v2 added the OR group, the exception and two actions.
  await expect(main(page)).toContainText('Number of recipients is greater than 5');
  await expect(main(page)).toContainText('E2E Finance');
  await expect(main(page)).toContainText('Alert administrators');
  await expectNoSeriousA11yViolations(page, '/policies/[id]/compare (seeded)');

  // The active version in view mode; its summary names the department, not its id.
  await page.goto(`/policies/${policies.policyId}/versions/2`);
  await expect(page.getByRole('heading', { level: 1 })).toHaveText(`${policies.policyName} · v2`);
  await expect(main(page).getByText('View mode')).toBeVisible();
  await expect(
    page.getByRole('complementary', { name: 'Readable summary of the policy' }),
  ).toContainText('Sender department is one of E2E Finance');
  await expectSettled(page, 'version 2');
  await expectNoSeriousA11yViolations(page, '/policies/[id]/versions/2 (view)');
});

test('security analyst edits and tests a draft but cannot publish', async ({ page }) => {
  const { policies } = readState();
  await signIn(page, 'alphaAnalyst', { next: `/policies/${policies.policyId}/versions/3` });
  await expect(page.getByRole('heading', { level: 1 })).toHaveText(`${policies.policyName} · v3`);
  await expect(main(page).getByText('Edit mode')).toBeVisible();
  const actions = versionActions(page);
  await expect(actions.getByRole('button', { name: 'Validate' })).toBeVisible();
  await expect(actions.getByRole('button', { name: 'Test' })).toBeVisible();
  await expect(actions.getByRole('button', { name: 'Dry run' })).toBeVisible();
  await expect(actions.getByRole('button', { name: /^Publish/ })).toHaveCount(0);

  // Edit and save the draft (expectedRowVersion), then test it.
  const rule = page.getByRole('region', { name: 'Rule hold-confidential', exact: true });
  await rule.getByRole('textbox', { name: 'Description (optional)' }).fill('Edited by the analyst');
  await actions.getByRole('button', { name: 'Save' }).click();
  await expect(actions.getByRole('button', { name: 'Save' })).toBeDisabled();
  const saved = await bff(page, 'GET', `/policies/${policies.policyId}/versions/3`);
  expect(JSON.stringify(saved.body?.definition)).toContain('Edited by the analyst');

  await actions.getByRole('button', { name: 'Test' }).click();
  const dialog = page.getByRole('dialog', { name: 'Test with synthetic facts' });
  await chooseOption(
    page,
    dialog.getByRole('combobox', { name: 'Start from an example' }),
    'Clean inbound message',
  );
  await dialog.getByRole('button', { name: 'Run test' }).click();
  await expect(
    dialog.getByRole('region', { name: 'Test result (evaluated by the server)' }),
  ).toBeVisible();
  await dialog.getByRole('button', { name: 'Close' }).last().click();

  // No publish, activate, enable/disable or delete-policy controls anywhere.
  await page.goto(`/policies/${policies.policyId}/versions/1`);
  await expect(
    versionActions(page).getByRole('button', { name: /^Roll back|^Activate/ }),
  ).toHaveCount(0);
  await page.goto(`/policies/${policies.policyId}`);
  await expect(page.getByRole('heading', { level: 1, name: policies.policyName })).toBeVisible();
  await expect(main(page).getByRole('switch', { name: 'Enabled' })).toHaveCount(0);
  await expect(main(page).getByRole('button', { name: 'Delete policy' })).toHaveCount(0);
  await expectNoSeriousA11yViolations(page, '/policies/[id] (security analyst)');

  // The api stays authoritative: a direct publish is refused.
  const draft = await bff(page, 'GET', `/policies/${policies.policyId}/versions/3`);
  const refused = await bff(page, 'POST', `/policies/${policies.policyId}/versions/3/publish`, {
    activate: true,
    expectedRowVersion: draft.body?.rowVersion,
  });
  expect(refused.status).toBe(403);
});

test('read-only user sees the builder in view mode only', async ({ page }) => {
  const { policies } = readState();
  await signIn(page, 'alphaReadOnly', { next: `/policies/${policies.policyId}/versions/3` });
  await expect(page.getByRole('heading', { level: 1 })).toHaveText(`${policies.policyName} · v3`);
  await expect(main(page).getByText('View mode')).toBeVisible();
  const actions = versionActions(page);
  for (const name of ['Validate', 'Save', 'Test', 'Dry run', 'Publish…', 'Delete draft']) {
    await expect(actions.getByRole('button', { name, exact: true })).toHaveCount(0);
  }
  const rules = page.getByRole('region', { name: /^Rules \(/ });
  await expect(rules.getByRole('textbox')).toHaveCount(0);
  await expect(rules.getByRole('spinbutton')).toHaveCount(0);
  await expect(rules.getByRole('button', { name: /^(Add|Remove|Move)/ })).toHaveCount(0);
  await expectNoSeriousA11yViolations(page, '/policies/[id]/versions/3 (read-only)');

  await page.goto('/policies');
  await expect(main(page).getByText(policies.policyName)).toBeVisible();
  await expect(main(page).getByRole('link', { name: 'New policy' })).toHaveCount(0);
  await page.goto(`/policies/${policies.policyId}`);
  await expect(page.getByRole('heading', { level: 1, name: policies.policyName })).toBeVisible();
  for (const name of ['New draft', 'Rename', 'Delete policy']) {
    await expect(main(page).getByRole('button', { name, exact: true })).toHaveCount(0);
  }
  await expect(main(page).getByRole('switch', { name: 'Enabled' })).toHaveCount(0);
});

test('cross-tenant: beta policy URLs are the 404 state; the sample never lists beta', async ({
  page,
}) => {
  const { policies, beta } = readState();
  await signIn(page, 'alphaAdmin', { next: `/policies/${policies.beta.policyId}` });
  await expect(main(page).getByText(NOT_FOUND).first()).toBeVisible();
  await expect(main(page).getByText(policies.beta.policyName)).toHaveCount(0);
  await page.goto(`/policies/${policies.beta.policyId}/versions/1`);
  await expect(main(page).getByText(NOT_FOUND).first()).toBeVisible();
  await expect(main(page).getByText('beta-only-rule')).toHaveCount(0);
  await expectNoSeriousA11yViolations(page, 'foreign policy version (404 state)');

  const policy = await bff(page, 'GET', `/policies/${policies.beta.policyId}`);
  expect(policy.status).toBe(404);
  expect(policy.body?.code).toBe('policy_not_found');
  const version = await bff(page, 'GET', `/policies/${policies.beta.policyId}/versions/1`);
  expect(version.status).toBe(404);
  // A foreign version as a dry-run target is unknown too, and the sample reads only alpha.
  const foreign = await bff(page, 'POST', '/policies/dry-run', {
    target: { policyId: policies.beta.policyId, versionNo: 1 },
  });
  expect(foreign.status).toBe(404);
  const sample = await bff(page, 'POST', '/policies/dry-run', { target: 'active' });
  expect(sample.status).toBe(200);
  const ids = (sample.body?.items as Array<{ messageId: string | null }>).map((i) => i.messageId);
  expect(ids.length).toBeGreaterThan(0);
  expect(ids).not.toContain(beta.twinMessageId);
  expect(ids).not.toContain(beta.messageId);
});

test('risk profile: draft, edit a threshold, save, publish, second version, roll back', async ({
  page,
}) => {
  await signIn(page, 'alphaAdmin', { next: '/policies?tab=risk' });
  const create = async (note: string) => {
    await main(page).getByRole('button', { name: 'New draft' }).click();
    const dialog = page.getByRole('dialog', { name: 'New risk-profile draft' });
    await dialog.getByRole('textbox', { name: 'Change note' }).fill(note);
    await dialog.getByRole('button', { name: 'Create draft' }).click();
    await page.waitForURL(/\/policies\/risk-profile\/[0-9a-f-]{36}$/);
  };
  const editAndPublish = async (input: string, value: string, versionNo: number) => {
    await expect(main(page).getByText('Edit mode')).toBeVisible();
    await page.getByRole('spinbutton', { name: input }).fill(value);
    const actions = page.getByRole('group', { name: 'Risk-profile actions' });
    const saves = page.waitForResponse(
      (res) =>
        res.request().method() === 'PUT' && res.url().includes('/risk-scoring/profile/versions/'),
    );
    await actions.getByRole('button', { name: 'Save' }).click();
    const saved = await saves;
    expect(saved.status()).toBe(200);
    const body = JSON.parse(saved.request().postData() ?? '{}') as {
      overrides: { thresholds?: Record<string, number> };
      expectedRowVersion: number;
    };
    expect(body.expectedRowVersion).toBeGreaterThanOrEqual(1);
    await expect(actions.getByRole('button', { name: 'Save' })).toBeDisabled();
    await expectNoSeriousA11yViolations(page, `/policies/risk-profile/[id] v${versionNo}`);
    await actions.getByRole('button', { name: 'Publish…' }).click();
    const publish = page.getByRole('dialog', { name: `Publish risk profile v${versionNo}?` });
    await expect(publish.getByRole('switch', { name: 'Activate now' })).toBeChecked();
    await publish.getByRole('button', { name: 'Publish and activate' }).click();
    await expect(publish).toHaveCount(0);
    return body;
  };

  await create('Raise the low threshold (e2e)');
  const first = await editAndPublish('Low from score', '120', 1);
  expect(JSON.stringify(first.overrides)).toContain('120');
  await page.goto('/policies?tab=risk');
  await create('Raise the medium threshold (e2e)');
  await expect(page.getByRole('spinbutton', { name: 'Low from score' })).toHaveValue('120');
  await editAndPublish('Medium from score', '320', 2);

  // Roll back to v1 from the versions table (confirmed, audited as an activation).
  await page.goto('/policies?tab=risk');
  const table = page.getByRole('table', { name: /risk profile versions/i });
  await expect(
    table.getByRole('row').filter({ hasText: 'Raise the medium threshold' }),
  ).toContainText('Active');
  await table
    .getByRole('row')
    .filter({ hasText: 'Raise the low threshold' })
    .getByRole('button', { name: /^Actions for/ })
    .click();
  await page.getByRole('menuitem', { name: 'Roll back to v1…' }).click();
  const rollback = page.getByRole('dialog', { name: 'Roll back to v1?' });
  await expectNoSeriousA11yViolations(page, 'risk rollback dialog');
  await rollback.getByRole('button', { name: 'Roll back to v1' }).click();
  await expect(rollback).toHaveCount(0);
  await expect(table.getByRole('row').filter({ hasText: 'Raise the low threshold' })).toContainText(
    'Active',
  );
  const levels = page.getByRole('table', { name: 'Risk level thresholds and recommended actions' });
  await expect(levels.getByRole('row', { name: /^Low 120/ })).toBeVisible();
  await expect(levels.getByRole('row', { name: /^Medium 300/ })).toBeVisible();
  await expectNoSeriousA11yViolations(page, '/policies?tab=risk (tenant versions)');
});

test('policy settings: toggle with confirmation', async ({ page }) => {
  await signIn(page, 'alphaAdmin', { next: '/policies?tab=settings' });
  const form = page.getByRole('form', { name: 'Policy settings' });
  const overrides = form.getByRole('switch', { name: 'Recommendation overrides' });
  await expect(overrides).not.toBeChecked();
  await overrides.click();
  const writes = page.waitForRequest(
    (req) => req.method() === 'PUT' && req.url().endsWith('/bff/api/v1/policy-settings'),
  );
  await form.getByRole('button', { name: 'Save settings' }).click();
  const confirm = page
    .getByRole('alertdialog', { name: 'Allow recommendation overrides?' })
    .or(page.getByRole('dialog', { name: 'Allow recommendation overrides?' }));
  await expectNoSeriousA11yViolations(page, 'settings overrides confirmation');
  await confirm.getByRole('button', { name: 'Allow overrides and save' }).click();
  const sent = JSON.parse((await writes).postData() ?? '{}') as Record<string, unknown>;
  expect(sent).toEqual({
    settings: { allowRecommendationOverrides: true },
    expectedRowVersion: expect.any(Number),
  });
  await expect(overrides).toBeChecked();
  await expect(form.getByRole('button', { name: 'Save settings' })).toBeDisabled();
  const settings = await bff(page, 'GET', '/policy-settings');
  expect(JSON.stringify(settings.body)).toContain('"allowRecommendationOverrides":true');

  // Turning it off again needs no confirmation.
  await overrides.click();
  await form.getByRole('button', { name: 'Save settings' }).click();
  await expect(form.getByRole('button', { name: 'Save settings' })).toBeDisabled();
  await expect(overrides).not.toBeChecked();
  await expectNoSeriousA11yViolations(page, '/policies?tab=settings');
});
