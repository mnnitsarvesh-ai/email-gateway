/**
 * Step API-2 (docs/plan/steps/36-api-mode-remediation.md R15, §9.5): API-mode remediation in the
 * browser against the real api (MySQL writer/replica, Redis), on the synthetic tenant zeta
 * (seed/api-mode.ts `seedRemediation`; never organizations 1, 2 or 16946 or user 21416):
 *
 * - the Remediation tab: the detect-only preset saved with a reason (stored, audited) and a domain
 *   override added and removed again;
 * - the History tab: the failed quarantine-folder move with its decision record, retried;
 * - detections: "Remediate…" queues an admin action, "Remove tag" queues the tag removal;
 * - /quarantine: the mailbox-located entry (Location column and filter, location block, detection
 *   link), "Restore to inbox" asks for approval (hard block) and a second user (MFA) approves it,
 *   which queues the `restore_inbox` action instead of a delivery;
 * - a read-only user sees every remediation view without a write control.
 *
 * No provider is contacted: the actions the spec queues stay in the table for the mailbox-worker's
 * `remediate` role; the spec checks what the api stored, never a mailbox change.
 */
import { randomBytes } from 'node:crypto';
import type { Page } from '@playwright/test';
import { signIn, signOut } from '../support/auth';
import { expect, test } from '../support/fixtures';
import { writerDb } from '../support/messages';
import { expectNoSeriousA11yViolations } from '../support/pages';
import { readState } from '../support/state';

test.describe.configure({ mode: 'serial', timeout: 240_000 });

const suffix = () => randomBytes(3).toString('hex');

async function zetaId(): Promise<bigint> {
  const org = await writerDb().organization.findUniqueOrThrow({
    where: { publicId: readState().orgs.zeta.id },
    select: { id: true },
  });
  return org.id;
}

async function copyOf(publicId: string) {
  return writerDb().apiMessageCopy.findFirstOrThrow({
    where: { publicId, organizationId: await zetaId() },
    select: { id: true, remediationState: true },
  });
}

/** The audit page lists the action (the audit search reads the replica: retried). */
async function expectAuditRow(page: Page, action: string) {
  await expect(async () => {
    await page.goto(`/audit-logs?range=7d&action=${action}`);
    await expect(page.locator('main table').first()).toContainText(action, { timeout: 3_000 });
  }).toPass({ timeout: 45_000 });
}

async function confirmWithReason(page: Page, confirmLabel: string, reason: string) {
  const dialog = page.getByRole('alertdialog');
  await expect(dialog).toBeVisible();
  await dialog.getByRole('textbox').first().fill(reason);
  await dialog.getByRole('button', { name: confirmLabel, exact: true }).click();
}

test('Remediation tab: detect-only preset saved with a reason; a domain override added and removed', async ({
  page,
}) => {
  const s = readState().apiMode;
  await signIn(page, 'zetaAdmin', { next: '/api-mode?tab=remediation' });
  const form = page.getByRole('form', { name: 'Remediation policy: organization' });
  await expect(form).toBeVisible({ timeout: 20_000 });
  await expect(page.getByText(/Platform default \(P1\)/).first()).toBeVisible();
  await expect(form.getByRole('listitem', { name: /^Rule \d+$/ })).toHaveCount(4);
  await expect(form.getByRole('note')).toContainText(
    'Detect only is the recommended start for new tenants',
  );
  await expectNoSeriousA11yViolations(page, '/api-mode (remediation)');

  await form
    .getByRole('button', { name: 'Apply Detect-only start (recommended for new tenants)' })
    .click();
  await expect(form.getByRole('radio', { name: 'Detect only' })).toBeChecked();
  const reason = `E2E detect-only start ${suffix()}`;
  await form.getByLabel('Reason (required)').fill(reason);
  await form.getByRole('button', { name: 'Save policy' }).click();
  await expect(page.getByText('Remediation policy saved.')).toBeVisible({ timeout: 20_000 });
  await expect
    .poll(async () =>
      writerDb().apiRemediationPolicy.findFirst({
        where: { organizationId: await zetaId(), domainId: null },
        select: { mode: true, rowVersion: true },
      }),
    )
    .toMatchObject({ mode: 'detect_only' });
  await expect(page.getByText(/Organization policy · updated/)).toBeVisible({ timeout: 20_000 });

  // A domain override for the Hybrid domain, then back to inheriting.
  await page.getByRole('button', { name: 'Add domain override' }).click();
  const dialog = page.getByRole('dialog', { name: 'Add a domain override' });
  await dialog.getByRole('combobox', { name: 'Domain' }).click();
  await page.getByRole('option', { name: s.domainNames.hybrid }).click();
  await dialog.getByRole('radio', { name: 'Enforce' }).click();
  await dialog.getByLabel('Reason (required)').fill(`${reason} (domain)`);
  await dialog.getByRole('button', { name: 'Save override' }).click();
  const overrides = page.getByRole('table', { name: 'Domain overrides' });
  await expect(overrides).toContainText(s.domainNames.hybrid, { timeout: 20_000 });
  await overrides
    .getByRole('button', { name: `Remove override of ${s.domainNames.hybrid}` })
    .click();
  await page
    .getByRole('alertdialog')
    .getByRole('button', { name: 'Remove override', exact: true })
    .click();
  await expect(page.getByText('No domain override: every domain inherits')).toBeVisible({
    timeout: 20_000,
  });
  expect(
    await writerDb().apiRemediationPolicy.count({
      where: { organizationId: await zetaId(), domainId: { not: null } },
    }),
  ).toBe(0);
  await expectAuditRow(page, 'api_mode.remediation_policy_updated');
});

test('History tab: the failed action with its decision record, retried', async ({ page }) => {
  const r = readState().apiMode.remediation;
  await signIn(page, 'zetaAdmin', { next: '/api-mode?tab=history&status=failed' });
  const table = page.getByRole('table', { name: 'Mailbox actions of API-mode remediation' });
  await expect(table).toContainText('Move to quarantine folder', { timeout: 20_000 });
  await expect(table).toContainText('provider_unavailable');
  await expectNoSeriousA11yViolations(page, '/api-mode (history)');

  await page.goto(`/api-mode?tab=history&status=failed&remediation=${r.failedActionId}`);
  const drawer = page.getByRole('dialog', { name: 'Mailbox action' });
  await expect(drawer).toContainText('p1-high-confidence-malware-phishing', { timeout: 20_000 });
  await expect(drawer).toContainText('provider_unavailable (HTTP 503)');
  await expect(drawer.getByRole('link', { name: 'Open the detection' })).toHaveAttribute(
    'href',
    `/api-mode?tab=detections&detection=${r.failedDetectionId}`,
  );
  await drawer.getByRole('button', { name: 'Retry', exact: true }).click();
  await page.getByRole('alertdialog').getByRole('button', { name: 'Retry', exact: true }).click();
  await expect(page.getByText(/Queued again/)).toBeVisible({ timeout: 20_000 });
  // Pending again with the attempts reset (a running remediate role may already hold it, so
  // only "no longer the seeded failure" is asserted).
  const row = await writerDb().apiRemediationAction.findFirstOrThrow({
    where: { publicId: r.failedActionId },
    select: { status: true, attempts: true },
  });
  expect(row.status !== 'failed' || row.attempts < 8).toBe(true);
});

test('Detections: "Remediate…" queues an admin action; "Remove tag" queues the tag removal', async ({
  page,
}) => {
  const r = readState().apiMode.remediation;
  await signIn(page, 'zetaAdmin', { next: '/api-mode?tab=detections' });
  const table = page.getByRole('table').first();
  await expect(table).toContainText('Remediated', { timeout: 20_000 });
  await expect(table).toContainText('Tag (category or label)');
  await expectNoSeriousA11yViolations(page, '/api-mode (detections, remediation)');

  // Remediate the phishing copy without remediation: move it to Junk.
  await page.goto(`/api-mode?tab=detections&detection=${r.remediableDetectionId}`);
  let drawer = page.getByRole('dialog', { name: 'Detection' });
  await expect(drawer).toContainText('No action', { timeout: 20_000 });
  await drawer.getByRole('button', { name: 'Remediate…' }).click();
  const remediate = page.getByRole('alertdialog');
  await remediate.getByRole('combobox', { name: 'Mailbox action' }).click();
  await expect(page.getByRole('option', { name: /Hard delete/ })).toHaveCount(0);
  await page.getByRole('option', { name: 'Move to Junk' }).click();
  await confirmWithReason(page, 'Remediate', `E2E reported phishing ${suffix()}`);
  await expect(page.getByText(/Mailbox action queued/)).toBeVisible({ timeout: 20_000 });
  const remediable = await copyOf(r.remediableDetectionId);
  expect(
    await writerDb().apiRemediationAction.count({
      where: { copyId: remediable.id, action: 'move_junk', trigger: 'admin' },
    }),
  ).toBe(1);

  // Remove the policy's tag from the suspicious copy.
  await page.goto(`/api-mode?tab=detections&detection=${r.taggedDetectionId}`);
  drawer = page.getByRole('dialog', { name: 'Detection' });
  await expect(drawer).toContainText('Remediated', { timeout: 20_000 });
  await drawer.getByRole('button', { name: 'Restore' }).click();
  await expect(
    page
      .getByRole('alertdialog')
      .getByRole('heading', { name: 'Remove the tag from this message?' }),
  ).toBeVisible();
  await confirmWithReason(page, 'Remove tag', `E2E tag not needed ${suffix()}`);
  await expect(page.getByText('Tag removal queued.')).toBeVisible({ timeout: 20_000 });
  const tagged = await copyOf(r.taggedDetectionId);
  expect(
    await writerDb().apiRemediationAction.count({
      where: { copyId: tagged.id, action: 'remove_tag', trigger: 'admin' },
    }),
  ).toBe(1);
});

test('Quarantine: the mailbox entry is restored to the inbox through an approval', async ({
  page,
}) => {
  const r = readState().apiMode.remediation;
  await signIn(page, 'zetaAdmin', { next: '/quarantine?location=mailbox&range=7d' });
  const entries = page.getByRole('table', { name: 'Quarantine entries' });
  await expect(entries).toContainText('In mailbox quarantine folder', { timeout: 20_000 });
  await expect(entries).not.toContainText('Gateway');
  await expectNoSeriousA11yViolations(page, '/quarantine (location mailbox)');

  await page.goto(`/quarantine/${r.entryId}`);
  const block = page.getByRole('group', { name: 'Location' });
  await expect(block).toContainText('In mailbox quarantine folder', { timeout: 20_000 });
  await expect(block).toContainText('Microsoft 365');
  await expect(block.getByRole('link', { name: 'Open the API-mode detection' })).toHaveAttribute(
    'href',
    `/api-mode?tab=detections&detection=${r.quarantinedDetectionId}`,
  );
  await expect(page.getByRole('link', { name: 'Open message details' })).toHaveCount(0);
  await expectNoSeriousA11yViolations(page, '/quarantine/[entryId] (mailbox)');
  await page.getByRole('button', { name: 'Restore to inbox' }).click();
  await expect(
    page
      .getByRole('alertdialog')
      .getByRole('heading', { name: 'Restore this message to the inbox?' }),
  ).toBeVisible();
  await confirmWithReason(page, 'Restore to inbox', `E2E false positive ${suffix()}`);
  await expect(page.getByText('Approval requested')).toBeVisible({ timeout: 20_000 });

  const entry = await writerDb().quarantineMessage.findFirstOrThrow({
    where: { publicId: r.entryId },
    select: { id: true, status: true },
  });
  expect(entry.status).toBe('pending_approval');
  const request = await writerDb().quarantineApprovalRequest.findFirstOrThrow({
    where: { quarantineMessageId: entry.id, status: 'pending' },
    select: { publicId: true },
  });
  await signOut(page);

  // A second user (MFA) approves: the restore is queued, never a delivery.
  await signIn(page, 'zetaApprover', { next: `/quarantine/approvals/${request.publicId}` });
  await expect(page.getByText(/approving restores it to the Inbox/)).toBeVisible({
    timeout: 20_000,
  });
  await page.getByRole('button', { name: 'Approve', exact: true }).click();
  await expect(page.getByRole('alertdialog')).toContainText('moved back to the Inbox');
  await confirmWithReason(page, 'Approve', `E2E approved restore ${suffix()}`);
  await expect(
    page.getByText('Approved. The mailbox worker restores the message to the Inbox.'),
  ).toBeVisible({ timeout: 20_000 });
  const restore = await writerDb().apiRemediationAction.findFirstOrThrow({
    where: { quarantineEntryId: entry.id, action: 'restore_inbox' },
    select: { trigger: true, releaseLogId: true },
  });
  expect(restore.trigger).toBe('release');
  expect(restore.releaseLogId).not.toBeNull();
  expect(
    (await writerDb().quarantineMessage.findUniqueOrThrow({ where: { id: entry.id } })).status,
  ).toMatch(/^(releasing|released)$/);
});

test('read-only user: remediation views without write controls', async ({ page }) => {
  const r = readState().apiMode.remediation;
  await signIn(page, 'zetaReadOnly', { next: '/api-mode?tab=remediation' });
  await expect(page.getByRole('table', { name: 'Rules of the organization policy' })).toBeVisible({
    timeout: 20_000,
  });
  await expect(page.getByRole('form')).toHaveCount(0);
  await expect(page.getByRole('button', { name: /^Apply / })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Add domain override' })).toHaveCount(0);

  await page.getByRole('tab', { name: 'History' }).click();
  await expect(
    page.getByRole('table', { name: 'Mailbox actions of API-mode remediation' }),
  ).toContainText('Move to quarantine folder', { timeout: 20_000 });
  await page.goto(`/api-mode?tab=history&remediation=${r.failedActionId}`);
  const drawer = page.getByRole('dialog', { name: 'Mailbox action' });
  await expect(drawer).toContainText('p1-high-confidence-malware-phishing', { timeout: 20_000 });
  await expect(drawer.getByRole('button', { name: 'Retry' })).toHaveCount(0);

  // The copy behind the mailbox entry stays remediated while its restore is queued (R10.2).
  await page.goto(`/api-mode?tab=detections&detection=${r.quarantinedDetectionId}`);
  const detection = page.getByRole('dialog', { name: 'Detection' });
  await expect(detection).toContainText('Remediated', { timeout: 20_000 });
  await expect(detection.getByRole('button', { name: 'Remediate…' })).toHaveCount(0);
  await expect(detection.getByRole('button', { name: 'Restore' })).toHaveCount(0);

  await page.goto('/api-mode');
  await expect(page.getByRole('list', { name: 'Remediation summary' })).toBeVisible({
    timeout: 20_000,
  });
  await expect(page.getByRole('switch')).toHaveCount(0);
});
