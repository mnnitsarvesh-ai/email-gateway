/**
 * Step API-3 (docs/plan/steps/37-api-mode-clawback-reporting.md C4–C14, §9.5): API-mode search and
 * purge, approvals, reported phishing and the organization settings in the browser against the
 * real api (MySQL writer/replica, Redis), on the synthetic tenant zeta (seed/api-mode.ts
 * `seedClawback`; never organizations 1, 2 or 16946 or user 21416):
 *
 * - search by Message-ID → the hit list → purge (Junk) below the threshold → the stored submit;
 * - settings saved with a reason and CAS (a concurrent change is explained, reloaded and saved
 *   again; the approval threshold is lowered to 1);
 * - a purge above the lowered threshold → approval requested → the requester only waits → a second
 *   user (MFA, `remediation:purge`) approves;
 * - cancel of a ready clawback;
 * - report triage: resolve malicious with reporter feedback for the whole group → "Claw back this
 *   message…" creates the report clawback and opens it;
 * - a read-only user sees every view without a write control.
 *
 * The clawback role of the mailbox-worker materializes searches; when the running worker image has
 * no `clawback` role yet (it is rebuilt by WP7), the spec writes the frozen targets exactly as that
 * role does (C4.2, C5.2: matched copies by Message-ID hash within the window, counts, `ready`)
 * after waiting for it. Every other row asserted is written by the api; assertions tolerate a
 * running worker that moves a queued purge on (queued → running → completed).
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
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function zetaId(): Promise<bigint> {
  const org = await writerDb().organization.findUniqueOrThrow({
    where: { publicId: readState().orgs.zeta.id },
    select: { id: true },
  });
  return org.id;
}

async function userId(email: string): Promise<bigint> {
  return (await writerDb().user.findFirstOrThrow({ where: { email }, select: { id: true } })).id;
}

async function clawbackRow(publicId: string) {
  return writerDb().apiClawback.findFirstOrThrow({
    where: { publicId, organizationId: await zetaId() },
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

/**
 * Waits for the mailbox-worker's `clawback` role; without it, writes what that role writes after a
 * Message-ID search (C4.2, C5.2): one `matched` target per copy of the criteria's Message-ID
 * hashes in the window and directions (report mailboxes and deleted mailboxes excluded), the
 * counts and status `ready`, CAS on the row version.
 */
async function materializeUnlessWorker(publicId: string): Promise<'worker' | 'spec'> {
  for (let i = 0; i < 15; i += 1) {
    if ((await clawbackRow(publicId)).status !== 'searching') return 'worker';
    await sleep(1_000);
  }
  const row = await clawbackRow(publicId);
  const criteria = row.criteria as {
    window: { from: string; to: string };
    keys: { messageIdHashes?: string[] };
    directions: Array<'inbound' | 'internal'>;
  };
  const copies = await writerDb().apiMessageCopy.findMany({
    where: {
      organizationId: row.organizationId,
      messageIdHash: { in: criteria.keys.messageIdHashes ?? [] },
      receivedAt: { gte: new Date(criteria.window.from), lte: new Date(criteria.window.to) },
      direction: { in: criteria.directions },
    },
    select: {
      id: true,
      receivedAt: true,
      mailboxId: true,
      messageId: true,
      apiConnectionId: true,
    },
  });
  const mailboxes = await writerDb().apiMailbox.findMany({
    where: { id: { in: copies.map((c) => c.mailboxId) } },
    select: { id: true, reportMailbox: true, status: true },
  });
  const eligible = copies.filter((c) =>
    mailboxes.some((m) => m.id === c.mailboxId && !m.reportMailbox && m.status !== 'deleted'),
  );
  const mailboxCount = new Set(eligible.map((c) => c.mailboxId)).size;
  await writerDb().$transaction(async (tx) => {
    for (const c of eligible) {
      await tx.apiClawbackTarget.create({
        data: {
          clawbackId: row.id,
          organizationId: row.organizationId,
          apiConnectionId: c.apiConnectionId,
          mailboxId: c.mailboxId,
          copyId: c.id,
          copyReceivedAt: c.receivedAt,
          messageId: c.messageId,
          matchKeys: ['message_id'],
          status: 'matched',
        },
      });
    }
    const updated = await tx.apiClawback.updateMany({
      where: { id: row.id, status: 'searching', rowVersion: row.rowVersion },
      data: {
        status: eligible.length === 0 ? 'no_match' : 'ready',
        targetsTotal: eligible.length,
        mailboxesTotal: mailboxCount,
        targetsEligible: eligible.length,
        mailboxesEligible: mailboxCount,
        rowVersion: { increment: 1 },
      },
    });
    if (updated.count !== 1) throw new Error('the clawback changed while materializing');
  });
  return 'spec';
}

test('search by Message-ID → hit list → purge (Junk) below the threshold', async ({ page }) => {
  const s = readState().apiMode.clawback;
  await signIn(page, 'zetaAdmin', { next: '/api-mode?tab=purge' });
  const list = page.getByRole('table', { name: 'Clawbacks and purges' });
  await expect(list).toContainText('Ready for review', { timeout: 20_000 });
  await expectNoSeriousA11yViolations(page, '/api-mode (search & purge)');

  await page.getByRole('button', { name: 'New search' }).click();
  const form = page.getByRole('form', { name: 'New search' });
  await form.getByRole('textbox', { name: 'Message-ID' }).fill(s.searchMessageId);
  const reason = `E2E reported invoice phishing ${suffix()}`;
  await form.getByLabel('Reason (required)').fill(reason);
  await form.getByRole('button', { name: 'Search' }).click();
  await expect(page).toHaveURL(/clawback=[0-9a-f-]{36}/, { timeout: 20_000 });
  const id = new URL(page.url()).searchParams.get('clawback')!;
  const created = await clawbackRow(id);
  expect(created).toMatchObject({
    trigger: 'admin',
    requestReason: reason,
    requestedByType: 'user',
  });
  expect(created.requestedByUserId).toBe(await userId(readState().users.zetaAdmin.email));
  expect(
    (created.criteria as { keys: { messageIdHashes: string[] } }).keys.messageIdHashes,
  ).toHaveLength(1);

  await materializeUnlessWorker(id);
  await expect(page.getByRole('heading', { name: 'Administrator search' })).toBeVisible();
  const hits = page.getByRole('table', { name: 'Messages found by the clawback' });
  await expect(hits).toContainText(readState().apiMode.mailboxes[0]!, { timeout: 30_000 });
  await expect(hits).toContainText(readState().apiMode.mailboxes[1]!);
  await expect(hits).toContainText('E2E clawback: your invoice is overdue');
  await expect(hits).toContainText('Message-ID');
  await expectNoSeriousA11yViolations(page, '/api-mode (clawback detail)');

  await page.getByRole('button', { name: 'Submit…' }).click();
  const submit = page.getByRole('form', { name: 'Submit the purge' });
  await expect(submit).toContainText('2 eligible mailboxes');
  await expect(submit).toContainText('Below the threshold');
  await submit.getByRole('radio', { name: 'Move to Junk' }).click();
  await submit.getByLabel('Reason (required)').fill(`${reason} (submit)`);
  await submit.getByRole('button', { name: 'Submit purge' }).click();
  await expect(submit).toHaveCount(0, { timeout: 20_000 });
  const row = await clawbackRow(id);
  expect(row).toMatchObject({
    decisionMode: 'explicit',
    action: 'move_junk',
    requiresApproval: false,
    approvalStatus: null,
  });
  expect(row.status).toMatch(/^(queued|running|completed|completed_with_errors)$/);
  expect(row.submittedByUserId).toBe(await userId(readState().users.zetaAdmin.email));
  expect(row.submittedAt).not.toBeNull();
  await expectAuditRow(page, 'api_mode.clawback_submitted');
});

test('settings: saved with a reason and CAS; the approval threshold lowered to 1', async ({
  page,
}) => {
  await signIn(page, 'zetaAdmin', { next: '/api-mode?tab=settings' });
  const form = page.getByRole('form', { name: 'Organization settings' });
  await expect(form).toBeVisible({ timeout: 20_000 });
  await expect(page.getByText(/Saved settings · updated/)).toBeVisible();
  await expect(page.getByRole('table', { name: 'Report mailboxes' })).toContainText(
    readState().apiMode.clawback.reportMailbox,
  );
  await expectNoSeriousA11yViolations(page, '/api-mode (settings)');

  // Another administrator changed the settings meanwhile (the row version moved on).
  const org = await zetaId();
  const before = await writerDb().apiModeOrgSetting.findUniqueOrThrow({
    where: { organizationId: org },
  });
  await writerDb().apiModeOrgSetting.update({
    where: { organizationId: org },
    data: { rowVersion: { increment: 1 } },
  });
  await form.getByLabel('Purge approval threshold (mailboxes)').fill('1');
  const reason = `E2E stricter purge approval ${suffix()}`;
  await form.getByLabel('Reason (required)').fill(reason);
  // The conflict reloads the settings (the draft is kept); the next save uses the new version.
  const reloaded = page.waitForResponse(
    (r) => r.request().method() === 'GET' && r.url().includes('/api-mode/settings') && r.ok(),
  );
  await form.getByRole('button', { name: 'Save settings' }).click();
  await expect(form.getByText(/changed by someone else/)).toBeVisible({ timeout: 20_000 });
  await reloaded;
  await expect(form.getByLabel('Purge approval threshold (mailboxes)')).toHaveValue('1');
  await form.getByRole('button', { name: 'Save settings' }).click();
  await expect(page.getByText('Mailbox protection settings saved.')).toBeVisible({
    timeout: 20_000,
  });
  const saved = await writerDb().apiModeOrgSetting.findUniqueOrThrow({
    where: { organizationId: org },
  });
  expect(saved.purgeApprovalMailboxes).toBe(1);
  expect(saved.rowVersion).toBe(before.rowVersion + 2);
  expect(saved.updatedByUserId).toBe(await userId(readState().users.zetaAdmin.email));
  await expectAuditRow(page, 'api_mode.settings_org_updated');
});

test('a purge above the threshold needs a second approver (MFA) who approves it', async ({
  page,
}) => {
  const s = readState().apiMode.clawback;
  await signIn(page, 'zetaAdmin', { next: `/api-mode?tab=purge&clawback=${s.approvalClawbackId}` });
  await page.getByRole('button', { name: 'Submit…' }).click({ timeout: 20_000 });
  const submit = page.getByRole('form', { name: 'Submit the purge' });
  await expect(submit).toContainText('Needs a second approver');
  await submit.getByRole('radio', { name: 'Move to quarantine folder' }).click();
  await submit.getByLabel('Reason (required)').fill(`E2E payroll phishing ${suffix()}`);
  await submit.getByRole('button', { name: 'Submit purge' }).click();
  await expect(page.getByText('Waiting for approval.')).toBeVisible({ timeout: 20_000 });
  await expect(page.getByText(/You requested this purge/)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Approve', exact: true })).toHaveCount(0);
  let row = await clawbackRow(s.approvalClawbackId);
  expect(row).toMatchObject({
    status: 'pending_approval',
    requiresApproval: true,
    approvalStatus: 'pending',
    action: 'move_quarantine',
  });
  expect(row.approvalReasons).toEqual(['mailbox_threshold']);
  expect(row.approvalExpiresAt).not.toBeNull();
  await signOut(page);

  await signIn(page, 'zetaApprover', {
    next: `/api-mode?tab=purge&clawback=${s.approvalClawbackId}`,
  });
  await page.getByRole('button', { name: 'Approve', exact: true }).click({ timeout: 20_000 });
  await confirmWithReason(page, 'Approve', `E2E checked the hit list ${suffix()}`);
  await expect(page.getByText('Approved: the purge is queued.')).toBeVisible({ timeout: 20_000 });
  row = await clawbackRow(s.approvalClawbackId);
  expect(row.approvalStatus).toBe('approved');
  expect(row.approvedByUserId).toBe(await userId(readState().users.zetaApprover.email));
  expect(row.approverPermissionsHash).toMatch(/^[0-9a-f]{64}$/);
  expect(row.status).toMatch(/^(queued|running|completed|completed_with_errors)$/);
  await expectAuditRow(page, 'api_mode.clawback_approved');
});

test('cancel of a ready clawback', async ({ page }) => {
  const s = readState().apiMode.clawback;
  await signIn(page, 'zetaAdmin', { next: `/api-mode?tab=purge&clawback=${s.cancelClawbackId}` });
  await page.getByRole('button', { name: 'Cancel clawback' }).click({ timeout: 20_000 });
  await confirmWithReason(page, 'Cancel clawback', `E2E wrong search ${suffix()}`);
  await expect(page.getByText('Cancel requested.')).toBeVisible({ timeout: 20_000 });
  const row = await clawbackRow(s.cancelClawbackId);
  expect(row.status).toBe('cancelled');
  expect(row.cancelRequestedAt).not.toBeNull();
  await expect(page.getByRole('button', { name: 'Submit…' })).toHaveCount(0, { timeout: 20_000 });
});

test('report triage: resolve malicious with feedback for the group, then claw back the message', async ({
  page,
}) => {
  const s = readState().apiMode.clawback;
  await signIn(page, 'zetaAdmin', { next: '/api-mode?tab=reports&status=pending_triage' });
  const queue = page.getByRole('table', { name: 'Reported messages' });
  await expect(queue).toContainText('Waiting for triage', { timeout: 20_000 });
  await expectNoSeriousA11yViolations(page, '/api-mode (reports)');

  await page.goto(`/api-mode?tab=reports&report=${s.reportIds[0]}`);
  const drawer = page.getByRole('dialog', { name: 'Reported message' });
  await expect(drawer).toContainText('untrusted text', { timeout: 20_000 });
  await expect(drawer).toContainText('e2e clawback: your invoice is overdue');
  await expect(drawer.getByRole('link', { name: 'Open the detection' })).toBeVisible();
  await expect(drawer).toContainText('Reports of the same message (2)');
  await expectNoSeriousA11yViolations(page, '/api-mode (report drawer)');
  await drawer.getByRole('button', { name: 'Resolve…' }).click();
  const resolve = page.getByRole('form', { name: 'Resolve the report' });
  await resolve.getByRole('radio', { name: 'Malicious' }).click();
  await expect(resolve.getByRole('checkbox', { name: 'Notify the reporter' })).toBeChecked();
  await expect(
    resolve.getByRole('checkbox', { name: 'Apply to all 2 reports of this message' }),
  ).toBeChecked();
  await resolve.getByLabel('Note (optional)').fill(`E2E credential phishing ${suffix()}`);
  await resolve.getByRole('button', { name: 'Resolve' }).click();
  await expect(resolve).toHaveCount(0, { timeout: 20_000 });
  const org = await zetaId();
  const reports = await writerDb().apiUserReport.findMany({
    where: { organizationId: org, publicId: { in: [...s.reportIds] } },
  });
  expect(reports).toHaveLength(2);
  for (const r of reports)
    expect(r).toMatchObject({
      status: 'resolved',
      analystVerdict: 'malicious',
      resultFeedback: 'queued',
    });
  expect(
    await writerDb().messageOutbox.count({
      where: { organizationId: org, eventType: 'mail.report.feedback_requested.v1' },
    }),
  ).toBeGreaterThanOrEqual(2);

  await expect(drawer.getByRole('button', { name: 'Claw back this message…' })).toBeVisible({
    timeout: 20_000,
  });
  await drawer.getByRole('button', { name: 'Claw back this message…' }).click();
  const claw = page.getByRole('form', { name: 'Claw back the reported message' });
  await claw.getByLabel('Reason (required)').fill(`E2E reported phishing clawback ${suffix()}`);
  await claw.getByRole('button', { name: 'Search' }).click();
  await expect(page).toHaveURL(/tab=purge&clawback=[0-9a-f-]{36}/, { timeout: 20_000 });
  const clawbackId = new URL(page.url()).searchParams.get('clawback')!;
  await expect(page.getByRole('heading', { name: 'User report' })).toBeVisible({
    timeout: 20_000,
  });
  const row = await clawbackRow(clawbackId);
  const report = reports.find((r) => r.publicId === s.reportIds[0])!;
  expect(row).toMatchObject({ trigger: 'report', reportId: report.id });
  expect(
    (await writerDb().apiUserReport.findUniqueOrThrow({ where: { id: report.id } })).clawbackId,
  ).toBe(row.id);
  await expectAuditRow(page, 'api_mode.report_triaged');
});

test('read-only user: clawbacks, reports and settings without write controls', async ({ page }) => {
  const s = readState().apiMode.clawback;
  await signIn(page, 'zetaReadOnly', { next: '/api-mode?tab=purge' });
  await expect(page.getByRole('table', { name: 'Clawbacks and purges' })).toBeVisible({
    timeout: 20_000,
  });
  await expect(page.getByRole('button', { name: 'New search' })).toHaveCount(0);

  await page.goto(`/api-mode?tab=purge&clawback=${s.cancelClawbackId}`);
  await expect(page.getByRole('heading', { name: 'Administrator search' })).toBeVisible({
    timeout: 20_000,
  });
  const hits = page.getByRole('table', { name: 'Messages found by the clawback' });
  await expect(hits).toContainText('***@', { timeout: 20_000 });
  for (const name of ['Submit…', 'Hard delete…', 'Cancel clawback', 'Restore…', 'Approve'])
    await expect(page.getByRole('button', { name, exact: true })).toHaveCount(0);

  await page.goto(`/api-mode?tab=reports&report=${s.reportIds[1]}`);
  const drawer = page.getByRole('dialog', { name: 'Reported message' });
  await expect(drawer).toContainText('Resolved', { timeout: 20_000 });
  for (const name of [
    'Start review',
    'Reopen for review',
    'Resolve…',
    'Reject…',
    'Claw back this message…',
  ])
    await expect(drawer.getByRole('button', { name })).toHaveCount(0);

  await page.goto('/api-mode?tab=settings');
  await expect(page.getByText('Automatic clawback').first()).toBeVisible({ timeout: 20_000 });
  await expect(page.getByRole('form', { name: 'Organization settings' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Add by address' })).toHaveCount(0);

  await page.goto('/api-mode');
  await expect(page.getByRole('list', { name: 'Clawback and reports summary' })).toBeVisible({
    timeout: 20_000,
  });
});
