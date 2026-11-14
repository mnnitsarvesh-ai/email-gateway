/**
 * Email Details (step 7.2 §2 E11–E13, §9) against the real api and the seeded engine rows
 * (seed/details.ts): the 14 sections with seeded data and axe; section access per role equal to
 * the §1.4 gates evaluated from the OpenAPI snapshot; masking for a read-only user (recipients,
 * To/Cc/Subject header values, no reveal, the reveal api refuses); the audited reveal listed in
 * the audit history section and on the writer; the sanitized preview requested only after the
 * explicit click; a quarantine action with an Idempotency-Key, the approval request and its
 * approval by a second MFA administrator; a rescan; cross-tenant isolation of the page, every
 * section's api, saved views and the reveal operations.
 */
import { randomUUID } from 'node:crypto';
import type { Page } from '@playwright/test';
import { signIn, user } from '../support/auth';
import { me } from '../support/contract';
import { expect, test } from '../support/fixtures';
import {
  SECTION_TABLE,
  bff,
  expectedSections,
  messageAuditRows,
  messageOf,
  spy,
  userPublicId,
} from '../support/messages';
import { expectNoSeriousA11yViolations, expectSettled } from '../support/pages';
import { readState, type UserKey } from '../support/state';

test.describe.configure({ timeout: 300_000 });

const FORBIDDEN = 'You do not have access to this section';

function main(page: Page) {
  return page.locator('main');
}

/** Opens `section` of a message by its URL and waits until the panel settled. */
async function openSection(page: Page, messageId: string, section: string): Promise<void> {
  await page.goto(`/messages/${messageId}?section=${section}`);
  const label = SECTION_TABLE.find((s) => s.id === section)!.label;
  await expect(main(page).getByRole('heading', { level: 2, name: label }).first()).toBeVisible({
    timeout: 20_000,
  });
  await expectSettled(page, `${messageId} ${section}`);
}

/** Clicks a section tab (desktop: vertical tabs) and waits for its panel. */
async function clickSection(page: Page, section: string): Promise<void> {
  const label = SECTION_TABLE.find((s) => s.id === section)!.label;
  await page
    .getByRole('tablist', { name: 'Message sections' })
    .getByRole('tab', { name: label })
    .click();
  // `summary` is the default section: its URL may carry no `section` key.
  await expect(page).toHaveURL(
    section === 'summary'
      ? /\/messages\/[^?]+(\?(?!.*section=)|$|.*[?&]section=summary)/
      : new RegExp(`[?&]section=${section}`),
  );
  await expect(main(page).getByRole('heading', { level: 2, name: label }).first()).toBeVisible();
  await expectSettled(page, section);
}

/** Per-section data of the details phish message (seed/plan.ts `alpha-detail-phish`). */
const PHISH_MARKERS: Record<string, Array<string | RegExp>> = {
  summary: ['it-support@lookalike-alpha.e2e-portal.test', 'Hidden'],
  people: ['a***@alpha.e2e-portal.test', 'c***@alpha.e2e-portal.test'],
  headers: [
    'helpdesk-reset@freemail.e2e-portal.test',
    '<pw-expiry.e2e@lookalike-alpha.e2e-portal.test>',
    'Hidden',
  ],
  authentication: [/fail/i, 'lookalike-alpha.e2e-portal.test'],
  spam: ['PHISHING', 'h***@freemail.e2e-portal.test'],
  phishing: ['bec.reply_to.freemail'],
  urls: ['login.lookalike-alpha.e2e-portal.test'],
  attachments: ['password-reset.html'],
  dlp: [],
  risk: ['rsk-default/1'],
  policy: ['pol-default/1'],
  delivery: [],
  // An organization admin decides on entries: their recipients are in clear (§2 E8).
  quarantine: [/phishing/i, 'ap@alpha.e2e-portal.test'],
  audit: ['message.rescan_requested'],
};

test('organization admin: the 14 sections show the seeded data and pass axe', async ({ page }) => {
  const phish = messageOf('alpha-detail-phish');
  await signIn(page, 'alphaAdmin', { next: `/messages/${phish}` });
  await expect(page.getByRole('heading', { level: 1, name: 'Email details' })).toBeVisible();
  // Desktop: the vertical section navigation lists all 14 sections.
  const tabs = page.getByRole('tablist', { name: 'Message sections' }).getByRole('tab');
  await expect(tabs).toHaveCount(14);
  for (const section of SECTION_TABLE) {
    await clickSection(page, section.id);
    for (const marker of PHISH_MARKERS[section.id] ?? []) {
      await expect(
        main(page).getByText(marker).first(),
        `${section.id} shows ${String(marker)}`,
      ).toBeVisible();
    }
    await expectNoSeriousA11yViolations(page, `details ${section.id}`);
  }
  // No body content anywhere: no iframe, no blob:/data: document.
  await expect(page.locator('main iframe')).toHaveCount(0);

  // The outbound message: masked DLP findings, deliveries with masked SMTP texts, events.
  const outbound = messageOf('alpha-detail-outbound');
  await openSection(page, outbound, 'dlp');
  await expect(main(page)).toContainText('************0366');
  await expect(main(page)).toContainText('dlp.payment_card.number');
  await expectNoSeriousA11yViolations(page, 'details dlp (findings)');
  await openSection(page, outbound, 'delivery');
  await expect(main(page)).toContainText('p***@partner-three.e2e-portal.test');
  await expect(main(page)).toContainText('550 5.1.1 <t***@partner-three.e2e-portal.test>');
  await expect(main(page)).not.toContainText('treasury@partner-three.e2e-portal.test');
  await expectNoSeriousA11yViolations(page, 'details delivery (events)');
});

const ROLE_CASES: Array<{ key: UserKey; role: string }> = [
  { key: 'alphaAdmin', role: 'organization_admin' },
  { key: 'alphaAnalyst', role: 'security_analyst' },
  { key: 'alphaReadOnly', role: 'read_only_user' },
  { key: 'alphaReviewer', role: 'quarantine_reviewer' },
  { key: 'alphaAuditor', role: 'compliance_auditor' },
];

for (const { key, role } of ROLE_CASES) {
  test(`${role}: sections and header actions follow the §1.4 gates`, async ({ page }) => {
    const phish = messageOf('alpha-detail-phish');
    await signIn(page, key, { next: `/messages/${phish}` });
    const profile = await me(page);
    expect(profile.roles).toContain(role);
    const allowed = expectedSections(profile.permissions);
    const labels = SECTION_TABLE.filter((s) => allowed.includes(s.id)).map((s) => s.label);
    const tabs = page.getByRole('tablist', { name: 'Message sections' }).getByRole('tab');
    await expect(tabs).toHaveCount(labels.length);
    expect((await tabs.allTextContents()).map((t) => t.trim())).toEqual(labels);

    const granted = new Set(profile.permissions);
    await expect(page.getByRole('button', { name: 'Reveal', exact: true })).toHaveCount(
      granted.has('message:reveal') ? 1 : 0,
    );
    await expect(page.getByRole('button', { name: 'Rescan', exact: true })).toHaveCount(
      granted.has('message:rescan') ? 1 : 0,
    );

    // Permitted sections through the navigation (client-side, as a user moves between them:
    // shared reads come from the query cache, so the tenant's request budget is not spent on
    // reloads); a forbidden section only through its direct URL.
    for (const section of SECTION_TABLE.filter((s) => allowed.includes(s.id))) {
      await clickSection(page, section.id);
      await expect(main(page).getByText(FORBIDDEN)).toHaveCount(0);
      if (section.id === 'people' && (role === 'read_only_user' || role === 'compliance_auditor')) {
        await expectNoSeriousA11yViolations(page, `${role} people`);
      }
    }
    for (const section of SECTION_TABLE.filter((s) => !allowed.includes(s.id))) {
      // A direct URL renders the panel's forbidden state, never the data.
      await page.goto(`/messages/${phish}?section=${section.id}`);
      await expect(main(page).getByText(FORBIDDEN)).toBeVisible();
      await expectNoSeriousA11yViolations(page, `${role} ${section.id} forbidden`);
    }

    // Quarantine recipients (§2 E8): clear for deciders and message:reveal holders.
    if (allowed.includes('quarantine')) {
      await openSection(page, phish, 'quarantine');
      const decides = [
        'quarantine:release',
        'quarantine:approve',
        'quarantine:reject',
        'quarantine:delete',
        'quarantine:request_release',
        'quarantine:manage',
      ].some((p) => granted.has(p));
      if (decides || granted.has('message:reveal')) {
        await expect(main(page)).toContainText(`ap@${readState().alpha.domainName}`);
      } else {
        await expect(main(page)).toContainText('a***@alpha.e2e-portal.test');
        await expect(main(page)).not.toContainText(`ap@${readState().alpha.domainName}`);
      }
      await page
        .getByRole('button', { name: /^Details and actions/ })
        .first()
        .click();
      if (decides) {
        await expect(page.getByRole('group', { name: 'Entry actions' })).toBeVisible();
      } else {
        await expect(main(page).getByText(/No action is available to you/)).toBeVisible();
      }
      await expectNoSeriousA11yViolations(page, `${role} quarantine section`);
    }
  });
}

test('read-only user: recipients and To/Cc/Subject masked, no reveal, the reveal api refuses', async ({
  page,
}) => {
  const phish = messageOf('alpha-detail-phish');
  const domain = readState().alpha.domainName;
  await signIn(page, 'alphaReadOnly', { next: `/messages/${phish}?section=people` });
  await expect(
    main(page).getByRole('heading', { level: 2, name: 'Sender and recipients' }),
  ).toBeVisible();
  await expectSettled(page, 'people');
  for (const masked of ['a***@', 'f***@', 'c***@']) {
    await expect(main(page)).toContainText(`${masked}${domain}`);
  }
  for (const clear of ['ap@', 'finance@', 'ceo@']) {
    await expect(main(page)).not.toContainText(`${clear}${domain}`);
  }
  await expect(main(page)).toContainText('Withheld until revealed');
  await expect(page.getByRole('button', { name: 'Reveal', exact: true })).toHaveCount(0);

  await openSection(page, phish, 'headers');
  const hidden = main(page).locator('[data-sensitive="masked"]');
  // To, Cc and Subject are withheld; the sender-side safe subset is in clear.
  await expect(hidden).toHaveCount(3);
  await expect(main(page)).toContainText('helpdesk-reset@freemail.e2e-portal.test');
  await expect(main(page)).not.toContainText('Password expiry notice');
  await expect(main(page)).not.toContainText(`finance@${domain}`);

  const single = await bff(page, 'POST', `/messages/${phish}/reveal`, { fields: ['subject'] });
  expect(single.status).toBe(403);
  const bulk = await bff(page, 'POST', '/messages/reveal', { messageIds: [phish] });
  expect(bulk.status).toBe(403);
  expect(JSON.stringify(single.body)).not.toContain('Password expiry');
});

test('security analyst: the reveal is audited and listed in the audit history section', async ({
  page,
}) => {
  const phish = messageOf('alpha-detail-phish');
  const domain = readState().alpha.domainName;
  const started = new Date(Date.now() - 1_000);
  await signIn(page, 'alphaAnalyst', { next: `/messages/${phish}?section=audit` });
  await expect(main(page).getByRole('heading', { level: 2, name: 'Audit history' })).toBeVisible();
  await expectSettled(page, 'audit');
  const events = main(page)
    .locator('section')
    .filter({ has: page.getByRole('heading', { name: 'Message events' }) });
  const revealedBefore = await events.getByText('message.revealed').count();

  const reveals = spy(
    page,
    (r) => r.method() === 'POST' && r.url().endsWith(`/messages/${phish}/reveal`),
  );
  await page.getByRole('button', { name: 'Reveal', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Hide again' })).toBeVisible();
  expect(reveals.seen).toHaveLength(1);
  expect(JSON.parse(reveals.seen[0]!.body ?? '{}')).toMatchObject({
    fields: ['subject', 'headers', 'recipients'],
  });
  // The new audit row: on the writer before the response, then in the section (replica).
  const actor = await userPublicId(user('alphaAnalyst').email);
  const rows = await messageAuditRows('message.revealed', [phish], started);
  expect(rows).toHaveLength(1);
  expect(rows[0]!.actorId).toBe(actor);
  expect(JSON.stringify(rows[0]!.metadata)).not.toContain(domain);
  await expect
    .poll(() => events.getByText('message.revealed').count(), { timeout: 20_000 })
    .toBe(revealedBefore + 1);

  // Revealed values in the sections, until "Hide again".
  await clickSection(page, 'people');
  await expect(main(page)).toContainText(`ceo@${domain}`);
  await expect(main(page).getByText('Revealed').first()).toBeVisible();
  await clickSection(page, 'headers');
  await expect(main(page)).toContainText('Re: Password expiry notice');
  await expectNoSeriousA11yViolations(page, 'details headers (revealed)');
  await page.getByRole('button', { name: 'Hide again' }).click();
  await expect(main(page)).not.toContainText('Re: Password expiry notice');
  reveals.stop();
});

test('sanitized preview: requested only after the explicit click', async ({ page }) => {
  const s = readState();
  await signIn(page, 'alphaAdmin', {
    next: `/messages/${s.alpha.previewMessageId}?section=quarantine`,
  });
  await expect(
    main(page).getByRole('heading', { level: 2, name: 'Quarantine actions' }),
  ).toBeVisible();
  const previews = spy(page, (r) => /\/quarantine\/entries\/[^/]+\/preview/.test(r.url()));
  await page
    .getByRole('button', { name: /^Details and actions/ })
    .first()
    .click();
  await expect(page.getByRole('button', { name: 'Show sanitized preview' })).toBeVisible();
  await page.waitForTimeout(1_000);
  expect(previews.seen, 'no preview request before the click').toHaveLength(0);
  await page.getByRole('button', { name: 'Show sanitized preview' }).click();
  await expect(page.getByLabel('Sanitized message text')).toContainText(s.alpha.previewText);
  expect(previews.seen).toHaveLength(1);
  await expect(main(page)).not.toContainText('window.__e2eInjected');
  await expect(page.locator('main iframe')).toHaveCount(0);
  previews.stop();
});

test('quarantine section: an entry created long after receipt is listed (no time window)', async ({
  page,
}) => {
  // seed/plan.ts `alpha-detail-late`: received 120 days ago, quarantined 80 days after receipt.
  const late = messageOf('alpha-detail-late');
  const searches = spy(
    page,
    (r) => r.method() === 'GET' && /\/quarantine\/entries\?/.test(r.url()),
  );
  await signIn(page, 'alphaAdmin', { next: `/messages/${late}?section=quarantine` });
  await expect(
    main(page).getByRole('heading', { level: 2, name: 'Quarantine actions' }),
  ).toBeVisible();
  const entries = main(page).getByRole('list', { name: 'Quarantine entries of this message' });
  await expect(entries.locator(':scope > li')).toHaveCount(1);
  await expect(entries).toContainText('legal@alpha.e2e-portal.test');
  await expect(entries).toContainText(/expired/i);
  const request = searches.seen.find((r) => r.url.includes('messageId='));
  expect(request, 'the entries search').toBeDefined();
  const params = new URL(request!.url).searchParams;
  expect(params.get('messageId')).toBe(late);
  expect(params.has('from')).toBe(false);
  expect(params.has('to')).toBe(false);
  await expectNoSeriousA11yViolations(page, 'details quarantine (late entry)');
  // The audit section lists that entry's history as well.
  await openSection(page, late, 'audit');
  await expect(
    main(page).getByRole('list', { name: 'Quarantine entry histories' }).locator(':scope > li'),
  ).toHaveCount(1);
  searches.stop();
});

test('quarantine action from details: Idempotency-Key, approval requested, approved by a second MFA admin', async ({
  page,
  context,
}) => {
  test.setTimeout(240_000);
  const target = messageOf('alpha-detail-approval');
  const reason = 'E2E details release: synthetic message, approval by a second admin';
  await signIn(page, 'alphaReviewer', { next: `/messages/${target}?section=quarantine` });
  await page
    .getByRole('button', { name: /^Details and actions/ })
    .first()
    .click();
  const actions = page.getByRole('group', { name: 'Entry actions' });
  await expect(actions).toBeVisible();
  const writes = spy(
    page,
    (r) =>
      r.method() === 'POST' &&
      /\/quarantine\/entries\/[^/]+\/release$/.test(new URL(r.url()).pathname),
  );
  await actions.getByRole('button', { name: 'Release', exact: true }).click();
  const dialog = page.getByRole('alertdialog');
  await dialog.getByRole('textbox').first().fill(reason);
  await dialog.getByRole('button', { name: 'Release', exact: true }).click();
  await expect(main(page).getByText('Approval requested')).toBeVisible({ timeout: 20_000 });
  expect(writes.seen).toHaveLength(1);
  expect(writes.seen[0]!.headers['idempotency-key']).toMatch(/^[0-9a-f-]{36}$/);
  writes.stop();
  const approvalLink = main(page).getByRole('link', { name: 'Open the approval request' }).first();
  const approvalHref = await approvalLink.getAttribute('href');
  expect(approvalHref).toMatch(/^\/quarantine\/approvals\//);
  await context.clearCookies();

  // The approver (organization admin with MFA) decides; the reviewer cannot approve their own.
  await signIn(page, 'alphaApprover', { next: approvalHref! });
  await expect(page.getByRole('heading', { level: 1, name: 'Approval request' })).toBeVisible();
  await page.getByRole('button', { name: 'Approve', exact: true }).click();
  const approve = page.getByRole('alertdialog');
  await approve.getByRole('textbox').first().fill(reason);
  await approve.getByRole('button', { name: 'Approve', exact: true }).click();
  await expect(main(page)).toContainText(/approved/i, { timeout: 20_000 });

  // Back in the details: the entry is no longer pending approval.
  await page.goto(`/messages/${target}?section=quarantine`);
  await expect(
    main(page).getByRole('heading', { level: 2, name: 'Quarantine actions' }),
  ).toBeVisible();
  await expect(main(page)).not.toContainText(/pending approval/i, { timeout: 30_000 });
});

test('rescan from details: reason, expected version and Idempotency-Key; audited', async ({
  page,
}) => {
  const target = messageOf('alpha-detail-rescan');
  const started = new Date(Date.now() - 1_000);
  await signIn(page, 'alphaAdmin', { next: `/messages/${target}` });
  const writes = spy(
    page,
    (r) => r.method() === 'POST' && r.url().endsWith(`/messages/${target}/rescan`),
  );
  await page.getByRole('button', { name: 'Rescan', exact: true }).click();
  const dialog = page.getByRole('alertdialog', { name: 'Rescan this message?' });
  await dialog.getByLabel('Reason (required)').fill('E2E rescan from the details page');
  await expectNoSeriousA11yViolations(page, 'rescan dialog');
  await dialog.getByRole('button', { name: 'Rescan', exact: true }).click();
  await expect(page.getByText(/Rescan started: round 1 is being scanned/)).toBeVisible({
    timeout: 20_000,
  });
  expect(writes.seen).toHaveLength(1);
  expect(writes.seen[0]!.headers['idempotency-key']).toMatch(/^[0-9a-f-]{36}$/);
  expect(JSON.parse(writes.seen[0]!.body ?? '{}')).toMatchObject({
    expectedVersion: expect.any(Number),
  });
  writes.stop();
  await expect
    .poll(
      async () => (await messageAuditRows('message.rescan_requested', [target], started)).length,
    )
    .toBe(1);
});

test('cross-tenant isolation: beta message, its sections and apis, saved view, reveal', async ({
  page,
}) => {
  const s = readState();
  await signIn(page, 'alphaAdmin', { next: '/messages' });
  const signature = async (path: string) => {
    await page.goto(path);
    const title = page.getByText('Not found', { exact: true });
    await expect(title.first()).toBeVisible({ timeout: 20_000 });
    return main(page)
      .getByText(/^[a-z_]+_not_found$/)
      .first()
      .textContent();
  };
  for (const betaId of [s.beta.messageId, s.beta.twinMessageId]) {
    const missing = randomUUID();
    expect(await signature(`/messages/${betaId}`)).toBe(await signature(`/messages/${missing}`));
    for (const section of ['headers', 'people', 'delivery', 'quarantine', 'audit']) {
      expect(await signature(`/messages/${betaId}?section=${section}`)).toBe('message_not_found');
    }
    await expect(main(page)).not.toContainText(s.beta.marker);
  }

  // Every section's read for the beta id answers like a missing id (404) or is empty.
  const beta = s.beta.twinMessageId;
  for (const path of [
    `/messages/${beta}`,
    `/messages/${beta}/recipients`,
    `/messages/${beta}/headers`,
    `/messages/${beta}/scans`,
    `/messages/${beta}/lifecycle`,
    `/messages/${beta}/deliveries`,
    `/messages/${beta}/attachments`,
    `/messages/${beta}/urls`,
  ]) {
    const res = await bff(page, 'GET', path);
    expect(res.status, path).toBe(404);
    expect(JSON.stringify(res.body)).not.toContain('BETA-ONLY');
  }
  const from = new Date(Date.now() - 2 * 86_400_000).toISOString();
  const to = new Date(Date.now() + 60_000).toISOString();
  const entries = await bff(
    page,
    'GET',
    `/quarantine/entries?messageId=${beta}&from=${from}&to=${to}`,
  );
  expect(entries.status).toBe(200);
  expect(entries.body?.items).toEqual([]);
  // The windowless search by messageId (§13 closer) is tenant-scoped the same way.
  const windowless = await bff(page, 'GET', `/quarantine/entries?messageId=${beta}`);
  expect(windowless.status).toBe(200);
  expect(windowless.body?.items).toEqual([]);
  const audit = await bff(
    page,
    'GET',
    `/audit/logs?resourceType=message&resourceId=${beta}&from=${from}&to=${to}`,
  );
  expect(audit.status).toBe(200);
  expect(audit.body?.data).toEqual([]);

  // Saved views and the reveal operations.
  const view = await bff(page, 'GET', `/saved-views/${s.beta.savedViewId}`);
  expect(view.status).toBe(404);
  expect((view.body as { code?: string }).code).toBe('saved_view_not_found');
  const views = await bff(page, 'GET', '/saved-views?kind=message_explorer');
  expect(JSON.stringify(views.body)).not.toContain(s.beta.savedViewId);
  const single = await bff(page, 'POST', `/messages/${beta}/reveal`, { fields: ['subject'] });
  expect(single.status).toBe(404);
  const bulk = await bff(page, 'POST', '/messages/reveal', {
    messageIds: [beta, messageOf('alpha-search-1')],
  });
  expect(bulk.status).toBe(200);
  const revealed = (bulk.body as { data: Array<{ id: string; subject: string | null }> }).data;
  expect(revealed.map((r) => r.id)).toEqual([messageOf('alpha-search-1')]);
  expect(JSON.stringify(revealed)).not.toContain('BETA-ONLY');
});
