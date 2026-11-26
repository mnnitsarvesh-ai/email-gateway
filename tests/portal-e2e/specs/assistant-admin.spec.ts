/**
 * Step AI-6 (docs/plan/steps/34-ai-chat-hardening-operations.md §9 item 9, D1–D5, D7; I24–I27):
 * the AI administration page, feedback on answers, content search, the pseudonymized data-sharing
 * level and background reports, against the real api with the deterministic fake provider
 * (tests/portal-e2e/assistant.override.yml: `ASSISTANT_PROVIDER=fake`, the report-job consumer on,
 * tenant-supplied keys off). Nothing reaches an LLM or the internet; synthetic `.test` values only.
 *
 * Tenant `delta` (seed/assistant.ts). Its organization admin (`assistant:configure` and
 * `audit:read`) asks a question, rates the answer with a reason and a comment, finds it again with
 * the content search, then sees the usage row of today, the rating in the Feedback tab and the
 * conversation's metadata-only audit (no question, answer or title text anywhere in it). The
 * Limits tab shows the tenant-key section in its "not offered by the platform" state; switching
 * the data-sharing level to pseudonymized makes the model see placeholders (checked in the stored
 * provider transcript) while the chat still shows the real values; the level is restored to
 * metadata afterwards. A 30-day report is queued and the card turns from "Generating in the
 * background…" into the sandboxed report once the api's consumer finished. delta's analyst
 * (`audit:read` only) sees the audit tabs only. Axe on every new state; a phone viewport.
 */
import type { Page, Response } from '@playwright/test';
import { signIn } from '../support/auth';
import { expect, test } from '../support/fixtures';
import { bff, writerDb } from '../support/messages';
import { expectNoSeriousA11yViolations } from '../support/pages';
import { readState } from '../support/state';

test.describe.configure({ timeout: 180_000 });

const TURNS = /\/bff\/api\/v1\/assistant\/conversations\/[0-9a-f-]{36}\/turns$/;
const DELTA_DOMAIN = 'delta.e2e-portal.test';

function composer(scope: ReturnType<Page['locator']> | Page) {
  return scope.getByRole('textbox', { name: 'Message to the AI assistant' });
}

async function ask(
  page: Page,
  scope: ReturnType<Page['locator']> | Page,
  message: string,
): Promise<Response> {
  const turn = page.waitForResponse(
    (res) => TURNS.test(new URL(res.url()).pathname) && res.request().method() === 'POST',
  );
  await composer(scope).fill(message);
  await composer(scope).press('Enter');
  return turn;
}

async function expectTurnDone(scope: ReturnType<Page['locator']> | Page): Promise<void> {
  await expect(scope.getByRole('button', { name: 'Stop the answer' })).toHaveCount(0, {
    timeout: 30_000,
  });
}

async function newConversation(page: Page) {
  await expect(page.getByRole('heading', { level: 1, name: 'AI assistant' })).toBeVisible({
    timeout: 20_000,
  });
  await page
    .getByRole('complementary', { name: 'Conversation history' })
    .getByRole('button', { name: 'New conversation' })
    .click();
  return page.getByRole('region', { name: 'Conversation' });
}

async function deltaOrganizationId(): Promise<bigint> {
  const org = await writerDb().organization.findUniqueOrThrow({
    where: { publicId: readState().orgs.delta.id },
    select: { id: true },
  });
  return org.id;
}

/** The data-sharing level of delta through the api (PUT with the current row version). */
async function setDataSharing(page: Page, level: 'metadata' | 'pseudonymized'): Promise<void> {
  const current = await bff(page, 'GET', '/assistant/settings');
  expect(current.status).toBe(200);
  const settings = current.body as Record<string, unknown>;
  if (settings.dataSharing === level) return;
  const saved = await bff(page, 'PUT', '/assistant/settings', {
    expectedRowVersion: settings.rowVersion,
    enabled: settings.enabled,
    externalProcessingAcknowledged: settings.externalProcessingAcknowledged,
    dailyTokenBudget: settings.dailyTokenBudget,
    retentionDays: settings.retentionDays,
    dataSharing: level,
  });
  expect(saved.status).toBe(200);
}

function utcToday(): string {
  return new Date().toISOString().slice(0, 10);
}

test('usage, feedback, content search and the metadata-only audit of a conversation', async ({
  page,
}) => {
  test.setTimeout(240_000);
  const tag = `e2eadm${Date.now().toString(36)}`;
  const question = `/text Admin page probe ${tag}`;
  const comment = `E2E feedback comment ${tag}`;

  await signIn(page, 'deltaAdmin', { next: '/assistant' });
  const conversation = await newConversation(page);
  const turn = await ask(page, conversation, question);
  expect(turn.status()).toBe(200);
  await expect(conversation.getByText(`Admin page probe ${tag}`, { exact: true })).toBeVisible({
    timeout: 30_000,
  });
  await expectTurnDone(conversation);

  // (a) Rate the answer (D2): toggle buttons, then the optional reason and comment form with the
  // visibility notice.
  const rating = conversation.getByRole('group', { name: 'Rate this answer' }).last();
  await expect(rating).toBeVisible({ timeout: 20_000 });
  const down = rating.getByRole('button', { name: 'Not helpful' });
  await expect(down).toHaveAttribute('aria-pressed', 'false');
  const firstPut = page.waitForResponse(
    (res) =>
      /\/assistant\/messages\/[0-9a-f-]{36}\/feedback$/.test(res.url()) &&
      res.request().method() === 'PUT',
  );
  await down.click();
  expect((await firstPut).status()).toBe(200);
  await expect(down).toHaveAttribute('aria-pressed', 'true');
  const form = conversation.getByRole('form', { name: 'Feedback details' });
  await expect(form).toContainText(
    "Your rating and comment are visible to your organization's AI administrators.",
  );
  await form.getByRole('combobox', { name: 'Reason (optional)' }).click();
  await page.getByRole('option', { name: 'Incomplete' }).click();
  await form.getByRole('textbox', { name: 'Comment (optional)' }).fill(comment);
  await expectNoSeriousA11yViolations(page, 'feedback form in the conversation');
  const secondPut = page.waitForResponse(
    (res) =>
      /\/assistant\/messages\/[0-9a-f-]{36}\/feedback$/.test(res.url()) &&
      res.request().method() === 'PUT',
  );
  await form.getByRole('button', { name: 'Send feedback' }).click();
  expect((await secondPut).status()).toBe(200);
  await expect(form).toHaveCount(0);
  const stored = await writerDb().aiChatFeedback.findFirstOrThrow({
    where: { organizationId: await deltaOrganizationId(), comment },
    select: { rating: true, reason: true },
  });
  expect(stored).toEqual({ rating: 'down', reason: 'incomplete' });

  // (b) Content search (D4): the answer's text is found with a snippet; the hit opens the
  // conversation at the message.
  const history = page.getByRole('complementary', { name: 'Conversation history' });
  await history.getByRole('button', { name: 'New conversation' }).click();
  await expect(conversation.getByText('Ask about your email security')).toBeVisible();
  await history.getByRole('searchbox', { name: 'Search conversations' }).fill(tag);
  const results = history.getByRole('list', { name: 'Search results' });
  const answerHit = results
    .getByRole('button')
    .filter({ hasText: `Assistant: Admin page probe ${tag}` });
  await expect(answerHit).toHaveCount(1, { timeout: 20_000 });
  await expectNoSeriousA11yViolations(page, 'content search results');
  await answerHit.click();
  await expect(page).toHaveURL(/\/assistant\?conversation=[0-9a-f-]{36}$/);
  const focused = page.locator('[data-message-id]:focus');
  await expect(focused).toContainText(`Admin page probe ${tag}`, { timeout: 20_000 });
  const conversationId = new URL(page.url()).searchParams.get('conversation') ?? '';

  // (c) The navigation item and the usage of today (D1).
  await page
    .getByRole('navigation', { name: 'Main' })
    .getByRole('link', { name: 'AI administration' })
    .click();
  await expect(page).toHaveURL(/\/assistant\/admin$/);
  await expect(page.getByRole('heading', { level: 1, name: 'AI administration' })).toBeVisible({
    timeout: 20_000,
  });
  const tabs = page.getByRole('tablist', { name: 'AI administration sections' });
  await expect(tabs.getByRole('tab')).toHaveText([
    'Usage',
    'Limits and provider',
    'Feedback',
    'Conversation audit',
    'Tool calls',
  ]);
  const usage = page.getByRole('table', { name: /usage per person and day/ });
  const todayRow = usage
    .getByRole('row')
    .filter({ hasText: utcToday() })
    .filter({ hasText: 'Delta Admin' });
  await expect(todayRow.first()).toBeVisible({ timeout: 20_000 });
  await expect(todayRow.first()).toContainText('Platform key');
  await expect(page.getByRole('region', { name: 'Usage totals', exact: true })).toContainText(
    'Estimated cost (USD, estimate)',
  );
  await expect(page.getByRole('figure', { name: 'Tokens per day' })).toBeVisible();
  await expectNoSeriousA11yViolations(page, 'AI administration: usage');

  // (d) Feedback tab: the rating with reason and comment, the turn's model and prompt.
  await tabs.getByRole('tab', { name: 'Feedback' }).click();
  const feedbackRow = page
    .getByRole('table', { name: /Feedback on AI answers/ })
    .getByRole('row')
    .filter({ hasText: comment });
  await expect(feedbackRow).toHaveCount(1, { timeout: 20_000 });
  await expect(feedbackRow).toContainText('Not helpful');
  await expect(feedbackRow).toContainText('Incomplete');
  await expect(feedbackRow).toContainText('assistant-system/7');
  await expectNoSeriousA11yViolations(page, 'AI administration: feedback');

  // (e) The conversation's audit (I24): metadata only, never the question, answer or title.
  const audited = page.waitForResponse(
    (res) =>
      res.url().includes(`/assistant/admin/conversations/${conversationId}`) &&
      res.request().method() === 'GET',
  );
  await feedbackRow.getByRole('button', { name: /Open audit/ }).click();
  const auditResponse = await audited;
  expect(auditResponse.status()).toBe(200);
  expect(await auditResponse.text()).not.toContain(tag);
  const drawer = page.getByRole('dialog', { name: 'Conversation audit' });
  await expect(drawer.getByRole('region', { name: 'Turns' })).toContainText('assistant-system/7');
  await expect(drawer.getByRole('region', { name: 'Ratings' })).toContainText('Incomplete');
  await expect(drawer).toContainText('Delta Admin');
  await expect(drawer).not.toContainText(tag);
  await expect(drawer).not.toContainText(comment);
  await expectNoSeriousA11yViolations(page, 'AI administration: conversation audit drawer');
  await page.keyboard.press('Escape');
  await expect(drawer).toHaveCount(0);

  // (f) The audit list and the tool-call search load (no content columns).
  await tabs.getByRole('tab', { name: 'Conversation audit' }).click();
  const auditTable = page.getByRole('table', { name: /AI conversations/ });
  await expect(auditTable.getByRole('row').nth(1)).toBeVisible({ timeout: 20_000 });
  await expect(auditTable).not.toContainText(tag);
  await tabs.getByRole('tab', { name: 'Tool calls' }).click();
  // A freshly seeded delta may have no tool call in the window yet: the table or its empty state.
  await expect(
    page.getByRole('table', { name: /AI tool calls/ }).or(page.getByText('No tool calls match')),
  ).toBeVisible({ timeout: 20_000 });
  await expectNoSeriousA11yViolations(page, 'AI administration: tool calls');
});

test('limits: tenant keys not offered; a pseudonymized turn still shows the real values', async ({
  page,
}) => {
  test.setTimeout(240_000);
  const tag = `e2epsn${Date.now().toString(36)}`;
  const address = `carol.${tag}@${DELTA_DOMAIN}`;
  const ip = '192.0.2.44';
  await signIn(page, 'deltaAdmin', { next: '/assistant/admin?tab=limits' });
  try {
    const form = page.getByRole('form', { name: 'AI limits and data sharing' });
    await expect(form).toBeVisible({ timeout: 20_000 });
    await expect(page.getByRole('region', { name: 'Effective limits' })).toContainText(
      'per minute',
    );
    // D7 with the platform gate off: an explanatory note and no key field.
    const keySection = page.getByRole('region', { name: 'Your own AI provider key' });
    await expect(keySection).toContainText('not offered by the platform');
    await expect(keySection.getByLabel('API key')).toHaveCount(0);
    await expect(
      form.getByRole('switch', { name: /Use your organization.s provider key/ }),
    ).toBeDisabled();
    await expectNoSeriousA11yViolations(page, 'AI administration: limits and provider');

    // D3: switch to pseudonymized through the form.
    await form.getByRole('combobox', { name: 'Data shared with the AI provider' }).click();
    await page.getByRole('option', { name: /Pseudonymized/ }).click();
    await expect(form).toContainText('are not detected');
    const saved = page.waitForResponse(
      (res) =>
        res.url().endsWith('/bff/api/v1/assistant/settings') && res.request().method() === 'PUT',
    );
    await form.getByRole('button', { name: 'Save' }).click();
    expect((await saved).status()).toBe(200);

    // A turn with an address and an IP: the chat shows the real values (streamed and stored).
    await page.goto('/assistant');
    const conversation = await newConversation(page);
    const turn = await ask(page, conversation, `/text Contact ${address} from ${ip} today`);
    expect(turn.status()).toBe(200);
    await expectTurnDone(conversation);
    await expect(
      conversation.getByText(`Contact ${address} from ${ip} today`, { exact: true }),
    ).toBeVisible({ timeout: 30_000 });
    await page.reload();
    await expect(
      page
        .getByRole('region', { name: 'Conversation' })
        .getByText(`Contact ${address} from ${ip} today`, { exact: true }),
    ).toBeVisible({ timeout: 30_000 });
    // What the model saw: placeholders only (I25).
    const conversationId = new URL(page.url()).searchParams.get('conversation') ?? '';
    const stored = await writerDb().aiChatTurn.findFirstOrThrow({
      where: { conversation: { publicId: conversationId } },
      select: { dataSharing: true, providerTranscript: true },
      orderBy: { id: 'desc' },
    });
    expect(stored.dataSharing).toBe('pseudonymized');
    expect(stored.providerTranscript ?? '').toContain('[EMAIL_1]');
    expect(stored.providerTranscript ?? '').toContain('[IP_1]');
    expect(stored.providerTranscript ?? '').not.toContain(address);
    expect(stored.providerTranscript ?? '').not.toContain(ip);
  } finally {
    await setDataSharing(page, 'metadata');
  }
});

test('a 30-day report is generated in the background: queued, then available in the card', async ({
  page,
}) => {
  test.setTimeout(240_000);
  await signIn(page, 'deltaAdmin', { next: '/assistant' });
  const conversation = await newConversation(page);
  const turn = await ask(page, conversation, 'generate a security report for the last 30 days');
  expect(turn.status()).toBe(200);
  await expectTurnDone(conversation);
  await expect(
    conversation.getByText(/Your security report for .+ is being generated; it will appear here/),
  ).toBeVisible({ timeout: 30_000 });
  const report = await writerDb().aiChatReport.findFirstOrThrow({
    where: { organizationId: await deltaOrganizationId() },
    select: { id: true, publicId: true },
    orderBy: { id: 'desc' },
  });
  const job = await writerDb().aiChatReportJob.findUniqueOrThrow({
    where: { reportId: report.id },
    select: { status: true },
  });
  expect(['queued', 'running', 'succeeded']).toContain(job.status);
  const card = conversation.getByRole('region', { name: /^Result: Security report/ }).last();
  await expect(card).toBeVisible();
  // The card polls `GET /assistant/reports/{id}` every 5 s until the consumer finished.
  const iframe = card.locator('iframe[title="Security report"]');
  await expect(iframe).toBeVisible({ timeout: 90_000 });
  await expect(iframe).toHaveAttribute('sandbox', '');
  await expect(card.getByText('Generating in the background…')).toHaveCount(0);
  await expect(card.getByRole('list', { name: 'Key figures' })).toBeVisible();
  const frame = card.frameLocator('iframe[title="Security report"]');
  await expect(frame.getByRole('heading', { level: 1, name: 'Security report' })).toBeVisible();
  const done = await writerDb().aiChatReportJob.findUniqueOrThrow({
    where: { reportId: report.id },
    select: { status: true },
  });
  expect(done.status).toBe('succeeded');
  const available = await writerDb().aiChatReport.findUniqueOrThrow({
    where: { id: report.id },
    select: { status: true },
  });
  expect(available.status).toBe('available');
  await expectNoSeriousA11yViolations(page, 'background report card (available)');
});

test('an analyst with audit:read only sees the audit tabs', async ({ page }) => {
  await signIn(page, 'deltaAnalyst', { next: '/assistant/admin' });
  await expect(page.getByRole('heading', { level: 1, name: 'AI administration' })).toBeVisible({
    timeout: 20_000,
  });
  await expect(
    page.getByRole('tablist', { name: 'AI administration sections' }).getByRole('tab'),
  ).toHaveText(['Conversation audit', 'Tool calls']);
  await expect(page.getByRole('table', { name: /AI conversations/ })).toBeVisible({
    timeout: 20_000,
  });
  // The settings and usage routes stay closed to the analyst.
  expect((await bff(page, 'GET', '/assistant/admin/usage/users')).status).toBe(403);
  await expectNoSeriousA11yViolations(page, 'AI administration (audit only)');
});

test.describe('phone viewport', () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test('the administration page fits a phone', async ({ page }) => {
    await signIn(page, 'deltaAdmin', { next: '/assistant/admin' });
    await expect(page.getByRole('heading', { level: 1, name: 'AI administration' })).toBeVisible({
      timeout: 20_000,
    });
    await expect(page.getByRole('tab', { name: 'Usage' })).toBeVisible();
    await expect(page.getByRole('region', { name: 'Usage totals', exact: true })).toBeVisible({
      timeout: 20_000,
    });
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
    );
    expect(overflow).toBeLessThanOrEqual(1);
    await expectNoSeriousA11yViolations(page, 'AI administration on a phone');
    await page.getByRole('tab', { name: 'Limits and provider' }).click();
    await expect(page.getByRole('form', { name: 'AI limits and data sharing' })).toBeVisible({
      timeout: 20_000,
    });
    await expectNoSeriousA11yViolations(page, 'AI administration limits on a phone');
  });
});
