/**
 * Step AI-1 (docs/plan/steps/28-ai-chat-management.md D14, §9 item 7; ADR-0091..0094): the AI
 * assistant in the portal against the real api, with the deterministic fake provider
 * (`ASSISTANT_PROVIDER=fake`, tests/portal-e2e/assistant.override.yml); nothing reaches an LLM or
 * the internet, and the origin guard of support/fixtures.ts fails any request leaving the portal.
 *
 * Seeded tenants (seed/assistant.ts): `delta` has the assistant on (feature + tenant setting with
 * the acknowledgement), three policies (two active, one draft) and two messages held in
 * quarantine today; `epsilon` has the feature but not the tenant setting.
 *
 * Covered: the header entry and Ctrl/Cmd+J; a fake directive (`/tool …`) and a demo intent ("show
 * active policies") answered over the `assistant-stream/1` event stream, with streamed text, tool
 * chips and table cards rendered from the real API response; "Load more" (a new execution, no
 * model call); a deep link from a card row to the policy page; the full `/assistant` page with a
 * new conversation, search by title, rename and clear with confirmation; a user without
 * `assistant:use` (no entry, `/assistant` forbidden); an organization admin of a tenant with the
 * setting off (the reason and the settings link); the panel as a full-screen sheet on a phone;
 * axe checks (WCAG 2.2 A/AA, serious and critical).
 */
import type { Page, Response } from '@playwright/test';
import { signIn } from '../support/auth';
import { me } from '../support/contract';
import { expect, test } from '../support/fixtures';
import { expectNoSeriousA11yViolations } from '../support/pages';
import { readState } from '../support/state';

test.describe.configure({ timeout: 180_000 });

const TURNS = /\/bff\/api\/v1\/assistant\/conversations\/[0-9a-f-]{36}\/turns$/;

function panel(page: Page) {
  return page.getByRole('dialog', { name: 'AI assistant' });
}

function composer(scope: ReturnType<Page['locator']> | Page) {
  return scope.getByRole('textbox', { name: 'Message to the AI assistant' });
}

/** Sends a question and waits for its turn response (the event stream's headers). */
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

/** The landing page finished rendering (its `<h1>` and the document title it sets). */
async function expectLanded(page: Page): Promise<void> {
  await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible({ timeout: 20_000 });
  await expect(page).toHaveTitle(/ · Email Security Gateway$/);
}

/** The turn finished: the composer offers Send again (no Stop button). */
async function expectTurnDone(scope: ReturnType<Page['locator']> | Page): Promise<void> {
  await expect(scope.getByRole('button', { name: 'Stop the answer' })).toHaveCount(0, {
    timeout: 30_000,
  });
}

function policyNames() {
  // Newest first: the draft, then the outbound and the inbound guard (creation order reversed).
  const policies = readState().assistant.delta.policies;
  return {
    all: [...policies].reverse(),
    active: [...policies].reverse().filter((p) => p.status === 'active'),
  };
}

test('analyst: header entry, Ctrl/Cmd+J, directive and demo intent, load more, deep link', async ({
  page,
}) => {
  await signIn(page, 'deltaAnalyst');
  await expectLanded(page);
  const profile = await me(page);
  expect(profile.permissions).toEqual(
    expect.arrayContaining(['assistant:use', 'policy:read', 'quarantine:read']),
  );
  expect(profile.permissions).not.toContain('assistant:configure');

  // The navigation entry and the header button.
  const nav = page.getByRole('navigation', { name: 'Main' });
  await expect(nav.getByRole('link', { name: 'AI assistant' })).toBeVisible();
  const launcher = page.getByRole('button', { name: 'Ask AI', exact: true });
  await expect(launcher).toBeVisible();

  // Ctrl/Cmd+J toggles the panel; Escape closes it and focus returns.
  await page.keyboard.press('ControlOrMeta+j');
  await expect(panel(page)).toBeVisible();
  await expect(panel(page).getByRole('list', { name: 'Suggested questions' })).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(panel(page)).toHaveCount(0);
  await launcher.click();
  const sheet = panel(page);
  await expect(sheet).toBeVisible();

  // A fake directive: exactly one tool call with these arguments, answered as an event stream.
  const { all, active } = policyNames();
  const first = await ask(page, sheet, '/tool policy_management_list {"limit":2}');
  expect(first.status()).toBe(200);
  expect(first.headers()['content-type']).toContain('text/event-stream');
  await expect(sheet.getByText('Found 2 records. More are available.')).toBeVisible({
    timeout: 30_000,
  });
  await expectTurnDone(sheet);
  const chips = sheet.getByRole('list', { name: 'Tools the assistant used' }).first();
  await expect(chips).toContainText('List policies');
  await expect(chips).toContainText('succeeded');
  const card = sheet.getByRole('region', { name: 'Result: List policies' }).first();
  await expect(card.getByText(/^2 rows/)).toBeVisible();
  for (const policy of all.slice(0, 2)) await expect(card.getByText(policy.name)).toBeVisible();
  await expect(card.getByText(all[2]!.name)).toHaveCount(0);

  // Load more: the next page from the stored cursor (a new execution, no model call).
  const more = page.waitForResponse(
    (res) =>
      /\/bff\/api\/v1\/assistant\/executions\/[0-9a-f-]{36}\/more$/.test(
        new URL(res.url()).pathname,
      ) && res.request().method() === 'POST',
  );
  await card.getByRole('button', { name: 'Load more' }).click();
  expect((await more).status()).toBe(200);
  await expect(card.getByText(/^3 rows/)).toBeVisible();
  await expect(card.getByText(all[2]!.name)).toBeVisible();
  await expect(card.getByRole('button', { name: 'Load more' })).toHaveCount(0);

  // A demo intent of the fake: "show active policies" → policy_management_list {status: active}.
  const second = await ask(page, sheet, 'show active policies');
  expect(second.status()).toBe(200);
  await expect(sheet.getByText('Found 2 records.', { exact: true })).toBeVisible({
    timeout: 30_000,
  });
  await expectTurnDone(sheet);
  const activeCard = sheet.getByRole('region', { name: 'Result: List policies' }).nth(1);
  await expect(activeCard.getByText(/^2 rows/)).toBeVisible();
  for (const policy of active) await expect(activeCard.getByText(policy.name)).toBeVisible();
  await expect(activeCard.getByText(all[0]!.name)).toHaveCount(0);
  await expectNoSeriousA11yViolations(page, 'assistant panel with result cards');

  // A deep link from a card row opens the policy page (and closes the panel).
  const target = active[0]!;
  await activeCard.getByRole('link', { name: `Open ${target.name}` }).click();
  await expect(page).toHaveURL(new RegExp(`/policies/${target.id}(\\?|$)`));
  await expect(panel(page)).toHaveCount(0);
  await expect(page.getByRole('heading', { level: 1, name: target.name })).toBeVisible({
    timeout: 20_000,
  });
});

test('assistant page: new conversation, search by title, rename and clear', async ({ page }) => {
  // A marker of this attempt: the admin keeps the conversations of earlier attempts and tests
  // (retries, the phone test), so the checks below look at this attempt's conversations only.
  const tag = `e2e${Date.now().toString(36)}`;
  const quarantineQuestion = `what was quarantined today (${tag})`;
  const greeting = `/text Hello from the e2e suite ${tag}`;
  const renamed = `E2E renamed conversation ${tag}`;

  await signIn(page, 'deltaAdmin', { next: '/assistant' });
  await expect(page.getByRole('heading', { level: 1, name: 'AI assistant' })).toBeVisible();
  // No header button on the full page itself.
  await expect(page.getByRole('button', { name: 'Ask AI', exact: true })).toHaveCount(0);
  const conversation = page.getByRole('region', { name: 'Conversation' });
  const history = page.getByRole('complementary', { name: 'Conversation history' });
  const list = history.getByRole('list', { name: 'Conversations' });
  const search = history.getByRole('searchbox', { name: 'Search conversations by title' });
  const item = (title: string) => list.getByRole('listitem').filter({ hasText: title });

  // Start from a new conversation, then a demo intent over today's seeded quarantine entries.
  await history.getByRole('button', { name: 'New conversation' }).click();
  const turn = await ask(page, conversation, quarantineQuestion);
  expect(turn.status()).toBe(200);
  await expectTurnDone(conversation);
  const card = conversation.getByRole('region', { name: 'Result: Search quarantine entries' });
  await expect(card).toBeVisible();
  // The seeded entries are 5 to 11 minutes old: both fall into "today" unless the run started
  // in the first minutes of the UTC day.
  const seeded = new Date(readState().seededAt);
  const minutesIntoDay = seeded.getUTCHours() * 60 + seeded.getUTCMinutes();
  if (minutesIntoDay > 15) {
    await expect(card.getByText(/^2 rows/)).toBeVisible();
    await expect(conversation.getByText('Found 2 records.', { exact: true })).toBeVisible();
  }
  await expect(page).toHaveURL(/\/assistant\?conversation=[0-9a-f-]{36}$/);
  await expect(item(quarantineQuestion)).toHaveCount(1);

  // A new conversation.
  await history.getByRole('button', { name: 'New conversation' }).click();
  await expect(page).toHaveURL(/\/assistant$/);
  await expect(conversation.getByText('Ask about your email security')).toBeVisible();
  await ask(page, conversation, greeting);
  await expect(
    conversation.getByText(`Hello from the e2e suite ${tag}`, { exact: true }),
  ).toBeVisible({ timeout: 30_000 });
  await expectTurnDone(conversation);
  await expect(item(greeting)).toHaveCount(1);

  // Search by title (the api's `q`, title contains).
  await search.fill(tag);
  await expect(list.getByRole('listitem')).toHaveCount(2);
  await search.fill(`quarantined today (${tag}`);
  await expect(list.getByRole('listitem')).toHaveCount(1);
  await expect(list).toContainText(quarantineQuestion);
  await search.fill('');
  await expect(item(greeting)).toHaveCount(1);

  // Rename.
  await list.getByRole('button', { name: `Actions for ${greeting}` }).click();
  await page.getByRole('menuitem', { name: 'Rename' }).click();
  const rename = page.getByRole('dialog', { name: 'Rename conversation' });
  await rename.getByLabel('Title').fill(renamed);
  await rename.getByRole('button', { name: 'Save' }).click();
  await expect(rename).toHaveCount(0);
  await expect(item(renamed)).toHaveCount(1);
  await expect(item(greeting)).toHaveCount(0);
  await expectNoSeriousA11yViolations(page, 'assistant page');

  // Clear with confirmation (soft delete + immediate content purge by the api).
  await list.getByRole('button', { name: `Actions for ${renamed}` }).click();
  await page.getByRole('menuitem', { name: 'Clear conversation' }).click();
  const confirm = page.getByRole('alertdialog').or(page.getByRole('dialog'));
  await expect(confirm.getByText(/cannot be undone/)).toBeVisible();
  const removed = page.waitForResponse(
    (res) =>
      /\/bff\/api\/v1\/assistant\/conversations\/[0-9a-f-]{36}$/.test(
        new URL(res.url()).pathname,
      ) && res.request().method() === 'DELETE',
  );
  await confirm.getByRole('button', { name: 'Clear conversation' }).click();
  expect((await removed).status()).toBe(204);
  await expect(item(renamed)).toHaveCount(0);
  await expect(item(quarantineQuestion)).toHaveCount(1);
  await search.fill(tag);
  await expect(list.getByRole('listitem')).toHaveCount(1);
});

test('user without assistant:use: no entry point, /assistant is forbidden', async ({ page }) => {
  await signIn(page, 'deltaMailbox');
  const profile = await me(page);
  expect(profile.permissions).not.toContain('assistant:use');
  await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible();
  await expect(page.getByRole('button', { name: /^Ask AI/ })).toHaveCount(0);
  await expect(
    page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'AI assistant' }),
  ).toHaveCount(0);
  await page.keyboard.press('ControlOrMeta+j');
  await expect(panel(page)).toHaveCount(0);
  await page.goto('/assistant');
  await expect(
    page.getByRole('heading', { level: 1, name: 'You do not have access to this page' }),
  ).toBeVisible();
});

test('tenant setting off: an organization admin sees the reason and the settings link', async ({
  page,
}) => {
  await signIn(page, 'epsilonAdmin');
  await expectLanded(page);
  const launcher = page.getByRole('button', { name: 'Ask AI (unavailable)' });
  await expect(launcher).toBeVisible();
  await launcher.click();
  const sheet = panel(page);
  const reason = sheet.getByRole('region', { name: 'AI assistant unavailable' });
  await expect(reason).toContainText('The AI assistant is turned off for your organization');
  await expect(composer(sheet)).toHaveCount(0);
  await expectNoSeriousA11yViolations(page, 'assistant panel (tenant setting off)');
  await reason.getByRole('link', { name: 'Open Settings → AI assistant' }).click();
  await expect(page).toHaveURL(/\/settings\?tab=assistant$/);
  const form = page.getByRole('form', { name: 'AI assistant settings' });
  await expect(form).toBeVisible({ timeout: 20_000 });
  await expect(
    form.getByRole('switch', { name: 'Turn on the AI assistant for this organization' }),
  ).not.toBeChecked();

  // The full page shows the same reason instead of the chat.
  await page.goto('/assistant');
  await expect(page.getByRole('heading', { level: 1, name: 'AI assistant' })).toBeVisible();
  await expect(page.getByRole('region', { name: 'AI assistant unavailable' })).toContainText(
    'turned off for your organization',
  );
});

test.describe('phone viewport', () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test('the panel is a full-screen sheet with card rows', async ({ page }) => {
    await signIn(page, 'deltaAdmin');
    await expectLanded(page);
    await page.getByRole('button', { name: 'Ask AI', exact: true }).click();
    const sheet = panel(page);
    await expect(sheet).toBeVisible();
    const box = await sheet.boundingBox();
    expect(box?.x ?? -1).toBeLessThanOrEqual(1);
    expect(box?.width ?? 0).toBeGreaterThanOrEqual(389);
    const turn = await ask(page, sheet, '/tool policy_management_list {}');
    expect(turn.status()).toBe(200);
    await expect(sheet.getByText('Found 3 records.', { exact: true })).toBeVisible({
      timeout: 30_000,
    });
    await expectTurnDone(sheet);
    const card = sheet.getByRole('region', { name: 'Result: List policies' }).last();
    await expect(card.getByTestId('data-table-cards')).toBeVisible();
    await expect(card.locator('table')).toHaveCount(0);
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
    );
    expect(overflow).toBeLessThanOrEqual(1);
    await expectNoSeriousA11yViolations(page, 'assistant panel on a phone');
  });
});
