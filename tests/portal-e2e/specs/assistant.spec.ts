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
 *
 * Step AI-2 (docs/plan/steps/29-ai-chat-confirmations-mail-writes.md §9 item 7, D10; ADR-0093
 * amended): writes are proposals shown in a confirmation card rendered from the server-authored
 * summary. "Create an inbound policy that quarantines executables" (the fake's plan validate →
 * test → create) shows the rule summary and nothing exists until Confirm; Confirm creates the
 * draft; "publish it" proposes a medium-risk publish with impact lines whose Confirm activates
 * it; a high-risk delete asks for the password and the authenticator code (a delta admin with
 * MFA, support/totp.ts) and runs after re-authentication; a cancelled proposal changes nothing; a
 * proposal past its expiry is refused by the api (`410`) and the card shows the expired state;
 * the card on a phone; axe on every card state. The single-use token is checked to stay out of
 * browser storage and the messages route.
 *
 * Step AI-3 (docs/plan/steps/30-ai-chat-identity-tenant-admin.md §9 item 7, D2–D4, D11, D12;
 * ADR-0093 amendment AI-3): identity and tenant administration through the fake's plans, as the
 * delta admin with MFA. "invite <address> as security_analyst" (roles_get → users_invite) is a
 * high-risk card listing the role and the invitation warning that runs after the password and the
 * authenticator code, and the Users page then lists the person as invited; "disable user <address>"
 * (users_list → users_change_status) on the seeded `leaver@` user is high risk too, but inside
 * the re-authentication window of the same session the card asks for nothing and the user ends
 * disabled; "add domain <name>" is a medium card with impact lines and the Domains page lists the
 * domain pending verification; a self-escalation directive (`users_replace_roles` with the signed-in
 * admin's own id) is refused by the proposal guard before anything is stored: a "Not allowed in
 * chat" card and no confirmation. An invitation card on a phone; axe on every new state.
 *
 * Step AI-R (docs/plan/steps/31-ai-chat-reports.md §9 item 8, D9; I15–I17): "generate a security
 * report" → a report card with the period and figures and the server's HTML in a sandboxed
 * iframe (`sandbox=""`, `srcdoc`; its heading and charts checked through the frame locator); "Open
 * full size" shows the same report on `/assistant/reports/<id>` and leads back to the
 * conversation; "send this report to my email" → a medium-risk confirmation card → Confirm → the
 * card's email list shows the delivery queued (sent once the stack's notification-worker ran);
 * "send the report to someone@outside.test" → the "Not allowed in chat" card and no confirmation.
 * The card on a phone; axe on every new state (including the frame's content).
 *
 * Step AI-5 (docs/plan/steps/33-ai-chat-compliance-integrations.md §9 item 6, D3, D11; I22): as
 * delta's compliance officer (MFA), "set retention policy "E2E retention <tag>" to 30 days" on the
 * seeded 365-day policy (the fake's plan list → get → update) is a high-risk card with the
 * shortening warning that runs after the password and the authenticator code, and the Retention
 * page then lists 30 days; "create ediscovery case "E2E chat case <tag>"" is a low-risk card and
 * the eDiscovery page lists the case after Confirm; "release the legal hold" (list → release, a
 * critical operation) is refused as "Not available in chat" with the Legal holds link, no
 * confirmation is stored and the hold stays active. An eDiscovery case card on a phone; axe on
 * every new state.
 */
import type { Page, Response } from '@playwright/test';
import { nextTotp, signIn, user } from '../support/auth';
import { me } from '../support/contract';
import { expect, test } from '../support/fixtures';
import { bff, writerDb } from '../support/messages';
import { expectNoSeriousA11yViolations, expectNoSeriousHtmlViolations } from '../support/pages';
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

// ---------------------------------------------------------------------------------------------
// Step AI-2: action confirmations (these run after the AI-1 tests above, which count delta's
// three seeded policies; every proposal below ends executed, cancelled or expired).
// ---------------------------------------------------------------------------------------------

/** The policy the fake's "quarantines executables" plan creates (packages/assistant fake.ts). */
const EXECUTABLES_POLICY = 'Quarantine inbound executables';

/** The confirmation card of a proposal (a region named by the summary's title). */
function confirmationCard(scope: ReturnType<Page['locator']> | Page, title: string) {
  return scope.getByRole('region', { name: title, exact: true }).last();
}

async function deltaOrganizationId(): Promise<bigint> {
  const org = await writerDb().organization.findUniqueOrThrow({
    where: { publicId: readState().orgs.delta.id },
    select: { id: true },
  });
  return org.id;
}

/** Delta's policy by name on the writer (archived rows included). */
async function deltaPolicy(name: string) {
  return writerDb().emailPolicy.findFirst({
    where: { organizationId: await deltaOrganizationId(), name },
    select: { publicId: true, status: true, activeVersionId: true },
    orderBy: { id: 'desc' },
  });
}

/** The newest confirmation of delta (one worker: the proposal this test just made). */
async function newestConfirmation() {
  return writerDb().aiChatActionConfirmation.findFirstOrThrow({
    where: { organizationId: await deltaOrganizationId() },
    select: { id: true, publicId: true, status: true, toolName: true, risk: true },
    orderBy: { id: 'desc' },
  });
}

/**
 * Test instrumentation: keeps a copy of every turn event stream the page receives (a clone of the
 * response, read alongside the app), so the test can read the single-use token of
 * `confirmation.required`. It lives in the page's memory only, as the app's own copy does.
 */
async function recordTurnStreams(page: Page): Promise<void> {
  await page.addInitScript(() => {
    const streams: string[] = [];
    (window as unknown as { __egTurnStreams: string[] }).__egTurnStreams = streams;
    const original = window.fetch.bind(window);
    window.fetch = async (input, init) => {
      const response = await original(input, init);
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
      if (
        /\/assistant\/conversations\/[0-9a-f-]{36}\/turns$/.test(
          new URL(url, location.href).pathname,
        )
      ) {
        void response
          .clone()
          .text()
          .then((text) => streams.push(text))
          .catch(() => undefined);
      }
      return response;
    };
  });
}

/** The token of the newest `confirmation.required` event the page received. */
async function newestToken(page: Page): Promise<string> {
  let token = '';
  await expect
    .poll(
      async () => {
        const streams = await page.evaluate(
          () => (window as unknown as { __egTurnStreams?: string[] }).__egTurnStreams ?? [],
        );
        const events = [
          ...streams.join('\n').matchAll(/event: confirmation\.required\ndata: (.+)\n/g),
        ];
        const last = events.at(-1);
        const value = last ? (JSON.parse(last[1]!) as { token?: unknown }).token : undefined;
        token = typeof value === 'string' ? value : '';
        return token;
      },
      { timeout: 15_000 },
    )
    .toMatch(/^[A-Za-z0-9_-]{43}$/);
  return token;
}

/** Neither browser storage nor the stored messages hold the token. */
async function expectTokenNowhere(page: Page, token: string): Promise<void> {
  const storage = await page.evaluate(() =>
    JSON.stringify({ local: { ...localStorage }, session: { ...sessionStorage } }),
  );
  expect(storage.includes(token)).toBe(false);
  const conversation = /conversation=([0-9a-f-]{36})/.exec(page.url())?.[1];
  if (!conversation) return;
  const messages = await page.evaluate(
    (id) =>
      fetch(`/bff/api/v1/assistant/conversations/${id}/messages`, {
        headers: { accept: 'application/json' },
      }).then((res) => res.text()),
    conversation,
  );
  expect(messages.length).toBeGreaterThan(0);
  expect(messages.includes(token)).toBe(false);
}

/** The policies page (in another tab) lists `name` with `status`, or not at all (`null`). */
async function expectPolicyListed(page: Page, name: string, status: string | null): Promise<void> {
  const row = page.locator('main').getByRole('row').filter({ hasText: name });
  // The list reads from the replica: reload until it caught up.
  await expect(async () => {
    await page.goto('/policies');
    await expect(page.getByRole('heading', { level: 1, name: 'Policy management' })).toBeVisible();
    await expect(page.locator('main').getByText('E2E Assistant inbound guard')).toBeVisible();
    if (status === null) await expect(row).toHaveCount(0, { timeout: 2_000 });
    else await expect(row.first()).toContainText(status, { timeout: 2_000 });
  }).toPass({ timeout: 30_000 });
}

test('confirmations: create a policy from a plan, publish it, delete it with re-authentication', async ({
  page,
}) => {
  test.setTimeout(300_000);
  // A retry in the same seeded run would meet the name of the first attempt (reserved by the
  // archived policy): the plan's fixed name needs a fresh seed.
  expect(await deltaPolicy(EXECUTABLES_POLICY), 'a fresh seed (no earlier attempt)').toBeNull();

  await recordTurnStreams(page);
  await signIn(page, 'deltaMfaAdmin', { next: '/assistant' });
  await expect(page.getByRole('heading', { level: 1, name: 'AI assistant' })).toBeVisible();
  const conversation = page.getByRole('region', { name: 'Conversation' });
  const history = page.getByRole('complementary', { name: 'Conversation history' });
  await history.getByRole('button', { name: 'New conversation' }).click();
  const policies = await page.context().newPage();

  // (a) The plan validates, tests, then proposes the create: a low-risk card with the rules.
  const created = await ask(
    page,
    conversation,
    'Create an inbound policy that quarantines executables',
  );
  expect(created.status()).toBe(200);
  await expectTurnDone(conversation);
  await expect(
    conversation.getByText('I prepared this change. Review it in the confirmation card', {
      exact: false,
    }),
  ).toBeVisible();
  const createCard = confirmationCard(conversation, 'Create policy');
  await expect(createCard).toBeVisible();
  await expect(createCard).toBeFocused();
  await expect(createCard.getByText('Low risk')).toBeVisible();
  await expect(createCard.getByText('Waiting for your confirmation')).toBeVisible();
  await expect(createCard.getByRole('table', { name: 'What it applies to' })).toContainText(
    EXECUTABLES_POLICY,
  );
  const rules = createCard.getByRole('list', { name: 'Policy rules' });
  await expect(rules).toContainText('quarantine-executables');
  await expect(rules).toContainText(/executable/i);
  await expect(rules).toContainText(/quarantine/i);
  await expect(createCard.getByText(/^Expires in \d+:\d{2}$/)).toBeVisible();
  const token = await newestToken(page);
  await expectTokenNowhere(page, token);
  await expectNoSeriousA11yViolations(page, 'confirmation card (low risk, pending)');

  // Nothing exists before the confirm: not in the database, not on the policies page.
  expect(await deltaPolicy(EXECUTABLES_POLICY)).toBeNull();
  await expectPolicyListed(policies, EXECUTABLES_POLICY, null);

  await createCard.getByRole('button', { name: 'Confirm', exact: true }).click();
  await expect(createCard.getByText('Done: the action was applied.')).toBeVisible({
    timeout: 30_000,
  });
  await expect(createCard.getByRole('button', { name: 'Confirm', exact: true })).toHaveCount(0);
  const draft = await deltaPolicy(EXECUTABLES_POLICY);
  expect(draft).toMatchObject({ status: 'draft', activeVersionId: null });
  expect((await newestConfirmation()).status).toBe('executed');
  await expectPolicyListed(policies, EXECUTABLES_POLICY, 'Draft');

  // (b) "publish it": the action update of the confirmed create gives the policy; a medium card
  // with impact lines; Confirm publishes and activates version 1.
  await page.bringToFront();
  await ask(page, conversation, 'publish it');
  await expectTurnDone(conversation);
  const publishCard = confirmationCard(conversation, 'Publish and activate policy version');
  await expect(publishCard).toBeVisible();
  await expect(publishCard.getByText('Medium risk')).toBeVisible();
  const impact = publishCard.getByRole('list', { name: 'Impact' });
  await expect(impact.getByRole('listitem').first()).toBeVisible();
  await expect(impact).toContainText('Version 1 evaluates new mail from now on');
  await expect(publishCard.getByRole('table', { name: 'Changes' })).toContainText('v1');
  expect((await deltaPolicy(EXECUTABLES_POLICY))?.status).toBe('draft');
  await expectNoSeriousA11yViolations(page, 'confirmation card (medium risk, pending)');
  await publishCard.getByRole('button', { name: 'Confirm', exact: true }).click();
  await expect(publishCard.getByText('Done: the action was applied.')).toBeVisible({
    timeout: 30_000,
  });
  const active = await deltaPolicy(EXECUTABLES_POLICY);
  expect(active?.status).toBe('active');
  expect(active?.activeVersionId).not.toBeNull();
  await expectPolicyListed(policies, EXECUTABLES_POLICY, 'Active');

  // (d) A high-risk delete asks for the password and the authenticator code.
  await page.bringToFront();
  await ask(
    page,
    conversation,
    `/tool policy_management_remove {"policyId":"${active!.publicId}"}`,
  );
  await expectTurnDone(conversation);
  const deleteCard = confirmationCard(conversation, 'Delete policy');
  await expect(deleteCard).toBeVisible();
  await expect(deleteCard.getByText('High risk')).toBeVisible();
  await expect(deleteCard.getByRole('list', { name: 'Warnings' })).toContainText(/cannot/i);
  await expect(deleteCard.getByText('This cannot be undone.')).toBeVisible();
  const identity = deleteCard.getByRole('group', { name: 'Confirm your identity' });
  await expect(identity).toBeVisible();
  const password = identity.getByLabel('Your password (required)', { exact: true });
  const code = identity.getByLabel('Authenticator code (required)', { exact: true });
  await expect(password).toBeVisible();
  await expect(code).toBeVisible();
  await expectNoSeriousA11yViolations(page, 'confirmation card (high risk, re-authentication)');

  // Empty fields are refused in the card (nothing is sent).
  await deleteCard.getByRole('button', { name: 'Confirm', exact: true }).click();
  await expect(deleteCard.getByText('Enter your password')).toBeVisible();
  // A wrong password: the api refuses (401 assistant_reauth_failed), the fields are cleared.
  const self = user('deltaMfaAdmin');
  await password.fill(`${self.password}-wrong`);
  await code.fill(await nextTotp('deltaMfaAdmin'));
  const refused = page.waitForResponse(
    (res) => /\/confirm$/.test(new URL(res.url()).pathname) && res.request().method() === 'POST',
  );
  await deleteCard.getByRole('button', { name: 'Confirm', exact: true }).click();
  expect((await refused).status()).toBe(401);
  await expect(deleteCard.getByRole('alert')).toContainText('The password is not correct.');
  await expect(password).toHaveValue('');
  await expect(code).toHaveValue('');
  expect((await deltaPolicy(EXECUTABLES_POLICY))?.status).toBe('active');
  expect((await newestConfirmation()).status).toBe('pending');

  // The right password and a fresh code: the delete runs.
  await password.fill(self.password);
  await code.fill(await nextTotp('deltaMfaAdmin'));
  await deleteCard.getByRole('button', { name: 'Confirm', exact: true }).click();
  await expect(deleteCard.getByText('Done: the action was applied.')).toBeVisible({
    timeout: 30_000,
  });
  expect((await deltaPolicy(EXECUTABLES_POLICY))?.status).toBe('archived');
  const deleted = await writerDb().aiChatActionConfirmation.findUniqueOrThrow({
    where: { id: (await newestConfirmation()).id },
    select: { status: true, reauthUsed: true, toolName: true, risk: true },
  });
  expect(deleted).toEqual({
    status: 'executed',
    reauthUsed: true,
    toolName: 'policy_management_remove',
    risk: 'high',
  });
  await expectPolicyListed(policies, EXECUTABLES_POLICY, null);
  await policies.close();
});

test('confirmations: a cancelled proposal changes nothing', async ({ page }) => {
  const inbound = readState().assistant.delta.policies.find(
    (p) => p.name === 'E2E Assistant inbound guard',
  )!;
  await signIn(page, 'deltaAdmin', { next: '/assistant' });
  const conversation = page.getByRole('region', { name: 'Conversation' });
  await page
    .getByRole('complementary', { name: 'Conversation history' })
    .getByRole('button', { name: 'New conversation' })
    .click();
  await ask(page, conversation, `/tool policy_management_disable {"policyId":"${inbound.id}"}`);
  await expectTurnDone(conversation);
  const card = confirmationCard(conversation, 'Disable policy');
  await expect(card).toBeVisible();
  await expect(card.getByText('Medium risk')).toBeVisible();
  await expect(card.getByRole('list', { name: 'Impact' })).toContainText(
    'Stops evaluating this policy for new mail',
  );
  const cancelled = page.waitForResponse(
    (res) => /\/cancel$/.test(new URL(res.url()).pathname) && res.request().method() === 'POST',
  );
  await card.getByRole('button', { name: 'Cancel', exact: true }).click();
  expect((await cancelled).status()).toBe(200);
  await expect(card.getByText('Cancelled. Nothing changed.')).toBeVisible();
  await expect(card.getByRole('button', { name: 'Confirm', exact: true })).toHaveCount(0);
  expect(await newestConfirmation()).toMatchObject({
    status: 'cancelled',
    toolName: 'policy_management_disable',
  });
  expect((await deltaPolicy(inbound.name))?.status).toBe('active');
  await expectNoSeriousA11yViolations(page, 'confirmation card (cancelled)');

  // The history (a reload: no token any more) shows the decided card without buttons.
  await page.reload();
  const again = confirmationCard(
    page.getByRole('region', { name: 'Conversation' }),
    'Disable policy',
  );
  await expect(again.getByText('Cancelled. Nothing changed.')).toBeVisible({ timeout: 20_000 });
  await expect(again.getByRole('button')).toHaveCount(0);
});

test('confirmations: an expired proposal is refused and shows the expired state', async ({
  page,
}) => {
  const outbound = readState().assistant.delta.policies.find(
    (p) => p.name === 'E2E Assistant outbound guard',
  )!;
  await recordTurnStreams(page);
  await signIn(page, 'deltaAdmin', { next: '/assistant' });
  const conversation = page.getByRole('region', { name: 'Conversation' });
  await page
    .getByRole('complementary', { name: 'Conversation history' })
    .getByRole('button', { name: 'New conversation' })
    .click();
  await ask(page, conversation, `/tool policy_management_disable {"policyId":"${outbound.id}"}`);
  await expectTurnDone(conversation);
  const card = confirmationCard(conversation, 'Disable policy');
  await expect(card.getByText('Waiting for your confirmation')).toBeVisible();

  const token = await newestToken(page);

  // Time passes: the stored expiry moves into the past (the TTL is 300 s). A confirm with the
  // valid token and digest is refused with 410 before any other check and the row becomes
  // `expired`; the card then shows the expired state (the view's expiry has passed).
  const pending = await newestConfirmation();
  expect(pending).toMatchObject({ status: 'pending', toolName: 'policy_management_disable' });
  const stored = await writerDb().aiChatActionConfirmation.update({
    where: { id: pending.id },
    data: { expiresAt: new Date(Date.now() - 1_000) },
    select: { actionDigest: true },
  });
  const refused = await bff(page, 'POST', `/assistant/confirmations/${pending.publicId}/confirm`, {
    token,
    actionDigest: stored.actionDigest,
  });
  expect(refused.status).toBe(410);
  expect(refused.body?.code).toBe('assistant_confirmation_expired');
  expect(
    (
      await writerDb().aiChatActionConfirmation.findUniqueOrThrow({
        where: { id: pending.id },
        select: { status: true },
      })
    ).status,
  ).toBe('expired');

  // The card (history after a reload, the server's view) shows the expired state, no buttons.
  await page.reload();
  const expired = confirmationCard(
    page.getByRole('region', { name: 'Conversation' }),
    'Disable policy',
  );
  await expect(expired.getByText('Expired', { exact: true })).toBeVisible({ timeout: 20_000 });
  await expect(
    expired.getByText(/^Expired without confirmation\. Nothing changed\./),
  ).toBeVisible();
  await expect(expired.getByRole('button')).toHaveCount(0);
  expect((await deltaPolicy(outbound.name))?.status).toBe('active');
  await expectNoSeriousA11yViolations(page, 'confirmation card (expired)');
});

test.describe('phone viewport (confirmations)', () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test('the confirmation card fits the full-screen sheet', async ({ page }) => {
    const draft = readState().assistant.delta.policies.find(
      (p) => p.name === 'E2E Assistant draft rule',
    )!;
    await signIn(page, 'deltaAdmin');
    await expectLanded(page);
    await page.getByRole('button', { name: 'Ask AI', exact: true }).click();
    const sheet = panel(page);
    await expect(sheet).toBeVisible();
    await ask(
      page,
      sheet,
      `/tool policy_management_update {"policyId":"${draft.id}","body":{"name":"E2E Assistant draft rule (renamed)"}}`,
    );
    await expectTurnDone(sheet);
    const card = confirmationCard(sheet, 'Update policy');
    await expect(card).toBeVisible();
    await expect(card.getByRole('table', { name: 'Changes' })).toContainText(
      'E2E Assistant draft rule (renamed)',
    );
    const confirmButton = card.getByRole('button', { name: 'Confirm', exact: true });
    const cancelButton = card.getByRole('button', { name: 'Cancel', exact: true });
    await confirmButton.scrollIntoViewIfNeeded();
    await expect(confirmButton).toBeInViewport();
    await expect(cancelButton).toBeInViewport();
    const box = await card.boundingBox();
    expect((box?.x ?? -1) >= 0 && (box?.x ?? 0) + (box?.width ?? 999) <= 390).toBe(true);
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
    );
    expect(overflow).toBeLessThanOrEqual(1);
    await expectNoSeriousA11yViolations(page, 'confirmation card on a phone');
    // Nothing is renamed: the proposal is cancelled.
    await cancelButton.click();
    await expect(card.getByText('Cancelled. Nothing changed.')).toBeVisible();
    expect((await deltaPolicy(draft.name))?.status).toBe('draft');
  });
});

// ---------------------------------------------------------------------------------------------
// Step AI-3: identity and tenant administration (design 30 §9 item 7). The delta admin with MFA
// signs in once, so the confirmations below share one session and its re-authentication window.
// ---------------------------------------------------------------------------------------------

/** The newest confirmation of delta, or null (the id only). */
async function newestConfirmationId(): Promise<bigint | null> {
  const row = await writerDb().aiChatActionConfirmation.findFirst({
    where: { organizationId: await deltaOrganizationId() },
    select: { id: true },
    orderBy: { id: 'desc' },
  });
  return row?.id ?? null;
}

/** A delta user by email on the writer (any status), or null. */
async function deltaUser(email: string) {
  return writerDb().user.findFirst({
    where: { organizationId: await deltaOrganizationId(), email },
    select: { publicId: true, status: true },
  });
}

/** `path` (another tab) lists a row containing `text` and `label`; the lists read the replica. */
async function expectListed(
  page: Page,
  path: string,
  heading: string,
  text: string,
  label: string,
): Promise<void> {
  const row = page.locator('main').getByRole('row').filter({ hasText: text });
  await expect(async () => {
    await page.goto(path);
    await expect(page.getByRole('heading', { level: 1, name: heading })).toBeVisible();
    await expect(row.first()).toContainText(label, { timeout: 3_000 });
  }).toPass({ timeout: 45_000 });
}

test('identity and tenant administration: invite with re-authentication, disable in the window, add a domain, self-escalation refused', async ({
  page,
}) => {
  test.setTimeout(300_000);
  const state = readState();
  const tag = Date.now().toString(36);
  const invitee = `invitee-${tag}@${state.users.deltaAdmin.email.split('@')[1]}`;
  const domain = `chat-${tag}.${state.users.deltaAdmin.email.split('@')[1]}`;
  const offboard = state.assistant.delta.offboardUser;
  expect(await deltaUser(invitee)).toBeNull();
  expect((await deltaUser(offboard.email))?.status, 'a fresh seed (leaver still active)').toBe(
    'active',
  );

  await recordTurnStreams(page);
  await signIn(page, 'deltaMfaAdmin', { next: '/assistant' });
  await expect(page.getByRole('heading', { level: 1, name: 'AI assistant' })).toBeVisible();
  const conversation = page.getByRole('region', { name: 'Conversation' });
  await page
    .getByRole('complementary', { name: 'Conversation history' })
    .getByRole('button', { name: 'New conversation' })
    .click();
  const lists = await page.context().newPage();

  // (a) Invite as security_analyst: roles_get, then a high-risk card with the role and the
  // invitation warning; it asks for the password and the authenticator code.
  await ask(page, conversation, `invite ${invitee} as security_analyst`);
  await expectTurnDone(conversation);
  const inviteCard = confirmationCard(conversation, 'Invite user');
  await expect(inviteCard).toBeVisible();
  await expect(inviteCard.getByText('High risk')).toBeVisible();
  const applies = inviteCard.getByRole('table', { name: 'What it applies to' });
  await expect(applies).toContainText(invitee);
  await expect(applies).toContainText('security_analyst');
  await expect(inviteCard.getByRole('list', { name: 'Warnings' })).toContainText(
    'An invitation email is sent; the person gets these roles when they accept.',
  );
  const identity = inviteCard.getByRole('group', { name: 'Confirm your identity' });
  const password = identity.getByLabel('Your password (required)', { exact: true });
  const code = identity.getByLabel('Authenticator code (required)', { exact: true });
  await expect(password).toBeVisible();
  await expect(code).toBeVisible();
  await expectNoSeriousA11yViolations(page, 'invitation card (high risk, re-authentication)');
  expect(await deltaUser(invitee)).toBeNull();

  await password.fill(user('deltaMfaAdmin').password);
  await code.fill(await nextTotp('deltaMfaAdmin'));
  await inviteCard.getByRole('button', { name: 'Confirm', exact: true }).click();
  await expect(inviteCard.getByText('Done: the action was applied.')).toBeVisible({
    timeout: 30_000,
  });
  expect(await deltaUser(invitee)).toMatchObject({ status: 'invited' });
  const invited = await writerDb().aiChatActionConfirmation.findUniqueOrThrow({
    where: { id: (await newestConfirmationId())! },
    select: { status: true, reauthUsed: true, toolName: true, risk: true },
  });
  expect(invited).toEqual({
    status: 'executed',
    reauthUsed: true,
    toolName: 'users_invite',
    risk: 'high',
  });
  await expectListed(lists, '/users', 'Users', invitee, 'Invited');

  // (b) Disable a seeded user: users_list finds exactly one row, then a high-risk card. The
  // session re-authenticated a moment ago, so the card asks for nothing (the window, A2-2).
  await page.bringToFront();
  await ask(page, conversation, `disable user ${offboard.email}`);
  await expectTurnDone(conversation);
  const disableCard = confirmationCard(conversation, 'Disable user');
  await expect(disableCard).toBeVisible();
  await expect(disableCard.getByText('High risk')).toBeVisible();
  await expect(disableCard.getByRole('table', { name: 'What it applies to' })).toContainText(
    offboard.email,
  );
  await expect(disableCard.getByRole('table', { name: 'Changes' })).toContainText('disabled');
  await expect(disableCard.getByRole('group', { name: 'Confirm your identity' })).toHaveCount(0);
  await expectNoSeriousA11yViolations(page, 'disable-user card (high risk, inside the window)');
  expect((await deltaUser(offboard.email))?.status).toBe('active');
  await disableCard.getByRole('button', { name: 'Confirm', exact: true }).click();
  await expect(disableCard.getByText('Done: the action was applied.')).toBeVisible({
    timeout: 30_000,
  });
  expect((await deltaUser(offboard.email))?.status).toBe('disabled');
  const disabled = await writerDb().aiChatActionConfirmation.findUniqueOrThrow({
    where: { id: (await newestConfirmationId())! },
    select: { status: true, reauthUsed: true, toolName: true, risk: true },
  });
  expect(disabled).toEqual({
    status: 'executed',
    reauthUsed: false,
    toolName: 'users_change_status',
    risk: 'high',
  });
  await expectListed(lists, '/users', 'Users', offboard.email, 'Disabled');

  // (c) Add a domain: a medium-risk card with impact lines; the domain then waits for its DNS.
  await page.bringToFront();
  await ask(page, conversation, `add domain ${domain}`);
  await expectTurnDone(conversation);
  const domainCard = confirmationCard(conversation, 'Add domain');
  await expect(domainCard).toBeVisible();
  await expect(domainCard.getByText('Medium risk')).toBeVisible();
  await expect(domainCard.getByRole('list', { name: 'Impact' })).toContainText(
    'Publish the DNS records shown on the domain page, then verify the domain.',
  );
  await expect(domainCard.getByRole('group', { name: 'Confirm your identity' })).toHaveCount(0);
  await expectNoSeriousA11yViolations(page, 'add-domain card (medium risk, pending)');
  await domainCard.getByRole('button', { name: 'Confirm', exact: true }).click();
  await expect(domainCard.getByText('Done: the action was applied.')).toBeVisible({
    timeout: 30_000,
  });
  const created = await writerDb().domain.findFirst({
    where: { organizationId: await deltaOrganizationId(), name: domain },
    select: { status: true },
  });
  expect(created).toEqual({ status: 'pending_verification' });
  await expectListed(lists, '/domains', 'Domains', domain, 'Pending verification');
  await lists.close();

  // (d) Self-escalation by directive: the proposal guard refuses before anything is stored or
  // sent (I12): a "Not allowed in chat" card, no confirmation card, the roles unchanged.
  await page.bringToFront();
  const before = await newestConfirmationId();
  const self = state.assistant.delta.mfaAdminUserId;
  await ask(
    page,
    conversation,
    `/tool users_replace_roles {"id":"${self}","body":{"roleKeys":["organization_admin"]}}`,
  );
  await expectTurnDone(conversation);
  const denied = conversation
    .getByRole('region', { name: /^Result: / })
    .filter({ hasText: 'Not allowed in chat' })
    .last();
  await expect(denied).toBeVisible();
  await expect(denied.getByRole('button')).toHaveCount(0);
  // The live card shows the server's fixed message from `tool.denied`; the stored turn that
  // replaces the streamed one carries the same message and the tool's title (design note 30 D12,
  // §11 #11), so the card text holds in both states, never the decision code.
  await expect(denied).toContainText(
    'Changes to your own account, roles, status, MFA or sessions are not available in chat.',
  );
  await expect(denied).toContainText('Replace the roles of a user');
  await expect(denied).not.toContainText('denied_guard');
  await expect
    .poll(async () => {
      const streams = await page.evaluate(
        () => (window as unknown as { __egTurnStreams?: string[] }).__egTurnStreams ?? [],
      );
      const events = [...streams.join('\n').matchAll(/event: tool\.denied\ndata: (.+)\n/g)];
      return events.map((e) => JSON.parse(e[1]!) as { decision?: string; message?: string });
    })
    .toContainEqual(
      expect.objectContaining({
        decision: 'denied_guard',
        message: expect.stringContaining(
          'Changes to your own account, roles, status, MFA or sessions are not available in chat.',
        ),
      }),
    );
  await expect(confirmationCard(conversation, 'Change user roles')).toHaveCount(0);
  expect(await newestConfirmationId()).toBe(before);
  const execution = await writerDb().aiChatToolExecution.findFirstOrThrow({
    where: { organizationId: await deltaOrganizationId(), toolName: 'users_replace_roles' },
    select: { decision: true, httpStatus: true },
    orderBy: { id: 'desc' },
  });
  expect(execution).toEqual({ decision: 'denied_guard', httpStatus: null });
  const roles = await writerDb().user.findFirstOrThrow({
    where: { publicId: self },
    select: { userRoles: { select: { role: { select: { key: true } } } } },
  });
  expect(roles.userRoles.map((r) => r.role.key)).toEqual(['organization_admin']);
  await expectNoSeriousA11yViolations(page, 'proposal guard refusal (not allowed in chat)');
});

test.describe('phone viewport (identity confirmations)', () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test('an invitation card with the password field fits the full-screen sheet', async ({
    page,
  }) => {
    const domainName = readState().users.deltaAdmin.email.split('@')[1]!;
    const email = `phone-${Date.now().toString(36)}@${domainName}`;
    await signIn(page, 'deltaAdmin');
    await expectLanded(page);
    await page.getByRole('button', { name: 'Ask AI', exact: true }).click();
    const sheet = panel(page);
    await expect(sheet).toBeVisible();
    await ask(
      page,
      sheet,
      `/tool users_invite {"body":{"email":"${email}","displayName":"Phone Invitee","roleKeys":["read_only_user"]}}`,
    );
    await expectTurnDone(sheet);
    const card = confirmationCard(sheet, 'Invite user');
    await expect(card).toBeVisible();
    await expect(card.getByText('High risk')).toBeVisible();
    // deltaAdmin has no MFA: the password only.
    const identity = card.getByRole('group', { name: 'Confirm your identity' });
    await expect(identity.getByLabel('Your password (required)', { exact: true })).toBeVisible();
    const confirmButton = card.getByRole('button', { name: 'Confirm', exact: true });
    const cancelButton = card.getByRole('button', { name: 'Cancel', exact: true });
    await confirmButton.scrollIntoViewIfNeeded();
    await expect(confirmButton).toBeInViewport();
    await expect(cancelButton).toBeInViewport();
    const box = await card.boundingBox();
    expect((box?.x ?? -1) >= 0 && (box?.x ?? 0) + (box?.width ?? 999) <= 390).toBe(true);
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
    );
    expect(overflow).toBeLessThanOrEqual(1);
    await expectNoSeriousA11yViolations(page, 'invitation card on a phone');
    // Nobody is invited: the proposal is cancelled.
    await cancelButton.click();
    await expect(card.getByText('Cancelled. Nothing changed.')).toBeVisible();
    expect(await deltaUser(email)).toBeNull();
  });
});

// ---------------------------------------------------------------------------------------------
// Step AI-R: HTML dashboard reports in chat and email delivery (design 31 §9 item 8).
// ---------------------------------------------------------------------------------------------

const REPORT_PATH = /^\/assistant\/reports\/([0-9a-f-]{36})$/;

/** The newest report card of a scope (`Result: Security report: …`). */
function reportCard(scope: ReturnType<Page['locator']> | Page) {
  return scope.getByRole('region', { name: /^Result: Security report/ }).last();
}

/** The report frame is inert: every sandbox restriction on, the HTML only as `srcdoc`. */
async function expectReportFrame(scope: ReturnType<Page['locator']>): Promise<void> {
  const iframe = scope.locator('iframe[title="Security report"]');
  await expect(iframe).toBeVisible({ timeout: 30_000 });
  await expect(iframe).toHaveAttribute('sandbox', '');
  await expect(iframe).not.toHaveAttribute('src', /.*/);
  expect((await iframe.getAttribute('srcdoc'))?.length ?? 0).toBeGreaterThan(1_000);
  const frame = scope.frameLocator('iframe[title="Security report"]');
  await expect(frame.getByRole('heading', { level: 1, name: 'Security report' })).toBeVisible();
  await expect(frame.locator('svg').first()).toBeAttached();
  expect(await frame.locator('svg').count()).toBeGreaterThan(0);
  // No script, link or external resource reached the frame's document (I16).
  expect(await frame.locator('script, a[href], img[src], link, iframe').count()).toBe(0);
}

async function newestDeltaReport() {
  return writerDb().aiChatReport.findFirstOrThrow({
    where: { organizationId: await deltaOrganizationId() },
    select: { id: true, publicId: true, status: true },
    orderBy: { id: 'desc' },
  });
}

test('reports: generate a security report, open it full size, email it to me; an outside address is refused', async ({
  page,
}) => {
  test.setTimeout(240_000);
  const adminEmail = readState().users.deltaAdmin.email;
  await signIn(page, 'deltaAdmin', { next: '/assistant' });
  await expect(page.getByRole('heading', { level: 1, name: 'AI assistant' })).toBeVisible();
  const conversation = page.getByRole('region', { name: 'Conversation' });
  await page
    .getByRole('complementary', { name: 'Conversation history' })
    .getByRole('button', { name: 'New conversation' })
    .click();

  // (a) A demo intent of the fake: report_generate over the last 7 days.
  const turn = await ask(page, conversation, 'generate a security report');
  expect(turn.status()).toBe(200);
  await expectTurnDone(conversation);
  await expect(conversation.getByText(/Your security report for .+ is ready below/)).toBeVisible({
    timeout: 30_000,
  });
  const card = reportCard(conversation);
  await expect(card).toBeVisible();
  await expect(card).toContainText('Last 7 days, UTC');
  await expect(card.getByRole('list', { name: 'Key figures' })).toBeVisible();
  await expectReportFrame(card);
  const stored = await newestDeltaReport();
  expect(stored.status).toBe('available');
  await expect(card.getByText(/Not emailed yet/)).toBeVisible();
  await expectNoSeriousA11yViolations(page, 'report card with the sandboxed report');
  const html = await card.locator('iframe[title="Security report"]').getAttribute('srcdoc');
  await expectNoSeriousHtmlViolations(page, html ?? '', 'the report HTML (frame content)');

  // (b) Open full size: the same report on its own page, then back to the conversation.
  await card.getByRole('link', { name: 'Open full size' }).click();
  await expect(page).toHaveURL((url) => REPORT_PATH.test(url.pathname));
  expect(REPORT_PATH.exec(new URL(page.url()).pathname)?.[1]).toBe(stored.publicId);
  const main = page.locator('main');
  await expect(main.getByRole('heading', { level: 1, name: /^Security report/ })).toBeVisible({
    timeout: 20_000,
  });
  await expectReportFrame(main);
  await expect(main.getByRole('button', { name: 'Download HTML' })).toBeEnabled();
  await expectNoSeriousA11yViolations(page, 'full-size report page');
  await main.getByRole('link', { name: 'Back to the conversation' }).click();
  await expect(page).toHaveURL(/\/assistant\?conversation=[0-9a-f-]{36}$/);
  const back = page.getByRole('region', { name: 'Conversation' });
  await expectReportFrame(reportCard(back));

  // (c) "send this report to my email": a medium-risk card, nothing sent before Confirm.
  const before = await newestConfirmationId();
  await ask(page, back, 'send this report to my email');
  await expectTurnDone(back);
  const sendCard = confirmationCard(back, 'Email security report');
  await expect(sendCard).toBeVisible();
  await expect(sendCard.getByText('Medium risk')).toBeVisible();
  await expect(sendCard.getByRole('table', { name: 'What it applies to' })).toContainText(
    adminEmail,
  );
  await expect(sendCard.getByRole('list', { name: 'Warnings' })).toContainText(
    'Emails cannot be recalled after sending.',
  );
  await expectNoSeriousA11yViolations(page, 'report email confirmation (medium risk)');
  expect(await writerDb().aiChatReportDelivery.count({ where: { reportId: stored.id } })).toBe(0);
  await sendCard.getByRole('button', { name: 'Confirm', exact: true }).click();
  await expect(sendCard.getByText('Done: the action was applied.')).toBeVisible({
    timeout: 30_000,
  });
  const delivery = await writerDb().aiChatReportDelivery.findFirstOrThrow({
    where: { reportId: stored.id },
    select: { status: true, recipientAddress: true },
  });
  expect(delivery.recipientAddress).toBe(adminEmail);
  expect(['queued', 'sent']).toContain(delivery.status);
  // The report card's email list follows (refreshed after the confirmation).
  const emails = reportCard(back).getByRole('list', { name: 'Emails of this report' });
  await expect(async () => {
    await reportCard(back).getByRole('button', { name: 'Refresh' }).click();
    await expect(emails.getByRole('listitem').first()).toContainText(adminEmail, {
      timeout: 3_000,
    });
  }).toPass({ timeout: 30_000 });
  await expect(emails.getByRole('listitem').first()).toContainText(/Queued|Sent/);

  // (d) An outside address: refused by the recipient guard (I17), no confirmation, no delivery.
  const afterSend = await newestConfirmationId();
  expect(afterSend).not.toBe(before);
  await ask(page, back, 'send the report to someone@outside.test');
  await expectTurnDone(back);
  const denied = back
    .getByRole('region', { name: /^Result: / })
    .filter({ hasText: 'Not allowed in chat' })
    .last();
  await expect(denied).toBeVisible();
  await expect(denied.getByRole('button')).toHaveCount(0);
  await expect(denied).not.toContainText('denied_guard');
  expect(await newestConfirmationId()).toBe(afterSend);
  expect(await writerDb().aiChatReportDelivery.count({ where: { reportId: stored.id } })).toBe(1);
  await expectNoSeriousA11yViolations(page, 'report email to an outside address refused');
});

test.describe('phone viewport (reports)', () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test('the report card and its frame fit the full-screen sheet', async ({ page }) => {
    await signIn(page, 'deltaAdmin');
    await expectLanded(page);
    await page.getByRole('button', { name: 'Ask AI', exact: true }).click();
    const sheet = panel(page);
    await expect(sheet).toBeVisible();
    await ask(page, sheet, 'security report for the last 24 hours');
    await expectTurnDone(sheet);
    const card = reportCard(sheet);
    await expect(card).toBeVisible({ timeout: 30_000 });
    await expectReportFrame(card);
    const iframe = card.locator('iframe[title="Security report"]');
    const frameBox = await iframe.boundingBox();
    // 420 px below `md`, inside the card.
    expect(Math.round(frameBox?.height ?? 0)).toBe(420);
    const box = await card.boundingBox();
    expect((box?.x ?? -1) >= 0 && (box?.x ?? 0) + (box?.width ?? 999) <= 390).toBe(true);
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
    );
    expect(overflow).toBeLessThanOrEqual(1);
    const download = card.getByRole('button', { name: 'Download HTML' });
    await download.scrollIntoViewIfNeeded();
    await expect(download).toBeInViewport();
    await expectNoSeriousA11yViolations(page, 'report card on a phone');
  });
});

// ---------------------------------------------------------------------------------------------
// Step AI-4: security operations through chat (design 32 §9 item 6, D3, D10, D12; I18, I20).
// ---------------------------------------------------------------------------------------------

const FOUR_EYES =
  'This response needs a different person to decide it. The person who requested a response, or who created the API key that requested it, can never approve or reject it';
const RESPONSE_REASON = 'E2E outbound burst from the account after a phishing report';

/** The newest ATO response of delta (writer). */
async function newestDeltaResponse() {
  return writerDb().atoResponseAction.findFirst({
    where: { organizationId: await deltaOrganizationId() },
    select: {
      publicId: true,
      actionType: true,
      status: true,
      requestedByType: true,
      requestedById: true,
      approvedByUserId: true,
    },
    orderBy: { id: 'desc' },
  });
}

async function deltaUserIds(email: string): Promise<{ id: bigint; publicId: string }> {
  return writerDb().user.findFirstOrThrow({
    where: { organizationId: await deltaOrganizationId(), email },
    select: { id: true, publicId: true },
  });
}

/** Opens a new conversation on `/assistant` as `key` and returns the conversation region. */
async function openAssistantPage(
  page: Page,
  key: 'deltaResponderA' | 'deltaResponderB' | 'deltaCompliance',
) {
  await signIn(page, key, { next: '/assistant' });
  await expect(page.getByRole('heading', { level: 1, name: 'AI assistant' })).toBeVisible();
  await page
    .getByRole('complementary', { name: 'Conversation history' })
    .getByRole('button', { name: 'New conversation' })
    .click();
  return page.getByRole('region', { name: 'Conversation' });
}

/** Fills password and authenticator code of a high-risk card and confirms it. */
async function confirmWithReauth(
  card: ReturnType<Page['locator']>,
  key: 'deltaResponderA' | 'deltaResponderB' | 'deltaCompliance',
): Promise<void> {
  const identity = card.getByRole('group', { name: 'Confirm your identity' });
  await identity.getByLabel('Your password (required)', { exact: true }).fill(user(key).password);
  await identity
    .getByLabel('Authenticator code (required)', { exact: true })
    .fill(await nextTotp(key));
  await card.getByRole('button', { name: 'Confirm', exact: true }).click();
}

test('security operations: four eyes for an ATO response in chat, and a DLP dictionary', async ({
  page,
  browser,
}) => {
  test.setTimeout(420_000);
  const target = readState().assistant.delta.ato;
  const tag = Date.now().toString(36);
  const dictionary = `E2E terms ${tag}`;
  const responderA = user('deltaResponderA');
  const responderB = user('deltaResponderB');
  expect(
    await writerDb().atoResponseAction.count({
      where: { organizationId: await deltaOrganizationId(), status: 'pending_approval' },
    }),
    'a fresh seed (no pending response in delta)',
  ).toBe(0);

  // (a) Analyst A requests a gateway response through chat: a high-risk card with the approval
  // line; after the password and the authenticator code the response waits for approval.
  const conversationA = await openAssistantPage(page, 'deltaResponderA');
  await ask(
    page,
    conversationA,
    `/tool ato_responses_request ${JSON.stringify({
      incidentId: target.incidentId,
      body: { actionType: 'restrict_smtp_sending', durationMinutes: 60, reason: RESPONSE_REASON },
    })}`,
  );
  await expectTurnDone(conversationA);
  const requestCard = confirmationCard(conversationA, 'Request ATO response');
  await expect(requestCard).toBeVisible();
  await expect(requestCard.getByText('High risk')).toBeVisible();
  await expect(requestCard.getByRole('list', { name: 'Impact' })).toContainText(
    "others wait for another responder's approval (you cannot approve your own request)",
  );
  await expectNoSeriousA11yViolations(page, 'ATO response request card (high risk)');
  expect(await newestDeltaResponse()).toBeNull();
  await confirmWithReauth(requestCard, 'deltaResponderA');
  await expect(
    requestCard.getByText(
      'Requested. If this action needs approval, another responder must approve it before it runs (you cannot approve your own request).',
    ),
  ).toBeVisible({ timeout: 30_000 });
  const requested = await newestDeltaResponse();
  expect(requested).toMatchObject({
    actionType: 'restrict_smtp_sending',
    status: 'pending_approval',
    requestedByType: 'user',
    requestedById: (await deltaUserIds(responderA.email)).publicId,
    approvedByUserId: null,
  });
  await expectNoSeriousA11yViolations(page, 'ATO response requested (outcome)');

  // (b) The requester asks to approve it: the four-eyes guard refuses before anything is stored
  // (I18): a "Not allowed in chat" card with the Responses link, no confirmation card.
  const beforeSelf = await newestConfirmationId();
  await ask(page, conversationA, 'approve the pending response');
  await expectTurnDone(conversationA);
  const denied = conversationA
    .getByRole('region', { name: /^Result: / })
    .filter({ hasText: 'Not allowed in chat' })
    .last();
  await expect(denied).toBeVisible();
  await expect(denied).toContainText(FOUR_EYES);
  await expect(denied).not.toContainText('denied_guard');
  await expect(denied.getByRole('button')).toHaveCount(0);
  await expect(denied.getByRole('link', { name: 'Open Responses in the portal' })).toHaveAttribute(
    'href',
    '/ato/responses',
  );
  await expect(confirmationCard(conversationA, 'Approve ATO response')).toHaveCount(0);
  expect(await newestConfirmationId()).toBe(beforeSelf);
  const refused = await writerDb().aiChatToolExecution.findFirstOrThrow({
    where: { organizationId: await deltaOrganizationId(), toolName: 'ato_responses_approve' },
    select: { decision: true, httpStatus: true },
    orderBy: { id: 'desc' },
  });
  expect(refused).toEqual({ decision: 'denied_guard', httpStatus: null });
  expect((await newestDeltaResponse())?.status).toBe('pending_approval');
  await expectNoSeriousA11yViolations(page, 'four-eyes refusal (not allowed in chat)');

  // (c) Analyst B (another responder, MFA session) approves it through chat: a high-risk card
  // with the action, the account, the requester type and the reason; password + code; it runs.
  const contextB = await browser.newContext();
  try {
    const pageB = await contextB.newPage();
    const conversationB = await openAssistantPage(pageB, 'deltaResponderB');
    await ask(pageB, conversationB, 'approve the pending response');
    await expectTurnDone(conversationB);
    const approveCard = confirmationCard(conversationB, 'Approve ATO response');
    await expect(approveCard).toBeVisible();
    await expect(approveCard.getByText('High risk')).toBeVisible();
    const applies = approveCard.getByRole('table', { name: 'What it applies to' });
    await expect(applies).toContainText('block outbound SMTP sending');
    await expect(applies).toContainText(target.accountId);
    await expect(applies).toContainText('Requested by');
    await expect(applies).toContainText('user');
    await expect(applies).toContainText(RESPONSE_REASON);
    await expect(approveCard.getByRole('list', { name: 'Warnings' })).toContainText(
      'Approving runs the action on the account.',
    );
    await expectNoSeriousA11yViolations(pageB, 'ATO response approval card (high risk)');
    expect((await newestDeltaResponse())?.status).toBe('pending_approval');
    await confirmWithReauth(approveCard, 'deltaResponderB');
    await expect(approveCard.getByText('Done: the action was applied.')).toBeVisible({
      timeout: 30_000,
    });
    const approved = await newestDeltaResponse();
    expect(approved?.publicId).toBe(requested?.publicId);
    expect(approved?.approvedByUserId).toBe((await deltaUserIds(responderB.email)).id);
    expect(['approved', 'executing', 'succeeded']).toContain(approved?.status);
    const confirmation = await writerDb().aiChatActionConfirmation.findUniqueOrThrow({
      where: { id: (await newestConfirmationId())! },
      select: { status: true, reauthUsed: true, toolName: true, risk: true },
    });
    expect(confirmation).toEqual({
      status: 'executed',
      reauthUsed: true,
      toolName: 'ato_responses_approve',
      risk: 'high',
    });
    const responses = await contextB.newPage();
    await expectListed(
      responses,
      '/ato/responses?tab=all',
      'Responses',
      'Restrict SMTP sending',
      'Succeeded',
    );
    await expectNoSeriousA11yViolations(responses, 'Responses page after the chat approval');
    await responses.close();

    // (d) A DLP dictionary from the fake's plan: a low-risk card; Confirm creates it.
    await pageB.bringToFront();
    await ask(pageB, conversationB, `add dlp dictionary "${dictionary}" with terms alpha, beta`);
    await expectTurnDone(conversationB);
    const dictionaryCard = confirmationCard(conversationB, 'Create DLP dictionary');
    await expect(dictionaryCard).toBeVisible();
    await expect(dictionaryCard.getByText('Low risk')).toBeVisible();
    await expect(dictionaryCard.getByRole('table', { name: 'Changes' })).toContainText(
      '2 terms: alpha, beta',
    );
    await expect(dictionaryCard.getByRole('group', { name: 'Confirm your identity' })).toHaveCount(
      0,
    );
    await expectNoSeriousA11yViolations(pageB, 'DLP dictionary card (low risk)');
    expect(
      await writerDb().dlpKeywordDictionary.count({
        where: { organizationId: await deltaOrganizationId(), name: dictionary },
      }),
    ).toBe(0);
    await dictionaryCard.getByRole('button', { name: 'Confirm', exact: true }).click();
    await expect(dictionaryCard.getByText('Done: the action was applied.')).toBeVisible({
      timeout: 30_000,
    });
    const dlp = await contextB.newPage();
    await expect(async () => {
      await dlp.goto('/policies?tab=dlp');
      await dlp
        .getByRole('tablist', { name: 'DLP sections' })
        .getByRole('tab', { name: 'Dictionaries', exact: true })
        .click();
      const section = dlp.getByRole('tabpanel', { name: 'Dictionaries', exact: true });
      await expect(section.getByRole('row').filter({ hasText: dictionary })).toBeVisible({
        timeout: 3_000,
      });
    }).toPass({ timeout: 45_000 });
    await dlp.close();
  } finally {
    await contextB.close();
  }
});

test.describe('phone viewport (security operations)', () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test('a DLP dictionary card fits the full-screen sheet', async ({ page }) => {
    const dictionary = `E2E phone terms ${Date.now().toString(36)}`;
    await signIn(page, 'deltaResponderA');
    await expectLanded(page);
    await page.getByRole('button', { name: 'Ask AI', exact: true }).click();
    const sheet = panel(page);
    await expect(sheet).toBeVisible();
    await ask(page, sheet, `add dlp dictionary "${dictionary}" with terms alpha, beta`);
    await expectTurnDone(sheet);
    const card = confirmationCard(sheet, 'Create DLP dictionary');
    await expect(card).toBeVisible();
    await expect(card.getByText('Low risk')).toBeVisible();
    const confirmButton = card.getByRole('button', { name: 'Confirm', exact: true });
    const cancelButton = card.getByRole('button', { name: 'Cancel', exact: true });
    await confirmButton.scrollIntoViewIfNeeded();
    await expect(confirmButton).toBeInViewport();
    await expect(cancelButton).toBeInViewport();
    const box = await card.boundingBox();
    expect((box?.x ?? -1) >= 0 && (box?.x ?? 0) + (box?.width ?? 999) <= 390).toBe(true);
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
    );
    expect(overflow).toBeLessThanOrEqual(1);
    await expectNoSeriousA11yViolations(page, 'DLP dictionary card on a phone');
    await cancelButton.click();
    await expect(card.getByText('Cancelled. Nothing changed.')).toBeVisible();
    expect(
      await writerDb().dlpKeywordDictionary.count({
        where: { organizationId: await deltaOrganizationId(), name: dictionary },
      }),
    ).toBe(0);
  });
});

// ---------------------------------------------------------------------------------------------
// Step AI-5: compliance through chat (design 33 §9 item 6, D3, D11; I22). Delta's compliance
// officer (MFA) on the rows prepareAssistantCompliance seeded through the api.
// ---------------------------------------------------------------------------------------------

const SHORTENING_WARNING =
  'Shortens retention: mail captured from now on that this policy matches is kept for fewer days (records already archived keep their stored dates).';

/** Delta's retention policy by name (writer). */
async function deltaRetentionPolicy(name: string) {
  return writerDb().archiveRetentionPolicy.findFirstOrThrow({
    where: { organizationId: await deltaOrganizationId(), name, deletedAt: null },
    select: { retentionDays: true, onExpiry: true, priority: true, rowVersion: true },
  });
}

/** Delta's eDiscovery cases with this name (writer). */
async function deltaCaseCount(name: string): Promise<number> {
  return writerDb().ediscoveryCase.count({
    where: { organizationId: await deltaOrganizationId(), name },
  });
}

test('compliance: shorten a retention policy with re-authentication, create an eDiscovery case; a legal-hold release stays in the portal', async ({
  page,
}) => {
  test.setTimeout(300_000);
  const seeded = readState().assistant.delta.compliance;
  const policy = seeded.retentionPolicy;
  const caseName = `E2E chat case ${Date.now().toString(36)}`;
  expect(await deltaRetentionPolicy(policy.name), 'a fresh seed (365 days)').toMatchObject({
    retentionDays: 365,
    onExpiry: 'delete',
    priority: 100,
  });

  // (a) Shortening a retention policy escalates to high (read-relative `below`): the card shows
  // the days before → after and the shortening warning, and runs after password + code.
  const conversation = await openAssistantPage(page, 'deltaCompliance');
  await ask(page, conversation, `set retention policy "${policy.name}" to 30 days`);
  await expectTurnDone(conversation);
  const retentionCard = confirmationCard(conversation, 'Change retention policy');
  await expect(retentionCard).toBeVisible();
  await expect(retentionCard.getByText('High risk')).toBeVisible();
  const days = retentionCard
    .getByRole('table', { name: 'Changes' })
    .getByRole('row')
    .filter({ has: page.getByRole('rowheader', { name: 'Retention (days)', exact: true }) });
  await expect(days).toContainText('365');
  await expect(days).toContainText('30');
  await expect(retentionCard.getByRole('list', { name: 'Warnings' })).toContainText(
    SHORTENING_WARNING,
  );
  await expect(retentionCard.getByRole('group', { name: 'Confirm your identity' })).toBeVisible();
  await expectNoSeriousA11yViolations(page, 'retention shortening card (high risk)');
  expect((await deltaRetentionPolicy(policy.name)).retentionDays).toBe(365);
  await confirmWithReauth(retentionCard, 'deltaCompliance');
  await expect(retentionCard.getByText('Done: the action was applied.')).toBeVisible({
    timeout: 30_000,
  });
  expect(await deltaRetentionPolicy(policy.name)).toMatchObject({
    retentionDays: 30,
    onExpiry: 'delete',
    priority: 100,
  });
  const retentionConfirmation = await writerDb().aiChatActionConfirmation.findUniqueOrThrow({
    where: { id: (await newestConfirmationId())! },
    select: { status: true, reauthUsed: true, toolName: true, risk: true },
  });
  expect(retentionConfirmation).toEqual({
    status: 'executed',
    reauthUsed: true,
    toolName: 'archive_retention_update',
    risk: 'high',
  });
  await expectNoSeriousA11yViolations(page, 'retention shortened (outcome)');
  const retention = await page.context().newPage();
  await expectListed(retention, '/archive/retention', 'Retention and lock', policy.name, '30 days');
  await expectNoSeriousA11yViolations(retention, 'Retention page after the chat change');
  await retention.close();

  // (b) An eDiscovery case from the fake's plan: a low-risk card; Confirm creates it.
  await page.bringToFront();
  await ask(page, conversation, `create ediscovery case "${caseName}"`);
  await expectTurnDone(conversation);
  const caseCard = confirmationCard(conversation, 'Create eDiscovery case');
  await expect(caseCard).toBeVisible();
  await expect(caseCard.getByText('Low risk')).toBeVisible();
  await expect(caseCard.getByRole('table', { name: 'What it applies to' })).toContainText(caseName);
  await expect(caseCard.getByRole('group', { name: 'Confirm your identity' })).toHaveCount(0);
  await expectNoSeriousA11yViolations(page, 'eDiscovery case card (low risk)');
  expect(await deltaCaseCount(caseName)).toBe(0);
  await caseCard.getByRole('button', { name: 'Confirm', exact: true }).click();
  await expect(caseCard.getByText('Done: the action was applied.')).toBeVisible({
    timeout: 30_000,
  });
  expect(await deltaCaseCount(caseName)).toBe(1);
  const cases = await page.context().newPage();
  await expectListed(cases, '/ediscovery', 'eDiscovery', caseName, 'Open');
  await expectNoSeriousA11yViolations(cases, 'eDiscovery page after the chat case');
  await cases.close();

  // (c) Releasing a legal hold is critical (portal only, I22): the release call is refused as
  // "Not available in chat" with the Legal holds link; nothing is stored, the hold stays active.
  await page.bringToFront();
  const beforeRelease = await newestConfirmationId();
  await ask(page, conversation, 'release the legal hold');
  await expectTurnDone(conversation);
  const notAvailable = conversation
    .getByRole('region', { name: /^Result: / })
    .filter({ hasText: 'Not available in chat' })
    .last();
  await expect(notAvailable).toBeVisible();
  await expect(notAvailable).not.toContainText('denied_not_applicable');
  await expect(notAvailable.getByRole('button')).toHaveCount(0);
  await expect(
    notAvailable.getByRole('link', { name: 'Open Legal holds in the portal' }),
  ).toHaveAttribute('href', '/legal-holds');
  expect(await newestConfirmationId()).toBe(beforeRelease);
  const refused = await writerDb().aiChatToolExecution.findFirstOrThrow({
    where: { organizationId: await deltaOrganizationId(), toolName: 'legal_holds_release' },
    select: { decision: true, httpStatus: true },
    orderBy: { id: 'desc' },
  });
  expect(refused).toEqual({ decision: 'denied_not_applicable', httpStatus: null });
  const hold = await writerDb().archiveLegalHold.findUniqueOrThrow({
    where: { publicId: seeded.hold.id },
    select: { status: true, releasedAt: true },
  });
  expect(hold).toEqual({ status: 'active', releasedAt: null });
  await expectNoSeriousA11yViolations(page, 'legal-hold release refused (not available in chat)');
});

test.describe('phone viewport (compliance)', () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test('an eDiscovery case card fits the full-screen sheet', async ({ page }) => {
    const caseName = `E2E phone case ${Date.now().toString(36)}`;
    await signIn(page, 'deltaCompliance');
    await expectLanded(page);
    await page.getByRole('button', { name: 'Ask AI', exact: true }).click();
    const sheet = panel(page);
    await expect(sheet).toBeVisible();
    await ask(page, sheet, `create ediscovery case "${caseName}"`);
    await expectTurnDone(sheet);
    const card = confirmationCard(sheet, 'Create eDiscovery case');
    await expect(card).toBeVisible();
    await expect(card.getByText('Low risk')).toBeVisible();
    const confirmButton = card.getByRole('button', { name: 'Confirm', exact: true });
    const cancelButton = card.getByRole('button', { name: 'Cancel', exact: true });
    await confirmButton.scrollIntoViewIfNeeded();
    await expect(confirmButton).toBeInViewport();
    await expect(cancelButton).toBeInViewport();
    const box = await card.boundingBox();
    expect((box?.x ?? -1) >= 0 && (box?.x ?? 0) + (box?.width ?? 999) <= 390).toBe(true);
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
    );
    expect(overflow).toBeLessThanOrEqual(1);
    await expectNoSeriousA11yViolations(page, 'eDiscovery case card on a phone');
    await cancelButton.click();
    await expect(card.getByText('Cancelled. Nothing changed.')).toBeVisible();
    expect(await deltaCaseCount(caseName)).toBe(0);
  });
});
