import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { HttpResponse } from 'msw';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { AppShell } from '@/features/shell/app-shell';
import {
  apiErrorJson,
  currentTestUrl,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  mockApi,
  noContentResponse,
  okJson,
  renderWithProviders,
} from '@/test';
import { makeMe } from '@/test/fixtures';
import { AssistantProvider } from './assistant-context';
import { isPanelShortcut } from './assistant-panel';
import { AssistantPage } from './assistant-page';
import { Composer } from './composer';
import { exchangesOf } from './conversation-view';
import { suggestedPrompts } from './model';
import {
  CONVERSATION,
  CONVERSATION_ID,
  CONVERSATION_ID_2,
  EXECUTION_ID,
  GUARD_TOOL_TITLE,
  MESSAGE_ID,
  SELF_GUARD_MESSAGE,
  ATO_FOUR_EYES_MESSAGE,
  STATUS_AVAILABLE,
  TABLE_CARD,
  TOOLS,
  TURN_ID,
  completedTurnFrames,
  deniedGuardExecution,
  execution,
  sseFrame,
  statusUnavailable,
  storedExchange,
  streamOf,
} from './test-data';
import type { StoredMessage } from './types';

const page = <p>page content</p>;

function sse(frames: readonly string[], options: { failAfter?: boolean } = {}) {
  return new HttpResponse(streamOf(frames, options), {
    headers: { 'content-type': 'text/event-stream' },
  });
}

/** A stream that sends `turn.started` and then stays open until the request is aborted. */
function hangingStream() {
  return new HttpResponse(
    new ReadableStream({
      start(controller) {
        controller.enqueue(
          new TextEncoder().encode(
            sseFrame('turn.started', { turnId: TURN_ID, conversationId: CONVERSATION_ID, seq: 1 }),
          ),
        );
      },
    }),
    { headers: { 'content-type': 'text/event-stream' } },
  );
}

describe('"Ask AI" entry points (D14 gating)', () => {
  beforeEach(() => {
    mockApi({
      AtoOverviewController_attention_v1: () =>
        okJson({ criticalIncidents: 0, pendingApprovals: 0 }),
      AssistantToolsController_list_v1: () => okJson(TOOLS),
    });
  });

  it('shows the button and the navigation item, opens a focus-trapped panel and toggles with Ctrl+J', async () => {
    mockApi({ AssistantStatusController_get_v1: () => okJson(STATUS_AVAILABLE) });
    const { user } = renderWithProviders(<AppShell>{page}</AppShell>, {
      role: 'security_analyst',
      route: '/dashboard',
    });
    const nav = screen.getByRole('navigation', { name: 'Main' });
    expect(within(nav).getByRole('link', { name: 'AI assistant' })).toHaveAttribute(
      'href',
      '/assistant',
    );
    const button = await screen.findByRole('button', { name: 'Ask AI' });
    await user.click(button);
    const dialog = await screen.findByRole('dialog', { name: 'AI assistant' });
    expect(
      within(dialog).getByRole('textbox', { name: 'Message to the AI assistant' }),
    ).toBeInTheDocument();
    expect(
      await within(dialog).findByRole('list', { name: 'Suggested questions' }),
    ).toBeInTheDocument();
    expect(within(dialog).getByRole('link', { name: 'Full page' })).toHaveAttribute(
      'href',
      '/assistant',
    );
    await expectNoAxeViolations(dialog);
    await user.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    await waitFor(() => expect(button).toHaveFocus());

    fireEvent.keyDown(window, { key: 'j', ctrlKey: true });
    expect(await screen.findByRole('dialog', { name: 'AI assistant' })).toBeInTheDocument();
    fireEvent.keyDown(window, { key: 'j', ctrlKey: true });
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(isPanelShortcut(new KeyboardEvent('keydown', { key: 'J', metaKey: true }))).toBe(true);
    expect(
      isPanelShortcut(new KeyboardEvent('keydown', { key: 'j', ctrlKey: true, shiftKey: true })),
    ).toBe(false);
  });

  it('reopens the panel on the same conversation after a reload, and falls back when it is gone', async () => {
    const me = makeMe({ role: 'security_analyst' });
    const key = `eg:assistant.lastConversation.${me.user.id}:${me.organization.id}`;
    window.localStorage.setItem(key, JSON.stringify(CONVERSATION_ID));
    window.sessionStorage.setItem('eg:assistant.panelOpen', '1');
    const messages = vi.fn(() => okJson({ data: storedExchange(), nextCursor: null }));
    mockApi({
      AssistantStatusController_get_v1: () => okJson(STATUS_AVAILABLE),
      AssistantToolsController_list_v1: () => okJson(TOOLS),
      AssistantMessagesController_list_v1: messages,
    });
    const first = renderWithProviders(<AppShell>{page}</AppShell>, { me, route: '/dashboard' });
    expect(await screen.findByRole('dialog', { name: 'AI assistant' })).toBeInTheDocument();
    await waitFor(() => expect(messages).toHaveBeenCalled());
    first.unmount();

    // The remembered conversation was deleted meanwhile: a new chat, and the key is cleared.
    mockApi({
      AssistantStatusController_get_v1: () => okJson(STATUS_AVAILABLE),
      AssistantToolsController_list_v1: () => okJson(TOOLS),
      AssistantMessagesController_list_v1: () =>
        apiErrorJson(404, 'assistant_conversation_not_found', 'Conversation not found'),
    });
    renderWithProviders(<AppShell>{page}</AppShell>, { me, route: '/dashboard' });
    const dialog = await screen.findByRole('dialog', { name: 'AI assistant' });
    expect(
      await within(dialog).findByRole('list', { name: 'Suggested questions' }),
    ).toBeInTheDocument();
    await waitFor(() => expect(window.localStorage.getItem(key)).toBe('null'));
  });

  it('shows administrators why it is unavailable, with a link to Settings', async () => {
    mockApi({
      AssistantStatusController_get_v1: () => okJson(statusUnavailable('tenant_disabled')),
    });
    const { user } = renderWithProviders(<AppShell>{page}</AppShell>, {
      role: 'organization_admin',
      route: '/dashboard',
    });
    await user.click(await screen.findByRole('button', { name: 'Ask AI (unavailable)' }));
    const dialog = await screen.findByRole('dialog', { name: 'AI assistant' });
    expect(
      within(dialog).getByRole('heading', {
        name: 'The AI assistant is turned off for your organization',
      }),
    ).toBeInTheDocument();
    expect(
      within(dialog).getByRole('link', { name: 'Open Settings → AI assistant' }),
    ).toHaveAttribute('href', '/settings?tab=assistant');
    expect(within(dialog).queryByRole('textbox')).not.toBeInTheDocument();
  });

  it('explains a platform switch without a Settings link', async () => {
    mockApi({
      AssistantStatusController_get_v1: () => okJson(statusUnavailable('platform_disabled')),
    });
    const { user } = renderWithProviders(<AppShell>{page}</AppShell>, {
      role: 'organization_admin',
      route: '/dashboard',
    });
    await user.click(await screen.findByRole('button', { name: 'Ask AI (unavailable)' }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText(/not enabled on this platform/)).toBeInTheDocument();
    expect(within(dialog).queryByRole('link', { name: /Settings/ })).not.toBeInTheDocument();
  });

  it('hides the button from users who cannot configure it while it is unavailable', async () => {
    const status = vi.fn(() => okJson(statusUnavailable('feature_disabled')));
    mockApi({ AssistantStatusController_get_v1: status });
    renderWithProviders(<AppShell>{page}</AppShell>, {
      role: 'read_only_user',
      route: '/dashboard',
    });
    await waitFor(() => expect(status).toHaveBeenCalled());
    await act(() => new Promise((resolve) => setTimeout(resolve, 20)));
    expect(screen.queryByRole('button', { name: /Ask AI/ })).not.toBeInTheDocument();
    // The navigation item follows the permission; the page explains the reason.
    expect(
      within(screen.getByRole('navigation', { name: 'Main' })).getByRole('link', {
        name: 'AI assistant',
      }),
    ).toBeInTheDocument();
  });

  it('shows nothing and asks nothing without assistant:use', async () => {
    const status = vi.fn(() => okJson(STATUS_AVAILABLE));
    mockApi({ AssistantStatusController_get_v1: status });
    renderWithProviders(<AppShell>{page}</AppShell>, { role: 'mailbox_user', route: '/settings' });
    await act(() => new Promise((resolve) => setTimeout(resolve, 20)));
    expect(status).not.toHaveBeenCalled();
    expect(screen.queryByRole('button', { name: /Ask AI/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'AI assistant' })).not.toBeInTheDocument();
  });
});

function renderPage(route = '/assistant') {
  return renderWithProviders(
    <AssistantProvider>
      <AssistantPage />
    </AssistantProvider>,
    { role: 'security_analyst', route },
  );
}

describe('/assistant conversation', () => {
  beforeEach(() => {
    mockApi({
      AssistantStatusController_get_v1: () => okJson(STATUS_AVAILABLE),
      AssistantToolsController_list_v1: () => okJson(TOOLS),
      AssistantConversationsController_list_v1: () =>
        okJson({ data: [CONVERSATION], nextCursor: null }),
    });
  });

  it('asks a suggested question: creates the conversation, streams text, tools and a table card', async () => {
    const created: unknown[] = [];
    const turns: unknown[] = [];
    let stored: StoredMessage[] = [];
    mockApi({
      AssistantConversationsController_create_v1: ({ body }) => {
        created.push(body);
        return okJson({ ...CONVERSATION, turnCount: 0, lastTurnAt: null }, 201);
      },
      AssistantTurnsController_create_v1: ({ body }) => {
        turns.push(body);
        stored = storedExchange({
          question: 'Which policies are active right now?',
          executions: [execution(TABLE_CARD)],
        });
        return sse(completedTurnFrames());
      },
      AssistantMessagesController_list_v1: () => okJson({ data: stored, nextCursor: null }),
    });
    const { user, container } = renderPage();
    const suggestions = await screen.findByRole('list', { name: 'Suggested questions' });
    expect(
      within(suggestions)
        .getAllByRole('button')
        .map((b) => b.textContent),
    ).toEqual([
      'PoliciesWhich policies are active right now?',
      'QuarantineShow the quarantined messages of the last 24 hours.',
      'ReportsSummarize mail traffic and threats of the last 7 days.',
    ]);
    await expectNoAxeViolations(container);
    await user.click(within(suggestions).getAllByRole('button')[0]!);

    await waitFor(() => expect(turns).toHaveLength(1));
    expect(created).toEqual([{ title: 'Which policies are active right now?' }]);
    expectRequestMatchesContract('AssistantConversationsController_create_v1', created[0]);
    expectRequestMatchesContract('AssistantTurnsController_create_v1', turns[0]);
    expect(turns[0]).toMatchObject({ message: 'Which policies are active right now?' });

    const conversation = screen.getByRole('region', { name: 'Conversation' });
    await waitFor(() => expect(conversation).toHaveTextContent('Two policies are active.'));
    expect(within(conversation).getByText('active', { selector: 'strong' })).toBeInTheDocument();
    const chips = screen.getByRole('list', { name: 'Tools the assistant used' });
    expect(within(chips).getByRole('listitem')).toHaveTextContent('Policies: succeeded');
    expect(screen.getByRole('table', { name: 'Policies' })).toBeInTheDocument();
    await waitFor(() =>
      expect(currentTestUrl()).toBe(`/assistant?conversation=${CONVERSATION_ID}`),
    );
    expect(screen.getByRole('button', { name: 'Send' })).toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('streams into a polite live region that is busy until the answer is complete', async () => {
    mockApi({
      AssistantConversationsController_create_v1: () => okJson(CONVERSATION, 201),
      AssistantTurnsController_create_v1: () => hangingStream(),
      AssistantTurnsController_cancel_v1: () => okJson({ turnId: TURN_ID, status: 'running' }, 202),
      AssistantMessagesController_list_v1: () =>
        okJson({ data: storedExchange({ answer: null, status: 'cancelled' }), nextCursor: null }),
    });
    const { user } = renderPage();
    await user.type(
      await screen.findByRole('textbox', { name: 'Message to the AI assistant' }),
      'Hello{Enter}',
    );
    const thinking = await screen.findByText('Thinking …');
    const live = thinking.closest('[aria-live]');
    expect(live).toHaveAttribute('aria-live', 'polite');
    expect(live).toHaveAttribute('aria-busy', 'true');
    expect(screen.queryByRole('button', { name: 'Send' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Stop the answer' }));
    await waitFor(() => expect(screen.getByRole('button', { name: 'Send' })).toBeInTheDocument());
    expect(await screen.findByText('Stopped.')).toBeInTheDocument();
  });

  it('cancels a running turn through the api and aborts the stream', async () => {
    const cancelled: string[] = [];
    mockApi({
      AssistantConversationsController_create_v1: () => okJson(CONVERSATION, 201),
      AssistantTurnsController_create_v1: () => hangingStream(),
      AssistantTurnsController_cancel_v1: ({ params }) => {
        cancelled.push(params.turnId ?? '');
        return okJson({ turnId: TURN_ID, status: 'running' }, 202);
      },
      AssistantMessagesController_list_v1: () =>
        okJson({
          data: storedExchange({ answer: 'Partial', status: 'cancelled' }),
          nextCursor: null,
        }),
    });
    const { user } = renderPage();
    await user.type(
      await screen.findByRole('textbox', { name: 'Message to the AI assistant' }),
      'Hello{Enter}',
    );
    await user.click(await screen.findByRole('button', { name: 'Stop the answer' }));
    await waitFor(() => expect(cancelled).toEqual([TURN_ID]));
    expect(await screen.findByText('Partial')).toBeInTheDocument();
  });

  it('shows a failed turn with Retry, which asks again with a new clientTurnId', async () => {
    const turns: { clientTurnId: string; message: string }[] = [];
    mockApi({
      AssistantConversationsController_create_v1: () => okJson(CONVERSATION, 201),
      AssistantTurnsController_create_v1: ({ body }) => {
        turns.push(body as { clientTurnId: string; message: string });
        if (turns.length === 1)
          return sse([
            sseFrame('turn.started', { turnId: TURN_ID, conversationId: CONVERSATION_ID, seq: 1 }),
            sseFrame('tool.started', { executionId: EXECUTION_ID, tool: 'x', title: 'Policies' }),
            sseFrame('turn.failed', {
              turnId: TURN_ID,
              code: 'assistant_turn_limit',
              message: 'Turn limit reached',
            }),
          ]);
        return sse(completedTurnFrames('All good now.'));
      },
      AssistantMessagesController_list_v1: () =>
        okJson({
          data:
            turns.length > 1
              ? storedExchange({ question: 'Show policies', answer: 'All good now.' })
              : [],
          nextCursor: null,
        }),
    });
    const { user } = renderPage();
    await user.type(
      await screen.findByRole('textbox', { name: 'Message to the AI assistant' }),
      'Show policies{Enter}',
    );
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('more steps or time than one turn allows');
    expect(
      within(screen.getByRole('list', { name: 'Tools the assistant used' })).getByRole('listitem'),
    ).toHaveTextContent('Policies: failed');
    await user.click(within(alert).getByRole('button', { name: 'Retry' }));
    await waitFor(() => expect(turns).toHaveLength(2));
    expect(turns[1]?.message).toBe('Show policies');
    expect(turns[1]?.clientTurnId).not.toBe(turns[0]?.clientTurnId);
    expect(await screen.findByText('All good now.')).toBeInTheDocument();
  });

  it('explains a refused turn (rate limit) and keeps the question for Retry', async () => {
    mockApi({
      AssistantConversationsController_create_v1: () => okJson(CONVERSATION, 201),
      AssistantTurnsController_create_v1: () =>
        apiErrorJson(429, 'rate_limited', 'Too many requests', {
          headers: { 'retry-after': '30' },
        }),
    });
    const { user } = renderPage();
    await user.type(
      await screen.findByRole('textbox', { name: 'Message to the AI assistant' }),
      'Again{Enter}',
    );
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('too many questions');
    expect(alert).toHaveTextContent('Try again in 30 s.');
    expect(within(alert).getByRole('button', { name: 'Retry' })).toBeInTheDocument();
    expect(screen.getByText('Again')).toBeInTheDocument();
  });

  it('opens the conversation of the URL and shows stored results and a stored failure', async () => {
    mockApi({
      AssistantMessagesController_list_v1: ({ params }) => {
        expect(params.conversationId).toBe(CONVERSATION_ID);
        return okJson({
          data: storedExchange({
            executions: [
              execution(TABLE_CARD),
              execution(null, {
                id: '01930000-0000-7000-8000-00000000e399',
                decision: 'denied_permission',
                status: 'refused',
                errorCode: 'forbidden',
              }),
            ],
          }),
          nextCursor: null,
        });
      },
    });
    const { container } = renderPage(`/assistant?conversation=${CONVERSATION_ID}`);
    expect(await screen.findByRole('table', { name: 'Policies' })).toBeInTheDocument();
    expect(screen.getByText('You do not have the permission this needs')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Load more' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^Policy review/ })).toHaveAttribute(
      'aria-current',
      'true',
    );
    await expectNoAxeViolations(container);
  });

  it('shows the guard message of a stored denied_guard execution, not its code (D12)', async () => {
    mockApi({
      AssistantMessagesController_list_v1: () =>
        okJson({
          data: storedExchange({
            answer: 'I cannot do that here.',
            executions: [deniedGuardExecution()],
          }),
          nextCursor: null,
        }),
    });
    renderPage(`/assistant?conversation=${CONVERSATION_ID}`);
    expect(await screen.findByText(SELF_GUARD_MESSAGE)).toBeInTheDocument();
    expect(screen.getAllByText(GUARD_TOOL_TITLE).length).toBeGreaterThan(0);
    expect(screen.queryByText('denied_guard')).not.toBeInTheDocument();
    expect(screen.queryByText('users_replace_roles')).not.toBeInTheDocument();
  });

  it('links a stored four-eyes refusal of an ATO approval to the Responses page (step AI-4)', async () => {
    mockApi({
      AssistantMessagesController_list_v1: () =>
        okJson({
          data: storedExchange({
            answer: 'Another responder must decide it.',
            executions: [
              {
                ...deniedGuardExecution(),
                tool: 'ato_responses_approve',
                title: 'Approve an ATO response',
                message: ATO_FOUR_EYES_MESSAGE,
              },
            ],
          }),
          nextCursor: null,
        }),
    });
    const { container } = renderPage(`/assistant?conversation=${CONVERSATION_ID}`);
    const card = await screen.findByRole('region', { name: 'Result: Approve an ATO response' });
    expect(within(card).getByText('Not allowed in chat')).toBeInTheDocument();
    expect(within(card).getByText(ATO_FOUR_EYES_MESSAGE)).toBeInTheDocument();
    expect(
      within(card).getByRole('link', { name: 'Open Responses in the portal' }),
    ).toHaveAttribute('href', '/ato/responses');
    expect(screen.queryByRole('button', { name: 'Confirm' })).not.toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('shows the unavailable reason on the page', async () => {
    mockApi({
      AssistantStatusController_get_v1: () => okJson(statusUnavailable('budget_exhausted')),
    });
    renderPage();
    expect(
      await screen.findByRole('heading', { name: 'The daily AI budget is used up' }),
    ).toBeInTheDocument();
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument();
  });
});

describe('conversation history', () => {
  beforeEach(() => {
    mockApi({
      AssistantStatusController_get_v1: () => okJson(STATUS_AVAILABLE),
      AssistantToolsController_list_v1: () => okJson(TOOLS),
      AssistantMessagesController_list_v1: () =>
        okJson({ data: storedExchange(), nextCursor: null }),
    });
  });

  const SECOND = { ...CONVERSATION, id: CONVERSATION_ID_2, title: 'Quarantine questions' };

  it('switches between active and archived; one character keeps the list (no content search)', async () => {
    const queries: Record<string, string | null>[] = [];
    let searches = 0;
    mockApi({
      AssistantConversationsController_list_v1: ({ url }) => {
        queries.push({ q: url.searchParams.get('q'), status: url.searchParams.get('status') });
        return okJson({ data: [CONVERSATION, SECOND], nextCursor: null });
      },
      AssistantSearchController_search_v1: () => {
        searches += 1;
        return okJson({ data: [], nextCursor: null });
      },
    });
    const { user } = renderPage();
    const history = await screen.findByRole('list', { name: 'Conversations' });
    expect(within(history).getAllByRole('listitem')).toHaveLength(2);
    await user.type(screen.getByRole('searchbox', { name: 'Search conversations' }), 'q');
    await user.click(screen.getByRole('switch', { name: 'Show archived' }));
    await waitFor(() => expect(queries.at(-1)).toEqual({ q: null, status: 'archived' }));
    expect(searches).toBe(0);
  });

  it('searches the text of the own conversations from two characters and opens a hit at its message (step AI-6 D4)', async () => {
    const searches: Record<string, string | null>[] = [];
    mockApi({
      AssistantConversationsController_list_v1: () =>
        okJson({ data: [CONVERSATION, SECOND], nextCursor: null }),
      AssistantSearchController_search_v1: ({ url }) => {
        searches.push({ q: url.searchParams.get('q'), limit: url.searchParams.get('limit') });
        return okJson({
          data: [
            {
              conversationId: CONVERSATION_ID,
              conversationTitle: 'Policy review',
              messageId: MESSAGE_ID,
              role: 'assistant',
              seq: 2,
              createdAt: '2026-11-20T09:00:03.000Z',
              snippet: '… Two policies are active and one quarantines executables …',
            },
          ],
          nextCursor: null,
        });
      },
    });
    const { user } = renderPage();
    await screen.findByRole('list', { name: 'Conversations' });
    await user.type(screen.getByRole('searchbox', { name: 'Search conversations' }), 'executables');
    const results = await screen.findByRole('list', { name: 'Search results' });
    expect(searches.at(-1)).toEqual({ q: 'executables', limit: '20' });
    expect(screen.queryByRole('list', { name: 'Conversations' })).not.toBeInTheDocument();
    expect(screen.queryByRole('switch', { name: 'Show archived' })).not.toBeInTheDocument();
    const hit = within(results).getByRole('button', { name: /Policy review/ });
    expect(hit).toHaveTextContent(
      'Assistant: … Two policies are active and one quarantines executables …',
    );
    await user.click(hit);
    // The conversation opens with the matching answer focused (and outlined).
    await waitFor(() =>
      expect(document.activeElement?.getAttribute('data-message-id')).toBe(MESSAGE_ID),
    );
    expect(currentTestUrl()).toContain(`conversation=${CONVERSATION_ID}`);
  });

  it('explains a search timeout (503 assistant_search_timeout)', async () => {
    mockApi({
      AssistantConversationsController_list_v1: () =>
        okJson({ data: [CONVERSATION], nextCursor: null }),
      AssistantSearchController_search_v1: () =>
        apiErrorJson(503, 'assistant_search_timeout', 'The search took too long'),
    });
    const { user } = renderPage();
    await screen.findByRole('list', { name: 'Conversations' });
    await user.type(screen.getByRole('searchbox', { name: 'Search conversations' }), 'ab');
    expect(await screen.findByText(/The search took too long/)).toBeInTheDocument();
  });

  it('renames, archives and clears a conversation (ConfirmDialog "Clear conversation")', async () => {
    const patches: unknown[] = [];
    const deletes: string[] = [];
    mockApi({
      AssistantConversationsController_list_v1: () =>
        okJson({ data: [CONVERSATION, SECOND], nextCursor: null }),
      AssistantConversationsController_update_v1: ({ body, params }) => {
        patches.push({ id: params.conversationId, body });
        return okJson({ ...CONVERSATION, ...(body as object) });
      },
      AssistantConversationsController_remove_v1: ({ params }) => {
        deletes.push(params.conversationId ?? '');
        return noContentResponse();
      },
    });
    const { user } = renderPage(`/assistant?conversation=${CONVERSATION_ID}`);
    await user.click(await screen.findByRole('button', { name: 'Actions for Policy review' }));
    await user.click(await screen.findByRole('menuitem', { name: 'Rename' }));
    const rename = await screen.findByRole('dialog', { name: 'Rename conversation' });
    const input = within(rename).getByRole('textbox', { name: 'Title' });
    await user.clear(input);
    await user.type(input, 'Policy audit');
    await user.click(within(rename).getByRole('button', { name: 'Save' }));
    await waitFor(() =>
      expect(patches).toEqual([{ id: CONVERSATION_ID, body: { title: 'Policy audit' } }]),
    );
    expectRequestMatchesContract('AssistantConversationsController_update_v1', {
      title: 'Policy audit',
    });

    await user.click(screen.getByRole('button', { name: 'Actions for Quarantine questions' }));
    await user.click(await screen.findByRole('menuitem', { name: 'Archive' }));
    await waitFor(() =>
      expect(patches.at(-1)).toEqual({ id: CONVERSATION_ID_2, body: { status: 'archived' } }),
    );

    await user.click(screen.getByRole('button', { name: 'Actions for Policy review' }));
    await user.click(await screen.findByRole('menuitem', { name: 'Clear conversation' }));
    const confirm = await screen.findByRole('alertdialog', { name: 'Clear conversation' });
    expect(confirm).toHaveTextContent('cannot be undone');
    await user.click(within(confirm).getByRole('button', { name: 'Clear conversation' }));
    await waitFor(() => expect(deletes).toEqual([CONVERSATION_ID]));
    // The open conversation was cleared: the page returns to a new conversation.
    await waitFor(() => expect(currentTestUrl()).toBe('/assistant'));
  });
});

describe('composer', () => {
  it('sends on Enter, adds a line on Shift+Enter, caps the length and is disabled while running', async () => {
    const onSend = vi.fn();
    const { user, rerender } = renderWithProviders(
      <Composer onSend={onSend} running={false} maxLength={20} />,
    );
    const box = screen.getByRole('textbox', { name: 'Message to the AI assistant' });
    await user.type(box, 'line one{Shift>}{Enter}{/Shift}two');
    expect(box).toHaveValue('line one\ntwo');
    expect(screen.getByText('12 / 20')).toBeInTheDocument();
    await user.type(box, '{Enter}');
    expect(onSend).toHaveBeenCalledWith('line one\ntwo');
    expect(box).toHaveValue('');
    await user.type(box, 'x'.repeat(30));
    expect(box).toHaveValue('x'.repeat(20));
    rerender(<Composer onSend={onSend} running maxLength={20} />);
    await user.type(box, '{Enter}');
    expect(onSend).toHaveBeenCalledTimes(1);
    expect(screen.getByRole('button', { name: 'Stop the answer' })).toBeInTheDocument();
  });
});

describe('model helpers', () => {
  it('derives suggested prompts from the tool modules', () => {
    expect(suggestedPrompts(['incidents', 'journaling', 'unknown']).map((p) => p.module)).toEqual([
      'incidents',
      'journaling',
    ]);
    expect(suggestedPrompts([])).toEqual([]);
  });

  it('groups stored messages by turn and never repeats an execution', () => {
    const messages = storedExchange({ executions: [execution(TABLE_CARD)] });
    const doubled: StoredMessage[] = [
      { ...messages[0]!, executions: [execution(TABLE_CARD)] },
      messages[1]!,
    ];
    const exchanges = exchangesOf(doubled);
    expect(exchanges).toHaveLength(1);
    expect(exchanges[0]?.tools).toHaveLength(1);
    expect(exchanges[0]?.user).toBe('Which policies are active?');
    expect(exchanges[0]?.assistant).toBe('Two policies are **active**.');
  });
});
