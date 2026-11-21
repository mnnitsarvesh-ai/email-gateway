import { screen, waitFor, within } from '@testing-library/react';
import { HttpResponse } from 'msw';
import { beforeEach, describe, expect, it } from 'vitest';
import {
  expectNoAxeViolations,
  expectRequestMatchesContract,
  mockApi,
  okJson,
  renderWithProviders,
} from '@/test';
import { AssistantProvider } from './assistant-context';
import { AssistantPage } from './assistant-page';
import { exchangesOf } from './conversation-view';
import {
  CONFIRMATION_TOKEN,
  CONVERSATION,
  CONVERSATION_ID,
  PROPOSAL_CARD,
  RESULT_CARD,
  RESULT_EXECUTION_ID,
  STATUS_AVAILABLE,
  TOOLS,
  confirmationView,
  proposalExecution,
  proposalTurnFrames,
  resultExecution,
  storedExchange,
  streamOf,
} from './test-data';
import type { StoredMessage } from './types';

/** Step AI-2 D10 in the conversation: live proposals, the token's lifetime, history. */

const QUESTION = 'Create an inbound policy that quarantines executables';
const ANSWER = 'I prepared this change. Review it in the confirmation card.';

function renderConversation() {
  return renderWithProviders(
    <AssistantProvider>
      <AssistantPage />
    </AssistantProvider>,
    { role: 'security_analyst', route: `/assistant?conversation=${CONVERSATION_ID}` },
  );
}

function executedView() {
  return confirmationView({
    status: 'executed',
    resultExecutionId: RESULT_EXECUTION_ID,
    decidedAt: '2026-11-20T09:01:00.000Z',
    executedAt: '2026-11-20T09:01:01.000Z',
    result: { httpStatus: 201, error: null },
  });
}

beforeEach(() => {
  mockApi({
    AssistantStatusController_get_v1: () => okJson(STATUS_AVAILABLE),
    AssistantToolsController_list_v1: () => okJson(TOOLS),
    AssistantConversationsController_list_v1: () =>
      okJson({ data: [CONVERSATION], nextCursor: null }),
  });
});

describe('confirmation card in the conversation (step AI-2)', () => {
  it('shows a live proposal, keeps its token after the turn, confirms and refreshes the messages', async () => {
    let stored: StoredMessage[] = [];
    let listCalls = 0;
    const confirms: unknown[] = [];
    mockApi({
      AssistantMessagesController_list_v1: () => {
        listCalls += 1;
        return okJson({ data: stored, nextCursor: null });
      },
      AssistantTurnsController_create_v1: () => {
        stored = storedExchange({
          question: QUESTION,
          answer: ANSWER,
          executions: [proposalExecution()],
        });
        return new HttpResponse(streamOf(proposalTurnFrames()), {
          headers: { 'content-type': 'text/event-stream' },
        });
      },
      AssistantConfirmationsController_confirm_v1: ({ body }) => {
        confirms.push(body);
        stored = storedExchange({
          question: QUESTION,
          answer: ANSWER,
          executions: [proposalExecution(executedView()), resultExecution()],
        });
        return okJson({ confirmation: executedView(), execution: resultExecution() });
      },
    });
    const { user, container } = renderConversation();
    await user.type(
      await screen.findByRole('textbox', { name: 'Message to the AI assistant' }),
      `${QUESTION}{Enter}`,
    );
    const conversation = screen.getByRole('region', { name: 'Conversation' });
    await waitFor(() => expect(conversation).toHaveTextContent(ANSWER));
    // The stored turn replaced the streamed one; the token survived in the tab's memory.
    await waitFor(() => expect(listCalls).toBeGreaterThanOrEqual(2));
    const card = await within(conversation).findByRole('region', { name: 'Create policy' });
    const confirm = within(card).getByRole('button', { name: 'Confirm' });
    await waitFor(() => expect(confirm).toBeEnabled());
    expect(
      within(screen.getByRole('list', { name: 'Tools the assistant used' })).getByRole('listitem'),
    ).toHaveTextContent('Create policy: awaiting your confirmation');
    // The proposal's "Waiting for your confirmation" message card is replaced by the card.
    expect(
      within(conversation).queryByRole('region', { name: `Result: ${PROPOSAL_CARD.title}` }),
    ).not.toBeInTheDocument();
    await expectNoAxeViolations(container);

    const before = listCalls;
    await user.click(confirm);
    await waitFor(() => expect(confirms).toHaveLength(1));
    expect(confirms[0]).toEqual({
      token: CONFIRMATION_TOKEN,
      actionDigest: confirmationView().actionDigest,
    });
    expectRequestMatchesContract('AssistantConfirmationsController_confirm_v1', confirms[0]);
    const done = await within(conversation).findByRole('region', { name: 'Create policy' });
    await waitFor(() => expect(done).toHaveTextContent('Done: the action was applied.'));
    expect(
      within(done).getByRole('region', { name: `Result: ${RESULT_CARD.title}` }),
    ).toBeVisible();
    await waitFor(() => expect(listCalls).toBeGreaterThan(before));
    await waitFor(() =>
      expect(
        within(screen.getByRole('list', { name: 'Tools the assistant used' })).getByRole(
          'listitem',
        ),
      ).toHaveTextContent('Create policy: succeeded'),
    );
    expect(screen.getByRole('status')).toHaveTextContent(
      'Create policy: Done: the action was applied.',
    );
    expect(JSON.stringify({ ...window.localStorage })).not.toContain(CONFIRMATION_TOKEN);
    expect(JSON.stringify({ ...window.sessionStorage })).not.toContain(CONFIRMATION_TOKEN);
  });

  it('moves focus to a live proposal and disables Confirm while the turn still streams', async () => {
    const view = confirmationView();
    mockApi({
      AssistantMessagesController_list_v1: () => okJson({ data: [], nextCursor: null }),
      AssistantTurnsController_create_v1: () =>
        new HttpResponse(
          new ReadableStream({
            start(controller) {
              const encoder = new TextEncoder();
              const frames = proposalTurnFrames(view).slice(0, 4);
              for (const frame of frames) controller.enqueue(encoder.encode(frame));
            },
          }),
          { headers: { 'content-type': 'text/event-stream' } },
        ),
    });
    const { user } = renderConversation();
    await user.type(
      await screen.findByRole('textbox', { name: 'Message to the AI assistant' }),
      `${QUESTION}{Enter}`,
    );
    const card = await screen.findByRole('region', { name: 'Create policy' });
    await waitFor(() => expect(card).toHaveFocus());
    expect(within(card).getByRole('button', { name: 'Confirm' })).toBeDisabled();
    expect(card).toHaveTextContent('Wait until the assistant has finished answering to confirm.');
    expect(within(card).getByRole('button', { name: 'Cancel' })).toBeEnabled();
  });

  it('keeps the focus on the live card when the stored turn replaces the streamed one', async () => {
    let stored: StoredMessage[] = [];
    let listCalls = 0;
    const frames = proposalTurnFrames();
    let finish: () => void = () => undefined;
    mockApi({
      AssistantMessagesController_list_v1: () => {
        listCalls += 1;
        return okJson({ data: stored, nextCursor: null });
      },
      AssistantTurnsController_create_v1: () => {
        stored = storedExchange({
          question: QUESTION,
          answer: ANSWER,
          executions: [proposalExecution()],
        });
        // The proposal arrives first; the rest of the turn only once the test says so.
        return new HttpResponse(
          new ReadableStream({
            start(controller) {
              const encoder = new TextEncoder();
              for (const frame of frames.slice(0, 4)) controller.enqueue(encoder.encode(frame));
              finish = () => {
                for (const frame of frames.slice(4)) controller.enqueue(encoder.encode(frame));
                controller.close();
              };
            },
          }),
          { headers: { 'content-type': 'text/event-stream' } },
        );
      },
    });
    const { user } = renderConversation();
    await user.type(
      await screen.findByRole('textbox', { name: 'Message to the AI assistant' }),
      `${QUESTION}{Enter}`,
    );
    const conversation = screen.getByRole('region', { name: 'Conversation' });
    const current = await within(conversation).findByRole('article', {
      name: 'Current question and answer',
    });
    const card = await within(current).findByRole('region', { name: 'Create policy' });
    await waitFor(() => expect(card).toHaveFocus());
    finish();
    // The streamed turn is gone: the stored one is shown, with the same card element, focused.
    await waitFor(() => expect(listCalls).toBeGreaterThanOrEqual(2));
    await waitFor(() =>
      expect(
        within(conversation).queryByRole('article', { name: 'Current question and answer' }),
      ).not.toBeInTheDocument(),
    );
    expect(within(conversation).getByRole('region', { name: 'Create policy' })).toBe(card);
    expect(card).toHaveFocus();
  });

  it('renders history: an executed proposal with its result card, and a pending one without a token', async () => {
    const pendingView = confirmationView({
      id: '01930000-0000-7000-8000-00000000c002',
      executionId: '01930000-0000-7000-8000-00000000e320',
    });
    const messages = storedExchange({
      question: QUESTION,
      answer: ANSWER,
      executions: [
        proposalExecution(executedView()),
        resultExecution(),
        proposalExecution(pendingView),
      ],
    });
    mockApi({
      AssistantMessagesController_list_v1: () => okJson({ data: messages, nextCursor: null }),
    });
    const { container } = renderConversation();
    const conversation = await screen.findByRole('region', { name: 'Conversation' });
    const cards = await within(conversation).findAllByRole('region', { name: 'Create policy' });
    expect(cards).toHaveLength(2);
    const [executed, waiting] = cards as [HTMLElement, HTMLElement];
    expect(executed).toHaveTextContent('Done: the action was applied.');
    expect(
      within(executed).getByRole('region', { name: `Result: ${RESULT_CARD.title}` }),
    ).toBeVisible();
    expect(waiting).toHaveTextContent('Confirm in the tab where it was proposed, or ask again.');
    expect(within(waiting).queryByRole('button', { name: 'Confirm' })).not.toBeInTheDocument();
    expect(within(waiting).getByRole('button', { name: 'Cancel' })).toBeEnabled();
    expect(waiting).not.toHaveFocus();
    const chips = within(screen.getByRole('list', { name: 'Tools the assistant used' }))
      .getAllByRole('listitem')
      .map((item) => item.textContent);
    expect(chips).toEqual([
      'Create policy: succeeded',
      'Create policy: awaiting your confirmation',
    ]);
    await expectNoAxeViolations(container);
  });

  it('groups the confirmed write under its proposal, never as a separate result', () => {
    const exchanges = exchangesOf(
      storedExchange({ executions: [proposalExecution(executedView()), resultExecution()] }),
    );
    expect(exchanges).toHaveLength(1);
    expect(exchanges[0]?.tools).toHaveLength(1);
    expect(exchanges[0]?.tools[0]).toMatchObject({
      state: 'succeeded',
      resultCard: RESULT_CARD,
    });
  });
});
