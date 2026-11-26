import { screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import {
  apiErrorJson,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  mockApi,
  noContentResponse,
  okJson,
  renderWithProviders,
} from '@/test';
import { AssistantProvider } from './assistant-context';
import { AssistantPage } from './assistant-page';
import { FEEDBACK_NOTICE } from './feedback';
import {
  CONVERSATION,
  CONVERSATION_ID,
  MESSAGE_ID,
  STATUS_AVAILABLE,
  TOOLS,
  storedExchange,
} from './test-data';
import type { StoredMessage } from './types';

/** Step AI-6 (design 34 D2): rating assistant answers in the chat. */

function renderConversation(messages: StoredMessage[]) {
  mockApi({
    AssistantStatusController_get_v1: () => okJson(STATUS_AVAILABLE),
    AssistantToolsController_list_v1: () => okJson(TOOLS),
    AssistantConversationsController_list_v1: () =>
      okJson({ data: [CONVERSATION], nextCursor: null }),
    AssistantMessagesController_list_v1: () => okJson({ data: messages, nextCursor: null }),
  });
  return renderWithProviders(
    <AssistantProvider>
      <AssistantPage />
    </AssistantProvider>,
    { role: 'security_analyst', route: `/assistant?conversation=${CONVERSATION_ID}` },
  );
}

function feedbackView(body: Record<string, unknown>) {
  return {
    messageId: MESSAGE_ID,
    rating: body.rating,
    reason: body.reason ?? null,
    comment: body.comment ?? null,
    createdAt: '2026-11-26T09:00:00.000Z',
    updatedAt: '2026-11-26T09:00:00.000Z',
  };
}

describe('feedback on assistant answers (D2)', () => {
  it('rates an answer with toggle buttons, adds a reason and comment under the notice, and removes it', async () => {
    const puts: Record<string, unknown>[] = [];
    const deletes: string[] = [];
    mockApi({
      AssistantFeedbackController_set_v1: ({ body, params }) => {
        expect(params.messageId).toBe(MESSAGE_ID);
        puts.push(body as Record<string, unknown>);
        return okJson(feedbackView(body as Record<string, unknown>));
      },
      AssistantFeedbackController_remove_v1: ({ params }) => {
        deletes.push(params.messageId ?? '');
        return noContentResponse();
      },
    });
    const { user, container } = renderConversation(storedExchange());
    const group = await screen.findByRole('group', { name: 'Rate this answer' });
    const up = within(group).getByRole('button', { name: 'Helpful' });
    const down = within(group).getByRole('button', { name: 'Not helpful' });
    expect(up).toHaveAttribute('aria-pressed', 'false');
    expect(down).toHaveAttribute('aria-pressed', 'false');
    expect(group).toHaveAccessibleDescription(FEEDBACK_NOTICE);

    await user.click(down);
    await waitFor(() => expect(puts).toEqual([{ rating: 'down' }]));
    expectRequestMatchesContract('AssistantFeedbackController_set_v1', puts[0]);
    await waitFor(() => expect(down).toHaveAttribute('aria-pressed', 'true'));
    expect(up).toHaveAttribute('aria-pressed', 'false');

    const form = await screen.findByRole('form', { name: 'Feedback details' });
    expect(form).toHaveTextContent(FEEDBACK_NOTICE);
    await user.click(within(form).getByRole('combobox', { name: 'Reason (optional)' }));
    await user.click(await screen.findByRole('option', { name: 'Incomplete' }));
    const comment = within(form).getByRole('textbox', { name: 'Comment (optional)' });
    expect(comment).toHaveAttribute('maxlength', '500');
    await user.type(comment, 'The quarantine count was missing.');
    await expectNoAxeViolations(container);
    await user.click(within(form).getByRole('button', { name: 'Send feedback' }));
    await waitFor(() => expect(puts).toHaveLength(2));
    expect(puts[1]).toEqual({
      rating: 'down',
      reason: 'incomplete',
      comment: 'The quarantine count was missing.',
    });
    expectRequestMatchesContract('AssistantFeedbackController_set_v1', puts[1]);
    await waitFor(() =>
      expect(screen.queryByRole('form', { name: 'Feedback details' })).not.toBeInTheDocument(),
    );
    expect(screen.getByRole('button', { name: 'Edit details' })).toBeVisible();

    // Pressing the selected thumb again removes the rating.
    await user.click(down);
    await waitFor(() => expect(deletes).toEqual([MESSAGE_ID]));
    await waitFor(() => expect(down).toHaveAttribute('aria-pressed', 'false'));
  });

  it('starts from the stored rating and offers no rating on a failed turn', async () => {
    const rated = storedExchange({
      feedback: { rating: 'up', reason: null, comment: null },
    });
    const { unmount } = renderConversation(rated);
    const group = await screen.findByRole('group', { name: 'Rate this answer' });
    expect(within(group).getByRole('button', { name: 'Helpful' })).toHaveAttribute(
      'aria-pressed',
      'true',
    );
    unmount();
    renderConversation(storedExchange({ status: 'failed', errorCode: 'assistant_provider_error' }));
    await screen.findByText(/The AI provider failed/);
    expect(screen.queryByRole('group', { name: 'Rate this answer' })).not.toBeInTheDocument();
  });

  it('shows the refusal of a rating that is not allowed', async () => {
    mockApi({
      AssistantFeedbackController_set_v1: () =>
        apiErrorJson(409, 'assistant_feedback_not_allowed', 'not allowed'),
    });
    const { user } = renderConversation(storedExchange());
    const group = await screen.findByRole('group', { name: 'Rate this answer' });
    await user.click(within(group).getByRole('button', { name: 'Helpful' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Only a finished answer can be rated.',
    );
    expect(within(group).getByRole('button', { name: 'Helpful' })).toHaveAttribute(
      'aria-pressed',
      'false',
    );
  });
});
