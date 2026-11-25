import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { useReducer } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  apiErrorJson,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  makeMe,
  mockApi,
  okJson,
  renderWithProviders,
} from '@/test';
import { ApiError } from '@/lib/api/errors';
import {
  ATO_RESPONSE_REQUESTED_TEXT,
  ConfirmationCard,
  QUEUED_202_TOOLS,
  awaitsApproval,
  confirmationRefusal,
  formatRemaining,
  outcomeText,
} from './confirmation-card';
import {
  CONFIRMATION_ID,
  CONFIRMATION_TOKEN,
  FAILED_RESULT_CARD,
  HIGH_VIEW_OVERRIDES,
  MEDIUM_SUMMARY,
  POLICY_ID,
  REPORT_ID,
  REPORT_SEND_SUMMARY,
  RESULT_CARD,
  RESULT_EXECUTION_ID,
  ROLES_VIEW_OVERRIDES,
  WEBHOOK_ESCALATED_VIEW_OVERRIDES,
  WEBHOOK_URL_WARNING,
  confirmationView,
  resultExecution,
} from './test-data';
import { EMPTY_CONFIRMATIONS, reduceConfirmations } from './turn-state';
import type { AssistantCard, ConfirmationView } from './types';

/** The card wired to a real confirmation store, as the conversation view does. */
function Harness({
  view,
  token = CONFIRMATION_TOKEN,
  streaming = false,
  onAnnounce,
  onChanged,
}: {
  view: ConfirmationView;
  token?: string | null;
  streaming?: boolean;
  onAnnounce?: (text: string) => void;
  onChanged?: () => void;
}) {
  const [store, dispatch] = useReducer(reduceConfirmations, EMPTY_CONFIRMATIONS, (empty) =>
    reduceConfirmations(empty, { type: 'proposed', view, token }),
  );
  const entry = store.get(view.executionId);
  if (!entry) return null;
  return (
    <>
      <ConfirmationCard
        view={entry.view}
        token={entry.view.status === 'pending' ? entry.token : null}
        phase={entry.phase}
        resultCard={entry.resultCard}
        focusPending={entry.focusPending}
        streaming={streaming}
        dispatch={dispatch}
        onAnnounce={onAnnounce}
        onChanged={onChanged}
      />
      <output data-testid="token-held">{entry.token ? 'yes' : 'no'}</output>
    </>
  );
}

const highView = (overrides: Partial<ConfirmationView> = {}) =>
  confirmationView({ ...HIGH_VIEW_OVERRIDES, ...overrides });

function executedView(overrides: Partial<ConfirmationView> = {}): ConfirmationView {
  return confirmationView({
    status: 'executed',
    resultExecutionId: RESULT_EXECUTION_ID,
    decidedAt: '2026-11-20T09:01:00.000Z',
    executedAt: '2026-11-20T09:01:01.000Z',
    result: { httpStatus: 201, error: null },
    ...overrides,
  });
}

function confirmResponse(view: ConfirmationView, card: AssistantCard, httpStatus = 201) {
  return okJson({ confirmation: view, execution: resultExecution(card, httpStatus) });
}

function region(name: string) {
  return screen.getByRole('region', { name });
}

afterEach(() => {
  vi.useRealTimers();
});

describe('ConfirmationCard (step AI-2 D10)', () => {
  it('renders a low-risk proposal from the server summary and confirms with exactly { token, actionDigest }', async () => {
    const bodies: unknown[] = [];
    const paths: string[] = [];
    mockApi({
      AssistantConfirmationsController_confirm_v1: ({ body, params }) => {
        bodies.push(body);
        paths.push(params.confirmationId ?? '');
        return confirmResponse(executedView(), RESULT_CARD);
      },
    });
    const announce = vi.fn();
    const changed = vi.fn();
    const { user, container } = renderWithProviders(
      <Harness view={confirmationView()} onAnnounce={announce} onChanged={changed} />,
    );
    const card = region('Create policy');
    await waitFor(() => expect(card).toHaveFocus());
    expect(within(card).getByText('Low risk')).toBeInTheDocument();
    expect(within(card).getByText('Waiting for your confirmation')).toBeInTheDocument();
    expect(card).toHaveTextContent(/Creates the draft policy "Quarantine inbound executables"/);
    const target = within(card).getByRole('table', { name: 'What it applies to' });
    expect(within(target).getByRole('rowheader', { name: 'Policy' })).toBeInTheDocument();
    const changes = within(card).getByRole('table', { name: 'Changes' });
    expect(within(changes).getAllByRole('row')).toHaveLength(3);
    const rules = within(card).getByRole('list', { name: 'Policy rules' });
    expect(rules).toHaveTextContent('quarantine-executables');
    expect(rules).toHaveTextContent('attachment.type_family in [executable] (any)');
    expect(card).toHaveTextContent('Policy rules (inbound, priority 100)');
    expect(within(card).queryByRole('list', { name: 'Impact' })).not.toBeInTheDocument();
    expect(within(card).queryByRole('list', { name: 'Warnings' })).not.toBeInTheDocument();
    expect(within(card).getByText('Technical details')).toBeInTheDocument();
    expect(card).toHaveTextContent('POST /api/v1/policies');
    expect(card).toHaveTextContent(/Expires in [45]:\d\d/);
    expect(within(card).queryByLabelText(/password/i)).not.toBeInTheDocument();
    await expectNoAxeViolations(container);

    await user.click(within(card).getByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(card).toHaveTextContent('Done: the action was applied.'));
    expect(paths).toEqual([CONFIRMATION_ID]);
    expect(bodies).toEqual([
      { token: CONFIRMATION_TOKEN, actionDigest: confirmationView().actionDigest },
    ]);
    expectRequestMatchesContract('AssistantConfirmationsController_confirm_v1', bodies[0]);
    expect(within(card).getByRole('region', { name: 'Result: Created policy' })).toBeVisible();
    expect(within(card).getByRole('link', { name: 'Open it in the portal' })).toHaveAttribute(
      'href',
      `/policies/${POLICY_ID}`,
    );
    expect(within(card).queryByRole('button', { name: 'Confirm' })).not.toBeInTheDocument();
    expect(within(card).getByText('Done')).toBeInTheDocument();
    expect(screen.getByTestId('token-held')).toHaveTextContent('no');
    expect(announce).toHaveBeenLastCalledWith('Create policy: Done: the action was applied.');
    expect(changed).toHaveBeenCalledTimes(1);
  });

  it('renders a medium-risk proposal with its impact lines', () => {
    renderWithProviders(
      <Harness view={confirmationView({ risk: 'medium', summary: MEDIUM_SUMMARY })} />,
    );
    const card = region('Publish policy');
    expect(within(card).getByText('Medium risk')).toBeInTheDocument();
    const impact = within(card).getByRole('list', { name: 'Impact' });
    expect(within(impact).getByRole('listitem')).toHaveTextContent(
      'Applies to new inbound mail of the organization within a minute',
    );
    const changes = within(card).getByRole('table', { name: 'Changes' });
    expect(changes).toHaveTextContent('draft');
    expect(changes).toHaveTextContent('active');
  });

  it('renders a high-risk proposal: warnings, untrusted values as text with a hint, password without MFA', async () => {
    const bodies: unknown[] = [];
    mockApi({
      AssistantConfirmationsController_confirm_v1: ({ body }) => {
        bodies.push(body);
        return bodies.length === 1
          ? apiErrorJson(401, 'assistant_reauth_failed', 'Re-authentication failed', {
              extra: { reason: 'password' },
            })
          : confirmResponse(
              executedView({ ...HIGH_VIEW_OVERRIDES, result: { httpStatus: 204, error: null } }),
              {
                ...FAILED_RESULT_CARD,
                status: 'ok',
                kind: 'message',
                error: undefined,
                title: 'Deleted',
                message: 'The message was deleted.',
              },
              204,
            );
      },
    });
    const { user, container } = renderWithProviders(<Harness view={highView()} />);
    const card = region('Delete quarantined message');
    expect(within(card).getByText('High risk')).toBeInTheDocument();
    const warnings = within(card).getByRole('list', { name: 'Warnings' });
    expect(warnings).toHaveTextContent('Deleting cannot be undone');
    expect(card).toHaveTextContent('This cannot be undone.');
    const subject = within(card).getByText('Invoice 4711 overdue');
    expect(subject).toHaveAttribute('data-untrusted');
    expect(subject.closest('a')).toBeNull();
    expect(within(card).getAllByText('(from the message)')).toHaveLength(2);
    const password = within(card).getByLabelText('Your password (required)');
    expect(password).toHaveAttribute('type', 'password');
    expect(within(card).queryByLabelText('Authenticator code (required)')).not.toBeInTheDocument();
    await expectNoAxeViolations(container);

    // Client-side check: no request without a password.
    await user.click(within(card).getByRole('button', { name: 'Confirm' }));
    expect(within(card).getByText('Enter your password')).toBeInTheDocument();
    expect(bodies).toHaveLength(0);

    await user.type(password, 'not-the-password');
    await user.click(within(card).getByRole('button', { name: 'Confirm' }));
    expect(await within(card).findByRole('alert')).toHaveTextContent(
      'The password is not correct.',
    );
    expect(bodies[0]).toEqual({
      token: CONFIRMATION_TOKEN,
      actionDigest: confirmationView().actionDigest,
      reauth: { password: 'not-the-password' },
    });
    expectRequestMatchesContract('AssistantConfirmationsController_confirm_v1', bodies[0]);
    // Cleared after the attempt; the token is kept (the confirmation stays pending).
    expect(password).toHaveValue('');
    expect(screen.getByTestId('token-held')).toHaveTextContent('yes');

    await user.type(password, 'correct-horse-battery');
    await user.click(within(card).getByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(card).toHaveTextContent('Done: the action was applied.'));
    expect(bodies[1]).toEqual({
      token: CONFIRMATION_TOKEN,
      actionDigest: confirmationView().actionDigest,
      reauth: { password: 'correct-horse-battery' },
    });
    expect(within(card).queryByLabelText('Your password (required)')).not.toBeInTheDocument();
  });

  it('asks for the authenticator code when MFA is enrolled and clears both fields after the attempt', async () => {
    const bodies: unknown[] = [];
    mockApi({
      AssistantConfirmationsController_confirm_v1: ({ body }) => {
        bodies.push(body);
        return apiErrorJson(401, 'assistant_reauth_failed', 'Re-authentication failed', {
          extra: { reason: 'totp' },
        });
      },
    });
    const { user } = renderWithProviders(<Harness view={highView()} />, {
      me: makeMe({ role: 'security_analyst', overrides: { mfaEnabled: true } }),
    });
    const card = region('Delete quarantined message');
    const password = within(card).getByLabelText('Your password (required)');
    const code = within(card).getByLabelText('Authenticator code (required)');
    await user.type(password, 'correct-horse-battery');
    await user.type(code, '12');
    await user.click(within(card).getByRole('button', { name: 'Confirm' }));
    expect(
      within(card).getByText('Enter the 6-digit code from your authenticator app'),
    ).toBeInTheDocument();
    expect(bodies).toHaveLength(0);
    await user.clear(code);
    await user.type(code, '123456');
    await user.click(within(card).getByRole('button', { name: 'Confirm' }));
    expect(await within(card).findByRole('alert')).toHaveTextContent(
      'The authenticator code is not correct.',
    );
    expect(bodies).toEqual([
      {
        token: CONFIRMATION_TOKEN,
        actionDigest: confirmationView().actionDigest,
        reauth: { password: 'correct-horse-battery', totpCode: '123456' },
      },
    ]);
    expect(password).toHaveValue('');
    expect(code).toHaveValue('');
  });

  it('skips the identity fields when the session re-authenticated recently', async () => {
    const bodies: unknown[] = [];
    mockApi({
      AssistantConfirmationsController_confirm_v1: ({ body }) => {
        bodies.push(body);
        return confirmResponse(executedView(HIGH_VIEW_OVERRIDES), RESULT_CARD);
      },
    });
    const { user } = renderWithProviders(<Harness view={highView({ reauthFresh: true })} />);
    const card = region('Delete quarantined message');
    expect(within(card).queryByLabelText('Your password (required)')).not.toBeInTheDocument();
    await user.click(within(card).getByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0]).toEqual({
      token: CONFIRMATION_TOKEN,
      actionDigest: confirmationView().actionDigest,
    });
  });

  it('reveals the identity fields on 401 assistant_reauth_required, and the code on totp_required', async () => {
    let calls = 0;
    mockApi({
      AssistantConfirmationsController_confirm_v1: () => {
        calls += 1;
        return calls === 1
          ? apiErrorJson(401, 'assistant_reauth_required', 'Re-authentication required')
          : apiErrorJson(401, 'assistant_reauth_failed', 'Re-authentication failed', {
              extra: { reason: 'totp_required' },
            });
      },
    });
    const { user } = renderWithProviders(<Harness view={highView({ reauthFresh: true })} />);
    const card = region('Delete quarantined message');
    await user.click(within(card).getByRole('button', { name: 'Confirm' }));
    expect(await within(card).findByRole('alert')).toHaveTextContent(
      'Confirm your identity to run this action.',
    );
    const password = within(card).getByLabelText('Your password (required)');
    await user.type(password, 'correct-horse-battery');
    await user.click(within(card).getByRole('button', { name: 'Confirm' }));
    await waitFor(() =>
      expect(within(card).getByRole('alert')).toHaveTextContent(
        'Enter the 6-digit code from your authenticator app.',
      ),
    );
    expect(within(card).getByLabelText('Authenticator code (required)')).toBeInTheDocument();
  });

  it.each([
    [
      410,
      'assistant_confirmation_expired',
      {},
      'This proposal expired before it was confirmed',
      true,
    ],
    [
      409,
      'assistant_confirmation_state_changed',
      {},
      'The record changed since this was proposed. Ask again to see the current state.',
      true,
    ],
    [
      409,
      'assistant_confirmation_not_pending',
      { status: 'executed' },
      'This action was already confirmed. It cannot be confirmed or cancelled again.',
      true,
    ],
    [
      403,
      'assistant_confirmation_session_mismatch',
      {},
      'This action was proposed in another sign-in session.',
      true,
    ],
    [
      403,
      'assistant_confirmation_token_invalid',
      {},
      'The confirmation could not be verified. Ask the assistant again.',
      true,
    ],
    [
      409,
      'assistant_confirmation_digest_mismatch',
      {},
      'The action no longer matches what this card shows.',
      true,
    ],
    [
      409,
      'assistant_confirmation_tool_changed',
      {},
      'This action is no longer available in chat.',
      true,
    ],
    [
      403,
      'assistant_action_not_allowed',
      {},
      'This change is not allowed in chat. Nothing changed.',
      true,
    ],
    [
      401,
      'assistant_reauth_failed',
      { reason: 'locked' },
      'Your account is temporarily locked after too many failed attempts.',
      false,
    ],
    [
      409,
      'assistant_turn_in_progress',
      {},
      'An answer is still running in this conversation. Confirm when it has finished.',
      false,
    ],
  ] as const)('explains %s %s and %s the token', async (status, code, extra, text, ends) => {
    const gets: string[] = [];
    mockApi({
      AssistantConfirmationsController_confirm_v1: () =>
        apiErrorJson(status, code, code, { extra: { ...extra } }),
      AssistantConfirmationsController_get_v1: ({ params }) => {
        gets.push(params.confirmationId ?? '');
        return apiErrorJson(404, 'assistant_confirmation_not_found');
      },
    });
    const view =
      code === 'assistant_reauth_failed' ? highView({ reauthFresh: true }) : confirmationView();
    const { user } = renderWithProviders(<Harness view={view} />);
    const card = region(view.summary?.title ?? '');
    await user.click(within(card).getByRole('button', { name: 'Confirm' }));
    expect(await within(card).findByRole('alert')).toHaveTextContent(text);
    expect(screen.getByTestId('token-held')).toHaveTextContent(ends ? 'no' : 'yes');
    if (ends) {
      expect(
        within(card).getByText('Confirm in the tab where it was proposed, or ask again.'),
      ).toBeInTheDocument();
      expect(within(card).queryByRole('button', { name: 'Confirm' })).not.toBeInTheDocument();
    } else {
      expect(within(card).getByRole('button', { name: 'Confirm' })).toBeEnabled();
    }
    if (code !== 'assistant_confirmation_session_mismatch' && ends) {
      await waitFor(() => expect(gets).toEqual([CONFIRMATION_ID]));
    }
  });

  it('maps network failures and unknown codes to readable messages', () => {
    expect(confirmationRefusal(new TypeError('x'))).toMatchObject({
      code: 'client_error',
      ends: false,
    });
  });

  it('disables Confirm while a turn of the conversation is streaming', () => {
    renderWithProviders(<Harness view={confirmationView()} streaming />);
    const card = region('Create policy');
    expect(within(card).getByRole('button', { name: 'Confirm' })).toBeDisabled();
    expect(within(card).getByRole('button', { name: 'Cancel' })).toBeEnabled();
    expect(card).toHaveTextContent('Wait until the assistant has finished answering to confirm.');
  });

  it('offers Cancel only without a token, and cancels without a body', async () => {
    const cancels: { id: string; body: unknown }[] = [];
    mockApi({
      AssistantConfirmationsController_cancel_v1: ({ params, body }) => {
        cancels.push({ id: params.confirmationId ?? '', body });
        return okJson({
          confirmation: confirmationView({
            status: 'cancelled',
            decidedAt: '2026-11-20T09:02:00.000Z',
          }),
        });
      },
    });
    const announce = vi.fn();
    const { user } = renderWithProviders(
      <Harness view={confirmationView()} token={null} onAnnounce={announce} />,
    );
    const card = region('Create policy');
    expect(card).not.toHaveFocus();
    expect(card).toHaveTextContent('Confirm in the tab where it was proposed, or ask again.');
    expect(within(card).getAllByRole('button')).toHaveLength(1);
    await user.click(within(card).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(card).toHaveTextContent('Cancelled. Nothing changed.'));
    expect(cancels).toEqual([{ id: CONFIRMATION_ID, body: null }]);
    expect(within(card).queryByRole('button')).not.toBeInTheDocument();
    expect(announce).toHaveBeenLastCalledWith('Create policy: Cancelled. Nothing changed.');
  });

  it('cancels a live proposal and drops its token', async () => {
    mockApi({
      AssistantConfirmationsController_cancel_v1: () =>
        okJson({ confirmation: confirmationView({ status: 'cancelled' }) }),
    });
    const { user } = renderWithProviders(<Harness view={confirmationView()} />);
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(await screen.findByText('Cancelled. Nothing changed.')).toBeInTheDocument();
    expect(screen.getByTestId('token-held')).toHaveTextContent('no');
  });

  it('counts down and turns into the expired state, dropping the token', () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval', 'Date'] });
    vi.setSystemTime(new Date('2026-11-20T09:00:00.000Z'));
    const announce = vi.fn();
    renderWithProviders(
      <Harness
        view={confirmationView({ expiresAt: '2026-11-20T09:01:05.000Z' })}
        onAnnounce={announce}
      />,
    );
    const card = region('Create policy');
    expect(card).toHaveTextContent('Expires in 1:05');
    act(() => {
      vi.advanceTimersByTime(5_000);
    });
    expect(card).toHaveTextContent('Expires in 1:00');
    act(() => {
      vi.advanceTimersByTime(61_000);
    });
    expect(card).toHaveTextContent(
      'Expired without confirmation. Nothing changed. Ask again to get a new proposal.',
    );
    expect(within(card).getByText('Expired')).toBeInTheDocument();
    expect(within(card).queryByRole('button')).not.toBeInTheDocument();
    expect(screen.getByTestId('token-held')).toHaveTextContent('no');
    expect(announce).toHaveBeenCalledWith('Create policy: the proposal expired. Nothing changed.');
    expect(formatRemaining(-5)).toBe('0:00');
  });

  it('shows a failed write with its code, message and error card', async () => {
    mockApi({
      AssistantConfirmationsController_confirm_v1: () =>
        confirmResponse(
          confirmationView({
            status: 'failed',
            resultExecutionId: RESULT_EXECUTION_ID,
            result: { httpStatus: 409, error: 'policy_conflict' },
          }),
          FAILED_RESULT_CARD,
          409,
        ),
    });
    const { user } = renderWithProviders(<Harness view={confirmationView()} />);
    const card = region('Create policy');
    await user.click(within(card).getByRole('button', { name: 'Confirm' }));
    await waitFor(() =>
      expect(card).toHaveTextContent('The action failed (HTTP 409, policy_conflict).'),
    );
    const error = within(card).getByRole('region', { name: 'Result: Create policy' });
    expect(error).toHaveTextContent('A policy with this name exists');
    expect(error).toHaveTextContent('policy_conflict');
    expect(within(card).getByText('Failed')).toBeInTheDocument();
  });

  it('shows an approval-pending answer (202)', async () => {
    mockApi({
      AssistantConfirmationsController_confirm_v1: () =>
        confirmResponse(
          executedView({ result: { httpStatus: 202, error: null } }),
          {
            ...FAILED_RESULT_CARD,
            status: 'ok',
            kind: 'message',
            error: undefined,
            title: 'Release requested',
            message: 'The release waits for approval.',
          },
          202,
        ),
    });
    renderWithProviders(<Harness view={confirmationView()} />);
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));
    expect(
      await screen.findByText(
        'Submitted for approval: another person must approve it before it takes effect.',
      ),
    ).toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Result: Release requested' })).toBeVisible();
  });

  it('follows an executing confirmation to its outcome and explains an unknown outcome', async () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] });
    mockApi({
      AssistantConfirmationsController_get_v1: () =>
        okJson(
          confirmationView({
            status: 'failed',
            result: { httpStatus: null, error: 'assistant_confirmation_outcome_unknown' },
          }),
        ),
    });
    renderWithProviders(<Harness view={confirmationView({ status: 'executing' })} token={null} />);
    const card = region('Create policy');
    expect(card).toHaveTextContent('Applying the action …');
    act(() => {
      vi.advanceTimersByTime(3_000);
    });
    vi.useRealTimers();
    await waitFor(() => expect(card).toHaveTextContent('The outcome is unknown'));
  });

  it('shows a purged confirmation without its details', () => {
    renderWithProviders(
      <Harness view={confirmationView({ status: 'expired', summary: null })} token={null} />,
    );
    const card = region('Proposed action');
    expect(card).toHaveTextContent('The details of this action are no longer available');
    expect(card).toHaveTextContent('Expired without confirmation.');
    expect(screen.getByTestId('token-held')).toHaveTextContent('no');
  });

  it('keeps the token in memory only', async () => {
    const setItem = vi.spyOn(Storage.prototype, 'setItem');
    mockApi({
      AssistantConfirmationsController_confirm_v1: () =>
        confirmResponse(executedView(), RESULT_CARD),
    });
    const { user } = renderWithProviders(<Harness view={confirmationView()} />);
    await user.click(screen.getByRole('button', { name: 'Confirm' }));
    await screen.findByText('Done: the action was applied.');
    for (const call of setItem.mock.calls) {
      expect(JSON.stringify(call)).not.toContain(CONFIRMATION_TOKEN);
    }
    expect(JSON.stringify({ ...window.localStorage })).not.toContain(CONFIRMATION_TOKEN);
    expect(JSON.stringify({ ...window.sessionStorage })).not.toContain(CONFIRMATION_TOKEN);
    setItem.mockRestore();
  });
});

describe('ConfirmationCard (step AI-3 identity and tenant administration)', () => {
  it('ends in the refused state on 403 assistant_action_not_allowed (confirm-time guard)', async () => {
    const failed = confirmationView({
      ...ROLES_VIEW_OVERRIDES,
      reauthFresh: true,
      status: 'failed',
      decidedAt: '2026-11-21T09:01:00.000Z',
      result: { httpStatus: 403, error: 'assistant_action_not_allowed' },
    });
    const confirms: unknown[] = [];
    mockApi({
      AssistantConfirmationsController_confirm_v1: ({ body }) => {
        confirms.push(body);
        return apiErrorJson(403, 'assistant_action_not_allowed', 'Not allowed in chat');
      },
      AssistantConfirmationsController_get_v1: () => okJson(failed),
    });
    const announced: string[] = [];
    const { user } = renderWithProviders(
      <Harness
        view={confirmationView({ ...ROLES_VIEW_OVERRIDES, reauthFresh: true })}
        onAnnounce={(text) => announced.push(text)}
      />,
    );
    const card = region('Replace user roles');
    await user.click(within(card).getByRole('button', { name: 'Confirm' }));
    expect(await within(card).findByRole('alert')).toHaveTextContent(
      'This change is not allowed in chat. Nothing changed.',
    );
    expect(screen.getByTestId('token-held')).toHaveTextContent('no');
    await waitFor(() =>
      expect(card).toHaveTextContent(
        'Not run: this change is not allowed in chat. Nothing changed.',
      ),
    );
    expect(within(card).queryByRole('button', { name: 'Confirm' })).not.toBeInTheDocument();
    expect(confirms).toHaveLength(1);
    expect(
      confirmationRefusal(
        new ApiError({ status: 403, code: 'assistant_action_not_allowed', message: 'x' }),
      ),
    ).toMatchObject({ ends: true, refresh: true });
  });

  it('keeps the tool-changed message for a recomputed risk difference', () => {
    expect(
      confirmationRefusal(
        new ApiError({ status: 409, code: 'assistant_confirmation_tool_changed', message: 'x' }),
      ).message,
    ).toBe('This action is no longer available in chat. Ask again or use the portal page.');
  });

  it('renders a high card raised by escalation: its warning and the re-authentication fields', async () => {
    const { container } = renderWithProviders(
      <Harness view={confirmationView(WEBHOOK_ESCALATED_VIEW_OVERRIDES)} />,
      { me: makeMe({ role: 'organization_admin', overrides: { mfaEnabled: true } }) },
    );
    const card = region('Update webhook');
    expect(within(card).getByText('High risk')).toBeInTheDocument();
    const warnings = within(card).getByRole('list', { name: 'Warnings' });
    expect(
      within(warnings)
        .getAllByRole('listitem')
        .map((item) => item.textContent),
    ).toEqual([WEBHOOK_URL_WARNING]);
    const changes = within(card).getByRole('table', { name: 'Changes' });
    const url = within(changes).getByRole('row', { name: /URL/ });
    expect(url).toHaveTextContent('https://siem.example.com/hooks/gateway');
    expect(url).toHaveTextContent('https://collector.example.net/ingest');
    // Addresses in a summary are values, never links.
    expect(within(changes).queryByRole('link')).not.toBeInTheDocument();
    expect(within(card).getByLabelText('Your password (required)')).toHaveAttribute(
      'type',
      'password',
    );
    expect(within(card).getByLabelText('Authenticator code (required)')).toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('renders a role replacement as a high card with the roles before and after', async () => {
    const bodies: unknown[] = [];
    mockApi({
      AssistantConfirmationsController_confirm_v1: ({ body }) => {
        bodies.push(body);
        return apiErrorJson(401, 'assistant_reauth_required', 'Re-authentication required');
      },
    });
    const { user, container } = renderWithProviders(
      <Harness view={confirmationView(ROLES_VIEW_OVERRIDES)} />,
    );
    const card = region('Replace user roles');
    expect(within(card).getByText('High risk')).toBeInTheDocument();
    const roles = within(within(card).getByRole('table', { name: 'Changes' })).getByRole('row', {
      name: /Roles/,
    });
    expect(roles).toHaveTextContent('security_analyst');
    expect(roles).toHaveTextContent('organization_admin');
    expect(within(card).getByText('Priya Raman')).toHaveAttribute('data-untrusted');
    expect(within(card).getByRole('list', { name: 'Warnings' })).toHaveTextContent(
      'Grants full administrative access to this organization.',
    );
    const password = within(card).getByLabelText('Your password (required)');
    await user.type(password, 'correct-horse-battery');
    await user.click(within(card).getByRole('button', { name: 'Confirm' }));
    expect(await within(card).findByRole('alert')).toHaveTextContent(
      'Confirm your identity to run this action.',
    );
    expect(bodies).toEqual([
      {
        token: CONFIRMATION_TOKEN,
        actionDigest: confirmationView().actionDigest,
        reauth: { password: 'correct-horse-battery' },
      },
    ]);
    expectRequestMatchesContract('AssistantConfirmationsController_confirm_v1', bodies[0]);
    await expectNoAxeViolations(container);
  });
});

describe('ConfirmationCard: report_send_email (step AI-R D9, generic template)', () => {
  it('renders the report email summary: recipient, impact, warnings and the report link', async () => {
    const { container } = renderWithProviders(
      <Harness
        view={confirmationView({
          tool: 'report_send_email',
          operationId: 'AssistantNative_reportSendEmail',
          risk: 'medium',
          summary: REPORT_SEND_SUMMARY,
        })}
      />,
    );
    const card = region('Email security report');
    expect(within(card).getByText('Medium risk')).toBeInTheDocument();
    expect(card).toHaveTextContent(
      'Sends the security report as an HTML email to analyst@example.test.',
    );
    const target = within(card).getByRole('table', { name: 'What it applies to' });
    for (const label of ['Report', 'Period', 'Recipient', 'Recipient type', 'Size'])
      expect(within(target).getByRole('rowheader', { name: label })).toBeInTheDocument();
    expect(target).toHaveTextContent('analyst@example.test');
    expect(target).toHaveTextContent('your own address');
    expect(within(card).queryByRole('table', { name: 'Changes' })).not.toBeInTheDocument();
    const impact = within(card).getByRole('list', { name: 'Impact' });
    expect(within(impact).getAllByRole('listitem')).toHaveLength(2);
    const warnings = within(card).getByRole('list', { name: 'Warnings' });
    expect(warnings).toHaveTextContent('Emails cannot be recalled after sending.');
    expect(warnings).toHaveTextContent('9 of 10 report emails left today for you');
    expect(card).toHaveTextContent('This cannot be undone.');
    expect(card).toHaveTextContent('POST native:report_send_email');
    expect(within(card).getByRole('button', { name: 'Confirm' })).toBeEnabled();
    await expectNoAxeViolations(container);
  });

  it('links the executed send to the full-size report (an allow-listed route)', () => {
    renderWithProviders(
      <Harness
        token={null}
        view={executedView({
          tool: 'report_send_email',
          operationId: 'AssistantNative_reportSendEmail',
          risk: 'medium',
          summary: REPORT_SEND_SUMMARY,
          result: { httpStatus: 202, error: null },
        })}
      />,
    );
    const card = region('Email security report');
    expect(within(card).getByRole('link', { name: 'Open it in the portal' })).toHaveAttribute(
      'href',
      `/assistant/reports/${REPORT_ID}`,
    );
    expect(within(card).queryByRole('button', { name: 'Confirm' })).not.toBeInTheDocument();
  });
});

describe('awaitsApproval', () => {
  it('treats a 202 as "waiting for approval" except for queued work such as a report email', () => {
    const executed = (tool: string, httpStatus: number) => ({
      ...confirmationView(),
      tool,
      status: 'executed' as const,
      result: { httpStatus, error: null },
    });
    expect(awaitsApproval(executed('quarantine_release', 202))).toBe(true);
    expect(awaitsApproval(executed('quarantine_release', 200))).toBe(false);
    expect(awaitsApproval(executed('report_send_email', 202))).toBe(false);
    expect(outcomeText(executed('report_send_email', 202), null)).toBe(
      'Done: the action was applied.',
    );
  });

  it('mirrors the package list of queued 202 tools (step AI-4 D10)', () => {
    expect([...QUEUED_202_TOOLS].sort()).toEqual(
      [
        'report_send_email',
        'ato_providers_health_check',
        'ato_providers_backfill',
        'ato_account_mailbox_refresh',
        'attachment_rescans_request',
        'message_lifecycle_rescan',
        'users_resend_invitation',
        'webhooks_test',
        'webhook_deliveries_replay',
        'webhook_deliveries_create_replay',
      ].sort(),
    );
    const executed = (tool: string, httpStatus: number) => ({
      ...confirmationView(),
      tool,
      status: 'executed' as const,
      result: { httpStatus, error: null },
    });
    for (const tool of QUEUED_202_TOOLS) {
      expect(awaitsApproval(executed(tool, 202))).toBe(false);
      expect(outcomeText(executed(tool, 202), null)).toBe('Done: the action was applied.');
    }
    expect(awaitsApproval(executed('quarantine_legacy_release', 202))).toBe(true);
  });

  it('says an executed ATO response request may wait for another responder (step AI-4 D10)', () => {
    const view = (httpStatus: number | null, status: ConfirmationView['status'] = 'executed') => ({
      ...confirmationView(),
      tool: 'ato_responses_request',
      status,
      result: httpStatus === null ? null : { httpStatus, error: null },
    });
    expect(ATO_RESPONSE_REQUESTED_TEXT).toBe(
      'Requested. If this action needs approval, another responder must approve it before it runs (you cannot approve your own request).',
    );
    expect(outcomeText(view(201), null)).toBe(ATO_RESPONSE_REQUESTED_TEXT);
    expect(outcomeText(view(null), null)).toBe(ATO_RESPONSE_REQUESTED_TEXT);
    expect(outcomeText(view(200), null)).toBe('Done: the action was applied.');
    expect(outcomeText(view(null, 'cancelled'), null)).toBe('Cancelled. Nothing changed.');
    expect(outcomeText({ ...view(201), tool: 'ato_responses_approve' }, null)).toBe(
      'Done: the action was applied.',
    );
  });
});
