import { act, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  apiErrorJson,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  mockApi,
  okJson,
  renderWithProviders,
} from '@/test';
import { ApprovalDetail } from './approvals';
import { RELEASE_POLL_MS, ReleaseStatus } from './release-status';
import {
  APPROVAL_ID,
  CATALOG,
  ENTRY_ID,
  HOSTILE,
  RELEASE_ID,
  approval,
  entryDetail,
  releaseView,
} from './test-data';

function mockApproval(a = approval(), extra: Parameters<typeof mockApi>[0] = {}) {
  mockApi({
    QuarantineToolsController_catalog_v1: () => okJson(CATALOG),
    QuarantineApprovalsController_get_v1: ({ params }) =>
      params.approvalId === APPROVAL_ID
        ? okJson(a)
        : apiErrorJson(404, 'quarantine_approval_not_found', 'Not found', {
            requestId: 'req-a-404',
          }),
    QuarantineEntriesController_detail_v1: () => okJson(entryDetail({ subject: HOSTILE })),
    ...extra,
  });
}

describe('Approval request (/quarantine/approvals/[approvalId])', () => {
  it('shows the request and the entry summary; approve sends a contract body with a key', async () => {
    let body: unknown = null;
    let key: string | null = null;
    mockApproval(approval(), {
      QuarantineApprovalsController_approve_v1: ({ body: b, request }) => {
        body = b;
        key = request.headers.get('idempotency-key');
        return okJson(
          {
            approvalRequestId: APPROVAL_ID,
            status: 'approved',
            entryId: ENTRY_ID,
            entryState: 'releasing',
            releaseId: RELEASE_ID,
            messageTransition: null,
          },
          202,
        );
      },
    });
    const { user, container } = renderWithProviders(<ApprovalDetail approvalId={APPROVAL_ID} />, {
      role: 'security_analyst',
    });
    expect(await screen.findByText(/window.__pwned/)).toBeInTheDocument();
    expect(
      screen.getByText(/Separation of duties|You cannot decide a request you made yourself/),
    ).toBeInTheDocument();
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('button', { name: 'Approve' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.type(within(dialog).getByLabelText(/Reason/), 'Verified by phone');
    await user.click(within(dialog).getByRole('button', { name: 'Approve' }));
    await waitFor(() => expect(body).toEqual({ reason: 'Verified by phone' }));
    expectRequestMatchesContract('QuarantineApprovalsController_approve_v1', body);
    expect(key).toBeTruthy();
    expect(await screen.findByRole('link', { name: 'Follow the release status' })).toHaveAttribute(
      'href',
      `/quarantine/releases/${RELEASE_ID}`,
    );
  });

  it('explains a separation-of-duties refusal', async () => {
    mockApproval(approval(), {
      QuarantineApprovalsController_deny_v1: ({ body }) => {
        expectRequestMatchesContract('QuarantineApprovalsController_deny_v1', body);
        return apiErrorJson(403, 'quarantine_approval_forbidden', 'Forbidden', {
          requestId: 'req-sod',
          extra: { reason: 'requester' },
        });
      },
    });
    const { user } = renderWithProviders(<ApprovalDetail approvalId={APPROVAL_ID} />, {
      role: 'quarantine_reviewer',
    });
    await user.click(await screen.findByRole('button', { name: 'Deny' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.type(within(dialog).getByLabelText(/Reason/), 'Not expected');
    await user.click(within(dialog).getByRole('button', { name: 'Deny' }));
    expect(
      await within(dialog).findByText(
        /Separation of duties: you cannot decide this request \(Requester\)/,
      ),
    ).toBeInTheDocument();
    expect(within(dialog).getByText(/req-sod/)).toBeInTheDocument();
  });

  it('cancels a request with a contract body; policy reviews cannot be cancelled', async () => {
    let body: unknown = null;
    mockApproval(approval(), {
      QuarantineApprovalsController_cancel_v1: ({ body: b }) => {
        body = b;
        return okJson({
          approvalRequestId: APPROVAL_ID,
          status: 'cancelled',
          entryId: ENTRY_ID,
          entryState: 'held',
          releaseId: null,
          messageTransition: null,
        });
      },
    });
    const { user, unmount } = renderWithProviders(<ApprovalDetail approvalId={APPROVAL_ID} />, {
      role: 'quarantine_reviewer',
    });
    await user.click(await screen.findByRole('button', { name: 'Cancel request' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.type(within(dialog).getByLabelText(/Reason/), 'Duplicate');
    await user.click(within(dialog).getByRole('button', { name: 'Cancel request' }));
    await waitFor(() => expect(body).toEqual({ reason: 'Duplicate' }));
    expectRequestMatchesContract('QuarantineApprovalsController_cancel_v1', body);
    unmount();
    mockApproval(approval({ kind: 'policy_review' }));
    renderWithProviders(<ApprovalDetail approvalId={APPROVAL_ID} />, {
      role: 'quarantine_reviewer',
    });
    await screen.findByRole('button', { name: 'Approve' });
    expect(screen.queryByRole('button', { name: 'Cancel request' })).not.toBeInTheDocument();
  });

  it('hides decisions from read-only users and for decided requests', async () => {
    mockApproval();
    const { unmount } = renderWithProviders(<ApprovalDetail approvalId={APPROVAL_ID} />, {
      role: 'read_only_user',
    });
    await screen.findByText('Approval reasons');
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Deny' })).not.toBeInTheDocument();
    unmount();
    mockApproval(
      approval({ status: 'approved', decidedAt: '2026-11-12T11:00:00.000Z', decisionReason: 'ok' }),
    );
    renderWithProviders(<ApprovalDetail approvalId={APPROVAL_ID} />, { role: 'security_analyst' });
    await screen.findByText('Approval reasons');
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument();
  });

  it('renders not-found with code and request id', async () => {
    mockApproval();
    renderWithProviders(<ApprovalDetail approvalId="01933c3a-1b2c-7d4e-8f00-0000000a00ff" />, {
      role: 'security_analyst',
    });
    const alert = await screen.findByRole('alert');
    expect(within(alert).getByText('quarantine_approval_not_found')).toBeInTheDocument();
    expect(within(alert).getByText('req-a-404')).toBeInTheDocument();
  });
});

describe('Release status (/quarantine/releases/[releaseId])', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('polls while pending and stops once the executor ran; passes axe', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    let calls = 0;
    mockApi({
      QuarantineToolsController_release_v1: () => {
        calls += 1;
        return okJson(
          calls < 2
            ? releaseView()
            : releaseView({
                status: 'dispatched',
                completedAt: '2026-11-12T10:00:20.000Z',
                deliveredObject: 'policy_copy',
              }),
        );
      },
    });
    const { container } = renderWithProviders(<ReleaseStatus releaseId={RELEASE_ID} />, {
      role: 'security_analyst',
    });
    expect(
      await screen.findByText('Queued. Waiting for the release executor.'),
    ).toBeInTheDocument();
    expect(screen.getByText(/executed by the release executor/)).toBeInTheDocument();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(RELEASE_POLL_MS + 100);
    });
    expect(await screen.findByText('Re-validated and handed to delivery.')).toBeInTheDocument();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(RELEASE_POLL_MS * 3);
    });
    expect(calls).toBe(2);
    expect(screen.getByRole('link', { name: ENTRY_ID })).toHaveAttribute(
      'href',
      `/quarantine/${ENTRY_ID}`,
    );
    vi.useRealTimers();
    await expectNoAxeViolations(container);
  });

  it('shows the error state with code and request id', async () => {
    mockApi({
      QuarantineToolsController_release_v1: () =>
        apiErrorJson(404, 'quarantine_release_not_found', 'Not found', { requestId: 'req-rel' }),
    });
    renderWithProviders(<ReleaseStatus releaseId={RELEASE_ID} />, { role: 'security_analyst' });
    const alert = await screen.findByRole('alert');
    expect(within(alert).getByText('quarantine_release_not_found')).toBeInTheDocument();
    expect(within(alert).getByText('req-rel')).toBeInTheDocument();
  });

  it('is forbidden for a mailbox user', async () => {
    renderWithProviders(<ReleaseStatus releaseId={RELEASE_ID} />, { role: 'mailbox_user' });
    expect(await screen.findByText(/quarantine:read/)).toBeInTheDocument();
  });
});
