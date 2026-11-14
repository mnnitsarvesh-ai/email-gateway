import { screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { OperationId } from '@/lib/api/types';
import {
  apiErrorJson,
  createTestQueryClient,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  okJson,
  renderWithProviders,
  type MockHandler,
  type SystemRoleKey,
} from '@/test';
import { APPROVAL_ID, entryDetail, entrySummary, preview } from '@/features/quarantine/test-data';
import { expectNoInjectedMarkup } from '../test-data';
import { MessageDetails } from './message-details';
import { ENTRY_ID, MESSAGE_ID, detailsRoute, mockDetails } from './test-helpers';

function renderQuarantine(
  role: SystemRoleKey = 'organization_admin',
  overrides: Partial<Record<OperationId, MockHandler>> = {},
) {
  const mocks = mockDetails(overrides);
  const queryClient = createTestQueryClient();
  const view = renderWithProviders(<MessageDetails messageId={MESSAGE_ID} />, {
    role,
    route: detailsRoute('section=quarantine'),
    queryClient,
  });
  return { ...mocks, ...view, queryClient };
}

async function expand(user: ReturnType<typeof renderWithProviders>['user']) {
  await user.click(await screen.findByRole('button', { name: /Details and actions/ }));
}

describe('Email details: quarantine actions (§2 E13)', () => {
  it('searches every entry of the message (no time window); details load only on expand', async () => {
    const { calls, user, container } = renderQuarantine();
    expect(await screen.findByText('priya.rao4@alpha.example.test')).toBeInTheDocument();
    const search = calls('QuarantineEntriesController_search_v1');
    expect(search).toHaveLength(1);
    const params = search[0]?.url.searchParams;
    expect(params?.get('messageId')).toBe(MESSAGE_ID);
    // No quarantined_at window: an entry created long after receipt (a manual quarantine, a
    // rescan) is found too (§2 E13 as amended by the closer).
    expect(params?.has('from')).toBe(false);
    expect(params?.has('to')).toBe(false);
    // The audited entry detail is not read until the entry is opened.
    expect(calls('QuarantineEntriesController_detail_v1')).toHaveLength(0);
    await expand(user);
    expect(await screen.findByRole('group', { name: 'Entry actions' })).toBeInTheDocument();
    expect(calls('QuarantineEntriesController_detail_v1')).toHaveLength(1);
    expect(await screen.findByText('Quarantine')).toBeInTheDocument();
    for (const name of ['Release', 'Request release', 'Download', 'Reject', 'Delete']) {
      expect(screen.getByRole('button', { name })).toBeInTheDocument();
    }
    expect(screen.getByRole('link', { name: 'Open the quarantine entry page' })).toHaveAttribute(
      'href',
      `/quarantine/${ENTRY_ID}`,
    );
    expectNoInjectedMarkup(container);
    await expectNoAxeViolations(container);
  });

  it('the sanitized preview is requested only after the explicit click, once, and never kept', async () => {
    const { calls, user, queryClient } = renderQuarantine('security_analyst', {
      QuarantineEntriesController_preview_v1: () => okJson(preview()),
    });
    await expand(user);
    await screen.findByRole('button', { name: 'Show sanitized preview' });
    expect(calls('QuarantineEntriesController_preview_v1')).toHaveLength(0);
    await user.click(screen.getByRole('button', { name: 'Show sanitized preview' }));
    expect(await screen.findByTestId('preview-text')).toBeInTheDocument();
    expect(calls('QuarantineEntriesController_preview_v1')).toHaveLength(1);
    // Collapse: the preview leaves the page and the cache (gcTime 0); reopening needs a new click.
    await user.click(screen.getByRole('button', { name: /Hide details/ }));
    await waitFor(() =>
      expect(
        queryClient
          .getQueryCache()
          .findAll({ queryKey: ['QuarantineEntriesController_preview_v1'] }),
      ).toHaveLength(0),
    );
    await expand(user);
    expect(
      await screen.findByRole('button', { name: 'Show sanitized preview' }),
    ).toBeInTheDocument();
    expect(screen.queryByTestId('preview-text')).not.toBeInTheDocument();
    expect(calls('QuarantineEntriesController_preview_v1')).toHaveLength(1);
  });

  it('release reuses its Idempotency-Key on retry and shows the approval outcome', async () => {
    const keys: string[] = [];
    let attempt = 0;
    const { user } = renderQuarantine('organization_admin', {
      QuarantineEntriesController_release_v1: ({ request, body }) => {
        keys.push(request.headers.get('idempotency-key') ?? '');
        expectRequestMatchesContract('QuarantineEntriesController_release_v1', body);
        attempt += 1;
        return attempt === 1
          ? apiErrorJson(503, 'service_unavailable', 'Try again', { requestId: 'req-q-503' })
          : okJson(
              {
                outcome: 'approval_requested',
                entryId: ENTRY_ID,
                state: 'pending_approval',
                approvalRequestId: APPROVAL_ID,
                approvalReasons: ['hard_block'],
                rowVersion: 3,
              },
              202,
            );
      },
    });
    await expand(user);
    await user.click(await screen.findByRole('button', { name: 'Release' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.type(
      within(dialog).getByLabelText('Reason (required)'),
      'Confirmed with the sender',
    );
    await user.click(within(dialog).getByRole('button', { name: 'Release' }));
    expect(await within(dialog).findByText('Code: service_unavailable')).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Retry the same request' }));
    await waitFor(() => expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument());
    expect(keys).toHaveLength(2);
    expect(keys[1]).toBe(keys[0]);
    expect(await screen.findByText('Approval requested')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Open the approval request' })).toHaveAttribute(
      'href',
      `/quarantine/approvals/${APPROVAL_ID}`,
    );
  });

  it.each([
    ['quarantine_rescan_required', 409, /must be rescanned first/],
    ['quarantine_approval_forbidden', 403, /Separation of duties/],
  ] as const)('%s is explained in the dialog', async (code, status, text) => {
    const { user } = renderQuarantine('organization_admin', {
      QuarantineEntriesController_release_v1: () =>
        apiErrorJson(status, code, code, { extra: { staleness: 'verdict_too_old' } }),
    });
    await expand(user);
    await user.click(await screen.findByRole('button', { name: 'Release' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.type(within(dialog).getByLabelText('Reason (required)'), 'Release it');
    await user.click(within(dialog).getByRole('button', { name: 'Release' }));
    expect(await within(dialog).findByText(text)).toBeInTheDocument();
    expect(within(dialog).getByText(`Code: ${code}`)).toBeInTheDocument();
  });

  it('a row-version conflict reloads the entry', async () => {
    const { user, calls } = renderQuarantine('organization_admin', {
      QuarantineEntriesController_reject_v1: () =>
        apiErrorJson(409, 'quarantine_version_conflict', 'The entry changed', {
          extra: { currentRowVersion: 5 },
        }),
    });
    await expand(user);
    await user.click(await screen.findByRole('button', { name: 'Reject' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.type(within(dialog).getByLabelText('Reason (required)'), 'Confirmed phishing');
    await user.click(within(dialog).getByRole('button', { name: 'Reject' }));
    expect(
      await within(dialog).findByText(/The entry changed since you opened it/),
    ).toBeInTheDocument();
    await waitFor(() =>
      expect(calls('QuarantineEntriesController_detail_v1').length).toBeGreaterThan(1),
    );
  });

  it('read-only users see the recipient masked (E8) and no action', async () => {
    const { user, container } = renderQuarantine('read_only_user', {
      QuarantineEntriesController_search_v1: () =>
        okJson({
          items: [entrySummary({ recipient: 'p***@alpha.example.test', recipientMasked: true })],
          nextCursor: null,
        }),
      QuarantineEntriesController_detail_v1: () =>
        okJson(
          entryDetail({
            recipient: 'p***@alpha.example.test',
            recipientMasked: true,
            allowedActions: [],
          }),
        ),
    });
    expect(await screen.findByText('p***@alpha.example.test')).toBeInTheDocument();
    expect(screen.getByText('(masked)')).toBeInTheDocument();
    await expand(user);
    expect(await screen.findByText(/No action is available to you/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Release' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Show sanitized preview' })).toBeNull();
    await expectNoAxeViolations(container);
  });

  it('the download goes through the 5.3 grant dialog (password required)', async () => {
    const { user } = renderQuarantine('organization_admin');
    await expand(user);
    await user.click(await screen.findByRole('button', { name: 'Download' }));
    const dialog = await screen.findByRole('dialog', { name: 'Download quarantined content' });
    expect(within(dialog).getByLabelText('Your password (required)')).toBeInTheDocument();
  });
});
