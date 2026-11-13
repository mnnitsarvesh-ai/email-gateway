import { screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { expectNoInjectedMarkup } from '@/features/messages/test-data';
import {
  apiErrorJson,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  makeMe,
  mockApi,
  okJson,
  renderWithProviders,
} from '@/test';
import { downloadNavigation } from './download-dialog';
import { EntryDetail } from './entry-detail';
import { downloadGrantBody } from './forms';
import { APPROVAL_ID, CATALOG, ENTRY_ID, HOSTILE, entryDetail, preview } from './test-data';

const HISTORY = {
  actions: [
    {
      action: 'quarantine',
      actor: { type: 'system' as const, id: null },
      result: 'held',
      reason: null,
      at: '2026-11-12T09:14:08.000Z',
    },
    {
      action: 'view',
      actor: { type: 'user' as const, id: 'u-1' },
      result: null,
      reason: '<b>checked</b>',
      at: '2026-11-12T10:00:00.000Z',
    },
  ],
  releases: [],
};

function mockEntry(detail = entryDetail(), extra: Parameters<typeof mockApi>[0] = {}) {
  mockApi({
    QuarantineToolsController_catalog_v1: () => okJson(CATALOG),
    QuarantineEntriesController_detail_v1: ({ params }) =>
      params.entryId === ENTRY_ID
        ? okJson(detail)
        : apiErrorJson(404, 'quarantine_entry_not_found', 'Not found', { requestId: 'req-404' }),
    QuarantineEntriesController_history_v1: () => okJson(HISTORY),
    ...extra,
  });
}

describe('Quarantine entry (/quarantine/[entryId])', () => {
  it('shows metadata, explanation, history and the hard-block state; passes axe', async () => {
    mockEntry(entryDetail({ subject: HOSTILE, hardBlocks: ['hb.malware_attachment'] }));
    const { container } = renderWithProviders(<EntryDetail entryId={ENTRY_ID} />, {
      role: 'security_analyst',
    });
    expect(await screen.findByText(/window.__pwned/)).toBeInTheDocument();
    expect(screen.getByText(/Hard block\./)).toBeInTheDocument();
    expect(screen.getByText(/Quarantined by rule block-high-risk/)).toBeInTheDocument();
    expect(await screen.findByText('<b>checked</b>')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Open message details' })).toHaveAttribute(
      'href',
      '/messages/01933c3a-1b2c-7d4e-8f00-00000000a001',
    );
    expectNoInjectedMarkup(container);
    await expectNoAxeViolations(container);
  });

  it('explains a pending approval and links to it', async () => {
    mockEntry(
      entryDetail({
        state: 'pending_approval',
        approvalRequestId: APPROVAL_ID,
        allowedActions: ['reject'],
      }),
    );
    renderWithProviders(<EntryDetail entryId={ENTRY_ID} />, { role: 'security_analyst' });
    expect(await screen.findByRole('link', { name: 'Open the approval request' })).toHaveAttribute(
      'href',
      `/quarantine/approvals/${APPROVAL_ID}`,
    );
    expect(screen.queryByRole('button', { name: 'Release' })).not.toBeInTheDocument();
  });

  it('releases with a contract body and Idempotency-Key; a retry reuses the key', async () => {
    const keys: (string | null)[] = [];
    const bodies: unknown[] = [];
    let calls = 0;
    mockEntry(entryDetail(), {
      QuarantineEntriesController_release_v1: ({ body, request }) => {
        keys.push(request.headers.get('idempotency-key'));
        bodies.push(body);
        calls += 1;
        if (calls === 1)
          return apiErrorJson(500, 'internal_error', 'Boom', { requestId: 'req-r-1' });
        return okJson(
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
    const { user } = renderWithProviders(<EntryDetail entryId={ENTRY_ID} />, {
      role: 'security_analyst',
    });
    await user.click(await screen.findByRole('button', { name: 'Release' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.type(within(dialog).getByLabelText(/Reason/), 'Verified with the sender');
    await user.click(within(dialog).getByRole('button', { name: 'Release' }));
    expect(await within(dialog).findByText(/req-r-1/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Retry the same request' }));
    await waitFor(() => expect(calls).toBe(2));
    expect(keys[0]).toBeTruthy();
    expect(keys[1]).toBe(keys[0]);
    expect(bodies[0]).toEqual({ reason: 'Verified with the sender', expectedRowVersion: 2 });
    expectRequestMatchesContract('QuarantineEntriesController_release_v1', bodies[0]);
    expect(await screen.findByText(/Approval requested/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Open the approval request' })).toHaveAttribute(
      'href',
      `/quarantine/approvals/${APPROVAL_ID}`,
    );
  });

  it('a new confirm after an error is a new intent with a new key', async () => {
    const keys: (string | null)[] = [];
    mockEntry(entryDetail(), {
      QuarantineEntriesController_reject_v1: ({ request }) => {
        keys.push(request.headers.get('idempotency-key'));
        return apiErrorJson(409, 'quarantine_version_conflict', 'Changed');
      },
    });
    const { user } = renderWithProviders(<EntryDetail entryId={ENTRY_ID} />, {
      role: 'security_analyst',
    });
    await user.click(await screen.findByRole('button', { name: 'Reject' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.type(within(dialog).getByLabelText(/Reason/), 'Phishing');
    await user.click(within(dialog).getByRole('button', { name: 'Reject' }));
    expect(
      await within(dialog).findByText(/The entry changed since you opened it/),
    ).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Reject' }));
    await waitFor(() => expect(keys).toHaveLength(2));
    expect(keys[1]).not.toBe(keys[0]);
  });

  it('rejects outbound mail with notifySender and deletes with a contract body', async () => {
    const bodies: Record<string, unknown> = {};
    mockEntry(entryDetail({ direction: 'outbound' }), {
      QuarantineEntriesController_reject_v1: ({ body }) => {
        bodies.reject = body;
        return okJson({
          entryId: ENTRY_ID,
          state: 'rejected',
          rowVersion: 3,
          messageTransition: null,
          purge: 'pending',
        });
      },
      QuarantineEntriesController_delete_v1: ({ body }) => {
        bodies.delete = body;
        return apiErrorJson(409, 'quarantine_legal_hold', 'Legal hold', {
          extra: { legalHoldId: '01933c3a-1b2c-7d4e-8f00-0000000f0001' },
        });
      },
    });
    const { user } = renderWithProviders(<EntryDetail entryId={ENTRY_ID} />, {
      role: 'organization_admin',
    });
    await user.click(await screen.findByRole('button', { name: 'Reject' }));
    let dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByRole('checkbox', { name: /Notify the sender/ })).toBeChecked();
    await user.type(within(dialog).getByLabelText(/Reason/), 'Policy violation');
    await user.click(within(dialog).getByRole('button', { name: 'Reject' }));
    await waitFor(() => expect(bodies.reject).toBeDefined());
    expect(bodies.reject).toEqual({
      reason: 'Policy violation',
      notifySender: true,
      expectedRowVersion: 2,
    });
    expectRequestMatchesContract('QuarantineEntriesController_reject_v1', bodies.reject);
    await waitFor(() => expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument());

    await user.click(screen.getByRole('button', { name: 'Delete' }));
    dialog = await screen.findByRole('alertdialog');
    await user.type(within(dialog).getByLabelText(/Reason/), 'Cleanup');
    await user.click(within(dialog).getByRole('button', { name: 'Delete' }));
    expect(await within(dialog).findByText(/under a legal hold \(01933c3a/)).toBeInTheDocument();
    expectRequestMatchesContract('QuarantineEntriesController_delete_v1', bodies.delete);
  });

  it('shows the sanitized preview as text only, on demand', async () => {
    let previews = 0;
    mockEntry(entryDetail(), {
      QuarantineEntriesController_preview_v1: () => {
        previews += 1;
        return okJson(preview());
      },
    });
    const { user, container } = renderWithProviders(<EntryDetail entryId={ENTRY_ID} />, {
      role: 'security_analyst',
    });
    await user.click(await screen.findByRole('button', { name: 'Show sanitized preview' }));
    await waitFor(() => expect(previews).toBe(1));
    const text = await screen.findByTestId('preview-text');
    expect(text.tagName).toBe('PRE');
    expect(text.textContent).toContain('<script>window.__pwned = 2</script>');
    expect(text.children).toHaveLength(0);
    expect(screen.getByText(/2 sensitive values masked/)).toBeInTheDocument();
    expect(screen.getByText('hxxps://login[.]example[.]test/verify')).toBeInTheDocument();
    expect(container.querySelector('iframe')).toBeNull();
    expect(container.querySelector('a[href^="hxxp"]')).toBeNull();
    expectNoInjectedMarkup(container);
    await expectNoAxeViolations(container);
  });

  it('downloads through a grant: contract body, navigation to the BFF door, token not kept', async () => {
    const assign = vi.spyOn(downloadNavigation, 'assign').mockImplementation(() => undefined);
    let body: unknown = null;
    mockEntry(entryDetail(), {
      QuarantineEntriesController_grant_v1: ({ body: b, request }) => {
        body = b;
        expect(request.headers.get('idempotency-key')).toBeNull();
        return okJson(
          {
            token: 'qdl1.secret-token.mac',
            expiresAt: '2026-11-12T10:01:00.000Z',
            filename: 'message.eml.bin',
            sizeBytes: 4096,
            sha256: 'f'.repeat(64),
          },
          201,
        );
      },
    });
    const { user, queryClient } = renderWithProviders(<EntryDetail entryId={ENTRY_ID} />, {
      me: makeMe({ role: 'organization_admin', overrides: { mfaEnabled: true } }),
    });
    await user.click(await screen.findByRole('button', { name: 'Download' }));
    const dialog = await screen.findByRole('dialog');
    await user.click(within(dialog).getByRole('radio', { name: /One attachment/ }));
    await user.type(within(dialog).getByLabelText(/Attachment part number/), '2');
    await user.type(within(dialog).getByLabelText(/Your password/), 'correct horse battery');
    await user.click(within(dialog).getByRole('button', { name: 'Download' }));
    expect(await within(dialog).findByText(/6-digit code/)).toBeInTheDocument();
    await user.type(within(dialog).getByLabelText(/Authenticator code/), '123456');
    await user.click(within(dialog).getByRole('button', { name: 'Download' }));
    await waitFor(() =>
      expect(assign).toHaveBeenCalledWith('/bff/api/v1/quarantine/downloads/qdl1.secret-token.mac'),
    );
    expect(body).toEqual({
      object: 'attachment',
      partIndex: 2,
      password: 'correct horse battery',
      totpCode: '123456',
    });
    expectRequestMatchesContract('QuarantineEntriesController_grant_v1', body);
    const cached = JSON.stringify(
      queryClient
        .getMutationCache()
        .getAll()
        .map((m) => m.state.data),
    );
    expect(cached).not.toContain('qdl1.secret-token.mac');
    expect(
      JSON.stringify(
        queryClient
          .getQueryCache()
          .getAll()
          .map((q) => q.state.data),
      ),
    ).not.toContain('qdl1');
  });

  it('explains a failed re-authentication without navigating', async () => {
    const assign = vi.spyOn(downloadNavigation, 'assign').mockImplementation(() => undefined);
    mockEntry(entryDetail(), {
      QuarantineEntriesController_grant_v1: () =>
        apiErrorJson(401, 'quarantine_reauth_failed', 'Re-authentication failed'),
    });
    const { user } = renderWithProviders(<EntryDetail entryId={ENTRY_ID} />, {
      role: 'organization_admin',
    });
    await user.click(await screen.findByRole('button', { name: 'Download' }));
    const dialog = await screen.findByRole('dialog');
    await user.type(within(dialog).getByLabelText(/Your password/), 'wrong');
    await user.click(within(dialog).getByRole('button', { name: 'Download' }));
    expect(
      await within(dialog).findByText(/password or authenticator code is not correct/),
    ).toBeInTheDocument();
    expect(assign).not.toHaveBeenCalled();
  });

  it('builds grant bodies that match the contract', () => {
    expectRequestMatchesContract(
      'QuarantineEntriesController_grant_v1',
      downloadGrantBody({ object: 'eml', partIndex: 3, password: 'p', totpCode: '' }),
    );
    expect(downloadGrantBody({ object: 'eml', partIndex: 3, password: 'p' })).toEqual({
      object: 'eml',
      password: 'p',
    });
  });

  it('shows only the actions the role and the api allow', async () => {
    mockEntry();
    const { unmount } = renderWithProviders(<EntryDetail entryId={ENTRY_ID} />, {
      role: 'read_only_user',
    });
    await screen.findByText(/No action is available to you/);
    for (const name of ['Release', 'Request release', 'Reject', 'Delete', 'Download']) {
      expect(screen.queryByRole('button', { name })).not.toBeInTheDocument();
    }
    expect(
      screen.queryByRole('button', { name: 'Show sanitized preview' }),
    ).not.toBeInTheDocument();
    unmount();
    mockEntry();
    renderWithProviders(<EntryDetail entryId={ENTRY_ID} />, { role: 'quarantine_reviewer' });
    expect(await screen.findByRole('button', { name: 'Release' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Request release' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Reject' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Delete' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Download' })).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Show sanitized preview' }),
    ).not.toBeInTheDocument();
  });

  it('renders the not-found state for unknown and foreign ids', async () => {
    mockEntry();
    renderWithProviders(<EntryDetail entryId="01933c3a-1b2c-7d4e-8f00-0000000e00ff" />, {
      role: 'security_analyst',
    });
    expect(screen.getByText(/Loading the entry/)).toBeInTheDocument();
    const alert = await screen.findByRole('alert');
    expect(within(alert).getByText('Not found')).toBeInTheDocument();
    expect(within(alert).getByText('quarantine_entry_not_found')).toBeInTheDocument();
    expect(within(alert).getByText('req-404')).toBeInTheDocument();
  });
});
