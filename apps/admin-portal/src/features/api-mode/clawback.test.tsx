import { screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import {
  apiErrorJson,
  currentTestUrl,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  mockApi,
  okJson,
  permissionsOf,
  renderWithProviders,
} from '@/test';
import { ApiModePage } from './api-mode-page';
import { approvalNeeded } from './clawback-detail';
import { createBodyOf, progressOf, validateSearch, type SearchDraft } from './clawback-model';
import { clawbackQuery } from './purge-tab';
import {
  ACTION,
  CLAWBACK,
  CONN,
  DETECTION,
  MAILBOX,
  ME,
  OTHER_USER,
  T,
  clawback,
  clawbackRow,
  connection,
  overview,
  settings,
  target,
} from './clawback-test-data';

/**
 * Step API-3 WP6 (docs/plan/steps/37-api-mode-clawback-reporting.md C4–C7, C13, C14, §9.5): the
 * "Search & purge" tab (list, filters, progress, new search with client hints and the contract
 * body), the clawback detail (criteria, counts, hit list, submit below and above the threshold,
 * hard delete only when the platform allows it, approval with separation of duties, cancel,
 * restore with per-target results), Detections (direction, revision badge, "Claw back
 * similar…"), the coverage tiles and check titles, and the gating cases. Synthetic values only.
 */

function base(extra: Parameters<typeof mockApi>[0] = {}) {
  mockApi({
    ApiModeController_overview_v1: () => okJson(overview()),
    ApiModeController_listConnections_v1: () => okJson({ data: [connection()] }),
    ApiModeSettingsController_get_v1: () => okJson(settings()),
    ...extra,
  });
}

const draft = (over: Partial<SearchDraft> = {}): SearchDraft => ({
  kind: 'message_id',
  messageId: '<abc@mail.example.test>',
  attachmentSha256: '',
  url: '',
  sender: '',
  subject: '',
  from: '2026-11-20T09:00',
  to: '2026-11-27T09:00',
  directions: ['inbound', 'internal'],
  reason: 'Reported phishing',
  ...over,
});

describe('clawback model (client hints only; the api decides)', () => {
  it('validates the search keys and window limits and builds the body', () => {
    const now = Date.parse('2026-11-27T10:00:00Z');
    expect(validateSearch(draft(), { maxWindowDays: 31 }, now)).toEqual([]);
    expect(validateSearch(draft({ messageId: '' }), { maxWindowDays: 31 }, now)[0]).toMatch(
      /Enter the Message-ID/,
    );
    expect(
      validateSearch(
        draft({ kind: 'attachment', attachmentSha256: 'abc' }),
        { maxWindowDays: 31 },
        now,
      ),
    ).toContain('An attachment SHA-256 is 64 hexadecimal characters.');
    expect(
      validateSearch(
        draft({
          kind: 'sender_subject',
          sender: 'a@b.example.test',
          subject: 'Hi',
          from: '2026-11-19T09:00',
        }),
        { maxWindowDays: 31 },
        now,
      ),
    ).toContain('A sender and subject search spans at most 7 days.');
    expect(
      validateSearch(draft({ from: '2026-10-01T00:00' }), { maxWindowDays: 31 }, now),
    ).toContain('The window spans at most 31 days.');
    expect(
      validateSearch(
        draft({ from: '2026-01-01T00:00', to: '2026-01-02T00:00' }),
        { maxWindowDays: 31 },
        now,
      ),
    ).toContain('Copies are kept 186 days: start the window later.');
    expect(
      validateSearch(draft({ reason: ' ', directions: [] }), { maxWindowDays: 31 }, now),
    ).toEqual(['Choose inbound, internal mail or both.', 'Enter a reason.']);
    const body = createBodyOf(
      draft({ kind: 'attachment', attachmentSha256: `${'AB'.repeat(32)}\n${'cd'.repeat(32)}` }),
    );
    expect(body).toEqual({
      criteria: {
        attachmentSha256: ['ab'.repeat(32), 'cd'.repeat(32)],
        from: '2026-11-20T09:00:00.000Z',
        to: '2026-11-27T09:00:00.000Z',
      },
      directions: ['inbound', 'internal'],
      reason: 'Reported phishing',
    });
    expectRequestMatchesContract('ApiModeClawbackController_create_v1', body);
    expect(
      clawbackQuery({ status: 'ready', approvalStatus: 'pending' }, { from: T, to: T }),
    ).toEqual({
      from: T,
      to: T,
      status: 'ready',
      approvalStatus: 'pending',
    });
  });

  it('progress and the approval preview follow the counts and the threshold', () => {
    expect(progressOf({ ...clawback().counts, succeeded: 2, failed: 1 })).toMatchObject({
      done: 3,
      total: 5,
      percent: 60,
    });
    expect(approvalNeeded(clawback(), 50).needed).toBe(false);
    expect(approvalNeeded(clawback(), 2)).toMatchObject({ needed: true });
    expect(
      approvalNeeded(
        clawback({
          status: 'review_required',
          approval: { ...clawback().approval, reasons: ['auto_cap'] },
        }),
        50,
      ).reasons,
    ).toEqual(['automatic clawback above its size cap']);
  });
});

describe('/api-mode Search & purge tab (C14 #1–#4)', () => {
  it('lists clawbacks with badges, progress and filters; New search posts the contract body and opens the detail', async () => {
    const queries: string[] = [];
    const bodies: unknown[] = [];
    const running = clawback({
      status: 'running',
      counts: { ...clawback().counts, queued: 2, succeeded: 3 },
    });
    base({
      ApiModeClawbackController_list_v1: ({ url }) => {
        queries.push(url.search);
        return okJson({
          data: [
            clawbackRow(running),
            clawbackRow(
              clawback({
                id: '0193f500-0000-7000-8000-000000000002',
                trigger: 'late_verdict',
                status: 'pending_approval',
                approval: { ...clawback().approval, required: true, status: 'pending' },
              }),
            ),
          ],
          nextCursor: null,
        });
      },
      ApiModeClawbackController_create_v1: ({ body }) => {
        bodies.push(body);
        return okJson({ id: CLAWBACK, status: 'searching', trigger: 'admin', rowVersion: 1 }, 202);
      },
      ApiModeClawbackController_detail_v1: () => okJson(clawback({ status: 'searching' })),
    });
    const { user, container } = renderWithProviders(<ApiModePage />, {
      route: '/api-mode?tab=purge',
    });
    const table = await screen.findByRole('table', { name: 'Clawbacks and purges' });
    expect(within(table).getByText('Running')).toBeInTheDocument();
    expect(within(table).getByText('Waiting for approval')).toBeInTheDocument();
    expect(within(table).getByText('Late verdict')).toBeInTheDocument();
    expect(
      within(table)
        .getAllByRole('progressbar')
        .some((bar) => bar.getAttribute('aria-valuenow') === '60'),
    ).toBe(true);
    await expectNoAxeViolations(container);

    await user.click(screen.getByRole('combobox', { name: 'Approval' }));
    await user.click(await screen.findByRole('option', { name: 'Pending' }));
    await waitFor(() =>
      expect(queries.some((q) => q.includes('approvalStatus=pending'))).toBe(true),
    );

    await user.click(screen.getByRole('button', { name: 'New search' }));
    const form = await screen.findByRole('form', { name: 'New search' });
    await user.click(within(form).getByRole('button', { name: 'Search' }));
    expect(await within(form).findByText(/Enter the Message-ID/)).toBeInTheDocument();
    expect(bodies).toHaveLength(0);
    await user.type(
      within(form).getByRole('textbox', { name: 'Message-ID' }),
      '<abc123@mail.example.test>',
    );
    await user.type(within(form).getByLabelText('Reason (required)'), 'User reported it');
    await user.click(within(form).getByRole('button', { name: 'Search' }));
    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0]).toMatchObject({
      criteria: { messageId: '<abc123@mail.example.test>' },
      directions: ['inbound', 'internal'],
      reason: 'User reported it',
    });
    expectRequestMatchesContract('ApiModeClawbackController_create_v1', bodies[0]);
    await waitFor(() => expect(currentTestUrl()).toContain(`clawback=${CLAWBACK}`));
    expect(await screen.findByText(/the mailbox worker searches/)).toBeInTheDocument();
  });

  it('detail: criteria, counts and hit list; submit below the threshold queues an explicit Junk purge', async () => {
    const bodies: unknown[] = [];
    base({
      ApiModeClawbackController_detail_v1: () => okJson(clawback()),
      ApiModeClawbackController_targets_v1: () =>
        okJson({
          data: [
            target(),
            target({
              mailbox: {
                id: '0193f700-0000-7000-8000-000000000002',
                address: 'cy@alpha.example.test',
              },
              status: 'skipped',
              reasonCode: 'already_remediated',
              copyRemediationState: 'remediated',
            }),
          ],
          nextCursor: null,
        }),
      ApiModeClawbackController_submit_v1: ({ body }) => {
        bodies.push(body);
        return okJson(
          {
            id: CLAWBACK,
            status: 'queued',
            requiresApproval: false,
            approvalReasons: [],
            approvalExpiresAt: null,
            rowVersion: 3,
          },
          202,
        );
      },
    });
    const { user, container } = renderWithProviders(<ApiModePage />, {
      route: `/api-mode?tab=purge&clawback=${CLAWBACK}`,
    });
    expect(
      await screen.findByRole('heading', { name: 'Administrator search' }),
    ).toBeInTheDocument();
    expect(screen.getByText('ab12cd34ef56…')).toBeInTheDocument();
    const counts = screen.getByRole('list', { name: 'Clawback counts' });
    expect(within(counts).getByText('3 mailboxes')).toBeInTheDocument();
    const hits = await screen.findByRole('table', { name: 'Messages found by the clawback' });
    expect(within(hits).getAllByText('billing@sender-2.example.test')).toHaveLength(2);
    expect(within(hits).getAllByText('Invoice 1002 overdue')).toHaveLength(2);
    expect(
      within(hits).getByText('Already remediated with an equal or stronger action'),
    ).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Hard delete…' })).not.toBeInTheDocument();
    await expectNoAxeViolations(container);

    await user.click(screen.getByRole('button', { name: 'Submit…' }));
    const form = await screen.findByRole('form', { name: 'Submit the purge' });
    expect(within(form).getByText(/3 eligible mailboxes/)).toBeInTheDocument();
    expect(within(form).getByText(/Below the threshold/)).toBeInTheDocument();
    await user.click(within(form).getByRole('radio', { name: 'Move to Junk' }));
    await user.type(within(form).getByLabelText('Reason (required)'), 'Confirmed phishing');
    await user.click(within(form).getByRole('button', { name: 'Submit purge' }));
    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0]).toEqual({
      mode: 'explicit',
      action: 'move_junk',
      reason: 'Confirmed phishing',
      expectedRowVersion: 2,
    });
    expectRequestMatchesContract('ApiModeClawbackController_submit_v1', bodies[0]);
  });

  it('submit above the threshold says a second approver is needed; policy mode sends verdict and level; hard delete when allowed', async () => {
    const bodies: unknown[] = [];
    const hardBodies: unknown[] = [];
    base({
      ApiModeSettingsController_get_v1: () =>
        okJson(
          settings({
            settings: { ...settings().settings, purgeApprovalMailboxes: 2 },
            platform: { ...settings().platform, hardDeleteAvailable: true },
          }),
        ),
      ApiModeClawbackController_detail_v1: () => okJson(clawback()),
      ApiModeClawbackController_targets_v1: () => okJson({ data: [target()], nextCursor: null }),
      ApiModeClawbackController_submit_v1: ({ body }) => {
        bodies.push(body);
        return okJson(
          {
            id: CLAWBACK,
            status: 'pending_approval',
            requiresApproval: true,
            approvalReasons: ['mailbox_threshold'],
            approvalExpiresAt: T,
            rowVersion: 3,
          },
          202,
        );
      },
      ApiModeClawbackController_submitHardDelete_v1: ({ body }) => {
        hardBodies.push(body);
        return okJson(
          {
            id: CLAWBACK,
            status: 'pending_approval',
            requiresApproval: true,
            approvalReasons: ['hard_delete'],
            approvalExpiresAt: T,
            rowVersion: 3,
          },
          202,
        );
      },
    });
    const { user } = renderWithProviders(<ApiModePage />, {
      route: `/api-mode?tab=purge&clawback=${CLAWBACK}`,
    });
    await user.click(await screen.findByRole('button', { name: 'Submit…' }));
    const form = await screen.findByRole('form', { name: 'Submit the purge' });
    expect(within(form).getByText(/Needs a second approver/)).toBeInTheDocument();
    await user.click(within(form).getByRole('radio', { name: /Remediation policy/ }));
    await user.type(within(form).getByLabelText('Reason (required)'), 'Use the policy');
    await user.click(within(form).getByRole('button', { name: 'Submit purge' }));
    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0]).toEqual({
      mode: 'policy',
      verdict: 'phishing',
      level: 'critical',
      reason: 'Use the policy',
      expectedRowVersion: 2,
    });
    expectRequestMatchesContract('ApiModeClawbackController_submit_v1', bodies[0]);

    await user.click(await screen.findByRole('button', { name: 'Hard delete…' }));
    const dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByText(/Irreversible\./)).toBeInTheDocument();
    expect(within(dialog).getByText(/Needs a second approver/)).toBeInTheDocument();
    await user.type(within(dialog).getByRole('textbox'), 'Malware with a worm');
    await user.click(within(dialog).getByRole('button', { name: 'Request hard delete' }));
    await waitFor(() => expect(hardBodies).toHaveLength(1));
    expect(hardBodies[0]).toEqual({ reason: 'Malware with a worm', expectedRowVersion: 2 });
    expectRequestMatchesContract('ApiModeClawbackController_submitHardDelete_v1', hardBodies[0]);
  });

  it('approval: the requester sees "waiting for approval"; another purge holder approves or denies with a reason', async () => {
    const pending = {
      status: 'pending_approval' as const,
      decisionMode: 'explicit' as const,
      action: 'move_junk' as const,
      submittedBy: ME,
      submittedAt: T,
      approval: {
        required: true,
        status: 'pending' as const,
        reasons: ['mailbox_threshold' as const],
        requestedAt: T,
        expiresAt: '2026-11-30T09:00:00.000Z',
        decidedAt: null,
      },
    };
    base({
      ApiModeClawbackController_detail_v1: () =>
        okJson(
          clawback({
            ...pending,
            hints: { canSubmit: false, canApprove: false, canCancel: true, canRestore: false },
          }),
        ),
      ApiModeClawbackController_targets_v1: () => okJson({ data: [target()], nextCursor: null }),
    });
    const first = renderWithProviders(<ApiModePage />, {
      route: `/api-mode?tab=purge&clawback=${CLAWBACK}`,
    });
    expect(await screen.findByText('Waiting for approval.')).toBeInTheDocument();
    expect(screen.getByText(/You requested this purge/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument();
    expect(screen.getByText('more mailboxes than the approval threshold')).toBeInTheDocument();
    first.unmount();

    const approvals: unknown[] = [];
    const denials: unknown[] = [];
    base({
      ApiModeClawbackController_detail_v1: () =>
        okJson(
          clawback({
            ...pending,
            requestedBy: { type: 'user', userId: OTHER_USER },
            submittedBy: OTHER_USER,
            hints: { canSubmit: false, canApprove: true, canCancel: true, canRestore: false },
          }),
        ),
      ApiModeClawbackController_targets_v1: () => okJson({ data: [target()], nextCursor: null }),
      ApiModeClawbackController_approve_v1: ({ body }) => {
        approvals.push(body);
        return approvals.length === 1
          ? apiErrorJson(403, 'api_mode_purge_approval_forbidden', 'no', {
              extra: { reason: 'requester' },
            })
          : okJson(clawbackRow(clawback({ status: 'queued' })));
      },
      ApiModeClawbackController_deny_v1: ({ body }) => {
        denials.push(body);
        return okJson(clawbackRow(clawback({ status: 'denied' })));
      },
    });
    const { user, container } = renderWithProviders(<ApiModePage />, {
      route: `/api-mode?tab=purge&clawback=${CLAWBACK}`,
    });
    await user.click(await screen.findByRole('button', { name: 'Approve' }));
    let dialog = await screen.findByRole('alertdialog');
    await user.type(within(dialog).getByRole('textbox'), 'Checked the hit list');
    await user.click(within(dialog).getByRole('button', { name: 'Approve' }));
    expect(await within(dialog).findByText(/Separation of duties/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Approve' }));
    await waitFor(() => expect(approvals).toHaveLength(2));
    expect(approvals[1]).toEqual({ reason: 'Checked the hit list', expectedRowVersion: 2 });
    expectRequestMatchesContract('ApiModeClawbackController_approve_v1', approvals[1]);
    await expectNoAxeViolations(container);

    await user.click(screen.getByRole('button', { name: 'Deny' }));
    dialog = await screen.findByRole('alertdialog');
    await user.type(within(dialog).getByRole('textbox'), 'Too broad');
    await user.click(within(dialog).getByRole('button', { name: 'Deny' }));
    await waitFor(() => expect(denials).toHaveLength(1));
    expectRequestMatchesContract('ApiModeClawbackController_deny_v1', denials[0]);
  });

  it('cancel and restore with per-target restore results', async () => {
    const cancels: unknown[] = [];
    const restores: unknown[] = [];
    let restored = false;
    const completed = clawback({
      status: 'completed',
      action: 'move_quarantine',
      decisionMode: 'explicit',
      counts: { ...clawback().counts, succeeded: 4, failed: 1 },
      hints: { canSubmit: false, canApprove: false, canCancel: false, canRestore: true },
    });
    base({
      ApiModeClawbackController_detail_v1: () =>
        okJson(
          restored
            ? {
                ...completed,
                restore: {
                  status: 'completed_with_errors',
                  queued: 0,
                  succeeded: 3,
                  failed: 0,
                  skipped: 1,
                },
                hints: { ...completed.hints, canRestore: false },
              }
            : completed,
        ),
      ApiModeClawbackController_targets_v1: () =>
        okJson({
          data: restored
            ? [
                target({
                  status: 'succeeded',
                  plannedAction: 'move_quarantine',
                  remediationId: ACTION,
                  restoreStatus: 'succeeded',
                }),
                target({
                  mailbox: {
                    id: '0193f700-0000-7000-8000-000000000003',
                    address: 'dee@alpha.example.test',
                  },
                  status: 'succeeded',
                  plannedAction: 'move_quarantine',
                  restoreStatus: 'skipped',
                  restoreReasonCode: 'approval_required',
                }),
              ]
            : [
                target({
                  status: 'succeeded',
                  plannedAction: 'move_quarantine',
                  remediationId: ACTION,
                }),
              ],
          nextCursor: null,
        }),
      ApiModeClawbackController_restore_v1: ({ body }) => {
        restores.push(body);
        restored = true;
        return okJson(clawbackRow(completed), 202);
      },
      ApiModeClawbackController_cancel_v1: ({ body }) => {
        cancels.push(body);
        return okJson(clawbackRow(clawback({ status: 'cancelled' })), 202);
      },
    });
    const { user } = renderWithProviders(<ApiModePage />, {
      route: `/api-mode?tab=purge&clawback=${CLAWBACK}`,
    });
    const hits = await screen.findByRole('table', { name: 'Messages found by the clawback' });
    expect(within(hits).getByRole('link', { name: 'Mailbox action' })).toHaveAttribute(
      'href',
      `/api-mode?tab=history&remediation=${ACTION}`,
    );
    expect(within(hits).getByRole('link', { name: 'Detection' })).toHaveAttribute(
      'href',
      `/api-mode?tab=detections&detection=${DETECTION}`,
    );
    expect(screen.queryByRole('button', { name: 'Cancel clawback' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Restore…' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.type(within(dialog).getByRole('textbox'), 'False positive');
    await user.click(within(dialog).getByRole('button', { name: 'Restore' }));
    await waitFor(() => expect(restores).toHaveLength(1));
    expect(restores[0]).toEqual({ reason: 'False positive' });
    expectRequestMatchesContract('ApiModeClawbackController_restore_v1', restores[0]);
    expect(await screen.findByText(/3 restored/)).toBeInTheDocument();
    expect(await screen.findByText(/The quarantine entry needs an approver/)).toBeInTheDocument();
    expect(cancels).toHaveLength(0);
  });

  it('cancel of a ready clawback sends the reason', async () => {
    const cancels: unknown[] = [];
    base({
      ApiModeClawbackController_detail_v1: () => okJson(clawback()),
      ApiModeClawbackController_targets_v1: () => okJson({ data: [target()], nextCursor: null }),
      ApiModeClawbackController_cancel_v1: ({ body }) => {
        cancels.push(body);
        return okJson(clawbackRow(clawback({ status: 'cancelled' })), 202);
      },
    });
    const { user } = renderWithProviders(<ApiModePage />, {
      route: `/api-mode?tab=purge&clawback=${CLAWBACK}`,
    });
    await user.click(await screen.findByRole('button', { name: 'Cancel clawback' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.type(within(dialog).getByRole('textbox'), 'Wrong search');
    await user.click(within(dialog).getByRole('button', { name: 'Cancel clawback' }));
    await waitFor(() => expect(cancels).toHaveLength(1));
    expect(cancels[0]).toEqual({ reason: 'Wrong search' });
    expectRequestMatchesContract('ApiModeClawbackController_cancel_v1', cancels[0]);
  });
});

describe('Detections: direction, revision and "Claw back similar…" (C2.4, C8)', () => {
  const detectionRow = (over: Record<string, unknown> = {}) => ({
    id: DETECTION,
    mailboxId: MAILBOX,
    mailboxAddress: 'ana@alpha.example.test',
    connectionId: CONN,
    source: 'journal' as const,
    seenJournal: true,
    seenApi: false,
    status: 'scanned' as const,
    verdict: 'malware' as const,
    riskScore: 950,
    verdictAuthority: 'copy' as const,
    receivedAt: T,
    providerDeliveredAt: T,
    verdictAt: T,
    lagMs: 60_000,
    subject: null,
    subjectMasked: true,
    headerFrom: 'b•••@sender-2.example.test',
    remediationState: 'none' as const,
    remediationAction: null,
    remediationId: null,
    quarantineEntryId: null,
    direction: 'internal' as const,
    verdictRevision: 1,
    clawbacks: [] as string[],
    ...over,
  });

  it('shows the direction column and filter, the revision badge, and seeds a campaign search', async () => {
    const queries: string[] = [];
    const bodies: unknown[] = [];
    base({
      ApiModeController_listDetections_v1: ({ url }) => {
        queries.push(url.search);
        return okJson({ data: [detectionRow()], nextCursor: null });
      },
      ApiModeClawbackController_create_v1: ({ body }) => {
        bodies.push(body);
        return okJson(
          { id: CLAWBACK, status: 'searching', trigger: 'campaign', rowVersion: 1 },
          202,
        );
      },
      ApiModeClawbackController_detail_v1: () =>
        okJson(clawback({ status: 'searching', trigger: 'campaign' })),
    });
    const { user, container } = renderWithProviders(<ApiModePage />, {
      route: '/api-mode?tab=detections',
    });
    const table = await screen.findByRole('table', { name: 'Detections of API-mode copies' });
    expect(within(table).getByText('Internal')).toBeInTheDocument();
    expect(within(table).getByText('Revised')).toBeInTheDocument();
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('combobox', { name: 'Direction' }));
    await user.click(await screen.findByRole('option', { name: 'Internal' }));
    await waitFor(() => expect(queries.some((q) => q.includes('direction=internal'))).toBe(true));

    await user.click(within(table).getByRole('button', { name: /^Actions for / }));
    await user.click(await screen.findByRole('menuitem', { name: 'Claw back similar…' }));
    const form = await screen.findByRole('form', { name: 'Claw back similar messages' });
    await user.click(within(form).getByLabelText('With the same attachments (SHA-256)'));
    await user.click(within(form).getByLabelText('From the same sender with the same subject'));
    await user.clear(within(form).getByLabelText('Hours before and after (1–168)'));
    await user.type(within(form).getByLabelText('Hours before and after (1–168)'), '48');
    await user.type(within(form).getByLabelText('Reason (required)'), 'Same campaign');
    await user.click(within(form).getByRole('button', { name: 'Search' }));
    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0]).toEqual({
      seedDetectionId: DETECTION,
      expand: { attachments: true, senderSubjectHours: 48 },
      reason: 'Same campaign',
    });
    expectRequestMatchesContract('ApiModeClawbackController_create_v1', bodies[0]);
    await waitFor(() => expect(currentTestUrl()).toBe(`/api-mode?tab=purge&clawback=${CLAWBACK}`));
  });

  it('a user without remediation:purge gets no "Claw back similar…"', async () => {
    base({
      ApiModeController_listDetections_v1: () =>
        okJson({ data: [detectionRow()], nextCursor: null }),
    });
    const { user } = renderWithProviders(<ApiModePage />, {
      permissions: permissionsOf('organization_admin').filter((p) => p !== 'remediation:purge'),
      route: '/api-mode?tab=detections',
    });
    const table = await screen.findByRole('table', { name: 'Detections of API-mode copies' });
    await user.click(within(table).getByRole('button', { name: /^Actions for / }));
    expect(await screen.findByRole('menuitem', { name: 'Details' })).toBeInTheDocument();
    expect(screen.queryByRole('menuitem', { name: 'Claw back similar…' })).not.toBeInTheDocument();
  });
});

describe('Coverage: clawback and report tiles, check titles (C13)', () => {
  it('shows internal copies, clawbacks and reports and the two new check titles', async () => {
    base({
      ApiModeController_overview_v1: () =>
        okJson(overview(['clawback.stalled', 'reports.backlog'])),
    });
    const { container } = renderWithProviders(<ApiModePage />, { route: '/api-mode' });
    const tiles = await screen.findByRole('list', { name: 'Clawback and reports summary' });
    expect(within(tiles).getByText('14')).toBeInTheDocument();
    expect(within(tiles).getByText(/1 awaiting review · 1 awaiting approval/)).toBeInTheDocument();
    expect(within(tiles).getByText(/37 messages removed · 2 failed/)).toBeInTheDocument();
    expect(within(tiles).getByText(/oldest 2\.0 h/)).toBeInTheDocument();
    const table = screen.getByRole('table');
    expect(
      within(table).getByText('Clawback stalled (queued or running without progress)'),
    ).toBeInTheDocument();
    expect(within(table).getByText('Reported messages waiting for triage')).toBeInTheDocument();
    await expectNoAxeViolations(container);
  });
});

describe('Search & purge gating', () => {
  it('read-only users see clawbacks and the detail without any write control', async () => {
    base({
      ApiModeClawbackController_list_v1: () => okJson({ data: [clawbackRow()], nextCursor: null }),
      ApiModeClawbackController_detail_v1: () =>
        okJson(
          clawback({
            hints: { canSubmit: false, canApprove: false, canCancel: false, canRestore: false },
          }),
        ),
      ApiModeClawbackController_targets_v1: () =>
        okJson({
          data: [
            target({
              mailbox: { id: MAILBOX, address: 'a•••@alpha.example.test' },
              headerFrom: null,
              subject: null,
            }),
          ],
          nextCursor: null,
        }),
    });
    const { user } = renderWithProviders(<ApiModePage />, {
      role: 'read_only_user',
      route: '/api-mode?tab=purge',
    });
    await screen.findByRole('table', { name: 'Clawbacks and purges' });
    expect(screen.queryByRole('button', { name: 'New search' })).not.toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Reports' })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Settings' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /open the clawback/ }));
    const hits = await screen.findByRole('table', { name: 'Messages found by the clawback' });
    expect(within(hits).getByText('a•••@alpha.example.test')).toBeInTheDocument();
    expect(within(hits).queryByText('Sender and subject')).not.toBeInTheDocument();
    for (const name of ['Submit…', 'Hard delete…', 'Cancel clawback', 'Restore…', 'Approve'])
      expect(screen.queryByRole('button', { name })).not.toBeInTheDocument();
  });

  it('a user without remediation:purge sees the list but no "New search"', async () => {
    base({
      ApiModeClawbackController_list_v1: () => okJson({ data: [clawbackRow()], nextCursor: null }),
    });
    renderWithProviders(<ApiModePage />, {
      permissions: permissionsOf('organization_admin').filter((p) => p !== 'remediation:purge'),
      route: '/api-mode?tab=purge',
    });
    await screen.findByRole('table', { name: 'Clawbacks and purges' });
    expect(screen.queryByRole('button', { name: 'New search' })).not.toBeInTheDocument();
  });

  it('a user without remediation:read has none of the new tabs', async () => {
    base();
    renderWithProviders(<ApiModePage />, {
      role: 'quarantine_reviewer',
      route: '/api-mode?tab=purge',
    });
    await waitFor(() =>
      expect(screen.queryByRole('tab', { name: 'Search & purge' })).not.toBeInTheDocument(),
    );
    expect(screen.queryByRole('tab', { name: 'Reports' })).not.toBeInTheDocument();
  });
});
