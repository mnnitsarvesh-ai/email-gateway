import { screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import {
  apiErrorJson,
  currentTestUrl,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  mockApi,
  okJson,
  renderWithProviders,
} from '@/test';
import { ApiModePage } from './api-mode-page';
import { expandBodyOf, validateExpand } from './clawback-dialogs';
import { reportQuery } from './reports-tab';
import {
  CLAWBACK,
  DETECTION,
  REPORT,
  REPORT_2,
  REPORT_MAILBOX,
  T,
  clawback,
  connection,
  overview,
  report,
  reportMailbox,
  reportRow,
  settings,
} from './clawback-test-data';

/**
 * Step API-3 WP6 (C9–C12, C14 #11–#19, §9.5): the Reports tab (queue and filters, drawer with the
 * untrusted original keys, detection link, group and history, Start review, Resolve with verdict,
 * feedback and group, Reject, "Claw back this message…") and the Settings tab (organization
 * settings with bounds and CAS conflict handling, report mailboxes: add by address, designate,
 * remove, limit), with the read-only gating. Synthetic values only.
 */

function base(extra: Parameters<typeof mockApi>[0] = {}) {
  mockApi({
    ApiModeController_overview_v1: () => okJson(overview()),
    ApiModeController_listConnections_v1: () => okJson({ data: [connection()] }),
    ApiModeSettingsController_get_v1: () => okJson(settings()),
    ...extra,
  });
}

describe('report helpers', () => {
  it('builds the list query and the expand body', () => {
    expect(
      reportQuery(
        { status: 'pending_triage', verdict: 'malicious', reporter: ' Ben@Alpha.example.test ' },
        { from: T, to: T },
      ),
    ).toEqual({
      from: T,
      to: T,
      status: 'pending_triage',
      analystVerdict: 'malicious',
      reporter: 'ben@alpha.example.test',
    });
    const draft = {
      attachments: true,
      urls: false,
      senderSubject: true,
      hours: '200',
      reason: 'x',
    };
    expect(validateExpand(draft)).toEqual(['The sender and subject window is 1 to 168 hours.']);
    expect(expandBodyOf({ ...draft, hours: '24' })).toEqual({
      expand: { attachments: true, senderSubjectHours: 24 },
      reason: 'x',
    });
    expect(expandBodyOf({ ...draft, attachments: false, senderSubject: false })).toEqual({
      reason: 'x',
    });
  });
});

describe('/api-mode Reports tab (C11, C14 #11–#14)', () => {
  it('queue with filters and group size; the drawer shows untrusted original keys, links, group and feedback', async () => {
    const queries: string[] = [];
    base({
      ApiModeReportsController_list_v1: ({ url }) => {
        queries.push(url.search);
        return okJson({ data: [reportRow()], nextCursor: null });
      },
      ApiModeReportsController_detail_v1: () =>
        okJson(
          report({
            history: [
              {
                at: T,
                actor: { type: 'user', userId: null },
                from: 'pending_triage',
                to: 'in_review',
                verdict: null,
                reopened: false,
              },
            ],
          }),
        ),
    });
    const { user, container } = renderWithProviders(<ApiModePage />, {
      route: '/api-mode?tab=reports',
    });
    const table = await screen.findByRole('table', { name: 'Reported messages' });
    expect(within(table).getByText('ben@alpha.example.test')).toBeInTheDocument();
    expect(within(table).getByText('Waiting for triage')).toBeInTheDocument();
    expect(within(table).getByText('Malicious (hint)')).toBeInTheDocument();
    expect(within(table).getByText('2')).toBeInTheDocument();
    await expectNoAxeViolations(container);

    await user.click(screen.getByRole('combobox', { name: 'Assessment' }));
    await user.click(await screen.findByRole('option', { name: 'Malicious' }));
    await waitFor(() => expect(queries.some((q) => q.includes('assessment=malicious'))).toBe(true));
    await user.type(screen.getByLabelText('Reporter address'), 'ben@alpha.example.test');
    await user.click(screen.getByRole('button', { name: 'Filter' }));
    await waitFor(() =>
      expect(queries.some((q) => q.includes('reporter=ben%40alpha.example.test'))).toBe(true),
    );

    await user.click(within(table).getByRole('button', { name: /open the report/ }));
    const drawer = await screen.findByRole('dialog', { name: 'Reported message' });
    expect(within(drawer).getByText(/untrusted text, shown as data/)).toBeInTheDocument();
    expect(within(drawer).getByText('invoice 1002 overdue')).toBeInTheDocument();
    expect(within(drawer).getByText('Forwarded as an attachment')).toBeInTheDocument();
    expect(within(drawer).getByRole('link', { name: 'Open the detection' })).toHaveAttribute(
      'href',
      `/api-mode?tab=detections&detection=${DETECTION}`,
    );
    expect(within(drawer).getByText('chen@alpha.example.test')).toBeInTheDocument();
    expect(
      within(drawer).getByText(/Acknowledgement: Queued · Result: Not sent/),
    ).toBeInTheDocument();
    expect(within(drawer).getByText(/Pending triage → In review/)).toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('Start review, then Resolve malicious with feedback for the group (CAS row version)', async () => {
    const bodies: unknown[] = [];
    let status: 'pending_triage' | 'in_review' = 'pending_triage';
    base({
      ApiModeSettingsController_get_v1: () =>
        okJson(settings({ settings: { ...settings().settings, reportFeedbackEnabled: false } })),
      ApiModeReportsController_list_v1: () => okJson({ data: [reportRow()], nextCursor: null }),
      ApiModeReportsController_detail_v1: () =>
        okJson(report({ status, rowVersion: status === 'pending_triage' ? 2 : 3 })),
      ApiModeReportsController_triage_v1: ({ body }) => {
        bodies.push(body);
        status = 'in_review';
        return okJson({
          report: reportRow(report({ status })),
          groupResolved: 2,
          feedbackQueued: 2,
        });
      },
    });
    const { user } = renderWithProviders(<ApiModePage />, {
      route: `/api-mode?tab=reports&report=${REPORT}`,
    });
    const drawer = await screen.findByRole('dialog', { name: 'Reported message' });
    await user.click(await within(drawer).findByRole('button', { name: 'Start review' }));
    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0]).toEqual({ status: 'in_review', expectedRowVersion: 2 });
    expectRequestMatchesContract('ApiModeReportsController_triage_v1', bodies[0]);
    await within(drawer).findByText('In review');

    await user.click(within(drawer).getByRole('button', { name: 'Resolve…' }));
    const form = await screen.findByRole('form', { name: 'Resolve the report' });
    // The settings default (feedback off) preselects "Notify the reporter".
    expect(within(form).getByRole('checkbox', { name: 'Notify the reporter' })).not.toBeChecked();
    expect(
      within(form).getByRole('checkbox', { name: 'Apply to all 2 reports of this message' }),
    ).toBeChecked();
    await user.click(within(form).getByRole('button', { name: 'Resolve' }));
    expect(await within(form).findByText('Choose a verdict.')).toBeInTheDocument();
    await user.click(within(form).getByRole('radio', { name: 'Malicious' }));
    await user.click(within(form).getByRole('checkbox', { name: 'Notify the reporter' }));
    await user.type(within(form).getByLabelText('Note (optional)'), 'Credential phishing');
    await user.click(within(form).getByRole('button', { name: 'Resolve' }));
    await waitFor(() => expect(bodies).toHaveLength(2));
    expect(bodies[1]).toEqual({
      status: 'resolved',
      verdict: 'malicious',
      note: 'Credential phishing',
      notifyReporter: true,
      applyToGroup: true,
      expectedRowVersion: 3,
    });
    expectRequestMatchesContract('ApiModeReportsController_triage_v1', bodies[1]);
  });

  it('a state conflict is explained; Reject sends the note; Claw back this message opens the new clawback', async () => {
    const bodies: unknown[] = [];
    const clawbacks: unknown[] = [];
    base({
      ApiModeReportsController_list_v1: () => okJson({ data: [reportRow()], nextCursor: null }),
      ApiModeReportsController_detail_v1: () => okJson(report({ status: 'in_review' })),
      ApiModeReportsController_triage_v1: ({ body }) => {
        bodies.push(body);
        return bodies.length === 1
          ? apiErrorJson(409, 'api_mode_report_state_conflict', 'stale', {
              extra: { status: 'resolved', currentRowVersion: 5 },
            })
          : okJson({
              report: reportRow(report({ status: 'rejected' })),
              groupResolved: 0,
              feedbackQueued: 0,
            });
      },
      ApiModeReportsController_clawback_v1: ({ body }) => {
        clawbacks.push(body);
        return okJson(
          { reportId: REPORT, clawbackId: CLAWBACK, status: 'searching', trigger: 'report' },
          202,
        );
      },
      ApiModeClawbackController_detail_v1: () =>
        okJson(clawback({ status: 'searching', trigger: 'report' })),
    });
    const { user } = renderWithProviders(<ApiModePage />, {
      route: `/api-mode?tab=reports&report=${REPORT}`,
    });
    const drawer = await screen.findByRole('dialog', { name: 'Reported message' });
    await user.click(await within(drawer).findByRole('button', { name: 'Reject…' }));
    const form = await screen.findByRole('form', { name: 'Reject the report' });
    await user.type(within(form).getByLabelText('Note (optional)'), 'Newsletter');
    await user.click(within(form).getByRole('button', { name: 'Reject' }));
    expect(
      await within(form).findByText(/The report changed since you opened it/),
    ).toBeInTheDocument();
    await user.click(within(form).getByRole('button', { name: 'Reject' }));
    await waitFor(() => expect(bodies).toHaveLength(2));
    expect(bodies[1]).toEqual({ status: 'rejected', note: 'Newsletter', expectedRowVersion: 2 });
    expectRequestMatchesContract('ApiModeReportsController_triage_v1', bodies[1]);

    await user.click(within(drawer).getByRole('button', { name: 'Claw back this message…' }));
    const claw = await screen.findByRole('form', { name: 'Claw back the reported message' });
    await user.click(within(claw).getByLabelText('With the same URLs'));
    await user.type(within(claw).getByLabelText('Reason (required)'), 'Confirmed phishing');
    await user.click(within(claw).getByRole('button', { name: 'Search' }));
    await waitFor(() => expect(clawbacks).toHaveLength(1));
    expect(clawbacks[0]).toEqual({ expand: { urls: true }, reason: 'Confirmed phishing' });
    expectRequestMatchesContract('ApiModeReportsController_clawback_v1', clawbacks[0]);
    await waitFor(() => expect(currentTestUrl()).toBe(`/api-mode?tab=purge&clawback=${CLAWBACK}`));
  });

  it('read-only users see the queue and the drawer without triage actions', async () => {
    base({
      ApiModeReportsController_list_v1: () => okJson({ data: [reportRow()], nextCursor: null }),
      ApiModeReportsController_detail_v1: () => okJson(report()),
    });
    renderWithProviders(<ApiModePage />, {
      role: 'read_only_user',
      route: `/api-mode?tab=reports&report=${REPORT_2}`,
    });
    const drawer = await screen.findByRole('dialog', { name: 'Reported message' });
    await within(drawer).findByText('Forwarded as an attachment');
    for (const name of ['Start review', 'Resolve…', 'Reject…', 'Claw back this message…'])
      expect(within(drawer).queryByRole('button', { name })).not.toBeInTheDocument();
  });
});

describe('/api-mode Settings tab (C14 #15–#19)', () => {
  it('saves the organization settings with a reason (CAS null), checks bounds and handles a conflict', async () => {
    const bodies: Array<{ expectedRowVersion: number | null }> = [];
    let reads = 0;
    base({
      ApiModeSettingsController_get_v1: () => {
        reads += 1;
        return okJson(
          reads === 1 ? settings() : settings({ source: 'row', rowVersion: 4, updatedAt: T }),
        );
      },
      ApiModeReportsController_listMailboxes_v1: () => okJson({ data: [reportMailbox()], max: 5 }),
      ApiModeSettingsController_put_v1: ({ body }) => {
        bodies.push(body as { expectedRowVersion: number | null });
        return bodies.length === 1
          ? apiErrorJson(409, 'api_mode_settings_conflict', 'stale', {
              extra: { currentRowVersion: 4 },
            })
          : okJson({
              ...settings({ source: 'row', rowVersion: 5, updatedAt: T }),
              changed: ['purgeApprovalMailboxes', 'autoClawback'],
              created: false,
            });
      },
    });
    const { user, container } = renderWithProviders(<ApiModePage />, {
      route: '/api-mode?tab=settings',
    });
    const form = await screen.findByRole('form', { name: 'Organization settings' });
    expect(
      screen.getByText('No settings of your own yet: the defaults apply.'),
    ).toBeInTheDocument();
    await expectNoAxeViolations(container);
    const threshold = within(form).getByLabelText('Purge approval threshold (mailboxes)');
    await user.clear(threshold);
    await user.type(threshold, '0');
    await user.type(within(form).getByLabelText('Reason (required)'), 'Smaller tenant');
    await user.click(within(form).getByRole('button', { name: 'Save settings' }));
    expect(
      await within(form).findByText(
        'Purge approval threshold (mailboxes): a whole number from 1 to 10000.',
      ),
    ).toBeInTheDocument();
    expect(bodies).toHaveLength(0);
    await user.clear(threshold);
    await user.type(threshold, '20');
    await user.click(within(form).getByRole('radio', { name: /^Review:/ }));
    await user.click(within(form).getByRole('switch', { name: 'Protect internal mail' }));
    await user.click(within(form).getByRole('button', { name: 'Save settings' }));
    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0]).toEqual({
      internalMailEnabled: false,
      autoClawback: 'review',
      autoMaxMailboxes: 500,
      purgeApprovalMailboxes: 20,
      clawbackLookbackDays: 14,
      tiMinConfidence: 80,
      reportAckEnabled: true,
      reportFeedbackEnabled: true,
      policyEvaluationEnabled: true,
      outboundDetectionEnabled: true,
      reason: 'Smaller tenant',
      expectedRowVersion: null,
    });
    expectRequestMatchesContract('ApiModeSettingsController_put_v1', bodies[0]);
    expect(await within(form).findByText(/changed by someone else/)).toBeInTheDocument();
    await waitFor(() => expect(reads).toBeGreaterThanOrEqual(2));
    // The draft is kept; the next save uses the reloaded row version.
    expect(within(form).getByLabelText('Purge approval threshold (mailboxes)')).toHaveValue('20');
    await user.click(within(form).getByRole('button', { name: 'Save settings' }));
    await waitFor(() => expect(bodies).toHaveLength(2));
    expect(bodies[1]).toMatchObject({ purgeApprovalMailboxes: 20, expectedRowVersion: 4 });
  });

  it('report mailboxes: add by address, designate an existing mailbox, remove', async () => {
    const adds: unknown[] = [];
    const sets: Array<{ path: string; body: unknown }> = [];
    base({
      ApiModeReportsController_listMailboxes_v1: () => okJson({ data: [reportMailbox()], max: 5 }),
      ApiModeController_listMailboxes_v1: () =>
        okJson({
          data: [
            {
              id: '0193f700-0000-7000-8000-000000000005',
              connectionId: '0193f400-0000-7000-8000-000000000001',
              address: 'shared-report@alpha.example.test',
              domain: { id: '0193fe00-0000-7000-8000-000000000001', name: 'alpha.example.test' },
              status: 'disabled',
              coverage: 'covered',
              coverageChangedAt: T,
              feedStatus: 'off',
              journalLastSeenAt: null,
              lastSyncAt: null,
              lastErrorCode: null,
            },
          ],
          nextCursor: null,
        }),
      ApiModeReportsController_addMailbox_v1: ({ body }) => {
        adds.push(body);
        return adds.length === 1
          ? apiErrorJson(422, 'api_mode_report_address_out_of_scope', 'no')
          : okJson({ mailbox: reportMailbox(), created: true, changed: true });
      },
      ApiModeReportsController_setMailbox_v1: ({ params, body }) => {
        sets.push({ path: String(params.mailboxId), body });
        return okJson({ mailbox: reportMailbox(), created: false, changed: true });
      },
    });
    const { user } = renderWithProviders(<ApiModePage />, { route: '/api-mode?tab=settings' });
    const table = await screen.findByRole('table', { name: 'Report mailboxes' });
    expect(within(table).getByText('report-phish@alpha.example.test')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Add by address' }));
    const form = await screen.findByRole('form', { name: 'Add a report mailbox' });
    await user.type(within(form).getByLabelText('Mailbox address'), 'report@other.example.test');
    await user.type(within(form).getByLabelText('Reason (required)'), 'New mailbox');
    await user.click(within(form).getByRole('button', { name: 'Add report mailbox' }));
    expect(
      await within(form).findByText(/not a mailbox of a domain in API or Hybrid mode/),
    ).toBeInTheDocument();
    await user.click(within(form).getByRole('button', { name: 'Add report mailbox' }));
    await waitFor(() => expect(adds).toHaveLength(2));
    expect(adds[1]).toEqual({ address: 'report@other.example.test', reason: 'New mailbox' });
    expectRequestMatchesContract('ApiModeReportsController_addMailbox_v1', adds[1]);

    await user.click(screen.getByRole('button', { name: 'Designate a mailbox' }));
    let dialog = await screen.findByRole('alertdialog');
    await within(dialog).findByText('shared-report@alpha.example.test');
    await user.type(within(dialog).getByRole('textbox'), 'Shared mailbox for reports');
    await user.click(within(dialog).getByRole('button', { name: 'Designate' }));
    await waitFor(() => expect(sets).toHaveLength(1));
    expect(sets[0]).toEqual({
      path: '0193f700-0000-7000-8000-000000000005',
      body: { enabled: true, reason: 'Shared mailbox for reports' },
    });
    expectRequestMatchesContract('ApiModeReportsController_setMailbox_v1', sets[0]!.body);

    await user.click(
      within(table).getByRole('button', {
        name: 'Remove report mailbox report-phish@alpha.example.test',
      }),
    );
    dialog = await screen.findByRole('alertdialog');
    await user.type(within(dialog).getByRole('textbox'), 'Not needed');
    await user.click(within(dialog).getByRole('button', { name: 'Remove' }));
    await waitFor(() => expect(sets).toHaveLength(2));
    expect(sets[1]).toEqual({
      path: REPORT_MAILBOX,
      body: { enabled: false, reason: 'Not needed' },
    });
  });

  it('read-only users see the values without the form; the limit disables adding', async () => {
    base({
      ApiModeReportsController_listMailboxes_v1: () => okJson({ data: [reportMailbox()], max: 1 }),
    });
    const first = renderWithProviders(<ApiModePage />, {
      role: 'read_only_user',
      route: '/api-mode?tab=settings',
    });
    expect(await screen.findByText('Automatic clawback')).toBeInTheDocument();
    expect(screen.queryByRole('form', { name: 'Organization settings' })).not.toBeInTheDocument();
    await screen.findByRole('table', { name: 'Report mailboxes' });
    expect(screen.queryByRole('button', { name: /^Remove/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Add by address' })).not.toBeInTheDocument();
    first.unmount();

    base({
      ApiModeReportsController_listMailboxes_v1: () => okJson({ data: [reportMailbox()], max: 1 }),
    });
    renderWithProviders(<ApiModePage />, { route: '/api-mode?tab=settings' });
    expect(
      await screen.findByText(/The limit of 1 report mailboxes is reached/),
    ).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Add by address' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Designate a mailbox' })).toBeDisabled();
  });
});
