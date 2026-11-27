import { screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import {
  expectNoAxeViolations,
  expectRequestMatchesContract,
  mockApi,
  okJson,
  renderWithProviders,
} from '@/test';
import { ApprovalDetail } from './approvals';
import { EntryDetail } from './entry-detail';
import { QuarantinePage } from './quarantine-page';
import { ReleaseStatus } from './release-status';
import { SelfEntryDetail } from './self-service';
import {
  APPROVAL_ID,
  CATALOG,
  DETECTION_ID,
  ENTRY_ID,
  RELEASE_ID,
  REMEDIATION_ID,
  SUMMARY,
  approval,
  entryDetail,
  entrySummary,
  mailboxLocationView,
  releaseView,
} from './test-data';

/**
 * Step API-2 WP6 (docs/plan/steps/36-api-mode-remediation.md R10.5, R15, §9.5): mailbox-located
 * quarantine entries in the entries list (Location column and filter), the entry detail (location
 * block, detection link instead of the explorer link, "Restore to inbox"), the approval request,
 * the release status and self-service. Synthetic values only.
 */

const HISTORY = { actions: [], releases: [] };
const mailboxEntry = (over: Parameters<typeof entryDetail>[0] = {}) =>
  entryDetail({
    origin: 'api_remediation',
    location: mailboxLocationView(),
    decisive: { source: null, policyId: null, versionNo: null, ruleId: null },
    explanation: {
      lines: [],
      text: 'Removed from the mailbox by the API-mode remediation policy (rule p1-suspicious).',
    },
    ...over,
  });

describe('Quarantine entries: location (R10.5)', () => {
  it('shows the Location column and sends the location filter', async () => {
    const searches: URLSearchParams[] = [];
    mockApi({
      QuarantineToolsController_catalog_v1: () => okJson(CATALOG),
      QuarantineToolsController_summary_v1: () => okJson(SUMMARY),
      QuarantineEntriesController_search_v1: ({ url }) => {
        searches.push(url.searchParams);
        return okJson({
          items: [
            entrySummary({ location: mailboxLocationView({ container: 'junk' }) }),
            entrySummary({ id: '01933c3a-1b2c-7d4e-8f00-0000000e0002' }),
          ],
          nextCursor: null,
        });
      },
    });
    const { user, container } = renderWithProviders(<QuarantinePage />, {
      role: 'security_analyst',
      route: '/quarantine?location=mailbox',
    });
    const table = await screen.findByRole('table', { name: 'Quarantine entries' });
    expect(await within(table).findByText('Mailbox')).toBeInTheDocument();
    expect(within(table).getByText('In mailbox Junk folder')).toBeInTheDocument();
    expect(within(table).getByText('Gateway')).toBeInTheDocument();
    expect(searches.at(-1)?.get('location')).toBe('mailbox');
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('combobox', { name: 'Location' }));
    await user.click(await screen.findByRole('option', { name: 'Gateway' }));
    await waitFor(() => expect(searches.at(-1)?.get('location')).toBe('gateway'));
  });
});

describe('Quarantine entry detail: mailbox entry (R10, R15)', () => {
  it('shows the location block with the detection link (no explorer link) and restores to the inbox', async () => {
    let body: unknown = null;
    mockApi({
      QuarantineToolsController_catalog_v1: () => okJson(CATALOG),
      QuarantineEntriesController_detail_v1: () => okJson(mailboxEntry()),
      QuarantineEntriesController_history_v1: () => okJson(HISTORY),
      QuarantineEntriesController_release_v1: ({ body: b }) => {
        body = b;
        return okJson(
          {
            outcome: 'queued',
            entryId: ENTRY_ID,
            state: 'releasing',
            releaseId: RELEASE_ID,
            rowVersion: 3,
          },
          202,
        );
      },
    });
    const { user, container } = renderWithProviders(<EntryDetail entryId={ENTRY_ID} />, {
      role: 'security_analyst',
    });
    const block = await screen.findByRole('group', { name: 'Location' });
    expect(within(block).getByText('In mailbox quarantine folder')).toBeInTheDocument();
    expect(within(block).getByText('Microsoft 365')).toBeInTheDocument();
    expect(within(block).getByText('Succeeded')).toBeInTheDocument();
    expect(
      within(block).getByRole('link', { name: 'Open the API-mode detection' }),
    ).toHaveAttribute('href', `/api-mode?tab=detections&detection=${DETECTION_ID}`);
    expect(within(block).getByRole('link', { name: 'Mailbox action' })).toHaveAttribute(
      'href',
      `/api-mode?tab=history&remediation=${REMEDIATION_ID}`,
    );
    expect(screen.queryByRole('link', { name: 'Open message details' })).not.toBeInTheDocument();
    await expectNoAxeViolations(container);

    expect(screen.queryByRole('button', { name: 'Release' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Restore to inbox' }));
    const dialog = await screen.findByRole('alertdialog');
    expect(
      within(dialog).getByRole('heading', { name: 'Restore this message to the inbox?' }),
    ).toBeInTheDocument();
    expect(within(dialog).getByText(/nothing is delivered again/)).toBeInTheDocument();
    await user.type(within(dialog).getByLabelText('Reason (required)'), 'Expected invoice');
    await user.click(within(dialog).getByRole('button', { name: 'Restore to inbox' }));
    await waitFor(() => expect(body).not.toBeNull());
    expectRequestMatchesContract('QuarantineEntriesController_release_v1', body);
    expect(await screen.findByText('Restore queued.')).toBeInTheDocument();
  });

  it('explains a releasing mailbox entry and shows the detection id without the API-mode permission', async () => {
    mockApi({
      QuarantineToolsController_catalog_v1: () => okJson(CATALOG),
      QuarantineEntriesController_detail_v1: () =>
        okJson(mailboxEntry({ state: 'releasing', allowedActions: [] })),
      QuarantineEntriesController_history_v1: () => okJson(HISTORY),
    });
    renderWithProviders(<EntryDetail entryId={ENTRY_ID} />, { role: 'quarantine_reviewer' });
    expect(
      await screen.findByText(/The mailbox worker moves the message back/),
    ).toBeInTheDocument();
    const block = screen.getByRole('group', { name: 'Location' });
    expect(within(block).queryByRole('link', { name: 'Open the API-mode detection' })).toBeNull();
    expect(within(block).getByText(DETECTION_ID.slice(0, 8), { exact: false })).toBeInTheDocument();
  });
});

describe('Approval request of a mailbox entry', () => {
  it('shows where the message is and that approving restores it to the Inbox', async () => {
    mockApi({
      QuarantineToolsController_catalog_v1: () => okJson(CATALOG),
      QuarantineApprovalsController_get_v1: () =>
        okJson(approval({ kind: 'release_approval', approvalReasons: ['hard_block'] })),
      QuarantineEntriesController_detail_v1: () =>
        okJson(mailboxEntry({ state: 'pending_approval', hardBlocks: ['hb.known_phishing'] })),
    });
    const { user, container } = renderWithProviders(<ApprovalDetail approvalId={APPROVAL_ID} />, {
      role: 'security_analyst',
    });
    expect(await screen.findByText(/approving restores it to the Inbox/)).toBeInTheDocument();
    expect(screen.getByText('In mailbox quarantine folder', { exact: false })).toBeInTheDocument();
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('button', { name: 'Approve' }));
    const dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByText(/moved back to the Inbox/)).toBeInTheDocument();
  });
});

describe('Release status of a mailbox restore', () => {
  it('explains the restored status', async () => {
    mockApi({
      QuarantineToolsController_release_v1: () =>
        okJson(releaseView({ status: 'restored', revalidation: null, deliveredObject: null })),
    });
    renderWithProviders(<ReleaseStatus releaseId={RELEASE_ID} />, { role: 'security_analyst' });
    expect(
      await screen.findByText('Restored: the message was moved back to the Inbox.'),
    ).toBeInTheDocument();
  });
});

describe('Self-service: mailbox entries (R10.5)', () => {
  it('lists the location and restores the message to my inbox', async () => {
    let body: unknown = null;
    const self = mailboxLocationView({ mailboxAddress: 'mailbox_user@example.com' });
    if (self.kind === 'mailbox') delete self.connectionId;
    mockApi({
      QuarantineToolsController_catalog_v1: () => okJson(CATALOG),
      QuarantineSelfController_search_v1: () =>
        okJson({ items: [entrySummary({ location: self })], nextCursor: null }),
      QuarantineSelfController_preferences_v1: () =>
        okJson({ digestOptOut: false, allowOptOut: true }),
    });
    const list = renderWithProviders(<QuarantinePage routeTab="me" />, {
      role: 'mailbox_user',
      route: '/quarantine/me',
    });
    const table = await screen.findByRole('table', { name: 'My quarantined messages' });
    expect(await within(table).findByText('Mailbox')).toBeInTheDocument();
    expect(within(table).getByText('In mailbox quarantine folder')).toBeInTheDocument();
    await expectNoAxeViolations(list.container);
    list.unmount();

    mockApi({
      QuarantineToolsController_catalog_v1: () => okJson(CATALOG),
      QuarantineSelfController_detail_v1: () =>
        okJson(
          mailboxEntry({
            location: self,
            reason: 'spam',
            allowedActions: ['release', 'request_release'],
          }),
        ),
      QuarantineSelfController_release_v1: ({ body: b }) => {
        body = b;
        return okJson(
          {
            outcome: 'queued',
            entryId: ENTRY_ID,
            state: 'releasing',
            releaseId: RELEASE_ID,
            rowVersion: 3,
          },
          202,
        );
      },
    });
    const { user } = renderWithProviders(<SelfEntryDetail entryId={ENTRY_ID} />, {
      role: 'mailbox_user',
    });
    await user.click(await screen.findByRole('button', { name: 'Restore to my inbox' }));
    const dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByText(/back to\s+your Inbox/)).toBeInTheDocument();
    // The self view never links the API-mode detection.
    expect(screen.queryByRole('link', { name: 'Open the API-mode detection' })).toBeNull();
    await user.type(within(dialog).getByLabelText(/required/), 'I expected it');
    await user.click(within(dialog).getByRole('button', { name: 'Restore to my inbox' }));
    await waitFor(() => expect(body).not.toBeNull());
    expectRequestMatchesContract('QuarantineSelfController_release_v1', body);
  });
});
