import { screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import {
  apiErrorJson,
  currentTestUrl,
  expectNoAxeViolations,
  mockApi,
  okJson,
  renderWithProviders,
} from '@/test';
import { MessageDetail } from './message-detail';
import { ScanDetails } from './scan-details';
import {
  HOSTILE_SUBJECT,
  MESSAGE_ID,
  attachmentRow,
  evaluation,
  expectNoInjectedMarkup,
  messageDetail,
  scanRound,
  urlRow,
} from './test-data';

describe('Email details (/messages/[messageId])', () => {
  it('shows every metadata field, copyable ids, the scan link and the 7.2 tabs; passes axe', async () => {
    mockApi({
      MessagesController_detail_v1: ({ params }) =>
        params.messageId === MESSAGE_ID
          ? okJson(messageDetail({ subject: HOSTILE_SUBJECT, clientHelo: '<b>helo</b>' }))
          : apiErrorJson(404, 'message_not_found', 'Message not found'),
    });
    const { container, user } = renderWithProviders(<MessageDetail messageId={MESSAGE_ID} />, {
      role: 'security_analyst',
      route: `/messages/${MESSAGE_ID}`,
    });
    expect(await screen.findByText(/window.__pwned/)).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Email details', level: 1 })).toBeInTheDocument();
    expectNoInjectedMarkup(container);
    for (const label of [
      'Envelope sender',
      'Header From',
      'Received',
      'Direction',
      'Status',
      'Status reason',
      'Final verdict',
      'Final action',
      'Risk score',
      'Recipients',
      'Attachments',
      'Size',
      'Message ID',
      'Internet Message-ID',
      'Domain ID',
      'Lifecycle round',
      'Version',
      'Client IP',
      'Client HELO',
      'MTA queue ID',
    ]) {
      expect(screen.getByText(label, { selector: 'dt' })).toBeInTheDocument();
    }
    expect(screen.getByText('policy_quarantine')).toBeInTheDocument();
    expect(screen.getByText('198.51.100.7')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Copy message ID' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Security scan details/ })).toHaveAttribute(
      'href',
      `/messages/${MESSAGE_ID}/scans`,
    );
    expect(screen.getByRole('link', { name: /Quarantine entries/ })).toHaveAttribute(
      'href',
      `/quarantine?messageId=${MESSAGE_ID}&range=30d`,
    );
    expect(screen.getByText('Detailed view arrives in step 7.2.')).toBeInTheDocument();
    await user.click(screen.getByRole('tab', { name: 'Deliveries' }));
    await waitFor(() => expect(currentTestUrl()).toContain('tab=deliveries'));
    expect(screen.getByRole('region', { name: 'Deliveries' })).toHaveTextContent(
      'Arrives in step 7.2',
    );
    await expectNoAxeViolations(container);
  });

  it('hides the quarantine link without quarantine:read', async () => {
    mockApi({ MessagesController_detail_v1: () => okJson(messageDetail()) });
    renderWithProviders(<MessageDetail messageId={MESSAGE_ID} />, {
      permissions: ['message:read'],
    });
    await screen.findByRole('link', { name: /Security scan details/ });
    expect(screen.queryByRole('link', { name: /Quarantine entries/ })).not.toBeInTheDocument();
  });

  it('renders the not-found state for unknown or foreign ids, and loading first', async () => {
    mockApi({
      MessagesController_detail_v1: async () => {
        await new Promise((resolve) => setTimeout(resolve, 20));
        return apiErrorJson(404, 'message_not_found', 'Message not found', {
          requestId: 'req-404',
        });
      },
    });
    renderWithProviders(<MessageDetail messageId="01933c3a-1b2c-7d4e-8f00-0000000000ff" />);
    expect(screen.getByText(/Loading message/)).toBeInTheDocument();
    const alert = await screen.findByRole('alert');
    expect(within(alert).getByText('Not found')).toBeInTheDocument();
    expect(
      within(alert).getByText('It does not exist, or you do not have access to it.'),
    ).toBeInTheDocument();
    expect(within(alert).getByText('message_not_found')).toBeInTheDocument();
    expect(within(alert).getByText('req-404')).toBeInTheDocument();
  });
});

const rounds = [scanRound({ scanId: '900002', round: 1, scanKind: 'rescan' }), scanRound()];
const fixture = {
  rounds,
  attachments: [attachmentRow()],
  urls: [urlRow()],
  evaluations: [evaluation({ lifecycleRound: 1 }), evaluation()],
};
const scanPage = { messageId: MESSAGE_ID, data: fixture.rounds, nextCursor: null };

function mockScans(overrides: Parameters<typeof mockApi>[0] = {}) {
  mockApi({
    MessageScansController_scansOf_v1: () => okJson(scanPage),
    AttachmentsController_ofMessage_v1: () =>
      okJson({
        data: [
          {
            ...attachmentRow(),
            filename: '<img src=x onerror=alert(1)>.pdf',
          },
        ],
        nextCursor: null,
      }),
    UrlProtectionController_ofMessage_v1: () =>
      okJson({
        data: [
          {
            ...urlRow(),
            url: 'javascript:alert(document.domain)',
          },
        ],
        nextCursor: null,
      }),
    PolicyMessagesController_evaluations_v1: () =>
      okJson({ messageId: MESSAGE_ID, data: fixture.evaluations }),
    ...overrides,
  });
}

describe('Security scan details (/messages/[messageId]/scans)', () => {
  it('lists scan rounds with engines, auth, risk and policy; hostile symbol options stay text', async () => {
    mockScans();
    const { container } = renderWithProviders(<ScanDetails messageId={MESSAGE_ID} />, {
      route: `/messages/${MESSAGE_ID}/scans`,
    });
    const round = fixture.rounds[0];
    expect(
      await screen.findByRole('heading', { name: new RegExp(`Round ${round?.round}`) }),
    ).toBeInTheDocument();
    expect(screen.getAllByText('Authentication results').length).toBeGreaterThan(0);
    expect(screen.getAllByRole('rowheader', { name: /Rspamd/ }).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Risk score \(revision 0/).length).toBeGreaterThan(0);
    expect(screen.getAllByText('Policy decision of this round').length).toBeGreaterThan(0);
    expect(screen.getAllByText(/<b onmouseover=alert\(1\)>/).length).toBeGreaterThan(0);
    expect(
      screen.getAllByText('DLP findings are not shown here (available in step 7.2).').length,
    ).toBeGreaterThan(0);
    expect(screen.getByRole('region', { name: 'DLP evidence' })).toHaveTextContent(
      'Arrives in step 7.2',
    );
    expectNoInjectedMarkup(container);
    await expectNoAxeViolations(container);
  });

  it('shows attachments with a hash link and URLs as non-clickable text', async () => {
    mockScans();
    const { container, user } = renderWithProviders(<ScanDetails messageId={MESSAGE_ID} />, {
      route: `/messages/${MESSAGE_ID}/scans?tab=attachments`,
    });
    expect(await screen.findByText('<img src=x onerror=alert(1)>.pdf')).toBeInTheDocument();
    const sha = attachmentRow().sha256;
    expect(screen.getByRole('link', { name: 'Other messages with this file' })).toHaveAttribute(
      'href',
      `/attachments?sha256=${sha}`,
    );
    expect(screen.getByRole('button', { name: 'Copy SHA-256' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /download/i })).not.toBeInTheDocument();
    await expectNoAxeViolations(container);

    await user.click(screen.getByRole('tab', { name: 'URLs' }));
    expect(await screen.findByText('javascript:alert(document.domain)')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Copy URL' })).toBeInTheDocument();
    expect(container.querySelector('a[href^="javascript:"]')).toBeNull();
    expectNoInjectedMarkup(container);
    await expectNoAxeViolations(container);

    await user.click(screen.getByRole('tab', { name: 'Policy evaluations' }));
    expect(await screen.findAllByText('Decided by')).not.toHaveLength(0);
    await waitFor(() => expect(currentTestUrl()).toContain('tab=policy'));
    await expectNoAxeViolations(container);
  });

  it('shows empty states and errors with code and request id', async () => {
    mockScans({
      MessageScansController_scansOf_v1: () =>
        okJson({ messageId: MESSAGE_ID, data: [], nextCursor: null }),
      AttachmentsController_ofMessage_v1: () =>
        apiErrorJson(500, 'internal_error', 'Try again', { requestId: 'req-att-1' }),
    });
    const { user } = renderWithProviders(<ScanDetails messageId={MESSAGE_ID} />);
    expect(await screen.findByText('No scan rounds yet')).toBeInTheDocument();
    await user.click(screen.getByRole('tab', { name: 'Attachments' }));
    const alert = await screen.findByRole('alert');
    expect(within(alert).getByText('internal_error')).toBeInTheDocument();
    expect(within(alert).getByText('req-att-1')).toBeInTheDocument();
  });

  it('paginates scan rounds with the v0 cursor', async () => {
    const seen: (string | null)[] = [];
    mockScans({
      MessageScansController_scansOf_v1: ({ url }) => {
        seen.push(url.searchParams.get('cursor'));
        return url.searchParams.get('cursor')
          ? okJson({ messageId: MESSAGE_ID, data: rounds.slice(0, 1), nextCursor: null })
          : okJson({ messageId: MESSAGE_ID, data: rounds.slice(0, 1), nextCursor: 'MTA' });
      },
    });
    const { user } = renderWithProviders(<ScanDetails messageId={MESSAGE_ID} />);
    await screen.findByText(/Page 1/);
    await user.click(screen.getByRole('button', { name: 'Next' }));
    await screen.findByText(/Page 2/);
    expect(seen).toEqual([null, 'MTA']);
  });
});
