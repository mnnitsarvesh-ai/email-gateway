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
import { ScanDetails } from './scan-details';
import {
  MESSAGE_ID,
  attachmentRow,
  evaluation,
  expectNoInjectedMarkup,
  scanRound,
  urlRow,
} from './test-data';

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
      screen.getAllByText(
        'DLP findings are listed in the DLP results section of the email details.',
      ).length,
    ).toBeGreaterThan(0);
    expect(screen.queryByText(/Arrives in step 7\.2/)).not.toBeInTheDocument();
    // Each round links back to the matching sections of the email details (same round).
    const links = screen.getByRole('navigation', { name: 'Email details sections for round 1' });
    expect(within(links).getByRole('link', { name: 'Spam' })).toHaveAttribute(
      'href',
      `/messages/${MESSAGE_ID}?section=spam&round=1`,
    );
    expect(within(links).getByRole('link', { name: 'DLP' })).toHaveAttribute(
      'href',
      `/messages/${MESSAGE_ID}?section=dlp&round=1`,
    );
    expect(screen.getByRole('link', { name: 'email details' })).toHaveAttribute(
      'href',
      `/messages/${MESSAGE_ID}`,
    );
    // A link inside running text is underlined, not told apart by colour alone (WCAG 1.4.1, axe
    // link-in-text-block; jsdom cannot compute colours, the Playwright suite checks it).
    expect(screen.getByRole('link', { name: 'email details' })).toHaveClass('underline');
    // The engines table's scroller contains the copy buttons' absolutely positioned live regions
    // (otherwise they widen the page on phones; see details/parts.test.tsx).
    for (const table of screen.getAllByRole('table', { name: /Engine results of round/ })) {
      expect(table.parentElement).toHaveClass('relative');
    }
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
  it('hides the DLP link without dlp:read', async () => {
    mockScans();
    renderWithProviders(<ScanDetails messageId={MESSAGE_ID} />, { role: 'read_only_user' });
    const links = await screen.findByRole('navigation', {
      name: 'Email details sections for round 1',
    });
    expect(within(links).queryByRole('link', { name: 'DLP' })).toBeNull();
    expect(within(links).getByRole('link', { name: 'Risk' })).toBeInTheDocument();
  });
});
