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
import { MessageExplorer } from './message-explorer';
import { HOSTILE_SUBJECT, expectNoInjectedMarkup, messageRow } from './test-data';

const requests: URLSearchParams[] = [];
function listHandler(pages: Record<string, { data: unknown[]; nextCursor: string | null }>) {
  requests.length = 0;
  mockApi({
    MessagesController_list_v1: ({ url }) => {
      requests.push(url.searchParams);
      const page = pages[url.searchParams.get('cursor') ?? 'first'] ?? pages.first;
      return okJson(page as never);
    },
  });
}
const last = () => requests[requests.length - 1] ?? new URLSearchParams();

describe('Email explorer (/messages)', () => {
  it('shows a loading skeleton, then rows with links, and the 7.2 note; passes axe', async () => {
    mockApi({
      MessagesController_list_v1: async () => {
        await new Promise((resolve) => setTimeout(resolve, 30));
        return okJson({ data: [messageRow()], nextCursor: null });
      },
    });
    const { container } = renderWithProviders(<MessageExplorer />, {
      role: 'security_analyst',
      route: '/messages',
    });
    expect(await screen.findByText(/Loading Messages/)).toBeInTheDocument();
    const link = await screen.findByRole('link', { name: /open message details/ });
    expect(link).toHaveAttribute('href', `/messages/${messageRow().id}`);
    expect(screen.getByText('Quarterly report')).toBeInTheDocument();
    expect(
      screen.getByText('Saved views, column sets, bulk actions and export arrive in step 7.2.'),
    ).toBeInTheDocument();
    expect(screen.getByText(/Searches by sender or recipient are recorded/)).toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('sends the default 24 h window and sort, and renders hostile subjects as text only', async () => {
    listHandler({
      first: {
        data: [messageRow({ subject: HOSTILE_SUBJECT, envelopeFrom: '<b>x</b>@example.com' })],
        nextCursor: null,
      },
    });
    const { container } = renderWithProviders(<MessageExplorer />, { route: '/messages' });
    expect(await screen.findByText(/window.__pwned/)).toBeInTheDocument();
    expectNoInjectedMarkup(container);
    expect(container.querySelector('b')).toBeNull();
    const q = last();
    expect(q.get('sort')).toBe('-receivedAt');
    const from = Date.parse(q.get('from') ?? '');
    const to = Date.parse(q.get('to') ?? '');
    expect(to - from).toBe(86_400_000);
    expect(q.get('limit')).toBe('50');
  });

  it('writes filters to the URL and the request; filter changes reset the cursor', async () => {
    listHandler({
      first: { data: [messageRow()], nextCursor: 'cursor-2' },
      'cursor-2': {
        data: [messageRow({ id: '01933c3a-1b2c-7d4e-8f00-00000000a002', subject: 'Second page' })],
        nextCursor: null,
      },
    });
    const { user } = renderWithProviders(<MessageExplorer />, { route: '/messages' });
    await screen.findByText('Quarterly report');
    await user.click(screen.getByRole('button', { name: 'Next' }));
    expect(await screen.findByText('Second page')).toBeInTheDocument();
    expect(last().get('cursor')).toBe('cursor-2');
    expect(screen.getByText(/Page 2/)).toBeInTheDocument();

    await user.click(screen.getByLabelText('Direction'));
    await user.click(await screen.findByRole('option', { name: 'Inbound' }));
    await waitFor(() => expect(currentTestUrl()).toContain('direction=inbound'));
    await waitFor(() => expect(last().get('direction')).toBe('inbound'));
    expect(last().get('cursor')).toBeNull();
    expect(await screen.findByText(/Page 1/)).toBeInTheDocument();

    const sender = screen.getByLabelText('Sender (exact)');
    await user.type(sender, 'alex.lee12@example.com{Enter}');
    await waitFor(() => expect(last().get('sender')).toBe('alex.lee12@example.com'));
    expect(currentTestUrl()).toContain('sender=alex.lee12%40example.com');

    await user.type(screen.getByLabelText('Risk from'), '600{Enter}');
    await waitFor(() => expect(last().get('riskScore.gte')).toBe('600'));
  });

  it('accepts at most five verdicts as a comma list', async () => {
    listHandler({ first: { data: [messageRow()], nextCursor: null } });
    const { user } = renderWithProviders(<MessageExplorer />, { route: '/messages' });
    await screen.findByText('Quarterly report');
    await user.click(screen.getByRole('button', { name: /Verdict/ }));
    for (const name of ['Spam', 'Phishing', 'Malware', 'BEC', 'Suspicious']) {
      await user.click(await screen.findByRole('menuitemcheckbox', { name }));
    }
    expect(screen.getByRole('menuitemcheckbox', { name: 'Clean' })).toHaveAttribute(
      'aria-disabled',
      'true',
    );
    await user.keyboard('{Escape}');
    await waitFor(() => expect(last().get('verdict')).toBe('spam,phishing,malware,bec,suspicious'));
    expect(currentTestUrl()).toContain('verdict=spam%2Cphishing%2Cmalware%2Cbec%2Csuspicious');
  });

  it('reads filters and sort from the URL and toggles the sort', async () => {
    listHandler({ first: { data: [messageRow()], nextCursor: null } });
    const { user } = renderWithProviders(<MessageExplorer />, {
      route:
        '/messages?range=7d&status=quarantined&attachments=true&recipient=a%40alpha.example.test',
    });
    await screen.findByText('Quarterly report');
    const q = last();
    expect(q.get('status')).toBe('quarantined');
    expect(q.get('hasAttachments')).toBe('true');
    expect(q.get('recipient')).toBe('a@alpha.example.test');
    expect(Date.parse(q.get('to') ?? '') - Date.parse(q.get('from') ?? '')).toBe(7 * 86_400_000);
    await user.click(screen.getByRole('button', { name: /Received, change sort order/ }));
    await waitFor(() => expect(last().get('sort')).toBe('receivedAt'));
  });

  it('explains scan-budget short pages', async () => {
    listHandler({
      first: { data: [], nextCursor: 'more' },
      more: { data: [messageRow()], nextCursor: null },
    });
    const { user } = renderWithProviders(<MessageExplorer />, {
      route: '/messages?status=delivered',
    });
    expect(await screen.findByText('More results may exist further back.')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Load next page' }));
    expect(await screen.findByText('Quarterly report')).toBeInTheDocument();
    expect(last().get('cursor')).toBe('more');
  });

  it('shows the empty and filtered-empty states', async () => {
    listHandler({ first: { data: [], nextCursor: null } });
    const { user } = renderWithProviders(<MessageExplorer />, { route: '/messages' });
    expect(await screen.findByText('No mail in this range')).toBeInTheDocument();
    renderWithProviders(<MessageExplorer />, { route: '/messages?direction=outbound' });
    expect(await screen.findByText('No results match these filters')).toBeInTheDocument();
    await user.click(screen.getAllByRole('button', { name: 'Clear filters' })[0] as HTMLElement);
    await waitFor(() => expect(currentTestUrl()).not.toContain('direction='));
  });

  it('shows the error state with code and request id', async () => {
    mockApi({
      MessagesController_list_v1: () =>
        apiErrorJson(400, 'cursor_invalid', 'The cursor is invalid', { requestId: 'req-msg-1' }),
    });
    renderWithProviders(<MessageExplorer />, { route: '/messages' });
    const alert = await screen.findByRole('alert');
    expect(within(alert).getByText('cursor_invalid')).toBeInTheDocument();
    expect(within(alert).getByText('req-msg-1')).toBeInTheDocument();
  });

  it('is forbidden for a mailbox user (no message:read)', async () => {
    renderWithProviders(<MessageExplorer />, { role: 'mailbox_user', route: '/messages' });
    expect(await screen.findByText(/message:read/)).toBeInTheDocument();
  });
});
