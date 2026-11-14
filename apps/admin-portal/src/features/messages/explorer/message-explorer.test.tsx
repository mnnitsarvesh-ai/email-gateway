import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  apiErrorJson,
  currentTestUrl,
  expectNoAxeViolations,
  okJson,
  renderWithProviders,
} from '@/test';
import { HOSTILE_SUBJECT, expectNoInjectedMarkup, messageRow } from '../test-data';
import { MessageExplorer } from './message-explorer';
import { DOMAIN_ID, mockExplorer, rows } from './test-helpers';

beforeEach(() => localStorage.clear());

const senderRequests = (requests: URLSearchParams[]) => requests.filter((q) => q.has('sender'));

describe('Email explorer (/messages): list, states and URL', () => {
  it('shows a skeleton, then rows with links and masked subjects; passes axe', async () => {
    mockExplorer({
      list: async () => {
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
    const cell = screen.getByText('Hidden').closest('[data-sensitive]');
    expect(cell).toHaveAttribute('data-sensitive', 'masked');
    expect(within(cell as HTMLElement).getByText('(masked)')).toHaveClass('sr-only');
    expect(screen.queryByText(/arrives in step 7.2/)).not.toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('sends the 24 h default window ending on a minute, the sort and 50 rows per page', async () => {
    const mocks = mockExplorer();
    renderWithProviders(<MessageExplorer />, { route: '/messages' });
    await screen.findByRole('link', { name: /open message details/ });
    const q = mocks.last();
    expect(q.get('sort')).toBe('-receivedAt');
    expect(q.get('limit')).toBe('50');
    expect(Date.parse(q.get('to') ?? '') - Date.parse(q.get('from') ?? '')).toBe(86_400_000);
    expect(Date.parse(q.get('to') ?? '') % 60_000).toBe(0);
    expect(q.has('view')).toBe(false);
  });

  it('renders attacker-controlled senders and revealed nothing as text only', async () => {
    mockExplorer({
      pages: {
        first: {
          data: [messageRow({ envelopeFrom: '<b>x</b>@example.com', headerFrom: HOSTILE_SUBJECT })],
          nextCursor: null,
        },
      },
    });
    const { container } = renderWithProviders(<MessageExplorer />, { route: '/messages' });
    expect(await screen.findByText(/window.__pwned/)).toBeInTheDocument();
    expectNoInjectedMarkup(container);
    expect(container.querySelector('b')).toBeNull();
  });

  it('keeps the 7.1 deep links (verdict=malware&attachments=true, hasAttachments alias)', async () => {
    const mocks = mockExplorer();
    renderWithProviders(<MessageExplorer />, {
      route: '/messages?verdict=malware&attachments=true',
    });
    await screen.findByRole('link', { name: /open message details/ });
    expect(mocks.last().get('verdict')).toBe('malware');
    expect(mocks.last().get('hasAttachments')).toBe('true');

    const alias = mockExplorer();
    renderWithProviders(<MessageExplorer />, {
      route: '/messages?verdict=malware&hasAttachments=true',
    });
    await waitFor(() => expect(alias.last().get('hasAttachments')).toBe('true'));
  });

  it('writes filters to the URL and the request; a filter change resets the cursor', async () => {
    const mocks = mockExplorer({
      pages: {
        first: { data: rows(1), nextCursor: 'cursor-2' },
        'cursor-2': { data: rows(1, 10), nextCursor: null },
      },
    });
    const { user } = renderWithProviders(<MessageExplorer />, {
      role: 'security_analyst',
      route: '/messages',
    });
    await screen.findAllByRole('link', { name: /open message details/ });
    await user.click(screen.getByRole('button', { name: 'Next' }));
    await waitFor(() => expect(mocks.last().get('cursor')).toBe('cursor-2'));
    expect(await screen.findByText(/Page 2/)).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /^Direction/ }));
    await user.click(await screen.findByRole('menuitemcheckbox', { name: 'Inbound' }));
    await user.click(await screen.findByRole('menuitemcheckbox', { name: 'Internal' }));
    await user.keyboard('{Escape}');
    await waitFor(() => expect(mocks.last().get('direction')).toBe('inbound,internal'));
    expect(currentTestUrl()).toContain('direction=inbound%2Cinternal');
    expect(mocks.last().get('cursor')).toBeNull();
    expect(await screen.findByText(/Page 1/)).toBeInTheDocument();

    await user.click(screen.getByLabelText('Delivery status'));
    await user.click(await screen.findByRole('option', { name: 'Deferred' }));
    await waitFor(() => expect(mocks.last().get('deliveryStatus')).toBe('deferred'));

    await user.click(screen.getByLabelText('Quarantine status'));
    await user.click(await screen.findByRole('option', { name: 'Pending approval' }));
    await waitFor(() => expect(mocks.last().get('quarantineStatus')).toBe('pending_approval'));

    await user.click(screen.getByLabelText('Domain'));
    await user.click(await screen.findByRole('option', { name: 'alpha-1.example.test' }));
    await waitFor(() => expect(mocks.last().get('domainId')).toBe(DOMAIN_ID));

    await user.click(screen.getByLabelText('Risk score band'));
    await user.click(await screen.findByRole('option', { name: '600–799' }));
    await waitFor(() => expect(mocks.last().get('riskScore.gte')).toBe('600'));
    expect(mocks.last().get('riskScore.lte')).toBe('799');
  });

  it('caps the multi-selects at the api maxima (five verdicts)', async () => {
    const mocks = mockExplorer();
    const { user } = renderWithProviders(<MessageExplorer />, { route: '/messages' });
    await screen.findByRole('link', { name: /open message details/ });
    await user.click(screen.getByRole('button', { name: /^Verdict/ }));
    for (const name of ['Spam', 'Phishing', 'Malware', 'BEC', 'Suspicious']) {
      await user.click(await screen.findByRole('menuitemcheckbox', { name }));
    }
    expect(screen.getByRole('menuitemcheckbox', { name: 'Clean' })).toHaveAttribute(
      'aria-disabled',
      'true',
    );
    await user.keyboard('{Escape}');
    await waitFor(() =>
      expect(mocks.last().get('verdict')).toBe('spam,phishing,malware,bec,suspicious'),
    );
  });

  it('flags risk bounds in the wrong order inline', async () => {
    mockExplorer();
    renderWithProviders(<MessageExplorer />, { route: '/messages?riskMin=800&riskMax=300' });
    expect(
      await screen.findByText('The lowest risk score is above the highest.'),
    ).toBeInTheDocument();
  });

  it('toggles the sort on the Received column', async () => {
    const mocks = mockExplorer();
    const { user } = renderWithProviders(<MessageExplorer />, { route: '/messages?range=7d' });
    await screen.findByRole('link', { name: /open message details/ });
    expect(
      Date.parse(mocks.last().get('to') ?? '') - Date.parse(mocks.last().get('from') ?? ''),
    ).toBe(7 * 86_400_000);
    await user.click(screen.getByRole('button', { name: /Received, change sort order/ }));
    await waitFor(() => expect(mocks.last().get('sort')).toBe('receivedAt'));
  });

  it('explains scan-budget short pages', async () => {
    const mocks = mockExplorer({
      pages: { first: { data: [], nextCursor: 'more' }, more: { data: rows(1), nextCursor: null } },
    });
    const { user } = renderWithProviders(<MessageExplorer />, {
      route: '/messages?status=delivered',
    });
    expect(await screen.findByText('More results may exist further back.')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Load next page' }));
    await screen.findByRole('link', { name: /open message details/ });
    expect(mocks.last().get('cursor')).toBe('more');
  });

  it('shows the empty and the filtered-empty states', async () => {
    mockExplorer({ pages: { first: { data: [], nextCursor: null } } });
    const { user } = renderWithProviders(<MessageExplorer />, { route: '/messages' });
    expect(await screen.findByText('No mail in this range')).toBeInTheDocument();
    renderWithProviders(<MessageExplorer />, { route: '/messages?direction=outbound' });
    expect(await screen.findByText('No results match these filters')).toBeInTheDocument();
    await user.click(screen.getAllByRole('button', { name: 'Clear filters' })[0] as HTMLElement);
    await waitFor(() => expect(currentTestUrl()).not.toContain('direction='));
  });

  it('shows the error state with code and request id', async () => {
    mockExplorer({
      list: () =>
        apiErrorJson(400, 'cursor_invalid', 'The cursor is invalid', { requestId: 'req-msg-1' }),
    });
    renderWithProviders(<MessageExplorer />, { route: '/messages' });
    const alert = await screen.findByRole('alert');
    expect(within(alert).getByText('cursor_invalid')).toBeInTheDocument();
    expect(within(alert).getByText('req-msg-1')).toBeInTheDocument();
  });

  it('shows 422 message_search_too_broad next to the search with the api message', async () => {
    mockExplorer({
      list: () =>
        apiErrorJson(
          422,
          'message_search_too_broad',
          'More than 5000 messages in this range start with that subject; type more of it',
          { requestId: 'req-broad-1', extra: { maxMatches: 5000 } },
        ),
    });
    const { container } = renderWithProviders(<MessageExplorer />, {
      role: 'security_analyst',
      route: '/messages?subjectPrefix=Weekly',
    });
    const search = await screen.findByRole('search', { name: 'Search messages' });
    const alert = await within(search).findByRole('alert');
    expect(alert).toHaveTextContent('The search matches too many messages');
    expect(alert).toHaveTextContent('type more of it');
    expect(alert).toHaveTextContent('message_search_too_broad');
    expect(alert).toHaveTextContent('req-broad-1');
    expect(screen.getByText('The search was refused')).toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('shows 503 message_search_timeout next to the search and does not retry it', async () => {
    const mocks = mockExplorer({
      list: () =>
        apiErrorJson(503, 'message_search_timeout', 'The subject search took too long', {
          requestId: 'req-slow-1',
        }),
    });
    renderWithProviders(<MessageExplorer />, {
      role: 'security_analyst',
      route: '/messages?subjectPrefix=Invoice',
    });
    const search = await screen.findByRole('search', { name: 'Search messages' });
    expect(await within(search).findByRole('alert')).toHaveTextContent('The search took too long');
    expect(mocks.requests).toHaveLength(1);
  });

  it('explains 403 message_filter_forbidden with the filter and permission', async () => {
    mockExplorer({
      list: () =>
        apiErrorJson(
          403,
          'message_filter_forbidden',
          'The deliveryStatus filter needs delivery:read',
          {
            extra: { filter: 'deliveryStatus', permission: 'delivery:read' },
          },
        ),
    });
    renderWithProviders(<MessageExplorer />, {
      role: 'security_analyst',
      route: '/messages?deliveryStatus=bounced',
    });
    expect(await screen.findByText('message_filter_forbidden')).toBeInTheDocument();
    expect(screen.getByText(/needs the permission/)).toHaveTextContent('delivery:read');
    expect(screen.queryByText(/Requires the permission/)).not.toBeInTheDocument();
  });

  it('counts down a 429 before Retry is enabled', async () => {
    mockExplorer({
      list: () =>
        apiErrorJson(429, 'rate_limited', 'Too many requests', { headers: { 'retry-after': '3' } }),
    });
    renderWithProviders(<MessageExplorer />, { route: '/messages' });
    expect(await screen.findByText('Try again in 3 s.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Retry' })).toBeDisabled();
    expect(
      await screen.findByText('Try again in 2 s.', {}, { timeout: 2_000 }),
    ).toBeInTheDocument();
  });

  it('is forbidden for a mailbox user (no message:read)', async () => {
    renderWithProviders(<MessageExplorer />, { role: 'mailbox_user', route: '/messages' });
    expect(await screen.findByText(/message:read/)).toBeInTheDocument();
  });

  it('renders stacked cards on mobile with the masked subject', async () => {
    vi.spyOn(window, 'matchMedia').mockImplementation(
      (query: string) =>
        ({
          matches: query.includes('max-width: 767px'),
          media: query,
          addEventListener: () => undefined,
          removeEventListener: () => undefined,
          addListener: () => undefined,
          removeListener: () => undefined,
        }) as unknown as MediaQueryList,
    );
    mockExplorer();
    const { container } = renderWithProviders(<MessageExplorer />, { route: '/messages' });
    const cards = await screen.findByTestId('data-table-cards');
    expect(within(cards).getByText('Hidden')).toBeInTheDocument();
    expect(within(cards).getByRole('link', { name: /open message details/ })).toBeInTheDocument();
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('hides columns through the column menu and remembers them for the viewer', async () => {
    mockExplorer();
    const { user, unmount } = renderWithProviders(<MessageExplorer />, { route: '/messages' });
    await screen.findByRole('link', { name: /open message details/ });
    await user.click(screen.getByRole('button', { name: 'Columns' }));
    expect(screen.queryByRole('menuitemcheckbox', { name: 'Received' })).not.toBeInTheDocument();
    await user.click(await screen.findByRole('menuitemcheckbox', { name: 'Size' }));
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('columnheader', { name: 'Size' })).not.toBeInTheDocument();
    expect(JSON.parse(localStorage.getItem('eg:table:messages:columns') ?? '{}')).toEqual({
      size: false,
    });
    unmount();
    renderWithProviders(<MessageExplorer />, { route: '/messages' });
    await screen.findByRole('link', { name: /open message details/ });
    expect(screen.queryByRole('columnheader', { name: 'Size' })).not.toBeInTheDocument();
  });
});

describe('Email explorer: search bar', () => {
  it('commits a valid value after 600 ms of idle time, once, never per keystroke', async () => {
    const mocks = mockExplorer();
    const { user } = renderWithProviders(<MessageExplorer />, { route: '/messages' });
    await screen.findByRole('link', { name: /open message details/ });
    const input = screen.getByRole('searchbox', { name: 'Search by Sender (envelope)' });
    await user.type(input, 'alex.lee12@example.com');
    expect(senderRequests(mocks.requests)).toHaveLength(0);
    await waitFor(() => expect(senderRequests(mocks.requests)).toHaveLength(1), { timeout: 2_000 });
    expect(mocks.last().get('sender')).toBe('alex.lee12@example.com');
    expect(currentTestUrl()).toContain('sender=alex.lee12%40example.com');
    const chips = screen.getByRole('list', { name: 'Active searches' });
    expect(within(chips).getByText('Sender (envelope):')).toBeInTheDocument();

    // The same value again (Enter) never re-commits.
    await user.type(input, '{Enter}');
    await new Promise((resolve) => setTimeout(resolve, 700));
    expect(senderRequests(mocks.requests)).toHaveLength(1);
  });

  it('commits on Enter only when the validator passes; shows why otherwise', async () => {
    const mocks = mockExplorer();
    const { user } = renderWithProviders(<MessageExplorer />, { route: '/messages' });
    await screen.findByRole('link', { name: /open message details/ });
    await user.click(screen.getByRole('combobox', { name: 'Search field' }));
    await user.click(await screen.findByRole('option', { name: 'Sender domain' }));
    const input = screen.getByRole('searchbox', { name: 'Search by Sender domain' });
    await user.type(input, 'not a domain{Enter}');
    expect(await screen.findByText(/Enter a domain such as example.com/)).toBeInTheDocument();
    expect(input).toHaveAttribute('aria-invalid', 'true');
    expect(mocks.requests.some((q) => q.has('senderDomain'))).toBe(false);
    await user.clear(input);
    await user.type(input, '@XN--MNCHEN-3YA.example.test{Enter}');
    await waitFor(() =>
      expect(mocks.last().get('senderDomain')).toBe('xn--mnchen-3ya.example.test'),
    );
  });

  it('combines several searches as chips; removing a chip removes its filter', async () => {
    const mocks = mockExplorer();
    const { user } = renderWithProviders(<MessageExplorer />, {
      route: '/messages?recipient=jane%40alpha.example.test&recipientDomain=partner.example',
    });
    await screen.findByRole('link', { name: /open message details/ });
    expect(mocks.last().get('recipient')).toBe('jane@alpha.example.test');
    expect(mocks.last().get('recipientDomain')).toBe('partner.example');
    await user.click(screen.getByRole('button', { name: 'Remove search Recipient' }));
    await waitFor(() => expect(mocks.last().has('recipient')).toBe(false));
    expect(mocks.last().get('recipientDomain')).toBe('partner.example');
    await user.click(screen.getByRole('button', { name: /Edit search Recipient domain/ }));
    expect(screen.getByRole('searchbox', { name: 'Search by Recipient domain' })).toHaveValue(
      'partner.example',
    );
  });

  it('offers "Open message" for a gateway id typed as Message ID', async () => {
    mockExplorer();
    const { user } = renderWithProviders(<MessageExplorer />, { route: '/messages' });
    await screen.findByRole('link', { name: /open message details/ });
    await user.click(screen.getByRole('combobox', { name: 'Search field' }));
    await user.click(await screen.findByRole('option', { name: 'Message ID' }));
    await user.type(
      screen.getByRole('searchbox', { name: 'Search by Message ID' }),
      '01933C3A-1B2C-7D4E-8F00-00000000A001',
    );
    expect(await screen.findByRole('link', { name: 'Open message' })).toHaveAttribute(
      'href',
      '/messages/01933c3a-1b2c-7d4e-8f00-00000000a001',
    );
  });
});

describe('Email explorer: permission-gated controls', () => {
  it('read_only_user: no recipient or subject search, masked subjects, no reveal switch', async () => {
    const mocks = mockExplorer();
    const { user, container } = renderWithProviders(<MessageExplorer />, {
      role: 'read_only_user',
      route: '/messages',
    });
    await screen.findByRole('link', { name: /open message details/ });
    expect(screen.getByText('Hidden')).toBeInTheDocument();
    expect(screen.queryByRole('switch', { name: 'Show subjects' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('combobox', { name: 'Search field' }));
    expect(screen.queryByRole('option', { name: 'Subject' })).not.toBeInTheDocument();
    expect(screen.queryByRole('option', { name: 'Subject starts with' })).not.toBeInTheDocument();
    // The exact recipient would confirm a masked address (ADR-0062); its domain stays open.
    expect(screen.queryByRole('option', { name: 'Recipient' })).not.toBeInTheDocument();
    expect(screen.getByRole('option', { name: 'Recipient domain' })).toBeInTheDocument();
    await user.keyboard('{Escape}');
    expect(mocks.requests.length).toBeGreaterThan(0);
    await expectNoAxeViolations(container);
  });

  it('read_only_user: a shared link with a subject search is not sent and is explained', async () => {
    const mocks = mockExplorer();
    renderWithProviders(<MessageExplorer />, {
      role: 'read_only_user',
      route: '/messages?subject=Invoice%204471&sender=a%40example.com',
    });
    expect(await screen.findByText(/need permissions you do not have/)).toHaveTextContent(
      'Subject',
    );
    await waitFor(() => expect(mocks.last().get('sender')).toBe('a@example.com'));
    expect(mocks.requests.every((q) => !q.has('subject'))).toBe(true);
  });

  it('read_only_user: a shared link with an exact recipient is not sent and is explained', async () => {
    const mocks = mockExplorer();
    renderWithProviders(<MessageExplorer />, {
      role: 'read_only_user',
      route: '/messages?recipient=jane%40alpha.example.test&recipientDomain=partner.example',
    });
    expect(await screen.findByText(/need permissions you do not have/)).toHaveTextContent(
      'Recipient',
    );
    await waitFor(() => expect(mocks.last().get('recipientDomain')).toBe('partner.example'));
    expect(mocks.requests.every((q) => !q.has('recipient'))).toBe(true);
  });

  it('message:read alone: no delivery, quarantine or domain filter', async () => {
    mockExplorer();
    renderWithProviders(<MessageExplorer />, {
      permissions: ['message:read'],
      route: '/messages',
    });
    await screen.findByRole('link', { name: /open message details/ });
    expect(screen.queryByLabelText('Delivery status')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Quarantine status')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Domain')).not.toBeInTheDocument();
    expect(screen.getByLabelText('Attachments')).toBeInTheDocument();
  });

  it('security_analyst: every search field, the status filters and the reveal switch', async () => {
    mockExplorer();
    const { user } = renderWithProviders(<MessageExplorer />, {
      role: 'security_analyst',
      route: '/messages',
    });
    await screen.findByRole('link', { name: /open message details/ });
    expect(screen.getByRole('switch', { name: 'Show subjects' })).not.toBeChecked();
    expect(screen.getByLabelText('Delivery status')).toBeInTheDocument();
    expect(screen.getByLabelText('Quarantine status')).toBeInTheDocument();
    expect(screen.getByLabelText('Domain')).toBeInTheDocument();
    await user.click(screen.getByRole('combobox', { name: 'Search field' }));
    expect(screen.getByRole('option', { name: 'Subject' })).toBeInTheDocument();
    await user.click(screen.getByRole('option', { name: 'Subject starts with' }));
    await user.type(
      screen.getByRole('searchbox', { name: 'Search by Subject starts with' }),
      'In{Enter}',
    );
    expect(await screen.findByText(/Enter at least 3 characters/)).toBeInTheDocument();
  });
});
