import { screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { expectNoInjectedMarkup } from '@/features/messages/test-data';
import {
  apiErrorJson,
  currentTestUrl,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  mockApi,
  okJson,
  renderWithProviders,
} from '@/test';
import { QuarantinePage } from './quarantine-page';
import { CATALOG, ENTRY_ID, HOSTILE, SUMMARY, approval, entrySummary } from './test-data';

const searches: URLSearchParams[] = [];
const lastSearch = () => searches[searches.length - 1] ?? new URLSearchParams();

function mockEntries(pages: Record<string, { items: unknown[]; nextCursor: string | null }>) {
  searches.length = 0;
  mockApi({
    QuarantineToolsController_catalog_v1: () => okJson(CATALOG),
    QuarantineToolsController_summary_v1: () => okJson(SUMMARY),
    QuarantineEntriesController_search_v1: ({ url }) => {
      searches.push(url.searchParams);
      return okJson((pages[url.searchParams.get('cursor') ?? 'first'] ?? pages.first) as never);
    },
  });
}

describe('Quarantine entries (/quarantine)', () => {
  it('lists `items` with the summary strip; hostile subjects stay text; passes axe', async () => {
    mockEntries({ first: { items: [entrySummary({ subject: HOSTILE })], nextCursor: null } });
    const { container } = renderWithProviders(<QuarantinePage />, {
      role: 'security_analyst',
      route: '/quarantine',
    });
    expect(await screen.findByText(/window.__pwned/)).toBeInTheDocument();
    expectNoInjectedMarkup(container);
    const summary = await screen.findByLabelText(/Quarantine summary/);
    expect(within(summary).getByText('Pending approvals')).toBeInTheDocument();
    expect(within(summary).getByText('12')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /open entry/ })).toHaveAttribute(
      'href',
      `/quarantine/${ENTRY_ID}`,
    );
    const q = lastSearch();
    expect(Date.parse(q.get('to') ?? '') - Date.parse(q.get('from') ?? '')).toBe(7 * 86_400_000);
    expect(screen.getAllByRole('tab').map((tab) => tab.textContent)).toEqual([
      'Entries',
      'Approvals',
      'Settings',
    ]);
    await expectNoAxeViolations(container);
  });

  it('writes filters to the URL and the request; cursors reset when a filter changes', async () => {
    mockEntries({
      first: { items: [entrySummary()], nextCursor: 'c2' },
      c2: {
        items: [entrySummary({ id: '01933c3a-1b2c-7d4e-8f00-0000000e0002', subject: 'Page two' })],
        nextCursor: null,
      },
    });
    const { user } = renderWithProviders(<QuarantinePage />, {
      role: 'security_analyst',
      route: '/quarantine',
    });
    await screen.findByText('Verify your account');
    await user.click(screen.getByRole('button', { name: 'Next' }));
    expect(await screen.findByText('Page two')).toBeInTheDocument();
    expect(lastSearch().get('cursor')).toBe('c2');
    await user.click(screen.getByLabelText('State'));
    await user.click(await screen.findByRole('option', { name: 'Held' }));
    await waitFor(() => expect(currentTestUrl()).toContain('state=held'));
    await waitFor(() => expect(lastSearch().get('state')).toBe('held'));
    expect(lastSearch().get('cursor')).toBeNull();
    await user.type(
      screen.getByLabelText('Recipient (exact)'),
      'priya.rao4@alpha.example.test{Enter}',
    );
    await waitFor(() =>
      expect(lastSearch().get('recipient')).toBe('priya.rao4@alpha.example.test'),
    );
    await user.click(screen.getByRole('button', { name: /More filters/ }));
    await user.type(screen.getByLabelText('Message ID'), `${ENTRY_ID}{Enter}`);
    await waitFor(() => expect(lastSearch().get('messageId')).toBe(ENTRY_ID));
  });

  it('runs a bulk release with a contract body and an Idempotency-Key; reports the result', async () => {
    mockEntries({
      first: {
        items: [entrySummary(), entrySummary({ id: '01933c3a-1b2c-7d4e-8f00-0000000e0002' })],
        nextCursor: null,
      },
    });
    let body: unknown = null;
    let key: string | null = null;
    mockApi({
      QuarantineToolsController_bulk_v1: ({ body: b, request }) => {
        body = b;
        key = request.headers.get('idempotency-key');
        return okJson({
          action: 'release',
          results: [
            { id: ENTRY_ID, status: 'queued', releaseId: '01933c3a-1b2c-7d4e-8f00-0000000b0001' },
            {
              id: '01933c3a-1b2c-7d4e-8f00-0000000e0002',
              status: 'refused',
              code: 'quarantine_state_conflict',
            },
          ],
          counts: { queued: 1, refused: 1 },
        });
      },
    });
    const { user, container } = renderWithProviders(<QuarantinePage />, {
      role: 'security_analyst',
      route: '/quarantine',
    });
    await screen.findAllByText('Verify your account');
    await user.click(screen.getByRole('checkbox', { name: 'Select all rows on this page' }));
    const bar = screen.getByRole('region', { name: 'Bulk actions' });
    expect(within(bar).getByRole('button', { name: 'Release selected' })).toBeInTheDocument();
    expect(within(bar).getByRole('button', { name: 'Reject selected' })).toBeInTheDocument();
    expect(within(bar).getByRole('button', { name: 'Delete selected' })).toBeInTheDocument();
    expect(within(bar).queryByRole('button', { name: /Approve/ })).not.toBeInTheDocument();
    await user.click(within(bar).getByRole('button', { name: 'Release selected' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Release 2' }));
    expect(await within(dialog).findByText(/Enter a reason/)).toBeInTheDocument();
    await user.type(within(dialog).getByLabelText(/Reason/), 'False positive confirmed');
    await user.click(within(dialog).getByRole('button', { name: 'Release 2' }));
    await waitFor(() => expect(body).not.toBeNull());
    expect(body).toEqual({
      action: 'release',
      ids: [ENTRY_ID, '01933c3a-1b2c-7d4e-8f00-0000000e0002'],
      reason: 'False positive confirmed',
    });
    expectRequestMatchesContract('QuarantineToolsController_bulk_v1', body);
    expect(key).toMatch(/^[0-9a-f-]{36}$/);
    expect(await screen.findByText(/Bulk release:/i)).toBeInTheDocument();
    expect(screen.getByText(/quarantine_state_conflict/)).toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('enforces the catalog bulk limit', async () => {
    mockEntries({
      first: {
        items: [
          entrySummary(),
          entrySummary({ id: '01933c3a-1b2c-7d4e-8f00-0000000e0002' }),
          entrySummary({ id: '01933c3a-1b2c-7d4e-8f00-0000000e0003' }),
        ],
        nextCursor: null,
      },
    });
    const { user } = renderWithProviders(<QuarantinePage />, {
      role: 'organization_admin',
      route: '/quarantine',
    });
    await screen.findAllByText('Verify your account');
    await user.click(screen.getByRole('checkbox', { name: 'Select all rows on this page' }));
    expect(screen.getByText('At most 2 items per bulk action.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Release selected' })).toBeDisabled();
  });

  it('hides selection and bulk actions from read-only users; reviewers get their actions', async () => {
    mockEntries({ first: { items: [entrySummary()], nextCursor: null } });
    renderWithProviders(<QuarantinePage />, { role: 'read_only_user', route: '/quarantine' });
    await screen.findByText('Verify your account');
    expect(
      screen.queryByRole('checkbox', { name: 'Select all rows on this page' }),
    ).not.toBeInTheDocument();
  });

  it('shows empty, filtered-empty and error states', async () => {
    mockEntries({ first: { items: [], nextCursor: null } });
    renderWithProviders(<QuarantinePage />, { role: 'security_analyst', route: '/quarantine' });
    expect(await screen.findByText('Nothing quarantined in this range')).toBeInTheDocument();
    mockApi({
      QuarantineEntriesController_search_v1: () =>
        apiErrorJson(400, 'quarantine_cursor_invalid', 'Invalid cursor', { requestId: 'req-q-1' }),
    });
    renderWithProviders(<QuarantinePage />, {
      role: 'security_analyst',
      route: '/quarantine?state=held',
    });
    const alerts = await screen.findAllByRole('alert');
    const alert = alerts.find((a) => within(a).queryByText('quarantine_cursor_invalid'));
    expect(alert).toBeDefined();
    expect(within(alert as HTMLElement).getByText('req-q-1')).toBeInTheDocument();
  });

  it('switches tabs through the URL and shows the approvals list', async () => {
    mockEntries({ first: { items: [], nextCursor: null } });
    const approvalsSeen: URLSearchParams[] = [];
    mockApi({
      QuarantineApprovalsController_list_v1: ({ url }) => {
        approvalsSeen.push(url.searchParams);
        return okJson({ items: [approval()], nextCursor: null });
      },
    });
    const { user, container } = renderWithProviders(<QuarantinePage />, {
      role: 'quarantine_reviewer',
      route: '/quarantine',
    });
    await screen.findByText('Nothing quarantined in this range');
    await user.click(screen.getByRole('tab', { name: 'Approvals' }));
    await waitFor(() => expect(currentTestUrl()).toBe('/quarantine?tab=approvals'));
    expect(await screen.findByRole('link', { name: /open approval request/ })).toBeInTheDocument();
    expect(approvalsSeen[0]?.get('status')).toBe('pending');
    expect(screen.getByText(/Separation of duties/)).toBeInTheDocument();
    await expectNoAxeViolations(container);
    await user.click(screen.getByLabelText('Status'));
    await user.click(await screen.findByRole('option', { name: 'Any status' }));
    await waitFor(() => expect(approvalsSeen[approvalsSeen.length - 1]?.get('status')).toBeNull());
  });

  it('shows only "My quarantine" to a mailbox user', async () => {
    mockApi({
      QuarantineToolsController_catalog_v1: () => okJson(CATALOG),
      QuarantineSelfController_search_v1: () =>
        okJson({
          items: [entrySummary({ subject: 'Your parcel', reason: 'spam' })],
          nextCursor: null,
        }),
      QuarantineSelfController_preferences_v1: () =>
        okJson({ digestOptOut: false, allowOptOut: true }),
    });
    const { container } = renderWithProviders(<QuarantinePage />, {
      role: 'mailbox_user',
      route: '/quarantine',
    });
    expect(
      await screen.findByRole('heading', { name: 'My quarantine', level: 1 }),
    ).toBeInTheDocument();
    expect(await screen.findByText('Your parcel')).toBeInTheDocument();
    expect(screen.queryByRole('tab')).not.toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('is forbidden on the approvals route for a mailbox user', async () => {
    mockApi({ QuarantineToolsController_catalog_v1: () => okJson(CATALOG) });
    renderWithProviders(<QuarantinePage routeTab="approvals" />, {
      role: 'mailbox_user',
      route: '/quarantine/approvals',
    });
    expect(await screen.findByText(/quarantine:read/)).toBeInTheDocument();
  });
});
