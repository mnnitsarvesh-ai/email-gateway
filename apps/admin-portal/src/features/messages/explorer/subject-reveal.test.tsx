import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import {
  apiErrorJson,
  createTestQueryClient,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  mockApi,
  okJson,
  renderWithProviders,
} from '@/test';
import { HOSTILE_SUBJECT, expectNoInjectedMarkup, messageRow } from '../test-data';
import { MessageExplorer } from './message-explorer';
import { mockExplorer, rows } from './test-helpers';

beforeEach(() => localStorage.clear());

const subjectOf = (id: string) => `Subject of ${id.slice(-4)}`;

/** Mocks `POST /messages/reveal`: answers each id with a subject, records the bodies. */
function mockReveal(options: { omit?: string[]; subjects?: Record<string, string | null> } = {}) {
  const bodies: { messageIds: string[] }[] = [];
  mockApi({
    MessageRevealController_revealMany_v1: ({ body }) => {
      const request = body as { messageIds: string[] };
      bodies.push(request);
      expectRequestMatchesContract('MessageRevealController_revealMany_v1', request);
      return okJson(
        {
          revealedAt: '2026-11-14T09:02:11.418Z',
          data: request.messageIds
            .filter((id) => !(options.omit ?? []).includes(id))
            .map((id) => ({ id, subject: options.subjects?.[id] ?? subjectOf(id) })),
        },
        200,
        { 'cache-control': 'no-store' },
      );
    },
  });
  return bodies;
}

/** Every JSON string held by the TanStack query and mutation caches. */
function cachedText(queryClient: ReturnType<typeof createTestQueryClient>): string {
  const queries = queryClient
    .getQueryCache()
    .getAll()
    .map((query) => query.state.data);
  const mutations = queryClient
    .getMutationCache()
    .getAll()
    .map((mutation) => mutation.state.data);
  return JSON.stringify([queries, mutations]);
}

describe('Email explorer: subject reveal (message:reveal, §2 E10)', () => {
  it('is off by default; turning it on reveals the page with one call and a Revealed badge', async () => {
    const page = rows(3);
    mockExplorer({ pages: { first: { data: page, nextCursor: null } } });
    const bodies = mockReveal();
    const queryClient = createTestQueryClient();
    const { user, container } = renderWithProviders(<MessageExplorer />, {
      role: 'security_analyst',
      route: '/messages',
      queryClient,
    });
    await screen.findAllByRole('link', { name: /open message details/ });
    expect(screen.getAllByText('Hidden')).toHaveLength(3);
    expect(bodies).toHaveLength(0);
    expect(screen.getByText(/Each revealed page is recorded in the audit log/)).toBeInTheDocument();

    await user.click(screen.getByRole('switch', { name: 'Show subjects' }));
    for (const row of page) expect(await screen.findByText(subjectOf(row.id))).toBeInTheDocument();
    expect(bodies).toEqual([{ messageIds: page.map((row) => row.id) }]);
    expect(screen.getAllByText('Revealed')).toHaveLength(3);
    expect(screen.queryByText('Hidden')).not.toBeInTheDocument();
    // Never in the TanStack caches (the mutation is reset and removed after use).
    expect(cachedText(queryClient)).not.toContain('Subject of');
    expect(
      queryClient
        .getMutationCache()
        .findAll({ mutationKey: ['MessageRevealController_revealMany_v1'] }),
    ).toHaveLength(0);
    // Never in the URL or browser storage.
    expect(window.location.search).not.toContain('Subject');
    expect(JSON.stringify({ ...localStorage })).not.toContain('Subject of');
    await expectNoAxeViolations(container);
  });

  it('reveals each newly loaded page once; a page already revealed is not requested again', async () => {
    mockExplorer({
      pages: {
        first: { data: rows(2), nextCursor: 'cursor-2' },
        'cursor-2': { data: rows(2, 10), nextCursor: null },
      },
    });
    const bodies = mockReveal();
    const { user } = renderWithProviders(<MessageExplorer />, {
      role: 'organization_admin',
      route: '/messages',
    });
    await screen.findAllByRole('link', { name: /open message details/ });
    await user.click(screen.getByRole('switch', { name: 'Show subjects' }));
    await screen.findByText(subjectOf(rows(1)[0]?.id ?? ''));
    await user.click(screen.getByRole('button', { name: 'Next' }));
    await screen.findByText(subjectOf(rows(1, 10)[0]?.id ?? ''));
    expect(bodies.map((b) => b.messageIds)).toEqual([
      rows(2).map((r) => r.id),
      rows(2, 10).map((r) => r.id),
    ]);
    await user.click(screen.getByRole('button', { name: 'Previous' }));
    await screen.findByText(subjectOf(rows(1)[0]?.id ?? ''));
    expect(bodies).toHaveLength(2);
  });

  it('asks only for masked subjects and shows omitted ids as still hidden', async () => {
    const [a, b, c] = rows(3);
    if (!a || !b || !c) throw new Error('rows');
    mockExplorer({
      pages: {
        first: {
          data: [a, { ...b, subjectMasked: false }, c],
          nextCursor: null,
        },
      },
    });
    const bodies = mockReveal({ omit: [c.id] });
    const { user } = renderWithProviders(<MessageExplorer />, {
      role: 'compliance_auditor',
      route: '/messages',
    });
    await screen.findAllByRole('link', { name: /open message details/ });
    expect(screen.getByText('(no subject)')).toBeInTheDocument();
    await user.click(screen.getByRole('switch', { name: 'Show subjects' }));
    expect(await screen.findByText(subjectOf(a.id))).toBeInTheDocument();
    expect(bodies).toEqual([{ messageIds: [a.id, c.id] }]);
    expect(screen.getAllByText('Hidden')).toHaveLength(1);
  });

  it('renders revealed hostile subjects as text only', async () => {
    const row = messageRow();
    mockExplorer({ pages: { first: { data: [row], nextCursor: null } } });
    mockReveal({ subjects: { [row.id]: HOSTILE_SUBJECT } });
    const { user, container } = renderWithProviders(<MessageExplorer />, {
      role: 'security_analyst',
      route: '/messages',
    });
    await screen.findByRole('link', { name: /open message details/ });
    await user.click(screen.getByRole('switch', { name: 'Show subjects' }));
    expect(await screen.findByText(/window.__pwned/)).toBeInTheDocument();
    expectNoInjectedMarkup(container);
  });

  it('forgets revealed subjects when switched off and after leaving the page', async () => {
    const page = rows(2);
    mockExplorer({ pages: { first: { data: page, nextCursor: null } } });
    const bodies = mockReveal();
    const queryClient = createTestQueryClient();
    const first = renderWithProviders(<MessageExplorer />, {
      role: 'security_analyst',
      route: '/messages',
      queryClient,
    });
    await screen.findAllByRole('link', { name: /open message details/ });
    await first.user.click(screen.getByRole('switch', { name: 'Show subjects' }));
    await screen.findByText(subjectOf(page[0]?.id ?? ''));
    await first.user.click(screen.getByRole('switch', { name: 'Show subjects' }));
    expect(screen.queryByText(subjectOf(page[0]?.id ?? ''))).not.toBeInTheDocument();
    expect(screen.getAllByText('Hidden')).toHaveLength(2);

    await first.user.click(screen.getByRole('switch', { name: 'Show subjects' }));
    await screen.findByText(subjectOf(page[0]?.id ?? ''));
    expect(bodies).toHaveLength(2);
    first.unmount();
    renderWithProviders(<MessageExplorer />, {
      role: 'security_analyst',
      route: '/messages',
      queryClient,
    });
    await screen.findAllByRole('link', { name: /open message details/ });
    expect(screen.getByRole('switch', { name: 'Show subjects' })).not.toBeChecked();
    expect(screen.queryByText(subjectOf(page[0]?.id ?? ''))).not.toBeInTheDocument();
    expect(cachedText(queryClient)).not.toContain('Subject of');
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(bodies).toHaveLength(2);
  });

  it('shows a refused reveal with its code and lets the user retry', async () => {
    mockExplorer({ pages: { first: { data: rows(1), nextCursor: null } } });
    let calls = 0;
    mockApi({
      MessageRevealController_revealMany_v1: ({ body }) => {
        calls += 1;
        if (calls === 1) {
          return apiErrorJson(503, 'service_unavailable', 'The audit log is unavailable', {
            requestId: 'req-reveal-1',
          });
        }
        const ids = (body as { messageIds: string[] }).messageIds;
        return okJson({
          revealedAt: '2026-11-14T09:02:11.418Z',
          data: ids.map((id) => ({ id, subject: subjectOf(id) })),
        });
      },
    });
    const { user } = renderWithProviders(<MessageExplorer />, {
      role: 'security_analyst',
      route: '/messages',
    });
    await screen.findByRole('link', { name: /open message details/ });
    await user.click(screen.getByRole('switch', { name: 'Show subjects' }));
    const alert = await screen.findByText('req-reveal-1');
    expect(alert).toBeInTheDocument();
    expect(screen.getByText('service_unavailable')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByText(subjectOf(rows(1)[0]?.id ?? ''))).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByText('req-reveal-1')).not.toBeInTheDocument());
    expect(calls).toBe(2);
  });

  it('is not offered without message:reveal (domain_admin, quarantine_reviewer)', async () => {
    for (const role of ['domain_admin', 'quarantine_reviewer'] as const) {
      mockExplorer();
      const { unmount } = renderWithProviders(<MessageExplorer />, { role, route: '/messages' });
      await screen.findByRole('link', { name: /open message details/ });
      expect(screen.queryByRole('switch', { name: 'Show subjects' })).not.toBeInTheDocument();
      expect(within(screen.getByRole('table')).getByText('Hidden')).toBeInTheDocument();
      unmount();
    }
  });
});
