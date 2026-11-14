import { screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import {
  apiErrorJson,
  createTestQueryClient,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  okJson,
  renderWithProviders,
} from '@/test';
import { MessageDetails } from './message-details';
import { MESSAGE_ID, REVEALED, detailsRoute, mockDetails, revealBody } from './test-helpers';

/** Every JSON string held by the TanStack query and mutation caches. */
function cachedText(queryClient: ReturnType<typeof createTestQueryClient>): string {
  return JSON.stringify([
    queryClient
      .getQueryCache()
      .getAll()
      .map((query) => query.state.data),
    queryClient
      .getMutationCache()
      .getAll()
      .map((mutation) => mutation.state.data),
  ]);
}

describe('Email details: reveal (message:reveal, §2 E11)', () => {
  it('reveals subject, header values and recipients with one audited call, then more recipients; nothing is cached', async () => {
    const bodies: unknown[] = [];
    const { calls } = mockDetails({
      MessageRevealController_reveal_v1: ({ body }) => {
        bodies.push(body);
        expectRequestMatchesContract('MessageRevealController_reveal_v1', body);
        const more = (body as { recipientsCursor?: string }).recipientsCursor;
        return okJson(
          more
            ? revealBody({ subject: false, recipients: [[1, REVEALED.addresses[1] ?? '']] })
            : revealBody({ nextCursor: 'cursor-page-2' }),
          200,
          { 'cache-control': 'no-store' },
        );
      },
    });
    const queryClient = createTestQueryClient();
    const { user, container } = renderWithProviders(<MessageDetails messageId={MESSAGE_ID} />, {
      role: 'security_analyst',
      route: detailsRoute(),
      queryClient,
    });
    await screen.findByRole('heading', { name: 'Message summary' });
    expect(calls('MessageRevealController_reveal_v1')).toHaveLength(0);
    await user.click(screen.getByRole('button', { name: 'Reveal' }));
    expect(await screen.findByText(REVEALED.subject)).toBeInTheDocument();
    expect(screen.getByText('Revealed')).toBeInTheDocument();
    const announcement = screen.getByText(
      'Revealed the subject, 2 header values and 1 recipient address. The reveal is recorded in the audit log.',
    );
    expect(announcement).toHaveAttribute('aria-live', 'polite');
    expect(bodies[0]).toEqual({
      fields: ['subject', 'headers', 'recipients'],
      recipientsLimit: 100,
    });

    await user.click(screen.getByRole('tab', { name: 'Sender and recipients' }));
    expect(await screen.findByText(REVEALED.addresses[0] ?? '')).toBeInTheDocument();
    expect(screen.getByText('m***@alpha.example.test')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Copy user ID' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Reveal more recipients' }));
    expect(await screen.findByText(REVEALED.addresses[1] ?? '')).toBeInTheDocument();
    expect(bodies[1]).toEqual({
      fields: ['recipients'],
      recipientsCursor: 'cursor-page-2',
      recipientsLimit: 100,
    });
    expect(screen.getByText(/Every recipient address is revealed \(2\)/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Reveal more recipients' })).toBeNull();

    await user.click(screen.getByRole('tab', { name: 'Email headers' }));
    expect(await screen.findByText(REVEALED.to)).toBeInTheDocument();
    expect(screen.getAllByText('Revealed').length).toBeGreaterThanOrEqual(2);

    await user.click(screen.getByRole('tab', { name: 'Delivery timeline' }));
    expect(await screen.findByText(REVEALED.addresses[0] ?? '')).toBeInTheDocument();

    // Never in the TanStack caches, the URL or storage.
    const cached = cachedText(queryClient);
    expect(cached).not.toContain(REVEALED.subject);
    expect(cached).not.toContain(REVEALED.addresses[0]);
    expect(
      queryClient
        .getMutationCache()
        .findAll({ mutationKey: ['MessageRevealController_reveal_v1'] }),
    ).toHaveLength(0);
    expect(window.location.href).not.toContain('priya');
    expect(JSON.stringify({ ...localStorage })).not.toContain('priya');
    await expectNoAxeViolations(container);

    await user.click(screen.getByRole('button', { name: 'Hide again' }));
    expect(screen.queryByText(REVEALED.addresses[0] ?? '')).not.toBeInTheDocument();
    expect(screen.getByText('Revealed values are hidden again.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Reveal' })).toBeInTheDocument();
    expect(calls('MessageRevealController_reveal_v1')).toHaveLength(2);
  });

  it('forgets revealed values on unmount', async () => {
    const { calls } = mockDetails();
    const queryClient = createTestQueryClient();
    const first = renderWithProviders(<MessageDetails messageId={MESSAGE_ID} />, {
      role: 'organization_admin',
      route: detailsRoute(),
      queryClient,
    });
    await first.user.click(await screen.findByRole('button', { name: 'Reveal' }));
    expect(await screen.findByText(REVEALED.subject)).toBeInTheDocument();
    first.unmount();
    renderWithProviders(<MessageDetails messageId={MESSAGE_ID} />, {
      role: 'organization_admin',
      route: detailsRoute(),
      queryClient,
    });
    await screen.findByRole('heading', { name: 'Message summary' });
    expect(screen.queryByText(REVEALED.subject)).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Reveal' })).toBeInTheDocument();
    expect(calls('MessageRevealController_reveal_v1')).toHaveLength(1);
  });

  it('429 shows the countdown and disables Reveal until it ends', async () => {
    mockDetails({
      MessageRevealController_reveal_v1: () =>
        apiErrorJson(429, 'rate_limited', 'Too many reveals', {
          requestId: 'req-429',
          headers: { 'retry-after': '30' },
          extra: { scope: 'route' },
        }),
    });
    const { user } = renderWithProviders(<MessageDetails messageId={MESSAGE_ID} />, {
      role: 'compliance_auditor',
      route: detailsRoute(),
    });
    await user.click(await screen.findByRole('button', { name: 'Reveal' }));
    const alert = await screen.findByRole('alert');
    expect(
      within(alert).getByText(/Too many reveals in the last minute. Try again in 30 s./),
    ).toBeInTheDocument();
    expect(within(alert).getByText('rate_limited')).toBeInTheDocument();
    expect(within(alert).getByText('req-429')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Reveal' })).toBeDisabled();
  });

  it.each([
    [403, 'forbidden', /You do not have the message:reveal permission/],
    [404, 'message_not_found', /no longer exists/],
  ] as const)('%i %s is explained and nothing is revealed', async (status, code, text) => {
    mockDetails({
      MessageRevealController_reveal_v1: () =>
        apiErrorJson(status, code, code, { requestId: 'req-x' }),
    });
    const { user } = renderWithProviders(<MessageDetails messageId={MESSAGE_ID} />, {
      role: 'organization_admin',
      route: detailsRoute(),
    });
    await user.click(await screen.findByRole('button', { name: 'Reveal' }));
    expect(await screen.findByText(text)).toBeInTheDocument();
    expect(screen.queryByText(REVEALED.subject)).not.toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole('button', { name: 'Reveal' })).toBeEnabled());
  });

  it('a reveal moves the audit window forward, so its message.revealed row is listed', async () => {
    const { calls } = mockDetails();
    const { user } = renderWithProviders(<MessageDetails messageId={MESSAGE_ID} />, {
      role: 'organization_admin',
      route: detailsRoute('section=audit'),
    });
    await screen.findAllByText('message.revealed');
    const before = calls('AuditLogsController_search_v1');
    const firstTo = Date.parse(before[0]?.url.searchParams.get('to') ?? '');
    await user.click(screen.getByRole('button', { name: 'Reveal' }));
    await screen.findByText(/Revealed the subject/);
    await waitFor(() =>
      expect(calls('AuditLogsController_search_v1').length).toBeGreaterThan(before.length),
    );
    const latest = calls('AuditLogsController_search_v1').at(-1);
    expect(Date.parse(latest?.url.searchParams.get('to') ?? '')).toBeGreaterThan(firstTo);
  });
});
