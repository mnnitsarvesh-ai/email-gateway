import { act, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import {
  apiErrorJson,
  createTestQueryClient,
  currentTestUrl,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  mockApi,
  okJson,
  renderWithProviders,
} from '@/test';
import { ArchiveSearchPage } from './archive-search-page';
import {
  ARCHIVE_URL_SHAPE,
  DEFAULT_ARCHIVE_STATE,
  archiveSearchQuery,
  caseSearchCriteria,
  customRangeError,
  permittedArchiveState,
  rangeOf,
} from './search-state';
import { parseSearchParams } from '@/hooks/use-url-state';
import {
  HOLD,
  MALICIOUS_ID,
  MESSAGE_ID,
  SECRET_RECIPIENT,
  SECRET_SUBJECT,
  message,
} from './test-data';

beforeEach(() => localStorage.clear());

const NOW = Date.parse('2026-11-17T08:20:00.000Z');

/** Every JSON string held by the TanStack query and mutation caches. */
function cachedText(queryClient: ReturnType<typeof createTestQueryClient>): string {
  return JSON.stringify([
    queryClient
      .getQueryCache()
      .getAll()
      .map((q) => q.state.data),
    queryClient
      .getMutationCache()
      .getAll()
      .map((m) => m.state.data),
  ]);
}

describe('archive search state (A17, §4.4 #15)', () => {
  it('maps every filter to the GET /archive/messages query (comma lists, risk bounds, range)', () => {
    const state = parseSearchParams(
      ARCHIVE_URL_SHAPE,
      new URLSearchParams(
        'range=30d&direction=inbound,outbound&category=delivered&status=expiry_review&verdict=phishing&finalAction=deliver' +
          '&sender=a@partner.example.test&recipientDomain=corp.example.test&subject=merger&internetMessageId=%3Cx%40y%3E' +
          '&attachmentSha256=' +
          'f'.repeat(64) +
          '&hasAttachments=true&malicious=false&legalHold=true&holdId=' +
          HOLD.id +
          '&riskMin=300&riskMax=900&sort=receivedAt',
      ),
    );
    const query = archiveSearchQuery(state, NOW);
    expect(query).toMatchObject({
      from: '2026-10-18T09:00:00.000Z',
      to: '2026-11-17T09:00:00.000Z',
      sort: 'receivedAt',
      direction: 'inbound,outbound',
      category: 'delivered',
      status: 'expiry_review',
      verdict: 'phishing',
      finalAction: 'deliver',
      sender: 'a@partner.example.test',
      recipientDomain: 'corp.example.test',
      subject: 'merger',
      internetMessageId: '<x@y>',
      attachmentSha256: 'f'.repeat(64),
      hasAttachments: 'true',
      malicious: 'false',
      legalHold: 'true',
      holdId: HOLD.id,
      'riskScore.gte': '300',
      'riskScore.lte': '900',
    });
  });

  it('falls back silently on invalid values and validates custom day ranges', () => {
    const state = parseSearchParams(
      ARCHIVE_URL_SHAPE,
      new URLSearchParams('range=bogus&direction=sideways&sender=not-an-address&riskMin=5000'),
    );
    expect(state.range).toBe('7d');
    expect(state.direction).toEqual([]);
    expect(state.sender).toBeUndefined();
    expect(state.riskMin).toBeUndefined();
    expect(customRangeError('2026-11-10', '2026-11-01')).toMatch(/must not be before/);
    expect(customRangeError('2024-01-01', '2026-01-01')).toMatch(/at most 366/);
    expect(customRangeError('2026-11-01', '2026-11-17')).toBeNull();
    expect(rangeOf({ range: 'custom', from: '2026-11-01', to: '2026-11-02' }, NOW)).toEqual({
      from: '2026-11-01T00:00:00.000Z',
      to: '2026-11-03T00:00:00.000Z',
    });
  });

  it('drops reveal-gated and hold filters the caller may not use, naming them', () => {
    const state = {
      ...DEFAULT_ARCHIVE_STATE,
      recipient: SECRET_RECIPIENT,
      subject: 'x',
      custodian: SECRET_RECIPIENT,
      holdId: HOLD.id,
    };
    const result = permittedArchiveState(state, { reveal: false, holds: false });
    expect(result.ignored).toEqual(['recipient', 'custodian', 'subject', 'holdId']);
    expect(result.state.recipient).toBeUndefined();
    expect(permittedArchiveState(state, { reveal: true, holds: true }).ignored).toEqual([]);
  });

  it('builds archive-search/1 criteria for a case search (contract-valid)', () => {
    const criteria = caseSearchCriteria(
      {
        ...DEFAULT_ARCHIVE_STATE,
        range: 'custom',
        from: '2020-01-01',
        to: '2026-11-17',
        direction: ['outbound'],
        sender: 'a@partner.example.test',
        malicious: 'true',
        riskMin: 500,
      },
      { useCaseCustodians: true, now: NOW },
    );
    expect(criteria).toEqual({
      from: '2020-01-01',
      to: '2026-11-17',
      directions: ['outbound'],
      senders: ['a@partner.example.test'],
      custodians: 'case',
      malicious: true,
      riskScoreGte: 500,
    });
    expectRequestMatchesContract('EdiscoverySearchesController_create_v1', { criteria });
  });
});

function mockSearch(
  rows = [message(), message({ messageId: MALICIOUS_ID, malicious: true, verdict: 'phishing' })],
  options: { lag?: string; capture?: URL[] } = {},
) {
  mockApi({
    ArchiveMessagesController_list_v1: ({ url }) => {
      options.capture?.push(url);
      return okJson({ data: rows, nextCursor: null }, 200, {
        'x-eg-index-lag-seconds': options.lag ?? '0',
      });
    },
    LegalHoldsController_list_v1: () => okJson({ data: [HOLD], nextCursor: null }),
  });
}

describe('/archive page (A17, A28)', () => {
  it('shows masked results to an organization admin, with the URL filters applied and axe clean', async () => {
    const capture: URL[] = [];
    mockSearch(undefined, { capture });
    const { container } = renderWithProviders(<ArchiveSearchPage />, {
      role: 'organization_admin',
      route: '/archive?direction=inbound&sender=sender@partner.example.test',
    });
    expect(await screen.findAllByRole('link', { name: /open archived message/ })).toHaveLength(2);
    expect(screen.getAllByText('Hidden').length).toBeGreaterThanOrEqual(2);
    expect(screen.getAllByText('p***@corp.example.test').length).toBeGreaterThan(0);
    expect(screen.queryByText(SECRET_SUBJECT)).not.toBeInTheDocument();
    const url = capture[0]!;
    expect(url.searchParams.get('direction')).toBe('inbound');
    expect(url.searchParams.get('sender')).toBe('sender@partner.example.test');
    expect(url.searchParams.get('from')).toBeTruthy();
    expect(url.searchParams.get('limit')).toBe('25');
    // Reveal-gated filters and the hold filter are offered to an organization admin.
    expect(screen.getByLabelText('Recipient address')).toBeInTheDocument();
    expect(screen.getByLabelText('Covered by legal hold')).toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('hides reveal-gated filters, the hold filter and Reveal without message:reveal; a shared link is not applied', async () => {
    const capture: URL[] = [];
    mockSearch(undefined, { capture });
    renderWithProviders(<ArchiveSearchPage />, {
      permissions: ['archive:search', 'archive:read'],
      route: `/archive?recipient=${SECRET_RECIPIENT}&holdId=${HOLD.id}`,
    });
    await screen.findAllByRole('link', { name: /open archived message/ });
    expect(screen.queryByLabelText('Recipient address')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Subject phrase')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Covered by legal hold')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Reveal this page' })).not.toBeInTheDocument();
    expect(screen.getByText(/they were not applied: recipient, holdId/)).toBeInTheDocument();
    expect(capture[0]!.searchParams.get('recipient')).toBeNull();
    expect(capture[0]!.searchParams.get('holdId')).toBeNull();
  });

  it('is forbidden for a read-only user (no archive:search)', async () => {
    renderWithProviders(<ArchiveSearchPage />, { role: 'read_only_user', route: '/archive' });
    expect(
      await screen.findByText(/You do not have access|do not have permission/i),
    ).toBeInTheDocument();
  });

  it('reveals the page with one audited call per message; values stay in component state only', async () => {
    mockSearch();
    const bodies: unknown[] = [];
    mockApi({
      ArchiveMessagesController_reveal_v1: ({ params, body }) => {
        bodies.push(body);
        expectRequestMatchesContract('ArchiveMessagesController_reveal_v1', body);
        return okJson(
          {
            messageId: params.messageId,
            revealedAt: '2026-11-17T08:00:00.000Z',
            subject: SECRET_SUBJECT,
            recipients: [{ seq: 0, address: SECRET_RECIPIENT }],
          },
          200,
          { 'cache-control': 'no-store' },
        );
      },
    });
    const queryClient = createTestQueryClient();
    const { user } = renderWithProviders(<ArchiveSearchPage />, {
      role: 'organization_admin',
      route: '/archive',
      queryClient,
    });
    await screen.findAllByRole('link', { name: /open archived message/ });
    await user.click(screen.getByRole('button', { name: 'Reveal this page' }));
    expect(await screen.findAllByText(SECRET_SUBJECT)).toHaveLength(2);
    expect(bodies).toEqual([
      { fields: ['subject', 'recipients'] },
      { fields: ['subject', 'recipients'] },
    ]);
    expect(cachedText(queryClient)).not.toContain(SECRET_SUBJECT);
    expect(cachedText(queryClient)).not.toContain(SECRET_RECIPIENT);
    expect(currentTestUrl()).not.toContain('EXAMPLE');
    expect(JSON.stringify({ ...localStorage, ...sessionStorage })).not.toContain(SECRET_SUBJECT);
    await user.click(screen.getByRole('button', { name: 'Hide again' }));
    expect(screen.queryByText(SECRET_SUBJECT)).not.toBeInTheDocument();
  });

  it('shows the index-lag banner from X-EG-Index-Lag-Seconds', async () => {
    mockSearch(undefined, { lag: '600' });
    renderWithProviders(<ArchiveSearchPage />, { role: 'organization_admin', route: '/archive' });
    expect(await screen.findByText(/search index is about 10 minutes behind/)).toBeInTheDocument();
  });

  it('explains 503 archive_search_unavailable without retrying it automatically', async () => {
    let calls = 0;
    mockApi({
      ArchiveMessagesController_list_v1: () => {
        calls += 1;
        return apiErrorJson(
          503,
          'archive_search_unavailable',
          'Archive search is temporarily unavailable',
        );
      },
      LegalHoldsController_list_v1: () => okJson({ data: [], nextCursor: null }),
    });
    renderWithProviders(<ArchiveSearchPage />, { role: 'organization_admin', route: '/archive' });
    expect(
      await screen.findByText('Archive search is temporarily unavailable'),
    ).toBeInTheDocument();
    expect(screen.getByText(/details, previews and downloads keep working/)).toBeInTheDocument();
    expect(calls).toBe(1);
  });

  it('counts a 429 down from Retry-After', async () => {
    mockApi({
      ArchiveMessagesController_list_v1: () =>
        apiErrorJson(429, 'rate_limited', 'Too many requests', { headers: { 'retry-after': '3' } }),
      LegalHoldsController_list_v1: () => okJson({ data: [], nextCursor: null }),
    });
    renderWithProviders(<ArchiveSearchPage />, { role: 'organization_admin', route: '/archive' });
    expect(await screen.findByText(/Try again in 3 s/)).toBeInTheDocument();
    await act(async () => {
      await new Promise((r) => setTimeout(r, 1100));
    });
    expect(screen.getByText(/Try again in 2 s/)).toBeInTheDocument();
  });

  it('writes filters to the URL (never revealed values) and resets the cursor', async () => {
    mockSearch();
    const { user } = renderWithProviders(<ArchiveSearchPage />, {
      role: 'organization_admin',
      route: '/archive',
    });
    await screen.findAllByRole('link', { name: /open archived message/ });
    const sender = screen.getByLabelText('Sender address');
    await user.type(sender, 'bad');
    await user.keyboard('{Enter}');
    expect(screen.getByText('Enter a complete email address')).toBeInTheDocument();
    await user.clear(sender);
    await user.type(sender, 'x@partner.example.test{Enter}');
    await waitFor(() => expect(currentTestUrl()).toContain('sender=x%40partner.example.test'));
    expect(MESSAGE_ID).toBeTruthy();
  });
});
