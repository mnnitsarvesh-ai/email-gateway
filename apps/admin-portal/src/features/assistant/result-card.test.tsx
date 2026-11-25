import { screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { apiErrorJson, expectNoAxeViolations, mockApi, okJson, renderWithProviders } from '@/test';
import { DeniedCard, ResultCard, deniedLinkOf, seriesRows } from './result-card';
import {
  ATO_FOUR_EYES_MESSAGE,
  CAPTURE_NOT_RETRYABLE_MESSAGE,
  CASE_ACTIVE_HOLDS_MESSAGE,
  ERROR_CARD,
  EXECUTION_ID,
  KV_CARD,
  POLICY_ID,
  POLICY_ID_3,
  RETENTION_DEFAULT_POLICY_MESSAGE,
  SELF_GUARD_MESSAGE,
  SERIES_CARD,
  TABLE_CARD,
  execution,
} from './test-data';
import type { AssistantCard } from './types';

const NEXT_EXECUTION = '01930000-0000-7000-8000-00000000e309';
const PAGE_2: AssistantCard = {
  ...TABLE_CARD,
  executionId: NEXT_EXECUTION,
  rows: [{ name: 'Quarantine archives', status: 'draft' }],
  refs: ['r3.1'],
  nextCursor: false,
  portalLinks: [
    { label: 'Policies', href: '/policies' },
    { label: 'Quarantine archives', href: `/policies/${POLICY_ID_3}`, ref: 'r3.1' },
  ],
};

describe('ResultCard (assistant-card/1)', () => {
  it('renders a table card with portal links and appends rows with Load more', async () => {
    const calls: string[] = [];
    mockApi({
      AssistantExecutionsController_more_v1: ({ params }) => {
        calls.push(params.executionId ?? '');
        return okJson(
          execution(PAGE_2, {
            id: NEXT_EXECUTION,
            parentExecutionId: EXECUTION_ID,
            hasMore: false,
          }),
        );
      },
    });
    const { user, container } = renderWithProviders(<ResultCard card={TABLE_CARD} hasMore />);
    const table = screen.getByRole('table', { name: 'Policies' });
    expect(within(table).getAllByRole('row')).toHaveLength(3);
    const open = within(table).getAllByRole('link');
    expect(open[0]).toHaveAttribute('href', `/policies/${POLICY_ID}`);
    expect(open[0]).toHaveAccessibleName('Open Block executables');
    expect(screen.getByRole('link', { name: 'Open Policies in the portal' })).toHaveAttribute(
      'href',
      '/policies',
    );
    expect(screen.getByText('2 rows')).toBeInTheDocument();
    await expectNoAxeViolations(container);

    await user.click(screen.getByRole('button', { name: 'Load more' }));
    await waitFor(() => expect(within(table).getAllByRole('row')).toHaveLength(4));
    expect(calls).toEqual([EXECUTION_ID]);
    expect(within(table).getByText('Quarantine archives')).toBeInTheDocument();
    expect(within(table).getAllByRole('link')[2]).toHaveAttribute(
      'href',
      `/policies/${POLICY_ID_3}`,
    );
    expect(screen.queryByRole('button', { name: 'Load more' })).not.toBeInTheDocument();
    expect(screen.getByText('3 rows')).toBeInTheDocument();
  });

  it('explains a failed Load more and stops offering it when the api has no more results', async () => {
    mockApi({
      AssistantExecutionsController_more_v1: () =>
        apiErrorJson(409, 'assistant_no_more_results', 'No more results'),
    });
    const { user } = renderWithProviders(<ResultCard card={TABLE_CARD} hasMore />);
    await user.click(screen.getByRole('button', { name: 'Load more' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('No more results');
    expect(screen.queryByRole('button', { name: 'Load more' })).not.toBeInTheDocument();
  });

  it('drops portal links that are not allow-listed internal routes', () => {
    renderWithProviders(
      <ResultCard
        card={{
          ...TABLE_CARD,
          nextCursor: false,
          portalLinks: [
            { label: 'Evil', href: 'https://evil.example/x' },
            { label: 'Block executables', href: '/bff/api/v1/policies', ref: 'r1.1' },
          ],
        }}
      />,
    );
    expect(screen.queryAllByRole('link')).toHaveLength(0);
  });

  it('renders mail-derived values as text, never as links or HTML', () => {
    const { container } = renderWithProviders(
      <ResultCard
        card={{
          ...TABLE_CARD,
          nextCursor: false,
          rows: [{ name: '<img src=x onerror=alert(1)> https://evil.example', status: 'active' }],
          refs: ['r1.1'],
          portalLinks: [],
        }}
      />,
    );
    expect(container.querySelector('img')).toBeNull();
    expect(screen.queryAllByRole('link')).toHaveLength(0);
    expect(screen.getByText(/<img src=x onerror=alert\(1\)>/)).toBeInTheDocument();
  });

  it('renders a key-value card', async () => {
    const { container } = renderWithProviders(<ResultCard card={KV_CARD} />);
    const region = screen.getByRole('region', { name: 'Result: Policy details' });
    expect(within(region).getByText('Priority').nextElementSibling).toHaveTextContent('10');
    expect(within(region).getByText('Enabled').nextElementSibling).toHaveTextContent('Yes');
    expect(within(region).getByText('Description').nextElementSibling).toHaveTextContent('—');
    expect(within(region).getByRole('link')).toHaveAttribute('href', `/policies/${POLICY_ID}`);
    await expectNoAxeViolations(container);
  });

  it('renders a series card with the time-series chart and its data table', async () => {
    const { user } = renderWithProviders(<ResultCard card={SERIES_CARD} />);
    expect(screen.getByRole('img', { name: /Traffic/ })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /View data as table/i }));
    expect(screen.getByRole('table')).toHaveTextContent('Delivered');
    expect(seriesRows(SERIES_CARD.series!)).toMatchObject({
      timeAxis: true,
      rows: [
        { x: '2026-11-18', s0: 120, s1: 4 },
        { x: '2026-11-19', s0: 140, s1: 9 },
        { x: '2026-11-20', s0: null, s1: 2 },
      ],
    });
    expect(seriesRows({ x: ['inbound', 'outbound'], series: [] }).timeAxis).toBe(false);
  });

  it('renders the error card with its coded error and a link to the page', async () => {
    const { container } = renderWithProviders(<ResultCard card={ERROR_CARD} />);
    expect(screen.getByText('Policy not found')).toBeInTheDocument();
    expect(screen.getByText('policy_not_found')).toBeInTheDocument();
    expect(screen.getByText(/HTTP 404/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Open Policies in the portal' })).toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('explains a denied tool call by its reason', () => {
    const onNavigate = vi.fn();
    void onNavigate;
    const { rerender } = renderWithProviders(
      <DeniedCard
        title="Platform organizations"
        decision="denied_permission"
        message="Requires platform:organizations"
      />,
    );
    expect(screen.getByText('You do not have the permission this needs')).toBeInTheDocument();
    expect(screen.getByText('Requires platform:organizations')).toBeInTheDocument();
    expect(screen.getByText(/only do what your role allows/)).toBeInTheDocument();
    rerender(
      <DeniedCard
        title="Download"
        decision="denied_not_applicable"
        message="Downloads are not available in chat."
      />,
    );
    expect(screen.getByText('Not available in chat; use the portal page')).toBeInTheDocument();
  });

  it('explains a proposal guard refusal with the server message as plain text (step AI-3 D3)', async () => {
    const { container } = renderWithProviders(
      <DeniedCard
        title="Replace user roles"
        decision="denied_guard"
        message={SELF_GUARD_MESSAGE}
      />,
    );
    const card = screen.getByRole('region', { name: 'Result: Replace user roles' });
    expect(within(card).getByText('Not allowed in chat')).toBeInTheDocument();
    expect(within(card).getByText(SELF_GUARD_MESSAGE)).toBeInTheDocument();
    expect(within(card).queryByText(/only do what your role allows/)).not.toBeInTheDocument();
    expect(within(card).queryByRole('link')).not.toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('links a four-eyes refusal of an ATO response decision to the Responses page (step AI-4 D10)', async () => {
    const onNavigate = vi.fn();
    const { container, rerender } = renderWithProviders(
      <DeniedCard
        title="Approve ATO response"
        decision="denied_guard"
        message={ATO_FOUR_EYES_MESSAGE}
        tool="ato_responses_approve"
        onNavigate={onNavigate}
      />,
    );
    let card = screen.getByRole('region', { name: 'Result: Approve ATO response' });
    expect(within(card).getByText('Not allowed in chat')).toBeInTheDocument();
    expect(within(card).getByText(ATO_FOUR_EYES_MESSAGE)).toBeInTheDocument();
    const link = within(card).getByRole('link', { name: 'Open Responses in the portal' });
    expect(link).toHaveAttribute('href', '/ato/responses');
    link.click();
    expect(onNavigate).toHaveBeenCalledTimes(1);
    await expectNoAxeViolations(container);

    rerender(
      <DeniedCard
        title="Reject ATO response"
        decision="denied_guard"
        message={ATO_FOUR_EYES_MESSAGE}
        tool="ato_responses_reject"
      />,
    );
    card = screen.getByRole('region', { name: 'Result: Reject ATO response' });
    expect(
      within(card).getByRole('link', { name: 'Open Responses in the portal' }),
    ).toHaveAttribute('href', '/ato/responses');
  });

  it('offers the Responses link only for a guard refusal of approve or reject', () => {
    expect(deniedLinkOf('ato_responses_approve', 'denied_guard')).toEqual({
      label: 'Responses',
      href: '/ato/responses',
    });
    expect(deniedLinkOf('ato_responses_reject', 'denied_guard')?.href).toBe('/ato/responses');
    expect(deniedLinkOf('ato_responses_approve', 'denied_permission')).toBeNull();
    expect(deniedLinkOf('ato_responses_cancel', 'denied_guard')).toBeNull();
    expect(deniedLinkOf('users_replace_roles', 'denied_guard')).toBeNull();
    expect(deniedLinkOf(undefined, 'denied_guard')).toBeNull();
    renderWithProviders(
      <DeniedCard
        title="Approve ATO response"
        decision="denied_permission"
        message="Requires ato:respond"
        tool="ato_responses_approve"
      />,
    );
    expect(
      within(screen.getByRole('region', { name: 'Result: Approve ATO response' })).queryByRole(
        'link',
      ),
    ).not.toBeInTheDocument();
  });

  it.each([
    [
      'archive_retention_delete',
      'Delete retention policy',
      RETENTION_DEFAULT_POLICY_MESSAGE,
      'Retention and lock',
      '/archive/retention',
    ],
    [
      'ediscovery_cases_close',
      'Close eDiscovery case',
      CASE_ACTIVE_HOLDS_MESSAGE,
      'Legal holds',
      '/legal-holds',
    ],
    [
      'archive_admin_retry',
      'Retry archive capture',
      CAPTURE_NOT_RETRYABLE_MESSAGE,
      'Capture issues',
      '/archive/retention?tab=capture',
    ],
  ])(
    'links the %s guard refusal to the page that resolves it (step AI-5 D11)',
    async (tool, title, message, label, href) => {
      const onNavigate = vi.fn();
      const { container } = renderWithProviders(
        <DeniedCard
          title={title}
          decision="denied_guard"
          message={message}
          tool={tool}
          onNavigate={onNavigate}
        />,
      );
      const card = screen.getByRole('region', { name: `Result: ${title}` });
      expect(within(card).getByText('Not allowed in chat')).toBeInTheDocument();
      expect(within(card).getByText(message)).toBeInTheDocument();
      const link = within(card).getByRole('link', { name: `Open ${label} in the portal` });
      expect(link).toHaveAttribute('href', href);
      link.click();
      expect(onNavigate).toHaveBeenCalledTimes(1);
      expect(deniedLinkOf(tool, 'denied_guard')).toEqual({ label, href });
      expect(deniedLinkOf(tool, 'denied_permission')).toBeNull();
      expect(deniedLinkOf(tool, 'denied_schema')).toBeNull();
      await expectNoAxeViolations(container);
    },
  );

  it('links a "Not available in chat" refusal of a portal-only operation to its page (step AI-5 D11)', async () => {
    const { container } = renderWithProviders(
      <DeniedCard
        title="Release legal hold"
        decision="denied_not_applicable"
        message="This action is not available in chat; use the portal page. Reason: critical: portal only by policy (chat links to the page)."
        tool="legal_holds_release"
      />,
    );
    const card = screen.getByRole('region', { name: 'Result: Release legal hold' });
    expect(
      within(card).getByText('Not available in chat; use the portal page'),
    ).toBeInTheDocument();
    expect(
      within(card).getByRole('link', { name: 'Open Legal holds in the portal' }),
    ).toHaveAttribute('href', '/legal-holds');
    await expectNoAxeViolations(container);

    expect(deniedLinkOf('archive_messages_dispose', 'denied_not_applicable')?.href).toBe(
      '/archive/retention?tab=review',
    );
    expect(deniedLinkOf('archive_admin_rotate', 'denied_not_applicable')?.href).toBe(
      '/archive/retention?tab=immutability',
    );
    for (const tool of [
      'provider_grants_create',
      'provider_grants_set_credentials',
      'provider_grants_complete_consent',
      'provider_validations_create',
    ])
      expect(deniedLinkOf(tool, 'denied_not_applicable')).toEqual({
        label: 'Provider connections',
        href: '/integrations/providers',
      });
    // Only the listed tools, only for their decision; never a prototype key.
    expect(deniedLinkOf('legal_holds_release', 'denied_guard')).toBeNull();
    expect(deniedLinkOf('legal_holds_release', 'denied_permission')).toBeNull();
    expect(deniedLinkOf('archive_retention_delete', 'denied_not_applicable')).toBeNull();
    expect(deniedLinkOf('api_keys_create', 'denied_not_applicable')).toBeNull();
    expect(deniedLinkOf('constructor', 'denied_not_applicable')).toBeNull();
    expect(deniedLinkOf('toString', 'denied_guard')).toBeNull();
  });

  it('never turns markup or URLs of a denial message into elements', () => {
    const message =
      'See [your account](/settings?tab=security) or https://example.com/help <b>now</b>';
    renderWithProviders(
      <DeniedCard title="Revoke sessions" decision="denied_guard" message={message} />,
    );
    const card = screen.getByRole('region', { name: 'Result: Revoke sessions' });
    expect(within(card).getByText(message)).toBeInTheDocument();
    expect(within(card).queryByRole('link')).not.toBeInTheDocument();
    expect(card.querySelector('b')).toBeNull();
  });
});
