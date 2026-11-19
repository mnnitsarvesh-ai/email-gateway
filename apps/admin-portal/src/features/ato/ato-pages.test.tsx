import { screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import {
  apiErrorJson,
  currentTestUrl,
  expectNoAxeViolations,
  makeMe,
  mockApi,
  okJson,
  renderWithProviders,
} from '@/test';
import { AtoAttentionBadge } from '@/features/shell/attention-badge';
import { AtoAccountsPage } from './accounts-page';
import { AtoDashboardPage } from './dashboard-page';
import { ACCOUNT_ID, account, overview, page, settings } from './test-data';

describe('ATO dashboard (/ato)', () => {
  it('shows the tiles, the incident trend with a table view and the geography unavailable state; axe', async () => {
    const ranges: string[] = [];
    mockApi({
      AtoOverviewController_overview_v1: ({ url }) => {
        ranges.push(url.searchParams.get('range') ?? '');
        return okJson(overview({ range: (url.searchParams.get('range') ?? '7d') as '7d' }));
      },
    });
    const { container, user } = renderWithProviders(<AtoDashboardPage />, { route: '/ato' });
    expect(
      await screen.findByRole('heading', { name: 'Account takeover', level: 1 }),
    ).toBeInTheDocument();
    const tiles = await screen.findByRole('group', { name: 'Key figures' });
    for (const label of [
      'Monitored accounts',
      'High-risk accounts',
      'Critical incidents',
      'Suspicious sign-ins',
      'Suspicious outbound activity',
      'Restricted accounts',
      'Mail held by ATO policy',
      'Pending approvals',
    ]) {
      expect(within(tiles).getByRole('heading', { name: label })).toBeInTheDocument();
    }
    expect(within(tiles).getByText('12')).toBeInTheDocument();
    expect(within(tiles).getByText('5')).toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Geography unavailable' })).toHaveTextContent(
      /GeoIP City database/,
    );
    expect(screen.getByRole('link', { name: 'View details: Pending approvals' })).toHaveAttribute(
      'href',
      '/ato/responses?status=pending_approval',
    );
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('combobox', { name: 'Range' }));
    await user.click(await screen.findByRole('option', { name: 'Last 30 days' }));
    await waitFor(() => expect(ranges).toContain('30d'));
    expect(currentTestUrl()).toBe('/ato?range=30d');
  });

  it('shows the feature-off state while ato_detection is off', async () => {
    mockApi({
      AtoOverviewController_overview_v1: () =>
        okJson(
          overview({
            monitoring: {
              featureEnabled: false,
              mode: 'monitor',
              learning: false,
              learningEndsAt: null,
            },
          }),
        ),
    });
    renderWithProviders(<AtoDashboardPage />, { route: '/ato' });
    expect(
      await screen.findByRole('region', { name: 'Account takeover detection is off' }),
    ).toBeInTheDocument();
    expect(screen.queryByLabelText('Key figures')).not.toBeInTheDocument();
  });

  it('is forbidden without ato:read', async () => {
    renderWithProviders(<AtoDashboardPage />, { role: 'read_only_user', route: '/ato' });
    expect(await screen.findByText(/ato:read/)).toBeInTheDocument();
  });
});

describe('Accounts (/ato/accounts)', () => {
  it('lists accounts with risk, incident links and filters in the URL; axe', async () => {
    const queries: URLSearchParams[] = [];
    mockApi({
      AtoSettingsController_get_v1: () => okJson(settings()),
      AtoAccountsController_list_v1: ({ url }) => {
        queries.push(url.searchParams);
        return okJson(
          page([
            account(),
            account({
              id: '01933c3a-1b2c-7d4e-8f00-0000000a7009',
              address: 'sales@alpha.example.test',
              riskScore: 12,
              riskLevel: 'low',
              activeIncident: null,
            }),
          ]),
        );
      },
    });
    const { container, user } = renderWithProviders(<AtoAccountsPage />, {
      route: '/ato/accounts?level=high,critical',
    });
    const table = await screen.findByRole('table', { name: 'Monitored accounts' });
    expect(within(table).getByRole('link', { name: 'finance@alpha.example.test' })).toHaveAttribute(
      'href',
      `/ato/accounts/${ACCOUNT_ID}`,
    );
    expect(
      within(table).getByRole('meter', { name: /risk score 90 of 100, Critical/ }),
    ).toBeInTheDocument();
    expect(queries[0]?.get('level')).toBe('high,critical');
    expect(queries[0]?.get('sort')).toBe('-riskScore');
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('combobox', { name: 'Sort by' }));
    await user.click(await screen.findByRole('option', { name: 'Latest signal first' }));
    await waitFor(() => expect(queries.at(-1)?.get('sort')).toBe('-lastSignalAt'));
    await user.click(screen.getByRole('combobox', { name: 'Active incident' }));
    await user.click(await screen.findByRole('option', { name: 'With an incident' }));
    await waitFor(() => expect(queries.at(-1)?.get('hasActiveIncident')).toBe('true'));
  });

  it('explains that detection is off', async () => {
    mockApi({
      AtoSettingsController_get_v1: () => okJson(settings({ featureEnabled: false })),
      AtoAccountsController_list_v1: () => okJson(page([])),
    });
    renderWithProviders(<AtoAccountsPage />, { route: '/ato/accounts' });
    expect(
      await screen.findByRole('region', { name: 'Account takeover detection is off' }),
    ).toBeInTheDocument();
  });
});

describe('Shell attention badge (D16)', () => {
  it('shows critical incidents plus pending approvals for ato:read holders', async () => {
    mockApi({
      AtoOverviewController_attention_v1: () =>
        okJson({ criticalIncidents: 1, pendingApprovals: 2 }),
    });
    renderWithProviders(<AtoAttentionBadge />, { role: 'security_analyst' });
    const badge = await screen.findByTestId('ato-attention-badge');
    expect(badge).toHaveTextContent('3');
    expect(badge).toHaveTextContent('1 critical incident, 2 pending approvals');
  });

  it('renders nothing at zero, on errors and without the permission (no request)', async () => {
    let calls = 0;
    mockApi({
      AtoOverviewController_attention_v1: () => {
        calls += 1;
        return calls === 1
          ? okJson({ criticalIncidents: 0, pendingApprovals: 0 })
          : apiErrorJson(500, 'internal_error');
      },
    });
    const { unmount } = renderWithProviders(<AtoAttentionBadge />, { role: 'organization_admin' });
    await waitFor(() => expect(calls).toBe(1));
    expect(screen.queryByTestId('ato-attention-badge')).not.toBeInTheDocument();
    unmount();
    renderWithProviders(<AtoAttentionBadge />, { me: makeMe({ role: 'domain_admin' }) });
    expect(screen.queryByTestId('ato-attention-badge')).not.toBeInTheDocument();
    expect(calls).toBe(1);
  });
});
