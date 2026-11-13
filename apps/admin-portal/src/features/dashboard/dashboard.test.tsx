import { screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import {
  apiErrorJson,
  expectNoAxeViolations,
  mockApi,
  mockBff,
  okJson,
  renderWithProviders,
} from '@/test';
import {
  PROCESSING_BOUNDS,
  deliveryReport,
  emptyTrafficReport,
  histogram,
  processingReport,
  threatsReport,
  topDomainsReport,
  trafficReport,
} from '@/features/reports/test-data';
import { spamBlocked } from '@/features/reports/report-utils';
import { DashboardPage } from './dashboard-page';

type Reports = {
  traffic?: Response | (() => Response);
  threats?: Response | (() => Response);
  delivery?: Response | (() => Response);
  processing?: Response | (() => Response);
  topDomains?: Response | (() => Response);
};

function mockReports(overrides: Reports = {}, seen: Record<string, URLSearchParams> = {}) {
  const pick = (name: keyof Reports, fallback: () => Response) => {
    const value = overrides[name];
    return value === undefined ? fallback() : typeof value === 'function' ? value() : value.clone();
  };
  mockApi({
    ReportsController_traffic_v1: ({ url }) => (
      (seen.traffic = url.searchParams),
      pick('traffic', () => okJson(trafficReport()))
    ),
    ReportsController_threats_v1: ({ url }) => (
      (seen.threats = url.searchParams),
      pick('threats', () => okJson(threatsReport()))
    ),
    ReportsController_delivery_v1: ({ url }) => (
      (seen.delivery = url.searchParams),
      pick('delivery', () => okJson(deliveryReport()))
    ),
    ReportsController_processing_v1: ({ url }) => (
      (seen.processing = url.searchParams),
      pick('processing', () => okJson(processingReport()))
    ),
    ReportsController_topDomains_v1: ({ url }) => (
      (seen.topDomains = url.searchParams),
      pick('topDomains', () => okJson(topDomainsReport()))
    ),
  });
  return seen;
}

const tile = (label: string) =>
  screen
    .getByRole('heading', { name: label, level: 3 })
    .closest('[data-slot="card"]') as HTMLElement;

describe('Dashboard (design §1.4)', () => {
  it('shows skeletons while loading, then every KPI computed from the report responses', async () => {
    mockReports();
    const { container } = renderWithProviders(<DashboardPage />, { route: '/dashboard' });
    expect(screen.getByText('Loading Total emails processed …')).toBeInTheDocument();
    expect(await screen.findByText('1,234')).toBeInTheDocument();
    expect(within(tile('Inbound emails')).getByText('900')).toBeInTheDocument();
    expect(within(tile('Outbound emails')).getByText('250')).toBeInTheDocument();
    expect(within(tile('Internal emails')).getByText('84')).toBeInTheDocument();
    await waitFor(() => expect(within(tile('Spam blocked')).getByText('54')).toBeInTheDocument());
    expect(spamBlocked(threatsReport().outcomes)).toBe(54);
    expect(within(tile('Malware detected')).getByText('9')).toBeInTheDocument();
    expect(within(tile('Phishing detected')).getByText('28')).toBeInTheDocument();
    expect(within(tile('Quarantined emails')).getByText('57')).toBeInTheDocument();
    expect(
      within(tile('Quarantined emails')).getByText('71 quarantine entries (one per recipient)'),
    ).toBeInTheDocument();
    await waitFor(() =>
      expect(within(tile('Delivery success rate')).getByText('98.4 %')).toBeInTheDocument(),
    );
    await waitFor(() =>
      expect(within(tile('Time to verdict (p95)')).getByText('≤ 5.0 s')).toBeInTheDocument(),
    );
    expect(within(tile('Time to verdict (p95)')).getByText('Average 1.7 s')).toBeInTheDocument();
    // Tiles link to the detailed reports with the same range.
    expect(within(tile('Spam blocked')).getByRole('link')).toHaveAttribute(
      'href',
      '/reports?tab=threats',
    );
    await screen.findByRole('img', { name: /Threat verdicts over time\. Total 138/ });
    await expectNoAxeViolations(container);
  });

  it('shows the definition of a widget in a tooltip', async () => {
    mockReports();
    const { user } = renderWithProviders(<DashboardPage />, { route: '/dashboard' });
    await screen.findByText('1,234');
    await user.hover(screen.getByRole('button', { name: 'Definition of Spam blocked' }));
    expect((await screen.findAllByText(/final verdict is spam or bulk/)).length).toBeGreaterThan(0);
  });

  it('reads success rate null and p95 in the overflow bin honestly', async () => {
    mockReports({
      delivery: okJson(
        deliveryReport({
          totals: {
            total: 4,
            statuses: {
              ...deliveryReport().totals.statuses,
              delivered: 0,
              bounced: 0,
              failed: 0,
              deferred: 4,
              queued: 0,
            },
            successRate: null,
          },
        }),
      ),
      processing: okJson(
        processingReport({
          totals: {
            ...processingReport().totals,
            p50UpperBoundMs: null,
            p95UpperBoundMs: null,
            averageMs: 1_200_000,
            histogram: histogram(PROCESSING_BOUNDS, { overflow: 12 }),
          },
        }),
      ),
    });
    renderWithProviders(<DashboardPage />, { route: '/dashboard' });
    expect(await screen.findByText('No completed deliveries in range')).toBeInTheDocument();
    expect(await screen.findByText('> 15 min')).toBeInTheDocument();
  });

  it('says so when no scan round completed (no samples)', async () => {
    mockReports({
      processing: okJson(
        processingReport({
          totals: {
            ...processingReport().totals,
            p50UpperBoundMs: null,
            p95UpperBoundMs: null,
            averageMs: null,
            histogram: histogram(PROCESSING_BOUNDS, {}),
          },
        }),
      ),
    });
    renderWithProviders(<DashboardPage />, { route: '/dashboard' });
    expect(await screen.findByText('No completed scan rounds in range')).toBeInTheDocument();
    expect(screen.getByText('No average (no completed rounds)')).toBeInTheDocument();
  });

  it('fails one report without hiding the others (code and request id shown)', async () => {
    mockReports({
      traffic: apiErrorJson(503, 'report_timeout', 'The report took too long', {
        requestId: 'req-dash-1',
      }),
    });
    renderWithProviders(<DashboardPage />, { route: '/dashboard' });
    await waitFor(() => expect(screen.getAllByText('req-dash-1').length).toBeGreaterThan(0));
    expect(screen.getAllByText('report_timeout').length).toBeGreaterThan(0);
    expect(screen.getByText(/Narrow the range/)).toBeInTheDocument();
    // Threats still render.
    await waitFor(() => expect(within(tile('Spam blocked')).getByText('54')).toBeInTheDocument());
  });

  it('shows "No mail in this range" for an empty traffic report', async () => {
    mockReports({ traffic: okJson(emptyTrafficReport()) });
    renderWithProviders(<DashboardPage />, { route: '/dashboard' });
    expect(await screen.findByText('No mail in this range')).toBeInTheDocument();
  });

  it('charts expose a summary and a table fallback; top domains link, mark deleted ones and the unattributed rest', async () => {
    mockReports();
    const { user } = renderWithProviders(<DashboardPage />, { route: '/dashboard' });
    const chart = await screen.findByRole('img', { name: /Threat verdicts over time\./ });
    expect(chart.getAttribute('aria-label')).toMatch(/Largest: Spam 90, Phishing 28, Malware 9/);
    const trends = screen.getByRole('figure', { name: 'Threat verdicts over time' });
    await user.click(within(trends).getByRole('button', { name: 'View data as table' }));
    const table = within(trends).getByRole('table', {
      name: 'Threat verdicts over time: data table',
    });
    expect(table).toHaveTextContent('6 Nov');
    expect(table).toHaveTextContent('DLP violation');

    const domains = await screen.findByRole('table', { name: 'Top attacked domains' });
    expect(within(domains).getByRole('link', { name: 'alpha.example.test' })).toHaveAttribute(
      'href',
      '/domains/01930000-0000-7000-8000-00000000d001',
    );
    expect(
      within(domains).queryByRole('link', { name: 'old.example.test' }),
    ).not.toBeInTheDocument();
    expect(within(domains).getByText('Deleted')).toBeInTheDocument();
    expect(
      screen.getByText(/4 inbound messages \(1 with a threat verdict\) could not be attributed/),
    ).toBeInTheDocument();
    expect(screen.getByRole('img', { name: /Threats per domain\./ })).toBeInTheDocument();
  });

  it('uses the URL range: 24 h preset with hour buckets, custom UTC days, links keep the range', async () => {
    const seen = mockReports();
    renderWithProviders(<DashboardPage />, { route: '/dashboard?range=24h' });
    await screen.findByText('1,234');
    expect(seen.traffic?.get('granularity')).toBe('hour');
    const from = Date.parse(seen.traffic?.get('from') ?? '');
    const to = Date.parse(seen.traffic?.get('to') ?? '');
    expect(to - from).toBe(86_400_000);
    expect(within(tile('Total emails processed')).getByRole('link')).toHaveAttribute(
      'href',
      '/reports?tab=traffic&range=24h',
    );
  });

  it('accepts a custom range up to 31 days and falls back to 7 days beyond it', async () => {
    const seen = mockReports();
    renderWithProviders(<DashboardPage />, { route: '/dashboard?from=2026-10-01&to=2026-10-31' });
    await screen.findByText('1,234');
    expect(seen.traffic?.get('from')).toBe('2026-10-01T00:00:00.000Z');
    expect(seen.traffic?.get('to')).toBe('2026-11-01T00:00:00.000Z');
    expect(seen.traffic?.get('granularity')).toBe('day');
    expect(seen.topDomains?.get('limit')).toBe('10');
  });

  it('ignores a custom range longer than 31 days (default 7 days)', async () => {
    const seen = mockReports();
    renderWithProviders(<DashboardPage />, { route: '/dashboard?from=2026-09-01&to=2026-10-31' });
    await screen.findByText('1,234');
    const days =
      (Date.parse(seen.traffic?.get('to') ?? '') - Date.parse(seen.traffic?.get('from') ?? '')) /
      86_400_000;
    expect(days).toBe(7);
  });

  it('shows the platform readiness card only to platform:operations holders', async () => {
    mockReports();
    mockBff('get', '/bff/platform/health', () =>
      okJson({
        status: 'ok',
        version: '1.2.3',
        checks: [{ name: 'mysql', status: 'ok', latencyMs: 3 }],
      }),
    );
    const { container } = renderWithProviders(<DashboardPage />, {
      route: '/dashboard',
      role: 'platform_admin',
    });
    expect(await screen.findByText('Platform dependencies')).toBeInTheDocument();
    expect(await screen.findByText('mysql')).toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('organization users do not see the platform card', async () => {
    mockReports();
    renderWithProviders(<DashboardPage />, { route: '/dashboard', role: 'read_only_user' });
    await screen.findByText('1,234');
    expect(screen.queryByText('Platform dependencies')).not.toBeInTheDocument();
  });

  it('without report:read the route gate shows 403', async () => {
    const { container } = renderWithProviders(<DashboardPage />, {
      route: '/dashboard',
      role: 'mailbox_user',
    });
    expect(
      screen.getByRole('heading', { name: 'You do not have access to this page' }),
    ).toBeInTheDocument();
    expect(screen.getByText('report:read')).toBeInTheDocument();
    await expectNoAxeViolations(container);
  });
});
