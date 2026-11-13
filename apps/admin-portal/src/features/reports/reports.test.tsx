import { screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  apiErrorJson,
  currentTestUrl,
  expectNoAxeViolations,
  mockApi,
  okJson,
  renderWithProviders,
} from '@/test';
import { csvCell, toCsv } from './csv';
import { ReportsPage } from './reports-page';
import {
  PROCESSING_BOUNDS,
  deliveryReport,
  histogram,
  processingReport,
  threatsReport,
  topDomainsReport,
  trafficReport,
  urlClicksReport,
} from './test-data';
import { outcomeMatrix } from './report-tabs';
import { percentileReading } from './report-utils';

function captureDownloads() {
  const blobs: Blob[] = [];
  const create = vi.fn((blob: Blob) => {
    blobs.push(blob);
    return 'blob:test';
  });
  Object.defineProperty(URL, 'createObjectURL', { value: create, configurable: true });
  Object.defineProperty(URL, 'revokeObjectURL', { value: vi.fn(), configurable: true });
  const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);
  return { blobs, click };
}

afterEach(() => vi.restoreAllMocks());

describe('CSV helpers', () => {
  it('quotes and neutralizes formula-like cells', () => {
    expect(csvCell('=SUM(A1)')).toBe("'=SUM(A1)");
    expect(csvCell('a,b')).toBe('"a,b"');
    expect(csvCell('say "hi"')).toBe('"say ""hi"""');
    expect(csvCell(null)).toBe('');
    expect(csvCell(-3)).toBe('-3');
    expect(toCsv(['a', 'b'], [[1, 'x']])).toBe('a,b\r\n1,x\r\n');
  });

  it('reads percentiles as bounds, overflow or none', () => {
    const h = histogram(PROCESSING_BOUNDS, { overflow: 3 });
    expect(percentileReading(5000, h)).toMatchObject({ kind: 'bound', text: '≤ 5.0 s' });
    expect(percentileReading(null, h)).toMatchObject({ kind: 'overflow', text: '> 15 min' });
    expect(percentileReading(null, histogram(PROCESSING_BOUNDS, {}))).toEqual({ kind: 'none' });
  });
});

describe('Reports page', () => {
  it('traffic tab: loading, totals, charts with summaries, CSV of the displayed aggregates', async () => {
    let params: URLSearchParams | null = null;
    mockApi({
      ReportsController_traffic_v1: ({ url }) => (
        (params = url.searchParams),
        okJson(trafficReport())
      ),
    });
    const { blobs, click } = captureDownloads();
    const { container, user } = renderWithProviders(<ReportsPage />, { route: '/reports' });
    expect(screen.getByText('Loading the traffic report …')).toBeInTheDocument();
    expect(
      await screen.findByRole('img', { name: /Messages by direction\. Total 1,234/ }),
    ).toBeInTheDocument();
    expect(screen.getByRole('img', { name: /Messages by verdict\./ })).toBeInTheDocument();
    expect(params!.get('granularity')).toBe('day');
    expect(params!.has('direction')).toBe(false);
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('button', { name: 'Download CSV' }));
    expect(click).toHaveBeenCalled();
    const text = await blobs[0]!.text();
    expect(text.split('\r\n')[0]).toBe(
      'bucket_start,total,inbound,outbound,internal,clean,spam,bulk,phishing,malware,bec,suspicious,dlp_violation,unknown,none',
    );
    expect(text).toContain('2026-11-06T00:00:00.000Z,700,500,150,50,600,60,10,20,5,3,2,0,0,0');
  });

  it('traffic filters write the URL and the request; hour is refused for ranges over 7 days', async () => {
    const seen: URLSearchParams[] = [];
    mockApi({
      ReportsController_traffic_v1: ({ url }) => (
        seen.push(url.searchParams),
        okJson(trafficReport())
      ),
    });
    const { user } = renderWithProviders(<ReportsPage />, {
      route: '/reports?range=30d&granularity=hour',
    });
    await screen.findByRole('img', { name: /Messages by direction/ });
    expect(seen.at(-1)?.get('granularity')).toBe('day');
    await user.click(screen.getByRole('combobox', { name: 'Direction' }));
    await user.click(await screen.findByRole('option', { name: 'Outbound' }));
    await waitFor(() => expect(currentTestUrl()).toContain('direction=outbound'));
    await waitFor(() => expect(seen.at(-1)?.get('direction')).toBe('outbound'));
    await user.click(screen.getByRole('combobox', { name: 'Granularity' }));
    expect(await screen.findByRole('option', { name: 'Hour (ranges ≤ 7 days)' })).toHaveAttribute(
      'aria-disabled',
      'true',
    );
  });

  it('threats tab: outcomes matrix, marginals, quarantine reasons and engines', async () => {
    mockApi({ ReportsController_threats_v1: () => okJson(threatsReport()) });
    const { container } = renderWithProviders(<ReportsPage />, { route: '/reports?tab=threats' });
    const matrix = await screen.findByRole('table', {
      name: /Outcomes: final verdict × final action/,
    });
    const spamRow = within(matrix).getByRole('row', { name: /^Spam/ });
    expect(spamRow).toHaveTextContent('Spam040301270'); // deliver 0, tag 40, quarantine 30, discard 12, reject 7, none 0
    expect(outcomeMatrix(threatsReport())[1]).toEqual([0, 40, 30, 12, 7, 0, 0, 0]);
    expect(
      screen.getByRole('table', { name: 'Quarantine entries by primary engine' }),
    ).toHaveTextContent('Rspamd30');
    await expectNoAxeViolations(container);
  });

  it('delivery tab: success rate, honest null, latency histogram', async () => {
    mockApi({
      ReportsController_delivery_v1: () =>
        okJson(
          deliveryReport({
            totals: { ...deliveryReport().totals, successRate: null },
          }),
        ),
    });
    renderWithProviders(<ReportsPage />, { route: '/reports?tab=delivery' });
    expect(await screen.findByText('No completed deliveries in range')).toBeInTheDocument();
    expect(screen.getByText('≤ 5.0 s')).toBeInTheDocument();
    expect(screen.getByRole('img', { name: /Delivery latency\./ })).toBeInTheDocument();
  });

  it('processing tab: p50/p95 upper bounds, overflow and the definition', async () => {
    mockApi({
      ReportsController_processing_v1: () =>
        okJson(
          processingReport({
            totals: {
              ...processingReport().totals,
              p95UpperBoundMs: null,
              histogram: histogram(PROCESSING_BOUNDS, { 1000: 10, overflow: 4 }),
            },
          }),
        ),
    });
    renderWithProviders(<ReportsPage />, { route: '/reports?tab=processing' });
    expect(await screen.findByText('> 15 min')).toBeInTheDocument();
    expect(screen.getByText('≤ 1.0 s')).toBeInTheDocument();
    expect(screen.getByText(/Time from receipt \(email_scans.received_at\)/)).toBeInTheDocument();
  });

  it('URL clicks tab: decisions over time', async () => {
    mockApi({ ReportsController_urlClicks_v1: () => okJson(urlClicksReport()) });
    renderWithProviders(<ReportsPage />, { route: '/reports?tab=url-clicks' });
    expect(
      await screen.findByRole('img', { name: /Clicks by decision\. Total 42/ }),
    ).toBeInTheDocument();
  });

  it('top domains tab: the limit selector writes the URL and the request', async () => {
    const seen: string[] = [];
    mockApi({
      ReportsController_topDomains_v1: ({ url }) => (
        seen.push(url.searchParams.get('limit') ?? ''),
        okJson(topDomainsReport())
      ),
    });
    const { user } = renderWithProviders(<ReportsPage />, { route: '/reports?tab=top-domains' });
    expect(await screen.findByRole('link', { name: 'alpha.example.test' })).toBeInTheDocument();
    expect(seen).toEqual(['10']);
    await user.click(screen.getByRole('combobox', { name: 'Domains shown' }));
    await user.click(await screen.findByRole('option', { name: '25' }));
    await waitFor(() => expect(currentTestUrl()).toContain('limit=25'));
    await waitFor(() => expect(seen.at(-1)).toBe('25'));
  });

  it('switching tabs writes the tab to the URL', async () => {
    mockApi({
      ReportsController_traffic_v1: () => okJson(trafficReport()),
      ReportsController_threats_v1: () => okJson(threatsReport()),
    });
    const { user } = renderWithProviders(<ReportsPage />, { route: '/reports?range=24h' });
    await screen.findByRole('img', { name: /Messages by direction/ });
    await user.click(screen.getByRole('tab', { name: 'Threats' }));
    await waitFor(() => expect(currentTestUrl()).toBe('/reports?range=24h&tab=threats'));
  });

  it('a report timeout explains how to recover (code and request id shown)', async () => {
    mockApi({
      ReportsController_traffic_v1: () =>
        apiErrorJson(503, 'report_timeout', 'The report did not finish in time', {
          requestId: 'req-rpt-9',
        }),
    });
    renderWithProviders(<ReportsPage />, { route: '/reports' });
    expect(await screen.findByText('report_timeout')).toBeInTheDocument();
    expect(screen.getByText('req-rpt-9')).toBeInTheDocument();
    expect(screen.getByText(/Narrow the range/)).toBeInTheDocument();
  });

  it('a rate-limited report counts down before Retry is offered', async () => {
    mockApi({
      ReportsController_threats_v1: () =>
        apiErrorJson(429, 'rate_limited', 'Too many requests', {
          headers: { 'retry-after': '12' },
        }),
    });
    renderWithProviders(<ReportsPage />, { route: '/reports?tab=threats' });
    expect(await screen.findByText('You can retry in 12 s.', { exact: false })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Retry' })).not.toBeInTheDocument();
  });

  it('without report:read the route gate shows 403', () => {
    renderWithProviders(<ReportsPage />, { route: '/reports', role: 'mailbox_user' });
    expect(
      screen.getByRole('heading', { name: 'You do not have access to this page' }),
    ).toBeInTheDocument();
  });
});
