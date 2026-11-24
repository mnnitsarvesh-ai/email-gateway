import { describe, expect, it } from 'vitest';
import {
  FIXTURE_GENERATED_AT,
  FIXTURE_ORGANIZATION,
  WINDOW_7D,
  atoAccountsBody,
  atoOverviewBody,
  okResults,
  topDomainsBody,
  trafficBody,
} from './fixtures.test-support';
import {
  buildReportModel,
  donutOf,
  histogramOf,
  periodLabel,
  reportDigestOf,
  reportHasNoData,
  type ReportSourceResults,
} from './model';
import {
  REPORT_SECTIONS,
  REPORT_TEMPLATE_VERSION,
  type ReportSection,
  type ReportWindow,
} from './types';

const build = (
  results: ReportSourceResults = okResults(),
  sections: readonly ReportSection[] = REPORT_SECTIONS,
  window: ReportWindow = WINDOW_7D,
) =>
  buildReportModel(results, {
    window,
    generatedAt: FIXTURE_GENERATED_AT,
    organizationName: FIXTURE_ORGANIZATION,
    sections,
  });

const section = (model: ReturnType<typeof build>, name: ReportSection) =>
  model.body.find((s) => s.section === name);

describe('buildReportModel (design D3)', () => {
  it('builds every section with the design visuals and the ≤ 8 summary figures', () => {
    const model = build();
    expect(model.version).toBe(REPORT_TEMPLATE_VERSION);
    expect(model.title).toBe('Security report: Last 7 days');
    expect(model.sections).toEqual([...REPORT_SECTIONS]);
    expect(model.omitted).toEqual([]);
    const kinds = Object.fromEntries(
      model.body.map((s) => [s.section, s.charts.map((c) => `${c.kind}:${c.id}`)]),
    );
    expect(kinds).toEqual({
      traffic: [
        'timeseries:chart-traffic-volume',
        'timeseries:chart-traffic-threats',
        'donut:chart-traffic-verdicts',
      ],
      threats: [
        'donut:chart-threat-types',
        'bar:chart-threat-actions',
        'bar:chart-quarantine-reasons',
        'bar:chart-detection-engines',
      ],
      domains: ['bar:chart-top-domains'],
      delivery: [
        'timeseries:chart-delivery-success',
        'donut:chart-delivery-statuses',
        'histogram:chart-delivery-latency',
      ],
      processing: ['timeseries:chart-processing-time', 'histogram:chart-processing-histogram'],
      url_clicks: ['timeseries:chart-url-clicks', 'donut:chart-url-decisions'],
      quarantine: ['donut:chart-quarantine-states'],
      ato: ['timeseries:chart-ato-incidents', 'bar:chart-ato-accounts'],
    });
    const all = model.body.flatMap((s) => s.charts);
    expect(all.filter((c) => c.kind === 'timeseries')).toHaveLength(6);
    expect(all.filter((c) => c.kind === 'donut')).toHaveLength(5);
    expect(all.filter((c) => c.kind === 'bar' || c.kind === 'histogram')).toHaveLength(7);
    expect(model.summary.map((c) => c.label)).toEqual([
      'Messages',
      'Inbound',
      'Outbound',
      'Threats',
      'Quarantined',
      'Delivery success rate',
      'p95 time to verdict',
      'Blocked URL clicks',
      'Held in quarantine',
      'Pending approvals',
      'High-risk accounts',
    ]);
    expect(model.figures.map((f) => f.label)).toEqual([
      'Messages',
      'Threats',
      'Quarantined',
      'Delivery success rate',
      'p95 time to verdict',
      'Held in quarantine',
      'Pending approvals',
      'High-risk accounts',
    ]);
    expect(model.figures.length).toBeLessThanOrEqual(8);
    expect(model.sources.map((s) => [s.tool, s.outcome])).toEqual([
      ['reports_traffic', 'ok'],
      ['reports_threats', 'ok'],
      ['reports_top_domains', 'ok'],
      ['reports_delivery', 'ok'],
      ['reports_processing', 'ok'],
      ['reports_url_clicks', 'ok'],
      ['quarantine_tools_summary', 'ok'],
      ['ato_overview_overview', 'ok'],
      ['ato_accounts_list', 'ok'],
    ]);
    expect(reportHasNoData(model)).toBe(false);
  });

  it('threats are the top-domains threat set (spam + phishing + malware + bec + suspicious); percentages and bounds', () => {
    const traffic = trafficBody();
    const v = traffic.totals.verdicts as Record<string, number>;
    const threats = v.spam! + v.phishing! + v.malware! + v.bec! + v.suspicious!;
    const model = build();
    const figure = (label: string) => model.figures.find((f) => f.label === label)?.value;
    expect(figure('Messages')).toBe(traffic.totals.total.toLocaleString('en-US'));
    expect(figure('Threats')).toBe(threats.toLocaleString('en-US'));
    expect(figure('Delivery success rate')).toBe('98.6%');
    expect(figure('p95 time to verdict')).toBe('≤ 2.5 s');
    expect(figure('High-risk accounts')).toBe('5');
    expect(figure('Held in quarantine')).toBe('42');
    const delivery = section(model, 'delivery')!;
    expect(delivery.cards.map((c) => `${c.label}=${c.value}`)).toEqual([
      'Average latency=1.8 s',
      'Median latency=≤ 1 s',
      'p95 latency=≤ 5 s',
    ]);
    const threatTypes = section(model, 'threats')!.charts[0]!;
    expect(threatTypes.kind === 'donut' && threatTypes.slices.map((s) => s.label)).toEqual([
      'Spam',
      'Phishing',
      'Suspicious',
      'Malware',
      'BEC',
    ]);
  });

  it('omits sections whose source the principal may not read (reason permission, the permission key)', () => {
    const results = okResults();
    results.quarantine_summary = { status: 'permission' };
    results.ato_overview = { status: 'permission' };
    results.ato_accounts = { status: 'permission' };
    const model = build(results);
    expect(model.omitted).toEqual([
      { section: 'quarantine', reason: 'permission', code: 'quarantine:read' },
      { section: 'ato', reason: 'permission', code: 'ato:read' },
    ]);
    expect(model.sections).not.toContain('quarantine');
    expect(model.summary.map((c) => c.label)).not.toContain('Held in quarantine');
    expect(model.figures.map((f) => f.label)).not.toContain('High-risk accounts');
    expect(model.sources.find((s) => s.tool === 'quarantine_tools_summary')?.outcome).toBe(
      'omitted_permission',
    );
  });

  it('ATO feature off (or mode off) → not_enabled; the accounts list is not called', () => {
    for (const body of [
      atoOverviewBody({ featureEnabled: false }),
      atoOverviewBody({ mode: 'off' }),
    ]) {
      const results = okResults({ ato_overview: body });
      delete results.ato_accounts;
      const model = build(results);
      expect(model.omitted).toEqual([{ section: 'ato', reason: 'not_enabled' }]);
      expect(model.sources.find((s) => s.tool === 'ato_accounts_list')?.outcome).toBe('not_called');
      expect(model.figures.map((f) => f.label)).not.toContain('High-risk accounts');
    }
  });

  it('unavailable and unexpected sources omit their sections with the code', () => {
    const results = okResults({ delivery: { buckets: 'nope' } });
    results.traffic = { status: 'unavailable', httpStatus: 503, code: 'report_timeout' };
    const model = build(results);
    expect(model.omitted).toEqual([
      { section: 'traffic', reason: 'unavailable', code: 'report_timeout' },
      { section: 'delivery', reason: 'unexpected_response' },
    ]);
    expect(model.summary.map((c) => c.label)).not.toContain('Messages');
    expect(model.sources.find((s) => s.tool === 'reports_traffic')).toMatchObject({
      outcome: 'unavailable',
      httpStatus: 503,
      code: 'report_timeout',
    });
    // A source the api did not read at all is unavailable, never silently included.
    const missing = okResults();
    delete missing.threats;
    expect(build(missing).omitted).toEqual([
      { section: 'threats', reason: 'unavailable', code: 'source_not_read' },
    ]);
  });

  it('an ATO accounts failure keeps the section with a note', () => {
    const results = okResults();
    results.ato_accounts = { status: 'unavailable', httpStatus: 500, code: 'internal_error' };
    const ato = section(build(results), 'ato')!;
    expect(ato.charts.map((c) => c.id)).toEqual(['chart-ato-incidents']);
    expect(ato.notes).toContain(
      'Accounts at highest takeover risk are not available (internal_error).',
    );
  });

  it('labels the ATO window separately for explicit windows and picks the covering range', () => {
    const window: ReportWindow = {
      from: '2026-11-20T00:00:00.000Z',
      to: '2026-11-23T00:00:00.000Z',
      granularity: 'day',
      range: null,
      atoRange: '7d',
    };
    const model = build(okResults(), REPORT_SECTIONS, window);
    expect(model.period).toEqual({
      from: window.from,
      to: window.to,
      granularity: 'day',
      atoRange: '7d',
      label: 'Nov 20, 2026 00:00 to Nov 23, 2026 00:00 UTC',
    });
    expect(section(model, 'ato')!.notes[0]).toMatch(
      /^Account takeover figures cover the last 7 days ending Nov 23, 2026 09:00 UTC/,
    );
    expect(section(build(), 'ato')!.notes).toEqual([]);
  });

  it('summary-only and no-data reports (design D2 step 7)', () => {
    const summaryOnly = build(okResults(), ['summary']);
    expect(summaryOnly.sections).toEqual(['summary']);
    expect(summaryOnly.body).toEqual([]);
    expect(reportHasNoData(summaryOnly)).toBe(false);
    const down: ReportSourceResults = Object.fromEntries(
      Object.keys(okResults()).map((k) => [
        k,
        { status: 'unavailable', httpStatus: 503, code: 'report_timeout' },
      ]),
    );
    const none = build(down);
    expect(none.sections).toEqual([]);
    expect(none.omitted[0]).toEqual({
      section: 'summary',
      reason: 'unavailable',
      code: 'no_source_available',
    });
    expect(reportHasNoData(none)).toBe(true);
    // Every non-summary section omitted while the summary has a value → still no data.
    const partial = okResults();
    partial.traffic = { status: 'unavailable', httpStatus: 503, code: 'report_timeout' };
    expect(reportHasNoData(build(partial, ['summary', 'traffic']))).toBe(true);
    expect(reportHasNoData(build(down, ['summary']))).toBe(true);
  });

  it('empty series stay empty (the renderer shows the placeholder)', () => {
    const empty = okResults({ traffic: { ...trafficBody([]), totals: trafficBody([]).totals } });
    const traffic = section(build(empty), 'traffic')!;
    const volume = traffic.charts[0]!;
    expect(volume.kind === 'timeseries' && volume.x).toEqual([]);
    const donut = traffic.charts[2]!;
    expect(donut.kind === 'donut' && donut.slices).toEqual([]);
  });

  it('sanitizes and caps data strings (domains, accounts, organization)', () => {
    const long = `${'d'.repeat(60)}.`.repeat(6) + 'test';
    const results = okResults({
      top_domains: topDomainsBody([`evil\u202e.example.test\u200b`, long]),
      ato_accounts: atoAccountsBody([{ address: `a\r\nb@x.test`, displayName: 'N'.repeat(200) }]),
    });
    const model = buildReportModel(results, {
      window: WINDOW_7D,
      generatedAt: FIXTURE_GENERATED_AT,
      organizationName: `Org\u0007${'o'.repeat(300)}`,
      sections: REPORT_SECTIONS,
    });
    expect(Array.from(model.organizationName)).toHaveLength(120);
    expect(model.organizationName.startsWith('Orgooo')).toBe(true);
    const domains = section(model, 'domains')!.tables[0]!.rows;
    expect(domains[0]![0]).toBe('evil.example.test');
    expect(Array.from(domains[1]![0]!.replace(' (deleted)', '')).length).toBeLessThanOrEqual(253);
    const accounts = section(model, 'ato')!.tables[0]!.rows[0]!;
    expect(accounts[0]).toBe('a b@x.test');
    expect(Array.from(accounts[1]!)).toHaveLength(80);
  });

  it('is deterministic and the digest copies the card fields', () => {
    expect(JSON.stringify(build())).toBe(JSON.stringify(build()));
    const digest = reportDigestOf(build());
    expect(Object.keys(digest)).toEqual(['title', 'period', 'sections', 'omitted', 'figures']);
  });
});

describe('chart builders', () => {
  it('donut: zero slices dropped, largest first, beyond 8 slices one "Other"', () => {
    const entries = Array.from({ length: 11 }, (_, i) => ({ label: `S${i}`, value: i, color: 0 }));
    const donut = donutOf('d', 'D', entries);
    expect(donut.slices).toHaveLength(8);
    expect(donut.slices.slice(0, 7).map((s) => s.label)).toEqual([
      'S10',
      'S9',
      'S8',
      'S7',
      'S6',
      'S5',
      'S4',
    ]);
    expect(donut.slices[7]).toEqual({ label: 'Other', value: 3 + 2 + 1, color: 'other' });
    expect(donutOf('d', 'D', [{ label: 'x', value: Number.NaN, color: 0 }]).slices).toEqual([]);
  });

  it('histogram labels are upper bounds formatted as durations, the open bucket "> last"', () => {
    const h = histogramOf('h', 'H', [
      { leMs: 250, count: 1 },
      { leMs: 1000, count: 2 },
      { leMs: 90_000, count: 3 },
      { leMs: null, count: Number.POSITIVE_INFINITY },
    ]);
    expect(h.bins).toEqual([
      { label: '≤ 250 ms', count: 1 },
      { label: '≤ 1 s', count: 2 },
      { label: '≤ 1.5 min', count: 3 },
      { label: '> 1.5 min', count: 0 },
    ]);
  });

  it('period labels', () => {
    expect(periodLabel({ ...WINDOW_7D, range: '24h' })).toBe('Last 24 hours');
    expect(periodLabel({ ...WINDOW_7D, range: '30d' })).toBe('Last 30 days');
  });
});
