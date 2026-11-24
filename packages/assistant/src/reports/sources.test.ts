import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { compileValidator, findTool } from '../registry/registry';
import {
  atoOverviewBody,
  atoAccountsBody,
  deliveryBody,
  okResults,
  processingBody,
  quarantineSummaryBody,
  threatsBody,
  topDomainsBody,
  trafficBody,
  urlClicksBody,
  WINDOW_24H,
  WINDOW_7D,
} from './fixtures.test-support';
import {
  REPORT_SOURCES,
  REPORT_SOURCE_DEFS,
  atoAccountsWanted,
  atoRangeFor,
  normalizeSections,
  parseSource,
  plannedSources,
  resolveReportWindow,
  sourcePermission,
  type ReportSourceKey,
} from './sources';
import { REPORT_SECTIONS } from './types';

const NOW = new Date('2026-11-23T09:00:30.000Z');
const opts = { now: NOW, maxRangeDays: 31 };

const OPERATION_OF: Record<ReportSourceKey, string> = {
  traffic: 'ReportsController_traffic_v1',
  threats: 'ReportsController_threats_v1',
  top_domains: 'ReportsController_topDomains_v1',
  delivery: 'ReportsController_delivery_v1',
  processing: 'ReportsController_processing_v1',
  url_clicks: 'ReportsController_urlClicks_v1',
  quarantine_summary: 'QuarantineToolsController_summary_v1',
  ato_overview: 'AtoOverviewController_overview_v1',
  ato_accounts: 'AtoAccountsController_list_v1',
};

interface OpenApiDoc {
  paths: Record<
    string,
    Record<
      string,
      {
        operationId?: string;
        responses?: Record<string, { content?: Record<string, { example?: unknown }> }>;
      }
    >
  >;
}
const openapi = JSON.parse(
  readFileSync(join(__dirname, '../../../../docs/api/openapi.json'), 'utf8'),
) as OpenApiDoc;
const exampleOf = (operationId: string): unknown => {
  for (const item of Object.values(openapi.paths))
    for (const op of Object.values(item))
      if (op.operationId === operationId)
        return op.responses?.['200']?.content?.['application/json']?.example;
  return undefined;
};

describe('report source plan (design D2 step 4)', () => {
  it('names the design table tools and arguments per section', () => {
    expect(REPORT_SOURCES).toEqual({
      summary: [],
      traffic: ['traffic'],
      threats: ['threats'],
      domains: ['top_domains'],
      delivery: ['delivery'],
      processing: ['processing'],
      url_clicks: ['url_clicks'],
      quarantine: ['quarantine_summary'],
      ato: ['ato_overview', 'ato_accounts'],
    });
    const w = WINDOW_7D;
    const args = Object.fromEntries(
      Object.values(REPORT_SOURCE_DEFS).map((def) => [def.tool, def.args(w)]),
    );
    expect(args).toEqual({
      reports_traffic: { from: w.from, to: w.to, granularity: 'day' },
      reports_threats: { from: w.from, to: w.to },
      reports_top_domains: { from: w.from, to: w.to, limit: 10 },
      reports_delivery: { from: w.from, to: w.to, granularity: 'day' },
      reports_processing: { from: w.from, to: w.to, granularity: 'day' },
      reports_url_clicks: { from: w.from, to: w.to, granularity: 'day' },
      quarantine_tools_summary: { from: w.from, to: w.to },
      ato_overview_overview: { range: '7d' },
      ato_accounts_list: { sort: '-riskScore', limit: '10' },
    });
  });

  it('every source tool is an enabled GET read of the registry and its arguments validate', () => {
    for (const def of Object.values(REPORT_SOURCE_DEFS)) {
      const tool = findTool(def.tool);
      expect(tool, def.tool).toBeDefined();
      expect(tool!.operationId).toBe(OPERATION_OF[def.key]);
      expect(tool!.enabled && tool!.access === 'read' && tool!.method === 'GET').toBe(true);
      for (const w of [WINDOW_7D, WINDOW_24H])
        expect(compileValidator(tool!)(def.args(w)), def.tool).toEqual({ ok: true });
    }
  });

  it('plans sources in a fixed order; summary reads its sources; ato_accounts comes after the overview', () => {
    expect(plannedSources(['traffic']).map((d) => d.key)).toEqual(['traffic']);
    expect(plannedSources(['ato', 'quarantine']).map((d) => d.key)).toEqual([
      'quarantine_summary',
      'ato_overview',
      'ato_accounts',
    ]);
    expect(plannedSources(['summary']).map((d) => d.key)).toEqual([
      'traffic',
      'threats',
      'delivery',
      'processing',
      'url_clicks',
      'quarantine_summary',
      'ato_overview',
    ]);
    expect(plannedSources([...REPORT_SECTIONS])).toHaveLength(9);
    expect(REPORT_SOURCE_DEFS.ato_accounts.after).toBe('ato_overview');
  });

  it('maps sources to the permission of their tool', () => {
    expect(sourcePermission(REPORT_SOURCE_DEFS.traffic)).toBe('report:read');
    expect(sourcePermission(REPORT_SOURCE_DEFS.quarantine_summary)).toBe('quarantine:read');
    expect(sourcePermission(REPORT_SOURCE_DEFS.ato_overview)).toBe('ato:read');
    expect(sourcePermission(REPORT_SOURCE_DEFS.ato_accounts)).toBe('ato:read');
  });
});

describe('report source parsers (design D2 step 6)', () => {
  const fixtures: Record<ReportSourceKey, unknown> = {
    traffic: trafficBody(),
    threats: threatsBody(),
    top_domains: topDomainsBody(),
    delivery: deliveryBody(),
    processing: processingBody(),
    url_clicks: urlClicksBody(),
    quarantine_summary: quarantineSummaryBody(),
    ato_overview: atoOverviewBody(),
    ato_accounts: atoAccountsBody(),
  };

  it('accept the synthetic fixtures and keep unknown fields (passthrough)', () => {
    for (const [key, body] of Object.entries(fixtures) as Array<[ReportSourceKey, unknown]>) {
      const parsed = parseSource(key, { ...(body as object), extraField: 1 });
      expect(parsed.ok, key).toBe(true);
      if (parsed.ok) expect((parsed.data as Record<string, unknown>).extraField).toBe(1);
    }
    expect(Object.keys(okResults())).toHaveLength(9);
  });

  it('accept the OpenAPI examples where the document has one', () => {
    let checked = 0;
    for (const [key, operationId] of Object.entries(OPERATION_OF) as Array<
      [ReportSourceKey, string]
    >) {
      const example = exampleOf(operationId);
      if (example === undefined) continue;
      checked += 1;
      expect(parseSource(key, example).ok, operationId).toBe(true);
    }
    expect(checked).toBeGreaterThanOrEqual(2);
  });

  it('refuse unexpected shapes (unexpected_response) without throwing', () => {
    const broken: Array<[ReportSourceKey, unknown]> = [
      ['traffic', null],
      ['traffic', 'text'],
      ['traffic', { ...trafficBody(), buckets: 'x' }],
      ['traffic', { ...trafficBody(), totals: { ...trafficBody().totals, total: -1 } }],
      ['threats', { ...threatsBody(), messages: {} }],
      ['top_domains', { ...topDomainsBody(), domains: [{ name: 1 }] }],
      ['delivery', { ...deliveryBody(), totals: { ...deliveryBody().totals, successRate: 2 } }],
      ['processing', { ...processingBody(), totals: { rounds: 1.5 } }],
      ['url_clicks', { ...urlClicksBody(), totals: { total: 1 } }],
      ['quarantine_summary', { ...quarantineSummaryBody(), counts: { held: 'many' } }],
      ['ato_overview', { ...atoOverviewBody(), range: '90d' }],
      ['ato_accounts', { data: [{ riskScore: 'high' }] }],
      ['ato_accounts', [1, 2, 3]],
    ];
    for (const [key, body] of broken) expect(parseSource(key, body), key).toEqual({ ok: false });
  });

  it('reads the accounts list only when monitoring is on', () => {
    const parse = (b: unknown) => {
      const r = parseSource('ato_overview', b);
      if (!r.ok) throw new Error('fixture');
      return r.data;
    };
    expect(atoAccountsWanted(parse(atoOverviewBody()))).toBe(true);
    expect(atoAccountsWanted(parse(atoOverviewBody({ featureEnabled: false })))).toBe(false);
    expect(atoAccountsWanted(parse(atoOverviewBody({ mode: 'off' })))).toBe(false);
  });
});

describe('report window (design D2 step 3)', () => {
  it('defaults to the last 7 days ending at the current minute, daily buckets', () => {
    expect(resolveReportWindow({}, opts)).toEqual({
      ok: true,
      window: {
        from: '2026-11-16T09:00:00.000Z',
        to: '2026-11-23T09:00:00.000Z',
        granularity: 'day',
        range: '7d',
        atoRange: '7d',
      },
    });
  });

  it('relative ranges: 24h hourly, 30d daily', () => {
    const day = resolveReportWindow({ range: '24h' }, opts);
    expect(day).toMatchObject({
      ok: true,
      window: { granularity: 'hour', range: '24h', atoRange: '24h' },
    });
    const month = resolveReportWindow({ range: '30d' }, opts);
    expect(month).toMatchObject({
      ok: true,
      window: { from: '2026-10-24T09:00:00.000Z', granularity: 'day', atoRange: '30d' },
    });
    expect(resolveReportWindow({ range: '90d' }, opts)).toMatchObject({ ok: false });
  });

  it('explicit windows replace the range; hourly up to 48 h; the ATO range covers the window', () => {
    const at = (from: string, to: string) => resolveReportWindow({ from, to, range: '30d' }, opts);
    expect(at('2026-11-21T09:00:00Z', '2026-11-23T09:00:00Z')).toEqual({
      ok: true,
      window: {
        from: '2026-11-21T09:00:00.000Z',
        to: '2026-11-23T09:00:00.000Z',
        granularity: 'hour',
        range: null,
        atoRange: '7d',
      },
    });
    expect(at('2026-11-22T10:00:00Z', '2026-11-23T09:00:00Z')).toMatchObject({
      window: { granularity: 'hour', atoRange: '24h' },
    });
    expect(at('2026-11-21T08:59:59Z', '2026-11-23T09:00:00Z')).toMatchObject({
      window: { granularity: 'day', atoRange: '7d' },
    });
    expect(at('2026-11-10T00:00:00Z', '2026-11-23T00:00:00Z')).toMatchObject({
      window: { granularity: 'day', atoRange: '30d' },
    });
    expect(at('2026-11-22T09:00:00+05:30', '2026-11-23T09:00:00+05:30')).toMatchObject({
      window: { from: '2026-11-22T03:30:00.000Z', to: '2026-11-23T03:30:00.000Z' },
    });
  });

  it('refuses invalid windows', () => {
    const bad = [
      { from: '2026-11-20T00:00:00Z' },
      { to: '2026-11-20T00:00:00Z' },
      { from: '2026-11-21T00:00:00Z', to: '2026-11-20T00:00:00Z' },
      { from: '2026-11-21T00:00:00Z', to: '2026-11-21T00:00:00Z' },
      { from: '2026-10-01T00:00:00Z', to: '2026-11-20T00:00:00Z' },
      { from: '2026-11-22T00:00:00Z', to: '2026-11-23T09:02:00Z' },
      { from: 'yesterday', to: 'today' },
      { from: 1, to: 2 },
      { from: '2026-11-21', to: '2026-11-22' },
    ];
    for (const args of bad)
      expect(resolveReportWindow(args, opts), JSON.stringify(args)).toMatchObject({
        ok: false,
        code: 'assistant_report_invalid_window',
      });
    expect(
      resolveReportWindow({ from: '2026-11-22T00:00:00Z', to: '2026-11-23T09:01:00Z' }, opts).ok,
    ).toBe(true);
    expect(
      resolveReportWindow({ from: '2026-10-23T09:00:00Z', to: '2026-11-23T09:00:00Z' }, opts).ok,
    ).toBe(true);
    expect(resolveReportWindow({}, { now: new Date(NaN), maxRangeDays: 31 }).ok).toBe(false);
  });

  it('ATO range selection', () => {
    const h = 3_600_000;
    expect(atoRangeFor(h)).toBe('24h');
    expect(atoRangeFor(24 * h)).toBe('24h');
    expect(atoRangeFor(24 * h + 1)).toBe('7d');
    expect(atoRangeFor(7 * 24 * h + 1)).toBe('30d');
    expect(atoRangeFor(31 * 24 * h)).toBe('30d');
  });

  it('normalizes sections to render order (default all)', () => {
    expect(normalizeSections(undefined)).toEqual([...REPORT_SECTIONS]);
    expect(normalizeSections([])).toEqual([...REPORT_SECTIONS]);
    expect(normalizeSections(['ato', 'summary', 'bogus'])).toEqual(['summary', 'ato']);
    expect(normalizeSections(['bogus'])).toEqual([...REPORT_SECTIONS]);
  });
});
