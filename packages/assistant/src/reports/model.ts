import {
  CLICK_DECISIONS,
  DELIVERY_STATUSES,
  FINAL_ACTIONS,
  INCIDENT_SEVERITIES,
  PRIMARY_ENGINES,
  QUARANTINE_REASONS,
  REPORT_SOURCES,
  REPORT_SOURCE_DEFS,
  REPORT_VERDICTS,
  THREAT_VERDICTS,
  atoAccountsWanted,
  parseSource,
  plannedSources,
  sourcePermission,
  type ReportSourceBodies,
  type ReportSourceKey,
  type VerdictKey,
} from './sources';
import { DATA_CAPS, dataText, finite, fmtDuration, fmtNumber, fmtPercent, fmtUtc } from './escape';
import {
  REPORT_SECTIONS,
  REPORT_TEMPLATE_VERSION,
  type BarSpec,
  type ChartSpec,
  type DonutSpec,
  type HistogramSpec,
  type ReportFigure,
  type ReportModel,
  type ReportOmission,
  type ReportPeriod,
  type ReportSection,
  type ReportSectionModel,
  type ReportSourceRecord,
  type ReportWindow,
  type SemanticColor,
  type SeriesColor,
  type SummaryCard,
  type TableSpec,
  type TimeSeriesSpec,
} from './types';

/**
 * `buildReportModel` (design D2 step 8, D3): the outcomes of the source reads → the report model
 * (sections with their cards, charts and tables, the omitted sections with reasons, the summary
 * figures of the card / envelope / email, the source records of the footer and the audit). Pure
 * and deterministic: `generatedAt` is an input, nothing reads the clock, data strings are
 * sanitized and capped here and escaped by the renderer.
 */

/** The outcome of one source read as the api records it. */
export type ReportSourceResult =
  | { status: 'ok'; httpStatus?: number; body: unknown }
  /** Not called: the principal does not satisfy the tool's requirement. */
  | { status: 'permission' }
  /** A non-2xx response (other than 401, which ends the turn) or a transport failure. */
  | { status: 'unavailable'; httpStatus: number | null; code: string };

export type ReportSourceResults = Partial<Record<ReportSourceKey, ReportSourceResult>>;

export interface BuildReportOptions {
  window: ReportWindow;
  /** ISO instant of generation (an input: the model never reads the clock). */
  generatedAt: string;
  organizationName: string;
  /** Requested sections (any order; rendered in `REPORT_SECTIONS` order). */
  sections: readonly ReportSection[];
}

export const REPORT_TITLE = 'Security report';
export const SUMMARY_FIGURES_MAX = 8;
/** Rows of the verdict × action outcome table. */
export const OUTCOME_ROWS_MAX = 15;
export const BAR_MAX = 10;
export const DONUT_MAX_SLICES = 8;

export const SECTION_TITLES: Readonly<Record<ReportSection, string>> = {
  summary: 'Summary',
  traffic: 'Mail traffic',
  threats: 'Threats',
  domains: 'Domains',
  delivery: 'Delivery',
  processing: 'Processing',
  url_clicks: 'URL clicks',
  quarantine: 'Quarantine',
  ato: 'Account takeover',
};

// ---------------------------------------------------------------------------------------------
// Labels
// ---------------------------------------------------------------------------------------------

const VERDICT_LABELS: Readonly<Record<VerdictKey, string>> = {
  clean: 'Clean',
  spam: 'Spam',
  bulk: 'Bulk',
  phishing: 'Phishing',
  malware: 'Malware',
  bec: 'BEC',
  dlp_violation: 'DLP violation',
  suspicious: 'Suspicious',
  unknown: 'Unknown',
  none: 'No verdict',
};
const ACTION_LABELS: Readonly<Record<(typeof FINAL_ACTIONS)[number], string>> = {
  deliver: 'Delivered',
  tag: 'Tagged',
  quarantine: 'Quarantined',
  discard: 'Discarded',
  reject: 'Rejected',
  require_approval: 'Held for approval',
  partial: 'Partial',
  none: 'No action',
};
const ENGINE_LABELS: Readonly<Record<(typeof PRIMARY_ENGINES)[number], string>> = {
  rspamd: 'Spam filter',
  attachment: 'Attachments',
  url: 'URLs',
  bec: 'BEC',
  dlp: 'DLP',
  sandbox: 'Sandbox',
  policy: 'Policy',
  none: 'None',
};

/** `engine_unavailable` → `Engine unavailable` (for fixed keys and sanitized data keys). */
export function humanize(key: string): string {
  const words = key.replace(/[_-]+/g, ' ').trim();
  return words.length === 0 ? '(none)' : words.charAt(0).toUpperCase() + words.slice(1);
}

const label = (map: Readonly<Record<string, string>>, key: string): string =>
  map[key] ?? humanize(dataText(key, DATA_CAPS.token));

const VERDICT_COLORS: Readonly<Record<VerdictKey, SemanticColor>> = {
  clean: 'clean',
  spam: 'spam',
  bulk: 'bulk',
  phishing: 'phishing',
  malware: 'malware',
  bec: 'bec',
  dlp_violation: 'dlp_violation',
  suspicious: 'suspicious',
  unknown: 'unknown',
  none: 'none',
};
const DELIVERY_COLORS: Readonly<Record<(typeof DELIVERY_STATUSES)[number], SeriesColor>> = {
  delivered: 'good',
  deferred: 'warning',
  bounced: 'critical',
  failed: 'serious',
  queued: 0,
  in_progress: 1,
  pending: 4,
  suppressed: 6,
  expired: 7,
  unknown: 'unknown',
};
const CLICK_COLORS: Readonly<Record<(typeof CLICK_DECISIONS)[number], SeriesColor>> = {
  allowed: 0,
  warned: 3,
  blocked: 7,
  continued: 1,
  expired: 4,
  not_found: 'other',
};
const SEVERITY_COLORS: Readonly<Record<(typeof INCIDENT_SEVERITIES)[number], SeriesColor>> = {
  low: 0,
  medium: 'warning',
  high: 'serious',
  critical: 'critical',
};
/** Quarantine states in a fixed color order; other (unknown) states share `other`. */
const QUARANTINE_STATE_COLORS: Readonly<Record<string, SeriesColor>> = {
  held: 0,
  pending_approval: 3,
  releasing: 2,
  released: 5,
  rejected: 7,
  expired: 4,
  superseded: 6,
  deleted: 'unknown',
};

// ---------------------------------------------------------------------------------------------
// Period
// ---------------------------------------------------------------------------------------------

const RANGE_LABELS = {
  '24h': 'Last 24 hours',
  '7d': 'Last 7 days',
  '30d': 'Last 30 days',
} as const;

/** `Last 7 days`, or `Nov 16, 2026 09:00 to Nov 23, 2026 09:00 UTC` for an explicit window. */
export function periodLabel(window: Pick<ReportWindow, 'from' | 'to' | 'range'>): string {
  if (window.range) return RANGE_LABELS[window.range];
  const bare = (iso: string) => fmtUtc(iso).replace(/ UTC$/, '');
  return `${bare(window.from)} to ${bare(window.to)} UTC`;
}

export function reportPeriodOf(window: ReportWindow): ReportPeriod {
  return {
    from: window.from,
    to: window.to,
    granularity: window.granularity,
    atoRange: window.atoRange,
    label: periodLabel(window),
  };
}

// ---------------------------------------------------------------------------------------------
// Chart builders
// ---------------------------------------------------------------------------------------------

interface Entry {
  label: string;
  value: number;
  color: SeriesColor;
}

/** Donut: zero slices dropped, largest first; beyond 8 slices the rest is one "Other" slice. */
export function donutOf(id: string, title: string, entries: readonly Entry[]): DonutSpec {
  const slices = entries
    .map((entry, index) => ({ ...entry, value: Math.max(0, finite(entry.value)), index }))
    .filter((entry) => entry.value > 0)
    .sort((a, b) => b.value - a.value || a.index - b.index);
  const kept =
    slices.length > DONUT_MAX_SLICES
      ? [
          ...slices.slice(0, DONUT_MAX_SLICES - 1),
          {
            label: 'Other',
            value: slices.slice(DONUT_MAX_SLICES - 1).reduce((sum, s) => sum + s.value, 0),
            color: 'other' as const,
            index: -1,
          },
        ]
      : slices;
  return {
    kind: 'donut',
    id,
    title,
    slices: kept.map(({ label: name, value, color }) => ({ label: name, value, color })),
  };
}

const bars = (
  id: string,
  title: string,
  entries: ReadonlyArray<{ label: string; value: number }>,
  color: SeriesColor = 0,
): BarSpec => ({
  kind: 'bar',
  id,
  title,
  unit: 'count',
  color,
  segments: [],
  bars: entries
    .slice(0, BAR_MAX)
    .map((entry) => ({ label: entry.label, value: Math.max(0, finite(entry.value)) })),
});

/** Histogram bins: `≤ <bound>` per bucket, `> <last bound>` for the open bucket (`leMs: null`). */
export function histogramOf(
  id: string,
  title: string,
  buckets: ReadonlyArray<{ leMs: number | null; count: number }>,
): HistogramSpec {
  let previous: number | null = null;
  const bins = buckets.map((bucket) => {
    const bound = bucket.leMs;
    const text =
      bound === null
        ? previous === null
          ? 'Any'
          : `> ${fmtDuration(previous)}`
        : `≤ ${fmtDuration(bound)}`;
    if (bound !== null) previous = bound;
    return { label: text, count: Math.max(0, finite(bucket.count)) };
  });
  return { kind: 'histogram', id, title, bins };
}

const series = (
  name: string,
  color: SeriesColor,
  values: ReadonlyArray<number | null>,
): TimeSeriesSpec['series'][number] => ({
  name,
  color,
  values: values.map((v) => (v === null ? null : finite(v))),
});

// ---------------------------------------------------------------------------------------------
// Sections
// ---------------------------------------------------------------------------------------------

type Parsed = Partial<{ [K in ReportSourceKey]: ReportSourceBodies[K] }>;

const sum = (values: readonly number[]): number => values.reduce((a, b) => a + finite(b), 0);
const threatTotal = (verdicts: Readonly<Record<ThreatVerdictKey, number>>): number =>
  sum(THREAT_VERDICTS.map((v) => verdicts[v]));
type ThreatVerdictKey = (typeof THREAT_VERDICTS)[number];
const upperBound = (ms: number | null): string => (ms === null ? 'n/a' : `≤ ${fmtDuration(ms)}`);

function trafficSection(t: ReportSourceBodies['traffic'], w: ReportWindow): ReportSectionModel {
  const x = t.buckets.map((b) => dataText(b.start, DATA_CAPS.token));
  const lineVerdicts = [
    'spam',
    'phishing',
    'malware',
    'bec',
    'suspicious',
    'dlp_violation',
  ] as const;
  return {
    section: 'traffic',
    title: SECTION_TITLES.traffic,
    cards: [],
    charts: [
      {
        kind: 'timeseries',
        id: 'chart-traffic-volume',
        title: 'Mail volume by direction',
        x,
        granularity: w.granularity,
        stacked: true,
        unit: 'count',
        series: [
          series(
            'Inbound',
            0,
            t.buckets.map((b) => b.inbound),
          ),
          series(
            'Outbound',
            1,
            t.buckets.map((b) => b.outbound),
          ),
          series(
            'Internal',
            2,
            t.buckets.map((b) => b.internal),
          ),
        ],
      },
      {
        kind: 'timeseries',
        id: 'chart-traffic-threats',
        title: 'Threat verdicts over time',
        x,
        granularity: w.granularity,
        stacked: false,
        unit: 'count',
        series: lineVerdicts.map((v) =>
          series(
            VERDICT_LABELS[v],
            VERDICT_COLORS[v],
            t.buckets.map((b) => b.verdicts[v]),
          ),
        ),
      },
      donutOf(
        'chart-traffic-verdicts',
        'Verdict mix',
        REPORT_VERDICTS.map((v) => ({
          label: VERDICT_LABELS[v],
          value: t.totals.verdicts[v],
          color: VERDICT_COLORS[v],
        })),
      ),
    ],
    tables: [],
    notes: [],
  };
}

function threatsSection(t: ReportSourceBodies['threats']): ReportSectionModel {
  const outcomes = t.outcomes
    .map((row, index) => ({ row, index }))
    .sort((a, b) => b.row.count - a.row.count || a.index - b.index)
    .slice(0, OUTCOME_ROWS_MAX)
    .map(({ row }) => [
      label(VERDICT_LABELS, row.verdict),
      label(ACTION_LABELS, row.action),
      fmtNumber(row.count),
    ]);
  return {
    section: 'threats',
    title: SECTION_TITLES.threats,
    cards: [],
    charts: [
      donutOf(
        'chart-threat-types',
        'Threat types',
        THREAT_VERDICTS.map((v) => ({
          label: VERDICT_LABELS[v],
          value: t.messages.verdicts[v],
          color: VERDICT_COLORS[v],
        })),
      ),
      bars(
        'chart-threat-actions',
        'Final actions',
        FINAL_ACTIONS.map((a) => ({ label: ACTION_LABELS[a], value: t.messages.actions[a] })),
        0,
      ),
      bars(
        'chart-quarantine-reasons',
        'Quarantine reasons',
        QUARANTINE_REASONS.map((r) => ({ label: humanize(r), value: t.quarantine.reasons[r] })),
        1,
      ),
      bars(
        'chart-detection-engines',
        'Primary detection engines',
        PRIMARY_ENGINES.map((e) => ({
          label: ENGINE_LABELS[e],
          value: t.quarantine.primaryEngines[e],
        })),
        6,
      ),
    ],
    tables: [
      {
        id: 'table-threat-outcomes',
        title: 'Verdicts and actions (top 15)',
        columns: ['Verdict', 'Action', 'Messages'],
        numeric: [false, false, true],
        rows: outcomes,
      },
    ],
    notes: [],
  };
}

function domainName(d: ReportSourceBodies['top_domains']['domains'][number]): string {
  const name = dataText(d.name, DATA_CAPS.domain);
  return d.deleted ? `${name} (deleted)` : name;
}

function domainsSection(t: ReportSourceBodies['top_domains']): ReportSectionModel {
  const domains = t.domains.slice(0, BAR_MAX);
  const chart: BarSpec = {
    kind: 'bar',
    id: 'chart-top-domains',
    title: 'Top attacked domains',
    unit: 'count',
    segments: THREAT_VERDICTS.map((v) => ({ name: VERDICT_LABELS[v], color: VERDICT_COLORS[v] })),
    bars: domains.map((d) => ({
      label: domainName(d),
      value: finite(d.threats),
      parts: THREAT_VERDICTS.map((v) => finite(d.verdicts[v])),
    })),
  };
  const rows = t.domains.map((d) => [
    domainName(d),
    humanize(dataText(d.status, DATA_CAPS.token)),
    fmtNumber(d.inbound),
    fmtNumber(d.threats),
    ...THREAT_VERDICTS.map((v) => fmtNumber(d.verdicts[v])),
  ]);
  rows.push([
    'Unattributed',
    '',
    fmtNumber(t.unattributed.inbound),
    fmtNumber(t.unattributed.threats),
    ...THREAT_VERDICTS.map(() => ''),
  ]);
  return {
    section: 'domains',
    title: SECTION_TITLES.domains,
    cards: [],
    charts: [chart],
    tables: [
      {
        id: 'table-domains',
        title: 'Domains',
        columns: [
          'Domain',
          'Status',
          'Inbound',
          'Threats',
          ...THREAT_VERDICTS.map((v) => VERDICT_LABELS[v]),
        ],
        numeric: [false, false, true, true, ...THREAT_VERDICTS.map(() => true)],
        rows,
      },
    ],
    notes: [
      'Unattributed: inbound mail whose recipient domain is not one of the organization’s domains.',
    ],
  };
}

function deliverySection(d: ReportSourceBodies['delivery'], w: ReportWindow): ReportSectionModel {
  return {
    section: 'delivery',
    title: SECTION_TITLES.delivery,
    cards: [
      { label: 'Average latency', value: fmtDuration(d.latency.averageMs) },
      {
        label: 'Median latency',
        value: upperBound(d.latency.p50UpperBoundMs),
        hint: 'upper bound',
      },
      { label: 'p95 latency', value: upperBound(d.latency.p95UpperBoundMs), hint: 'upper bound' },
    ],
    charts: [
      {
        kind: 'timeseries',
        id: 'chart-delivery-success',
        title: 'Delivery success rate',
        x: d.buckets.map((b) => dataText(b.start, DATA_CAPS.token)),
        granularity: w.granularity,
        stacked: false,
        unit: 'percent',
        series: [
          series(
            'Success rate',
            'good',
            d.buckets.map((b) => b.successRate),
          ),
        ],
      },
      donutOf(
        'chart-delivery-statuses',
        'Delivery statuses',
        DELIVERY_STATUSES.map((s) => ({
          label: humanize(s),
          value: d.totals.statuses[s],
          color: DELIVERY_COLORS[s],
        })),
      ),
      histogramOf('chart-delivery-latency', 'Delivery latency', d.latency.histogram),
    ],
    tables: [],
    notes: [],
  };
}

function processingSection(
  p: ReportSourceBodies['processing'],
  w: ReportWindow,
): ReportSectionModel {
  return {
    section: 'processing',
    title: SECTION_TITLES.processing,
    cards: [
      { label: 'Scan rounds', value: fmtNumber(p.totals.rounds) },
      { label: 'Average time to verdict', value: fmtDuration(p.totals.averageMs) },
      {
        label: 'p95 time to verdict',
        value: upperBound(p.totals.p95UpperBoundMs),
        hint: 'upper bound',
      },
    ],
    charts: [
      {
        kind: 'timeseries',
        id: 'chart-processing-time',
        title: 'Time to verdict',
        x: p.buckets.map((b) => dataText(b.start, DATA_CAPS.token)),
        granularity: w.granularity,
        stacked: false,
        unit: 'duration',
        series: [
          series(
            'Average',
            0,
            p.buckets.map((b) => b.averageMs),
          ),
          series(
            'p95 (upper bound)',
            1,
            p.buckets.map((b) => b.p95UpperBoundMs),
          ),
        ],
      },
      histogramOf('chart-processing-histogram', 'Time-to-verdict distribution', p.totals.histogram),
    ],
    tables: [],
    notes: ['Time from receipt to the completed initial scan round; completed rounds only.'],
  };
}

function urlClicksSection(
  u: ReportSourceBodies['url_clicks'],
  w: ReportWindow,
): ReportSectionModel {
  return {
    section: 'url_clicks',
    title: SECTION_TITLES.url_clicks,
    cards: [],
    charts: [
      {
        kind: 'timeseries',
        id: 'chart-url-clicks',
        title: 'Clicks by decision',
        x: u.buckets.map((b) => dataText(b.start, DATA_CAPS.token)),
        granularity: w.granularity,
        stacked: true,
        unit: 'count',
        series: CLICK_DECISIONS.map((c) =>
          series(
            humanize(c),
            CLICK_COLORS[c],
            u.buckets.map((b) => b.decisions[c]),
          ),
        ),
      },
      donutOf(
        'chart-url-decisions',
        'Click decisions',
        CLICK_DECISIONS.map((c) => ({
          label: humanize(c),
          value: u.totals.decisions[c],
          color: CLICK_COLORS[c],
        })),
      ),
    ],
    tables: [],
    notes: [],
  };
}

function quarantineSection(q: ReportSourceBodies['quarantine_summary']): ReportSectionModel {
  const states = Object.keys(q.counts).sort((a, b) => a.localeCompare(b, 'en'));
  return {
    section: 'quarantine',
    title: SECTION_TITLES.quarantine,
    cards: [
      { label: 'Held', value: fmtNumber(q.counts.held ?? 0) },
      { label: 'Pending approvals', value: fmtNumber(q.pendingApprovals) },
    ],
    charts: [
      donutOf(
        'chart-quarantine-states',
        'Entries by state',
        states.map((state) => ({
          label: humanize(dataText(state, DATA_CAPS.token)),
          value: q.counts[state] ?? 0,
          color: Object.prototype.hasOwnProperty.call(QUARANTINE_STATE_COLORS, state)
            ? QUARANTINE_STATE_COLORS[state]!
            : 'other',
        })),
      ),
    ],
    tables: [],
    notes: ['Entries quarantined in the period, by their current state.'],
  };
}

function atoSection(
  o: ReportSourceBodies['ato_overview'],
  accounts: ReportSourceBodies['ato_accounts'] | null,
  accountsNote: string | null,
  w: ReportWindow,
): ReportSectionModel {
  const charts: ChartSpec[] = [
    {
      kind: 'timeseries',
      id: 'chart-ato-incidents',
      title: 'Incidents by severity',
      x: o.incidents.trend.map((b) => dataText(b.bucketStart, DATA_CAPS.token)),
      granularity: o.range === '24h' ? 'hour' : 'day',
      stacked: true,
      unit: 'count',
      series: INCIDENT_SEVERITIES.map((s) =>
        series(
          humanize(s),
          SEVERITY_COLORS[s],
          o.incidents.trend.map((b) => b[s]),
        ),
      ),
    },
  ];
  const tables: TableSpec[] = [];
  const notes: string[] = [];
  if (!w.range || w.range !== o.range)
    notes.push(
      `Account takeover figures cover the ${periodLabel({ from: o.from, to: o.to, range: o.range }).toLowerCase()} ending ${fmtUtc(o.to)} (the overview supports 24 hours, 7 days and 30 days).`,
    );
  if (accounts) {
    const rows = accounts.data.slice(0, BAR_MAX);
    const name = (a: (typeof rows)[number]) =>
      a.address
        ? dataText(a.address, DATA_CAPS.address)
        : a.displayName
          ? dataText(a.displayName, DATA_CAPS.displayName)
          : humanize(dataText(a.kind, DATA_CAPS.token));
    charts.push({
      kind: 'bar',
      id: 'chart-ato-accounts',
      title: 'Accounts at highest takeover risk',
      unit: 'count',
      color: 'critical',
      segments: [],
      bars: rows.map((a) => ({ label: name(a), value: finite(a.riskScore) })),
    });
    tables.push({
      id: 'table-ato-accounts',
      title: 'Accounts at highest takeover risk',
      columns: ['Account', 'Display name', 'Kind', 'Risk level', 'Risk score', 'Active incident'],
      numeric: [false, false, false, false, true, false],
      rows: rows.map((a) => [
        a.address ? dataText(a.address, DATA_CAPS.address) : '',
        a.displayName ? dataText(a.displayName, DATA_CAPS.displayName) : '',
        humanize(dataText(a.kind, DATA_CAPS.token)),
        humanize(dataText(a.riskLevel, DATA_CAPS.token)),
        fmtNumber(a.riskScore),
        a.activeIncident
          ? `${humanize(dataText(a.activeIncident.severity, DATA_CAPS.token))} (${dataText(a.activeIncident.status, DATA_CAPS.token).replace(/_/g, ' ')})`
          : 'None',
      ]),
    });
  } else if (accountsNote) notes.push(accountsNote);
  if (o.geography.available && o.geography.topCountries.length > 0)
    tables.push({
      id: 'table-ato-countries',
      title: 'Top sign-in countries',
      columns: ['Country', 'Successful sign-ins', 'New-country signals'],
      numeric: [false, true, true],
      rows: o.geography.topCountries
        .slice(0, BAR_MAX)
        .map((c) => [
          dataText(c.countryCode, DATA_CAPS.token),
          fmtNumber(c.successfulAuth),
          fmtNumber(c.newCountrySignals),
        ]),
    });
  return {
    section: 'ato',
    title: SECTION_TITLES.ato,
    cards: [
      { label: 'Monitored accounts', value: fmtNumber(o.accounts.monitored) },
      { label: 'High risk', value: fmtNumber(o.accounts.highRisk) },
      { label: 'Critical risk', value: fmtNumber(o.accounts.criticalRisk) },
      { label: 'Active incidents', value: fmtNumber(o.incidents.active) },
      { label: 'Suspicious sign-ins', value: fmtNumber(o.logins.suspiciousInRange) },
      { label: 'Restricted accounts', value: fmtNumber(o.outbound.restrictedAccounts) },
    ],
    charts,
    tables,
    notes,
  };
}

// ---------------------------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------------------------

function atoOn(o: ReportSourceBodies['ato_overview'] | undefined): boolean {
  return Boolean(o && atoAccountsWanted(o));
}

/** The summary cards (design D3 row `summary`) from whatever sources succeeded. */
export function summaryCards(parsed: Parsed): SummaryCard[] {
  const cards: SummaryCard[] = [];
  const { traffic, threats, delivery, processing, url_clicks, quarantine_summary, ato_overview } =
    parsed;
  if (traffic) {
    cards.push({ label: 'Messages', value: fmtNumber(traffic.totals.total) });
    cards.push({ label: 'Inbound', value: fmtNumber(traffic.totals.inbound) });
    cards.push({ label: 'Outbound', value: fmtNumber(traffic.totals.outbound) });
    cards.push({ label: 'Threats', value: fmtNumber(threatTotal(traffic.totals.verdicts)) });
  }
  if (threats) cards.push({ label: 'Quarantined', value: fmtNumber(threats.quarantine.total) });
  if (delivery)
    cards.push({ label: 'Delivery success rate', value: fmtPercent(delivery.totals.successRate) });
  if (processing)
    cards.push({
      label: 'p95 time to verdict',
      value: upperBound(processing.totals.p95UpperBoundMs),
      hint: 'upper bound',
    });
  if (url_clicks)
    cards.push({
      label: 'Blocked URL clicks',
      value: fmtNumber(url_clicks.totals.decisions.blocked),
    });
  if (quarantine_summary) {
    cards.push({
      label: 'Held in quarantine',
      value: fmtNumber(quarantine_summary.counts.held ?? 0),
    });
    cards.push({
      label: 'Pending approvals',
      value: fmtNumber(quarantine_summary.pendingApprovals),
    });
  }
  if (ato_overview && atoOn(ato_overview))
    cards.push({
      label: 'High-risk accounts',
      value: fmtNumber(ato_overview.accounts.highRisk + ato_overview.accounts.criticalRisk),
      hint: 'high and critical',
    });
  return cards;
}

/** The ≤ 8 figures of the card, the envelope and the email (design D2 step 11). */
const FIGURE_LABELS = [
  'Messages',
  'Threats',
  'Quarantined',
  'Delivery success rate',
  'p95 time to verdict',
  'Held in quarantine',
  'Pending approvals',
  'High-risk accounts',
] as const;

export function summaryFigures(cards: readonly SummaryCard[]): ReportFigure[] {
  return FIGURE_LABELS.flatMap((name) => {
    const card = cards.find((c) => c.label === name);
    return card ? [{ label: card.label, value: card.value }] : [];
  }).slice(0, SUMMARY_FIGURES_MAX);
}

// ---------------------------------------------------------------------------------------------
// Assembly
// ---------------------------------------------------------------------------------------------

const ATO_ACCOUNTS_UNAVAILABLE = 'Accounts at highest takeover risk are not available';

/** Builds the report model (design D2 step 8, D3). */
export function buildReportModel(
  results: ReportSourceResults,
  options: BuildReportOptions,
): ReportModel {
  const requested = REPORT_SECTIONS.filter((s) => options.sections.includes(s));
  const parsed: Parsed = {};
  const failed = new Map<ReportSourceKey, Omit<ReportOmission, 'section'>>();
  const sources: ReportSourceRecord[] = [];

  for (const def of plannedSources(requested)) {
    const result = results[def.key];
    const base = { tool: def.tool, label: def.label };
    if (def.after === 'ato_overview' && !atoOn(parsed.ato_overview) && !result) {
      sources.push({ ...base, outcome: 'not_called', httpStatus: null });
      continue;
    }
    if (!result) {
      failed.set(def.key, { reason: 'unavailable', code: 'source_not_read' });
      sources.push({ ...base, outcome: 'not_called', httpStatus: null, code: 'source_not_read' });
      continue;
    }
    if (result.status === 'permission') {
      const permission = sourcePermission(def);
      failed.set(def.key, { reason: 'permission', ...(permission ? { code: permission } : {}) });
      sources.push({ ...base, outcome: 'omitted_permission', httpStatus: null });
      continue;
    }
    if (result.status === 'unavailable') {
      const code = dataText(result.code, DATA_CAPS.code) || 'request_failed';
      failed.set(def.key, { reason: 'unavailable', code });
      sources.push({ ...base, outcome: 'unavailable', httpStatus: result.httpStatus, code });
      continue;
    }
    const outcome = parseSource(def.key, result.body);
    const httpStatus = result.httpStatus ?? 200;
    if (!outcome.ok) {
      failed.set(def.key, { reason: 'unexpected_response' });
      sources.push({ ...base, outcome: 'unexpected', httpStatus });
      continue;
    }
    (parsed as Record<string, unknown>)[def.key] = outcome.data;
    const body = outcome.data as { from?: unknown; to?: unknown; generatedAt?: unknown };
    sources.push({
      ...base,
      outcome: 'ok',
      httpStatus,
      ...(typeof body.from === 'string' ? { from: dataText(body.from, DATA_CAPS.token) } : {}),
      ...(typeof body.to === 'string' ? { to: dataText(body.to, DATA_CAPS.token) } : {}),
      ...(typeof body.generatedAt === 'string'
        ? { generatedAt: dataText(body.generatedAt, DATA_CAPS.token) }
        : {}),
    });
  }

  const omitted: ReportOmission[] = [];
  const included: ReportSection[] = [];
  const body: ReportSectionModel[] = [];
  const w = options.window;
  const cards = summaryCards(parsed);

  for (const section of requested) {
    if (section === 'summary') {
      if (cards.length > 0) included.push(section);
      else omitted.push({ section, reason: 'unavailable', code: 'no_source_available' });
      continue;
    }
    const required = REPORT_SOURCES[section].filter((key) => !REPORT_SOURCE_DEFS[key].after);
    const failure = required.map((key) => failed.get(key)).find(Boolean);
    if (failure) {
      omitted.push({ section, ...failure });
      continue;
    }
    if (section === 'ato' && !atoOn(parsed.ato_overview)) {
      omitted.push({ section, reason: 'not_enabled' });
      continue;
    }
    included.push(section);
    switch (section) {
      case 'traffic':
        body.push(trafficSection(parsed.traffic!, w));
        break;
      case 'threats':
        body.push(threatsSection(parsed.threats!));
        break;
      case 'domains':
        body.push(domainsSection(parsed.top_domains!));
        break;
      case 'delivery':
        body.push(deliverySection(parsed.delivery!, w));
        break;
      case 'processing':
        body.push(processingSection(parsed.processing!, w));
        break;
      case 'url_clicks':
        body.push(urlClicksSection(parsed.url_clicks!, w));
        break;
      case 'quarantine':
        body.push(quarantineSection(parsed.quarantine_summary!));
        break;
      case 'ato': {
        const accountsFailure = failed.get('ato_accounts');
        const note = accountsFailure
          ? accountsFailure.reason === 'permission'
            ? `${ATO_ACCOUNTS_UNAVAILABLE} (requires ${accountsFailure.code ?? 'a permission'}).`
            : `${ATO_ACCOUNTS_UNAVAILABLE} (${accountsFailure.code ?? accountsFailure.reason}).`
          : null;
        body.push(atoSection(parsed.ato_overview!, parsed.ato_accounts ?? null, note, w));
        break;
      }
    }
  }

  const period = reportPeriodOf(w);
  return {
    version: REPORT_TEMPLATE_VERSION,
    title: `${REPORT_TITLE}: ${period.label}`,
    organizationName: dataText(options.organizationName, DATA_CAPS.organization),
    window: { ...w },
    period,
    generatedAt: dataText(options.generatedAt, DATA_CAPS.token),
    sections: included,
    omitted,
    summary: included.includes('summary') ? cards : [],
    figures: summaryFigures(cards),
    body,
    sources,
  };
}

/**
 * Design D2 step 7: true when every requested non-summary section is omitted (the execution
 * fails `503 assistant_report_sources_unavailable`); a summary-only request has no data when the
 * summary itself is omitted.
 */
export function reportHasNoData(model: ReportModel): boolean {
  const requested = [...model.sections, ...model.omitted.map((o) => o.section)];
  const nonSummary = requested.filter((s) => s !== 'summary');
  if (nonSummary.length === 0) return !model.sections.includes('summary');
  return !model.sections.some((s) => s !== 'summary');
}

/** What the card, the envelope and the report row carry (design D2 steps 10–11). */
export interface ReportDigest {
  title: string;
  period: ReportPeriod;
  sections: ReportSection[];
  omitted: ReportOmission[];
  figures: ReportFigure[];
}

export function reportDigestOf(model: ReportModel): ReportDigest {
  return {
    title: model.title,
    period: { ...model.period },
    sections: [...model.sections],
    omitted: model.omitted.map((o) => ({ ...o })),
    figures: model.figures.map((f) => ({ ...f })),
  };
}
