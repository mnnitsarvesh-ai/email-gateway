/**
 * Report model types of step AI-R (design `docs/plan/steps/31-ai-chat-reports.md` D2–D4,
 * ADR-0095): the period, the sections, the summary figures and the chart and table specs that
 * `buildReportModel` produces from validated API responses and `renderReportHtml` turns into one
 * inert HTML document. Every string in a model is either a fixed English label or a sanitized
 * data string; colors are palette indexes or verdict keys, never data.
 */

export const REPORT_TEMPLATE_VERSION = 'assistant-report/1';

/** The report sections in render order (design D3). */
export const REPORT_SECTIONS = [
  'summary',
  'traffic',
  'threats',
  'domains',
  'delivery',
  'processing',
  'url_clicks',
  'quarantine',
  'ato',
] as const;
export type ReportSection = (typeof REPORT_SECTIONS)[number];

export const REPORT_RANGES = ['24h', '7d', '30d'] as const;
export type ReportRange = (typeof REPORT_RANGES)[number];

export type ReportGranularity = 'hour' | 'day';

/** The resolved period of a report (design D2 step 3). */
export interface ReportWindow {
  /** Inclusive start, ISO 8601 UTC (`toISOString`). */
  from: string;
  /** Exclusive end, ISO 8601 UTC. */
  to: string;
  granularity: ReportGranularity;
  /** The relative range the user asked for, or null for an explicit window. */
  range: ReportRange | null;
  /** Range of the ATO overview (its API takes a relative range only). */
  atoRange: ReportRange;
}

export const REPORT_OMIT_REASONS = [
  'permission',
  'not_enabled',
  'unavailable',
  'unexpected_response',
] as const;
export type ReportOmitReason = (typeof REPORT_OMIT_REASONS)[number];

/** A requested section that is not in the report, and why (the "Not included" footer). */
export interface ReportOmission {
  section: ReportSection;
  reason: ReportOmitReason;
  /** The missing permission (`quarantine:read`) or the error code of the source (`report_timeout`). */
  code?: string;
}

/** A summary figure of the card, the envelope and the email text part (≤ 8). */
export interface ReportFigure {
  label: string;
  /** Formatted value (`1,248`, `98.6%`, `≤ 5 s`). */
  value: string;
}

/** The period as the card, the envelope and the report view carry it. */
export interface ReportPeriod {
  from: string;
  to: string;
  granularity: ReportGranularity;
  atoRange: ReportRange | null;
  /** `Last 7 days` or `Nov 16, 2026 09:00 to Nov 23, 2026 09:00 UTC`. */
  label: string;
}

/** Semantic color keys (verdicts, statuses); categorical colors are palette indexes 0–7. */
export type SemanticColor =
  | 'clean'
  | 'spam'
  | 'bulk'
  | 'phishing'
  | 'malware'
  | 'bec'
  | 'dlp_violation'
  | 'suspicious'
  | 'unknown'
  | 'none'
  | 'other'
  | 'good'
  | 'warning'
  | 'serious'
  | 'critical';

/** A categorical palette index (0–7) or a semantic key. */
export type SeriesColor = number | SemanticColor;

export type ValueUnit = 'count' | 'percent' | 'duration';

export interface TimeSeriesSpec {
  kind: 'timeseries';
  /** Constant element id (`chart-traffic-volume`). */
  id: string;
  title: string;
  /** Bucket starts (ISO 8601 UTC). */
  x: string[];
  granularity: ReportGranularity;
  /** Stacked area when true, else lines. */
  stacked: boolean;
  unit: ValueUnit;
  series: Array<{ name: string; color: SeriesColor; values: Array<number | null> }>;
}

export interface DonutSpec {
  kind: 'donut';
  id: string;
  title: string;
  slices: Array<{ label: string; value: number; color: SeriesColor }>;
}

export interface BarSpec {
  kind: 'bar';
  id: string;
  title: string;
  unit: ValueUnit;
  /** Color of single-value bars (default palette slot 0). */
  color?: SeriesColor;
  /** Segment names (stacked bars) with their colors; empty for single-value bars. */
  segments: Array<{ name: string; color: SeriesColor }>;
  bars: Array<{ label: string; value: number; parts?: number[] }>;
}

export interface HistogramSpec {
  kind: 'histogram';
  id: string;
  title: string;
  /** Upper bound labels (`≤ 1 s`, `> 1 d`) and counts. */
  bins: Array<{ label: string; count: number }>;
}

export type ChartSpec = TimeSeriesSpec | DonutSpec | BarSpec | HistogramSpec;

export interface TableSpec {
  id: string;
  title: string;
  columns: string[];
  /** Right-aligned (numeric) columns. */
  numeric: boolean[];
  rows: string[][];
}

export interface SummaryCard {
  label: string;
  value: string;
  /** A short qualifier (`upper bound`, `of 1,248 messages`). */
  hint?: string;
}

export interface ReportSectionModel {
  section: ReportSection;
  title: string;
  cards: SummaryCard[];
  charts: ChartSpec[];
  tables: TableSpec[];
  notes: string[];
}

export type ReportSourceOutcome =
  'ok' | 'omitted_permission' | 'unavailable' | 'unexpected' | 'not_called';

/** One source read of the report (the "Sources" footer and the audit metadata). */
export interface ReportSourceRecord {
  tool: string;
  /** The operation's summary (`Traffic report`). */
  label: string;
  outcome: ReportSourceOutcome;
  httpStatus: number | null;
  code?: string;
  /** The window as the API aligned it, and when it computed the response. */
  from?: string;
  to?: string;
  generatedAt?: string;
}

export interface ReportModel {
  version: typeof REPORT_TEMPLATE_VERSION;
  title: string;
  organizationName: string;
  window: ReportWindow;
  period: ReportPeriod;
  generatedAt: string;
  /** Requested sections that are in the report, in render order. */
  sections: ReportSection[];
  omitted: ReportOmission[];
  /** The summary cards (only when `summary` is included). */
  summary: SummaryCard[];
  figures: ReportFigure[];
  body: ReportSectionModel[];
  sources: ReportSourceRecord[];
}
