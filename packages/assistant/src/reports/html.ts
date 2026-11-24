import { escapeHtml, finite, fmtNumber, fmtShare, fmtUtc } from './escape';
import { swatchClass, swatchCss } from './palette';
import { isEmptyChart, renderChart, valueText } from './svg';
import type {
  ChartSpec,
  ReportModel,
  ReportOmission,
  ReportSectionModel,
  ReportSourceRecord,
  SummaryCard,
  TableSpec,
} from './types';
import { SECTION_TITLES } from './model';

/**
 * `renderReportHtml` (design D4): the report model → one self-contained, inert HTML document
 * (constant CSP meta, constant `<style>`, header, summary cards, section grid of chart cards,
 * section tables, a data appendix with a table per chart, Sources, Not included and the footer
 * text of D3). No script, no link, no URL, no external resource; every string is escaped and no
 * attribute value is data. Deterministic: the same model renders to the same bytes.
 */

export const REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:";

/** Appendix rows kept per table by the size-cap fallback (design D2 step 8). */
export const APPENDIX_FALLBACK_ROWS = 50;

export const NO_DATA_TEXT = 'No data in this period';

/** The constant style block (no data; tested byte-equal). */
export const REPORT_STYLE = [
  '*{box-sizing:border-box}',
  'html{background:#ffffff;color:#0b0b0b}',
  'body{margin:0;background:#ffffff;color:#0b0b0b;font-family:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;font-size:14px;line-height:1.45}',
  '.report{max-width:1080px;margin:0 auto;padding:24px 16px 32px}',
  '.report-header{border-bottom:1px solid #e1e0d9;padding-bottom:12px;margin-bottom:20px}',
  'h1{font-size:24px;margin:0 0 4px}',
  'h2{font-size:18px;margin:0 0 12px}',
  'h3{font-size:14px;margin:0 0 8px}',
  '.org{font-size:16px;font-weight:600;margin:0 0 4px}',
  '.meta{color:#52514e;margin:0}',
  '.meta span{margin-right:16px}',
  '.section{margin:0 0 28px}',
  '.cards{display:flex;flex-wrap:wrap;gap:12px;margin:0 0 16px}',
  '.card{flex:1 1 150px;min-width:150px;border:1px solid #e1e0d9;border-radius:8px;padding:10px 12px;background:#ffffff}',
  '.card-label{display:block;color:#52514e;font-size:12px}',
  '.card-value{display:block;font-size:22px;font-weight:700;margin-top:2px}',
  '.card-hint{display:block;color:#6b6a65;font-size:11px}',
  '.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}',
  '.chart-card{margin:0;border:1px solid #e1e0d9;border-radius:8px;padding:12px;background:#ffffff;min-width:0}',
  '.chart-card figcaption{font-weight:600;margin:0 0 8px}',
  '.chart-svg{display:block;width:100%;height:auto}',
  '.chart-donut{max-width:220px;margin:0 auto}',
  '.empty{color:#6b6a65;text-align:center;padding:48px 0;margin:0;border:1px dashed #e1e0d9;border-radius:6px}',
  '.legend{list-style:none;margin:10px 0 0;padding:0;display:flex;flex-wrap:wrap;gap:4px 14px;font-size:12px;color:#52514e}',
  '.legend li{display:flex;align-items:center;gap:6px}',
  '.legend strong{color:#0b0b0b;font-weight:600}',
  '.sw{display:inline-block;width:10px;height:10px;border-radius:2px;flex:none}',
  swatchCss(),
  '.table-wrap{overflow-x:auto;margin:0 0 16px}',
  'table{border-collapse:collapse;width:100%;font-size:12px}',
  'caption{text-align:left;font-weight:600;padding:0 0 6px;font-size:13px}',
  'th,td{border-bottom:1px solid #e1e0d9;padding:4px 8px;text-align:left;vertical-align:top;word-break:break-word}',
  'th{color:#52514e;font-weight:600;background:#f7f7f5}',
  '.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}',
  '.note{color:#52514e;font-size:12px;margin:0 0 8px}',
  '.report-footer{border-top:1px solid #e1e0d9;padding-top:16px;color:#52514e;font-size:12px}',
  '.report-footer h2{font-size:14px;color:#0b0b0b;margin:12px 0 6px}',
  '.report-footer ul{margin:0 0 8px;padding-left:18px}',
  '.fineprint{margin:12px 0 0}',
  '@media (max-width:720px){.grid{grid-template-columns:minmax(0,1fr)}.card{flex-basis:130px;min-width:130px}}',
  '@media print{.report{max-width:none;padding:0}.chart-card,.card,table{break-inside:avoid}}',
].join('');

export interface RenderReportOptions {
  /** Size cap in UTF-8 bytes (ASSISTANT_REPORT_MAX_HTML_BYTES). */
  maxBytes?: number;
}

/** The rendered document exceeds the size cap even with the appendix rows capped. */
export class ReportTooLargeError extends Error {
  readonly code = 'assistant_report_too_large';
  constructor(
    readonly bytes: number,
    readonly maxBytes: number,
  ) {
    super(`The report is ${bytes} bytes, more than the ${maxBytes} bytes allowed.`);
    this.name = 'ReportTooLargeError';
  }
}

const e = escapeHtml;

function cardsHtml(cards: readonly SummaryCard[]): string {
  if (cards.length === 0) return '';
  return `<div class="cards">${cards
    .map(
      (card) =>
        `<div class="card"><span class="card-label">${e(card.label)}</span><strong class="card-value">${e(card.value)}</strong>${
          card.hint ? `<small class="card-hint">${e(card.hint)}</small>` : ''
        }</div>`,
    )
    .join('')}</div>`;
}

function legendHtml(spec: ChartSpec): string {
  const items: string[] = [];
  const swatch = (cls: string) => `<span class="sw ${cls}" aria-hidden="true"></span>`;
  if (spec.kind === 'timeseries' && spec.series.length >= 2)
    for (const s of spec.series) {
      const total =
        spec.unit === 'count'
          ? ` <strong>${e(fmtNumber(s.values.reduce<number>((a, v) => a + finite(v ?? 0), 0)))}</strong>`
          : '';
      items.push(`<li>${swatch(swatchClass(s.color))}${e(s.name)}${total}</li>`);
    }
  if (spec.kind === 'donut') {
    const total = spec.slices.reduce((sum, s) => sum + finite(s.value), 0);
    for (const s of spec.slices)
      items.push(
        `<li>${swatch(swatchClass(s.color))}${e(s.label)} <strong>${e(fmtNumber(s.value))}</strong> <small>(${e(fmtShare(s.value, total))})</small></li>`,
      );
  }
  if (spec.kind === 'bar' && spec.segments.length >= 2)
    for (const s of spec.segments)
      items.push(`<li>${swatch(swatchClass(s.color))}${e(s.name)}</li>`);
  return items.length > 0 ? `<ul class="legend">${items.join('')}</ul>` : '';
}

function chartHtml(spec: ChartSpec): string {
  const body = isEmptyChart(spec) ? `<p class="empty">${e(NO_DATA_TEXT)}</p>` : renderChart(spec);
  return `<figure class="chart-card"><figcaption>${e(spec.title)}</figcaption>${body}${
    isEmptyChart(spec) ? '' : legendHtml(spec)
  }</figure>`;
}

function tableHtml(table: TableSpec, rowCap = Number.POSITIVE_INFINITY): string {
  const rows = table.rows.slice(0, rowCap);
  const capped = rows.length < table.rows.length;
  const caption = capped
    ? `${table.title} (first ${fmtNumber(rows.length)} of ${fmtNumber(table.rows.length)} rows)`
    : table.title;
  const cls = (i: number) => (table.numeric[i] ? ' class="num"' : '');
  const head = table.columns.map((c, i) => `<th scope="col"${cls(i)}>${e(c)}</th>`).join('');
  const body =
    rows.length === 0
      ? `<tr><td colspan="${Math.max(1, table.columns.length)}">${e(NO_DATA_TEXT)}</td></tr>`
      : rows
          .map((row) => `<tr>${row.map((cell, i) => `<td${cls(i)}>${e(cell)}</td>`).join('')}</tr>`)
          .join('');
  return `<div class="table-wrap"><table><caption>${e(caption)}</caption><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>`;
}

/** The data table of a chart (the appendix; every chart has one). */
export function chartTable(spec: ChartSpec): TableSpec {
  switch (spec.kind) {
    case 'timeseries':
      return {
        id: `${spec.id}-data`,
        title: spec.title,
        columns: [
          spec.granularity === 'hour' ? 'Hour (UTC)' : 'Day (UTC)',
          ...spec.series.map((s) => s.name),
        ],
        numeric: [false, ...spec.series.map(() => true)],
        rows: spec.x.map((x, i) => [
          spec.granularity === 'hour' ? fmtUtc(x) : fmtUtc(x, 'date'),
          ...spec.series.map((s) => valueText(s.values[i] ?? null, spec.unit)),
        ]),
      };
    case 'donut': {
      const total = spec.slices.reduce((sum, s) => sum + finite(s.value), 0);
      return {
        id: `${spec.id}-data`,
        title: spec.title,
        columns: ['Category', 'Count', 'Share'],
        numeric: [false, true, true],
        rows: spec.slices.map((s) => [s.label, fmtNumber(s.value), fmtShare(s.value, total)]),
      };
    }
    case 'bar':
      return {
        id: `${spec.id}-data`,
        title: spec.title,
        columns: ['Item', 'Value', ...spec.segments.map((s) => s.name)],
        numeric: [false, true, ...spec.segments.map(() => true)],
        rows: spec.bars.map((b) => [
          b.label,
          valueText(b.value, spec.unit),
          ...spec.segments.map((_, k) => fmtNumber(b.parts?.[k] ?? 0)),
        ]),
      };
    case 'histogram':
      return {
        id: `${spec.id}-data`,
        title: spec.title,
        columns: ['Upper bound', 'Count'],
        numeric: [false, true],
        rows: spec.bins.map((b) => [b.label, fmtNumber(b.count)]),
      };
  }
}

function sectionHtml(section: ReportSectionModel): string {
  const charts =
    section.charts.length > 0
      ? `<div class="grid">${section.charts.map(chartHtml).join('')}</div>`
      : '';
  const tables = section.tables.map((t) => tableHtml(t)).join('');
  const notes = section.notes.map((n) => `<p class="note">${e(n)}</p>`).join('');
  return `<section class="section" id="section-${section.section.replace(/_/g, '-')}" aria-label="${e(section.title)}"><h2>${e(section.title)}</h2>${cardsHtml(section.cards)}${charts}${tables}${notes}</section>`;
}

const OUTCOME_TEXT: Readonly<Record<ReportSourceRecord['outcome'], string>> = {
  ok: 'included',
  omitted_permission: 'not read (missing permission)',
  unavailable: 'unavailable',
  unexpected: 'unexpected response',
  not_called: 'not read',
};

function sourceLine(source: ReportSourceRecord): string {
  const parts = [`${source.label} (${source.tool}): ${OUTCOME_TEXT[source.outcome]}`];
  if (source.code) parts.push(`code ${source.code}`);
  if (source.httpStatus !== null && source.outcome !== 'ok')
    parts.push(`HTTP ${source.httpStatus}`);
  if (source.from && source.to) parts.push(`window ${fmtUtc(source.from)} to ${fmtUtc(source.to)}`);
  if (source.generatedAt) parts.push(`generated ${fmtUtc(source.generatedAt)}`);
  return parts.join(', ');
}

/** "Not included" text of an omission (design D3 footer). */
export function omissionText(omission: ReportOmission): string {
  const title = SECTION_TITLES[omission.section];
  switch (omission.reason) {
    case 'permission':
      return `${title}: missing permission${omission.code ? ` (requires ${omission.code})` : ''}`;
    case 'not_enabled':
      return `${title}: feature not enabled`;
    case 'unavailable':
      return `${title}: unavailable${omission.code ? ` (${omission.code})` : ''}`;
    case 'unexpected_response':
      return `${title}: unexpected response from the report API`;
  }
}

function documentHtml(model: ReportModel, appendixRows: number): string {
  const summary = model.sections.includes('summary')
    ? `<section class="section" id="section-summary" aria-label="Summary"><h2>Summary</h2>${cardsHtml(model.summary)}</section>`
    : '';
  const sections = model.body.map(sectionHtml).join('');
  const charts = model.body.flatMap((s) => s.charts);
  const appendix =
    charts.length > 0
      ? `<section class="section" id="section-appendix" aria-label="Data appendix"><h2>Data appendix</h2><p class="note">${e(
          'The data behind every chart above.',
        )}</p>${charts.map((c) => tableHtml(chartTable(c), appendixRows)).join('')}</section>`
      : '';
  const sources = `<h2>Sources</h2><ul>${model.sources.map((s) => `<li>${e(sourceLine(s))}</li>`).join('')}</ul>`;
  const notIncluded = `<h2>Not included</h2>${
    model.omitted.length > 0
      ? `<ul>${model.omitted.map((o) => `<li>${e(omissionText(o))}</li>`).join('')}</ul>`
      : `<p>${e('Every requested section is included.')}</p>`
  }`;
  const fineprint = `All times are UTC. Generated by the AI assistant from the platform's report APIs for ${model.organizationName}; numbers are counts of recorded rows, not estimates.`;
  return [
    '<!doctype html><html lang="en"><head><meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    `<meta http-equiv="Content-Security-Policy" content="${e(REPORT_CSP)}">`,
    '<meta name="referrer" content="no-referrer">',
    `<title>${e(model.title)}</title><style>${REPORT_STYLE}</style></head>`,
    '<body><main class="report">',
    `<header class="report-header"><h1>${e('Security report')}</h1><p class="org">${e(model.organizationName)}</p>`,
    `<p class="meta"><span>${e(`Period: ${model.period.label}`)}</span><span>${e(
      `Generated ${fmtUtc(model.generatedAt)}`,
    )}</span></p></header>`,
    summary,
    sections,
    appendix,
    `<footer class="report-footer">${sources}${notIncluded}<p class="fineprint">${e(fineprint)}</p></footer>`,
    '</main></body></html>',
  ].join('');
}

/** UTF-8 byte length. */
export const byteLength = (html: string): number => Buffer.byteLength(html, 'utf8');

/**
 * The report HTML. With `maxBytes`: when the document is larger, the data appendix keeps the
 * first 50 rows per table and the document is rendered once more; still too large →
 * `ReportTooLargeError` (`413 assistant_report_too_large`).
 */
export function renderReportHtml(model: ReportModel, options: RenderReportOptions = {}): string {
  const full = documentHtml(model, Number.POSITIVE_INFINITY);
  if (options.maxBytes === undefined || byteLength(full) <= options.maxBytes) return full;
  const capped = documentHtml(model, APPENDIX_FALLBACK_ROWS);
  const bytes = byteLength(capped);
  if (bytes > options.maxBytes) throw new ReportTooLargeError(bytes, options.maxBytes);
  return capped;
}
