import { sanitizeText } from '../results/sanitize';
import { coord, escapeHtml, finite, fmtDuration, fmtNumber, fmtShare, fmtUtc } from './escape';
import { CHROME, colorOf } from './palette';
import type {
  BarSpec,
  ChartSpec,
  DonutSpec,
  HistogramSpec,
  ReportGranularity,
  TimeSeriesSpec,
  ValueUnit,
} from './types';

/**
 * Static SVG chart primitives (design D4): line / stacked area, donut, horizontal bar and
 * vertical histogram. Output is a string with a fixed `viewBox` per kind, coordinates rounded to
 * 2 decimals, `role="img"` with `aria-labelledby` pointing at a `<title>` and a one-line
 * `<desc>`. Attribute values are constants, palette colors or formatted finite numbers; every
 * text node is escaped. No script, no link, no external reference.
 */

export const VIEWBOX = {
  timeseries: { width: 640, height: 260 },
  donut: { width: 220, height: 220 },
  bar: { width: 640, height: 300 },
  histogram: { width: 640, height: 240 },
} as const;

/** Label width (characters) of bar and axis labels inside a chart (tables keep the full text). */
export const BAR_LABEL_CHARS = 30;
const X_LABELS_MAX = 6;
const FONT = 'font-size';

const ID = /^[a-z][a-z0-9-]{0,63}$/;
const safeId = (id: string): string => (ID.test(id) ? id : 'chart');

// ---------------------------------------------------------------------------------------------
// Scales and ticks
// ---------------------------------------------------------------------------------------------

/** A "nice" step (1, 2, 2.5, 5 × 10^k) for about `count` intervals up to `max`. */
export function niceStep(max: number, count = 4): number {
  const value = finite(max);
  if (value <= 0) return 1;
  const raw = value / Math.max(1, count);
  const power = 10 ** Math.floor(Math.log10(raw));
  const fraction = raw / power;
  const nice =
    fraction <= 1 ? 1 : fraction <= 2 ? 2 : fraction <= 2.5 ? 2.5 : fraction <= 5 ? 5 : 10;
  return nice * power;
}

/** Ticks from 0 to the first nice value ≥ max (at least [0, step]). */
export function niceTicks(max: number, count = 4): number[] {
  const step = niceStep(max, count);
  const top = Math.max(step, Math.ceil(finite(max) / step - 1e-9) * step);
  const ticks: number[] = [];
  for (let i = 0; i * step <= top + step / 1e6 && ticks.length < 50; i += 1)
    ticks.push(Math.round(i * step * 1e6) / 1e6);
  return ticks;
}

/** Axis tick text of a value of the unit. */
export function tickText(value: number, unit: ValueUnit): string {
  if (unit === 'percent') return `${Math.round(finite(value) * 100)}%`;
  if (unit === 'duration') return value === 0 ? '0' : fmtDuration(value);
  const v = finite(value);
  if (v >= 1_000_000) return `${Math.round(v / 100_000) / 10}M`;
  if (v >= 10_000) return `${Math.round(v / 100) / 10}k`;
  return fmtNumber(v) === '0' && v > 0 ? String(Math.round(v * 100) / 100) : fmtNumber(v);
}

/** A value of the unit as legend / table text. */
export function valueText(value: number | null, unit: ValueUnit): string {
  if (value === null) return 'n/a';
  if (unit === 'percent') return `${(Math.round(finite(value) * 1000) / 10).toFixed(1)}%`;
  if (unit === 'duration') return fmtDuration(value);
  return fmtNumber(value);
}

/** An x-axis label of a bucket start: `HH:mm` (hourly; `MMM d` at midnight) or `MMM d`. */
export function bucketLabel(iso: string, granularity: ReportGranularity): string {
  if (granularity === 'day') return fmtUtc(iso, 'day');
  const time = fmtUtc(iso, 'time');
  return time === '00:00' ? fmtUtc(iso, 'day') : time;
}

/** Indexes of at most `max` evenly spaced labels (always the first; the last when it fits). */
export function labelIndexes(count: number, max = X_LABELS_MAX): number[] {
  if (count <= 0) return [];
  const step = Math.max(1, Math.ceil(count / max));
  const out: number[] = [];
  for (let i = 0; i < count; i += step) out.push(i);
  return out;
}

// ---------------------------------------------------------------------------------------------
// Shared pieces
// ---------------------------------------------------------------------------------------------

function open(kind: keyof typeof VIEWBOX, id: string, title: string, desc: string): string {
  const box = VIEWBOX[kind];
  const sid = safeId(id);
  return (
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${box.width} ${box.height}" class="chart-svg chart-${kind}" role="img" aria-labelledby="${sid}-title ${sid}-desc" focusable="false">` +
    `<title id="${sid}-title">${escapeHtml(title)}</title><desc id="${sid}-desc">${escapeHtml(desc)}</desc>`
  );
}

const text = (
  x: number,
  y: number,
  content: string,
  attrs: {
    anchor?: 'start' | 'middle' | 'end';
    size?: number;
    weight?: 'bold';
    fill?: string;
  } = {},
): string =>
  `<text x="${coord(x)}" y="${coord(y)}" ${FONT}="${attrs.size ?? 11}"${attrs.anchor ? ` text-anchor="${attrs.anchor}"` : ''}${attrs.weight ? ` font-weight="${attrs.weight}"` : ''} fill="${attrs.fill ?? CHROME.muted}">${escapeHtml(content)}</text>`;

const line = (x1: number, y1: number, x2: number, y2: number, stroke: string): string =>
  `<line x1="${coord(x1)}" y1="${coord(y1)}" x2="${coord(x2)}" y2="${coord(y2)}" stroke="${stroke}" stroke-width="1"/>`;

/** True when a chart has nothing to draw (the renderer shows "No data in this period"). */
export function isEmptyChart(spec: ChartSpec): boolean {
  switch (spec.kind) {
    case 'timeseries':
      return (
        spec.x.length === 0 ||
        !spec.series.some((s) => s.values.some((v) => v !== null && finite(v) > 0))
      );
    case 'donut':
      return !spec.slices.some((s) => finite(s.value) > 0);
    case 'bar':
      return !spec.bars.some((b) => finite(b.value) > 0);
    case 'histogram':
      return !spec.bins.some((b) => finite(b.count) > 0);
  }
}

// ---------------------------------------------------------------------------------------------
// Line / stacked area
// ---------------------------------------------------------------------------------------------

const TS = { left: 56, right: 14, top: 12, bottom: 30 } as const;

/** Per bucket, the stacked tops of each series (nulls count as 0). */
export function stackSeries(series: TimeSeriesSpec['series'], length: number): number[][] {
  const out: number[][] = [];
  const running = new Array<number>(length).fill(0);
  for (const s of series) {
    for (let i = 0; i < length; i += 1)
      running[i] = running[i]! + Math.max(0, finite(s.values[i] ?? 0));
    out.push([...running]);
  }
  return out;
}

export function renderTimeSeries(spec: TimeSeriesSpec): string {
  const { width, height } = VIEWBOX.timeseries;
  const plotW = width - TS.left - TS.right;
  const plotH = height - TS.top - TS.bottom;
  const n = spec.x.length;
  const stacks = spec.stacked ? stackSeries(spec.series, n) : null;
  const max = stacks
    ? Math.max(0, ...(stacks[stacks.length - 1] ?? [0]))
    : Math.max(0, ...spec.series.flatMap((s) => s.values.map((v) => (v === null ? 0 : finite(v)))));
  const ticks = spec.unit === 'percent' ? [0, 0.25, 0.5, 0.75, 1] : niceTicks(max === 0 ? 1 : max);
  const top = ticks[ticks.length - 1]!;
  const xAt = (i: number) => TS.left + (n <= 1 ? plotW / 2 : (i * plotW) / (n - 1));
  const yAt = (v: number) => TS.top + plotH - (Math.min(finite(v), top) / top) * plotH;

  const parts: string[] = [];
  for (const tick of ticks) {
    const y = yAt(tick);
    parts.push(line(TS.left, y, width - TS.right, y, tick === 0 ? CHROME.axis : CHROME.grid));
    parts.push(text(TS.left - 6, y + 4, tickText(tick, spec.unit), { anchor: 'end', size: 10 }));
  }
  for (const i of labelIndexes(n)) {
    const x = xAt(i);
    const anchor = n > 1 && i === 0 ? 'start' : 'middle';
    parts.push(
      text(x, height - 10, bucketLabel(spec.x[i] ?? '', spec.granularity), { anchor, size: 10 }),
    );
  }

  if (stacks) {
    spec.series.forEach((s, k) => {
      const upper = stacks[k]!;
      const lower = k === 0 ? new Array<number>(n).fill(0) : stacks[k - 1]!;
      if (n === 0) return;
      const forward = upper.map((v, i) => `${coord(xAt(i))},${coord(yAt(v))}`);
      const back = lower.map((v, i) => `${coord(xAt(i))},${coord(yAt(v))}`).reverse();
      const d =
        n === 1
          ? `M${coord(xAt(0) - 4)},${coord(yAt(upper[0]!))}H${coord(xAt(0) + 4)}V${coord(yAt(lower[0]!))}H${coord(xAt(0) - 4)}Z`
          : `M${forward.join('L')}L${back.join('L')}Z`;
      parts.push(
        `<path d="${d}" fill="${colorOf(s.color)}" opacity="0.85" stroke="${CHROME.surface}" stroke-width="1"/>`,
      );
    });
  } else {
    for (const s of spec.series) {
      let d = '';
      let pen = false;
      s.values.forEach((v, i) => {
        if (v === null) {
          pen = false;
          return;
        }
        d += `${pen ? 'L' : 'M'}${coord(xAt(i))},${coord(yAt(v))}`;
        pen = true;
      });
      if (d)
        parts.push(`<path d="${d}" fill="none" stroke="${colorOf(s.color)}" stroke-width="2"/>`);
      if (n <= 2)
        s.values.forEach((v, i) => {
          if (v !== null)
            parts.push(
              `<circle cx="${coord(xAt(i))}" cy="${coord(yAt(v))}" r="4" fill="${colorOf(s.color)}" stroke="${CHROME.surface}" stroke-width="2"/>`,
            );
        });
    }
  }

  const first = spec.x[0];
  const last = spec.x[n - 1];
  const totals = spec.series
    .map((s) => {
      const present = s.values.filter((v): v is number => v !== null);
      const value =
        spec.unit === 'count'
          ? `total ${fmtNumber(present.reduce((a, b) => a + finite(b), 0))}`
          : `peak ${valueText(present.length ? Math.max(...present.map(finite)) : null, spec.unit)}`;
      return `${s.name} ${value}`;
    })
    .join('; ');
  const desc = `${spec.stacked ? 'Stacked area' : 'Line'} chart of ${n} ${spec.granularity === 'hour' ? 'hourly' : 'daily'} buckets${
    first && last ? ` from ${fmtUtc(first)} to ${fmtUtc(last)}` : ''
  }: ${totals}.`;
  return `${open('timeseries', spec.id, spec.title, desc)}<g>${parts.join('')}</g></svg>`;
}

// ---------------------------------------------------------------------------------------------
// Donut
// ---------------------------------------------------------------------------------------------

const DONUT = { cx: 110, cy: 110, outer: 100, inner: 62 } as const;

const polar = (radius: number, angle: number) => ({
  x: DONUT.cx + radius * Math.cos(angle),
  y: DONUT.cy + radius * Math.sin(angle),
});

/** The path of a donut slice from `start` to `end` (radians, 0 = 3 o'clock, clockwise). */
export function arcPath(start: number, end: number): string {
  const large = end - start > Math.PI ? 1 : 0;
  const a = polar(DONUT.outer, start);
  const b = polar(DONUT.outer, end);
  const c = polar(DONUT.inner, end);
  const d = polar(DONUT.inner, start);
  return (
    `M${coord(a.x)},${coord(a.y)}A${DONUT.outer},${DONUT.outer} 0 ${large} 1 ${coord(b.x)},${coord(b.y)}` +
    `L${coord(c.x)},${coord(c.y)}A${DONUT.inner},${DONUT.inner} 0 ${large} 0 ${coord(d.x)},${coord(d.y)}Z`
  );
}

export function renderDonut(spec: DonutSpec): string {
  const slices = spec.slices.filter((s) => finite(s.value) > 0);
  const total = slices.reduce((sum, s) => sum + finite(s.value), 0);
  const parts: string[] = [];
  let angle = -Math.PI / 2;
  for (const slice of slices) {
    const sweep = (finite(slice.value) / total) * Math.PI * 2;
    const fill = colorOf(slice.color);
    const attrs = `fill="${fill}" stroke="${CHROME.surface}" stroke-width="2"`;
    if (slices.length === 1) {
      parts.push(`<path d="${arcPath(angle, angle + Math.PI)}" ${attrs}/>`);
      parts.push(`<path d="${arcPath(angle + Math.PI, angle + 2 * Math.PI)}" ${attrs}/>`);
    } else parts.push(`<path d="${arcPath(angle, angle + sweep)}" ${attrs}/>`);
    angle += sweep;
  }
  parts.push(
    text(DONUT.cx, DONUT.cy + 4, fmtNumber(total), {
      anchor: 'middle',
      size: 22,
      weight: 'bold',
      fill: CHROME.ink,
    }),
  );
  parts.push(text(DONUT.cx, DONUT.cy + 22, 'total', { anchor: 'middle', size: 11 }));
  const largest = slices[0];
  const desc = `Donut chart, total ${fmtNumber(total)}${
    largest
      ? `; largest ${largest.label} ${fmtNumber(largest.value)} (${fmtShare(largest.value, total)})`
      : ''
  }; ${slices.length} categor${slices.length === 1 ? 'y' : 'ies'}.`;
  return `${open('donut', spec.id, spec.title, desc)}<g>${parts.join('')}</g></svg>`;
}

// ---------------------------------------------------------------------------------------------
// Horizontal bars
// ---------------------------------------------------------------------------------------------

const BAR = {
  labelRight: 196,
  barLeft: 204,
  barRight: 574,
  top: 8,
  slot: 28,
  thickness: 16,
} as const;

export function renderBars(spec: BarSpec): string {
  const rows = spec.bars.slice(0, 10);
  const max = Math.max(0, ...rows.map((b) => finite(b.value)));
  const span = BAR.barRight - BAR.barLeft;
  const scale = max > 0 ? span / max : 0;
  const parts: string[] = [
    line(BAR.barLeft, BAR.top - 4, BAR.barLeft, BAR.top + rows.length * BAR.slot, CHROME.axis),
  ];
  rows.forEach((bar, i) => {
    const y = BAR.top + i * BAR.slot + (BAR.slot - BAR.thickness) / 2;
    parts.push(
      text(BAR.labelRight, y + BAR.thickness / 2 + 4, sanitizeText(bar.label, BAR_LABEL_CHARS), {
        anchor: 'end',
        size: 11,
        fill: CHROME.secondary,
      }),
    );
    const value = Math.max(0, finite(bar.value));
    const width = value * scale;
    if (spec.segments.length > 0 && bar.parts) {
      let x = BAR.barLeft;
      bar.parts.forEach((part, k) => {
        const w = Math.max(0, finite(part)) * scale;
        if (w <= 0) return;
        const segment = spec.segments[k];
        parts.push(
          `<rect x="${coord(x)}" y="${coord(y)}" width="${coord(w)}" height="${BAR.thickness}" fill="${colorOf(segment ? segment.color : 'other')}" stroke="${CHROME.surface}" stroke-width="1"/>`,
        );
        x += w;
      });
    } else if (width > 0)
      parts.push(
        `<rect x="${BAR.barLeft}" y="${coord(y)}" width="${coord(width)}" height="${BAR.thickness}" fill="${colorOf(spec.color ?? 0)}"/>`,
      );
    parts.push(
      text(BAR.barLeft + width + 6, y + BAR.thickness / 2 + 4, valueText(value, spec.unit), {
        size: 11,
        fill: CHROME.ink,
      }),
    );
  });
  const top = rows.reduce<(typeof rows)[number] | null>(
    (best, bar) => (best === null || finite(bar.value) > finite(best.value) ? bar : best),
    null,
  );
  const desc = `Bar chart of ${rows.length} item${rows.length === 1 ? '' : 's'}${
    top ? `; highest ${top.label} ${valueText(top.value, spec.unit)}` : ''
  }.`;
  return `${open('bar', spec.id, spec.title, desc)}<g>${parts.join('')}</g></svg>`;
}

// ---------------------------------------------------------------------------------------------
// Vertical histogram
// ---------------------------------------------------------------------------------------------

const HIST = { left: 52, right: 8, top: 12, bottom: 34 } as const;

export function renderHistogram(spec: HistogramSpec): string {
  const { width, height } = VIEWBOX.histogram;
  const plotW = width - HIST.left - HIST.right;
  const plotH = height - HIST.top - HIST.bottom;
  const n = spec.bins.length;
  const max = Math.max(0, ...spec.bins.map((b) => finite(b.count)));
  const ticks = niceTicks(max === 0 ? 1 : max);
  const top = ticks[ticks.length - 1]!;
  const band = n > 0 ? plotW / n : plotW;
  const barW = band * 0.72;
  const yAt = (v: number) => HIST.top + plotH - (Math.min(finite(v), top) / top) * plotH;
  const parts: string[] = [];
  for (const tick of ticks) {
    const y = yAt(tick);
    parts.push(line(HIST.left, y, width - HIST.right, y, tick === 0 ? CHROME.axis : CHROME.grid));
    parts.push(text(HIST.left - 6, y + 4, tickText(tick, 'count'), { anchor: 'end', size: 10 }));
  }
  const size = n > 8 ? 9 : 10;
  spec.bins.forEach((bin, i) => {
    const x = HIST.left + i * band + (band - barW) / 2;
    const y = yAt(bin.count);
    const h = HIST.top + plotH - y;
    if (h > 0)
      parts.push(
        `<rect x="${coord(x)}" y="${coord(y)}" width="${coord(barW)}" height="${coord(h)}" fill="${colorOf(0)}"/>`,
      );
    parts.push(
      text(HIST.left + i * band + band / 2, height - 14, sanitizeText(bin.label, 12), {
        anchor: 'middle',
        size,
      }),
    );
  });
  const total = spec.bins.reduce((sum, b) => sum + finite(b.count), 0);
  const desc = `Histogram of ${fmtNumber(total)} values in ${n} bucket${n === 1 ? '' : 's'}.`;
  return `${open('histogram', spec.id, spec.title, desc)}<g>${parts.join('')}</g></svg>`;
}

/** The SVG of a chart spec. */
export function renderChart(spec: ChartSpec): string {
  switch (spec.kind) {
    case 'timeseries':
      return renderTimeSeries(spec);
    case 'donut':
      return renderDonut(spec);
    case 'bar':
      return renderBars(spec);
    case 'histogram':
      return renderHistogram(spec);
  }
}
