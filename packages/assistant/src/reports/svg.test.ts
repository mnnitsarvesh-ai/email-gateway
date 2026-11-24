import { describe, expect, it } from 'vitest';
import {
  coord,
  escapeHtml,
  fmtDuration,
  fmtNumber,
  fmtPercent,
  fmtUtc,
  fmtBytes,
  finite,
} from './escape';
import { CATEGORICAL_PALETTE, SEMANTIC_COLORS, colorOf, swatchClass } from './palette';
import {
  VIEWBOX,
  bucketLabel,
  isEmptyChart,
  labelIndexes,
  niceStep,
  niceTicks,
  renderBars,
  renderChart,
  renderDonut,
  renderHistogram,
  renderTimeSeries,
  stackSeries,
} from './svg';
import type { BarSpec, DonutSpec, HistogramSpec, TimeSeriesSpec } from './types';

const X = ['2026-11-20T00:00:00.000Z', '2026-11-21T00:00:00.000Z', '2026-11-22T00:00:00.000Z'];

const ts = (patch: Partial<TimeSeriesSpec> = {}): TimeSeriesSpec => ({
  kind: 'timeseries',
  id: 'chart-test',
  title: 'Test',
  x: X,
  granularity: 'day',
  stacked: false,
  unit: 'count',
  series: [
    { name: 'A', color: 0, values: [1, 2, 3] },
    { name: 'B', color: 'spam', values: [4, null, 6] },
  ],
  ...patch,
});

/** Every number in the attribute values has at most 2 decimals. */
const coordinates = (svg: string): string[] =>
  [...svg.matchAll(/(?:x|y|x1|y1|x2|y2|cx|cy|r|width|height|d|points)="([^"]*)"/g)].flatMap(
    (m) => m[1]!.match(/-?\d+(?:\.\d+)?/g) ?? [],
  );

describe('formatting and escaping (design D4)', () => {
  it('escapes & < > " \'', () => {
    expect(escapeHtml(`<a href="x">&'</a>`)).toBe(
      '&lt;a href=&quot;x&quot;&gt;&amp;&#39;&lt;/a&gt;',
    );
  });

  it('formats numbers, percentages, durations, bytes and UTC instants deterministically', () => {
    expect(fmtNumber(1248.4)).toBe('1,248');
    expect(fmtNumber(Number.NaN)).toBe('0');
    expect(fmtNumber('12')).toBe('0');
    expect(fmtPercent(0.9856)).toBe('98.6%');
    expect(fmtPercent(null)).toBe('n/a');
    expect(fmtPercent(Number.POSITIVE_INFINITY)).toBe('n/a');
    expect([250, 1500, 90_000, 4 * 3_600_000, 86_400_000, -5].map(fmtDuration)).toEqual([
      '250 ms',
      '1.5 s',
      '1.5 min',
      '4 h',
      '1 d',
      '0 ms',
    ]);
    expect(fmtDuration(null)).toBe('n/a');
    expect([812, 12_595, 1_258_291].map(fmtBytes)).toEqual(['812 B', '12.3 KiB', '1.2 MiB']);
    expect(fmtUtc('2026-11-16T09:05:00Z')).toBe('Nov 16, 2026 09:05 UTC');
    expect(fmtUtc('2026-11-16T09:05:00+05:30', 'time')).toBe('03:35');
    expect(fmtUtc('2026-11-16T09:05:00Z', 'date')).toBe('Nov 16, 2026');
    expect(fmtUtc('2026-11-16T09:05:00Z', 'day')).toBe('Nov 16');
    expect(fmtUtc('<script>')).toBe('n/a');
    expect(coord(12.3456)).toBe('12.35');
    expect(coord(-0.001)).toBe('0');
    expect(coord(Number.NaN)).toBe('0');
    expect(finite(Number.NEGATIVE_INFINITY)).toBe(0);
  });
});

describe('palette (design D4)', () => {
  it('is a fixed 8-color categorical palette plus semantic verdict colors, chosen by index or key', () => {
    expect(CATEGORICAL_PALETTE).toHaveLength(8);
    expect(new Set(CATEGORICAL_PALETTE).size).toBe(8);
    for (const hex of [...CATEGORICAL_PALETTE, ...Object.values(SEMANTIC_COLORS)])
      expect(hex).toMatch(/^#[0-9a-f]{6}$/);
    expect(colorOf(3)).toBe(CATEGORICAL_PALETTE[3]);
    expect(colorOf(8)).toBe(SEMANTIC_COLORS.other);
    expect(colorOf(-1)).toBe(SEMANTIC_COLORS.other);
    expect(colorOf(1.5)).toBe(SEMANTIC_COLORS.other);
    expect(colorOf('phishing')).toBe(SEMANTIC_COLORS.phishing);
    expect(colorOf('__proto__' as never)).toBe(SEMANTIC_COLORS.other);
    expect(swatchClass(2)).toBe('sw-c2');
    expect(swatchClass('toString' as never)).toBe('sw-other');
  });

  it('threat colors are warm and distinct from the neutral clean color', () => {
    expect(SEMANTIC_COLORS.clean).not.toBe(SEMANTIC_COLORS.phishing);
    expect(
      new Set([SEMANTIC_COLORS.spam, SEMANTIC_COLORS.phishing, SEMANTIC_COLORS.malware]).size,
    ).toBe(3);
  });
});

describe('scales', () => {
  it('nice steps and ticks', () => {
    expect(niceStep(0)).toBe(1);
    expect(niceStep(100)).toBe(25);
    expect(niceStep(7)).toBe(2);
    expect(niceTicks(0)).toEqual([0, 1]);
    expect(niceTicks(1)).toEqual([0, 0.25, 0.5, 0.75, 1]);
    expect(niceTicks(9)).toEqual([0, 2.5, 5, 7.5, 10]);
    expect(niceTicks(1234)).toEqual([0, 500, 1000, 1500]);
    expect(niceTicks(Number.NaN)).toEqual([0, 1]);
    for (const max of [3, 17, 99, 101, 5000, 123_456]) {
      const ticks = niceTicks(max);
      expect(ticks[ticks.length - 1]).toBeGreaterThanOrEqual(max);
      expect(ticks.length).toBeLessThanOrEqual(7);
    }
  });

  it('stacks series per bucket (nulls count as 0)', () => {
    expect(stackSeries(ts().series, 3)).toEqual([
      [1, 2, 3],
      [5, 2, 9],
    ]);
  });

  it('x labels: UTC days, hours, midnight as the day; at most 6 labels', () => {
    expect(bucketLabel('2026-11-20T00:00:00Z', 'day')).toBe('Nov 20');
    expect(bucketLabel('2026-11-20T13:00:00Z', 'hour')).toBe('13:00');
    expect(bucketLabel('2026-11-20T00:00:00Z', 'hour')).toBe('Nov 20');
    expect(labelIndexes(0)).toEqual([]);
    expect(labelIndexes(3)).toEqual([0, 1, 2]);
    expect(labelIndexes(24).length).toBeLessThanOrEqual(6);
  });
});

describe('chart primitives', () => {
  it('line chart: fixed viewBox, role img, title and desc, 2-decimal coordinates, gaps for nulls', () => {
    const svg = renderTimeSeries(ts());
    expect(svg.startsWith('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 260"')).toBe(
      true,
    );
    expect(svg).toContain('role="img" aria-labelledby="chart-test-title chart-test-desc"');
    expect(svg).toContain('<title id="chart-test-title">Test</title>');
    expect(svg).toContain(
      '<desc id="chart-test-desc">Line chart of 3 daily buckets from Nov 20, 2026 00:00 UTC to Nov 22, 2026 00:00 UTC: A total 6; B total 10.</desc>',
    );
    const paths = [...svg.matchAll(/<path d="([^"]+)"/g)].map((m) => m[1]!);
    expect(paths).toHaveLength(2);
    expect(paths[1]!.match(/M/g)).toHaveLength(2); // the null splits series B
    for (const n of coordinates(svg)) expect(n).toMatch(/^-?\d+(\.\d{1,2})?$/);
  });

  it('stacked area: the top series reaches the stacked total', () => {
    const svg = renderTimeSeries(ts({ stacked: true }));
    expect(svg).toContain('Stacked area chart');
    expect([...svg.matchAll(/<path d="M[^"]+Z"/g)]).toHaveLength(2);
  });

  it('percent axis is 0–100 %; single-bucket series still render', () => {
    const svg = renderTimeSeries(
      ts({ unit: 'percent', series: [{ name: 'Rate', color: 'good', values: [0.5] }], x: [X[0]!] }),
    );
    expect(svg).toContain('>100%</text>');
    expect(svg).toContain('<circle');
    expect(svg).toContain('peak 50.0%');
  });

  it('donut: centre total, one ring for a single slice, legend data in desc', () => {
    const spec: DonutSpec = {
      kind: 'donut',
      id: 'chart-donut',
      title: 'Mix',
      slices: [
        { label: 'Clean', value: 90, color: 'clean' },
        { label: 'Spam', value: 10, color: 'spam' },
      ],
    };
    const svg = renderDonut(spec);
    expect(svg).toContain(`viewBox="0 0 ${VIEWBOX.donut.width} ${VIEWBOX.donut.height}"`);
    expect(svg).toContain('>100</text>');
    expect(svg).toContain('largest Clean 90 (90.0%); 2 categories.');
    expect([...svg.matchAll(/<path /g)]).toHaveLength(2);
    const single = renderDonut({ ...spec, slices: [{ label: 'Only', value: 5, color: 0 }] });
    expect([...single.matchAll(/<path /g)]).toHaveLength(2); // two half arcs
  });

  it('bars: at most 10, value labels, labels capped, stacked segments', () => {
    const spec: BarSpec = {
      kind: 'bar',
      id: 'chart-bars',
      title: 'Bars',
      unit: 'count',
      segments: [],
      bars: Array.from({ length: 12 }, (_, i) => ({
        label: `item-${'x'.repeat(i * 4)}`,
        value: 12 - i,
      })),
    };
    const svg = renderBars(spec);
    expect([...svg.matchAll(/<rect /g)]).toHaveLength(10);
    expect(svg).toContain('Bar chart of 10 items; highest item- 12.');
    const labels = [...svg.matchAll(/fill="#52514e">([^<]*)<\/text>/g)].map((m) => m[1]!);
    for (const label of labels) expect(Array.from(label).length).toBeLessThanOrEqual(30);
    const stacked = renderBars({
      ...spec,
      segments: [
        { name: 'A', color: 0 },
        { name: 'B', color: 1 },
      ],
      bars: [{ label: 'd', value: 5, parts: [3, 2] }],
    });
    expect([...stacked.matchAll(/<rect /g)]).toHaveLength(2);
  });

  it('histogram: bucket labels and counts', () => {
    const spec: HistogramSpec = {
      kind: 'histogram',
      id: 'chart-hist',
      title: 'Latency',
      bins: [
        { label: '≤ 1 s', count: 5 },
        { label: '> 1 s', count: 1 },
      ],
    };
    const svg = renderHistogram(spec);
    expect(svg).toContain('>≤ 1 s</text>');
    expect(svg).toContain('Histogram of 6 values in 2 buckets.');
  });

  it('finite-number guard: NaN and Infinity never reach an attribute', () => {
    const svg = renderChart(
      ts({ series: [{ name: 'A', color: 0, values: [Number.NaN, Number.POSITIVE_INFINITY, 2] }] }),
    );
    expect(svg).not.toMatch(/NaN|Infinity/);
    const bars = renderBars({
      kind: 'bar',
      id: 'b',
      title: 'b',
      unit: 'count',
      segments: [],
      bars: [{ label: 'x', value: Number.NaN }],
    });
    expect(bars).not.toMatch(/NaN|Infinity/);
    expect(
      isEmptyChart({
        kind: 'donut',
        id: 'd',
        title: 'd',
        slices: [{ label: 'x', value: Number.NaN, color: 0 }],
      }),
    ).toBe(true);
    expect(isEmptyChart(ts({ x: [] }))).toBe(true);
    expect(isEmptyChart(ts())).toBe(false);
  });

  it('unsafe ids fall back to a constant', () => {
    expect(renderTimeSeries(ts({ id: '"><x' }))).toContain(
      'aria-labelledby="chart-title chart-desc"',
    );
  });
});
