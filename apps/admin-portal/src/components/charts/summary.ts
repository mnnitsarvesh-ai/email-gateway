import { formatNumber } from '@/lib/format';

export type ChartRow = Record<string, string | number | null | undefined>;

export interface ChartSeries {
  readonly key: string;
  readonly label: string;
}

/** Categorical colour of series `index` (fixed order, never cycled past 8: fold into "Other"). */
export function seriesColor(index: number): string {
  return `var(--chart-${(index % 8) + 1})`;
}

function rowTotal(row: ChartRow, series: readonly ChartSeries[]): number | null {
  let total = 0;
  let any = false;
  for (const s of series) {
    const value = row[s.key];
    if (typeof value === 'number' && Number.isFinite(value)) {
      total += value;
      any = true;
    }
  }
  return any ? total : null;
}

/**
 * Text summary for `aria-label` (design P13): total, peak and trend, computed from the data
 * the chart draws. Missing values are skipped, never counted as zero.
 */
export function summarizeSeries(
  rows: readonly ChartRow[],
  xKey: string,
  series: readonly ChartSeries[],
  formatX: (value: string | number) => string = String,
  formatValue: (value: number) => string = formatNumber,
): string {
  const totals = rows.map((row) => rowTotal(row, series));
  const present = totals.filter((t): t is number => t !== null);
  if (present.length === 0) return 'No data in this range.';
  const sum = present.reduce((a, b) => a + b, 0);
  let peakIndex = 0;
  totals.forEach((t, i) => {
    if (t !== null && t > (totals[peakIndex] ?? -Infinity)) peakIndex = i;
  });
  const peakX = rows[peakIndex]?.[xKey];
  const first = present[0] ?? 0;
  const last = present[present.length - 1] ?? 0;
  const trend = present.length < 2 || first === last ? 'flat' : last > first ? 'rising' : 'falling';
  const bySeries = series
    .map((s) => ({
      label: s.label,
      total: rows.reduce(
        (acc, row) => acc + (typeof row[s.key] === 'number' ? (row[s.key] as number) : 0),
        0,
      ),
    }))
    .sort((a, b) => b.total - a.total)
    .slice(0, 3)
    .filter((s) => s.total > 0)
    .map((s) => `${s.label} ${formatValue(s.total)}`);
  return [
    `Total ${formatValue(sum)} across ${rows.length} ${rows.length === 1 ? 'point' : 'points'}.`,
    peakX !== undefined && peakX !== null
      ? `Peak ${formatValue(totals[peakIndex] ?? 0)} at ${formatX(peakX)}.`
      : '',
    `Trend ${trend}.`,
    series.length > 1 && bySeries.length > 0 ? `Largest: ${bySeries.join(', ')}.` : '',
  ]
    .filter(Boolean)
    .join(' ');
}
