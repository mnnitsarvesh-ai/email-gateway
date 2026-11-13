'use client';

import type { ReactNode } from 'react';
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts';
import { formatNumber } from '@/lib/format';
import { ChartFigure } from './chart-figure';
import { seriesColor, type ChartRow } from './summary';
import { ChartTooltipContent } from './tooltip-content';

export interface DonutSlice {
  readonly label: string;
  readonly value: number;
}

/** At most 6 slices; the rest are grouped into "Other" (never a generated 9th hue). */
export function groupSlices(slices: readonly DonutSlice[], max = 6): DonutSlice[] {
  const sorted = [...slices].filter((s) => s.value > 0).sort((a, b) => b.value - a.value);
  if (sorted.length <= max) return sorted;
  const head = sorted.slice(0, max - 1);
  const rest = sorted.slice(max - 1).reduce((acc, s) => acc + s.value, 0);
  return [...head, { label: 'Other', value: rest }];
}

export function DonutChart({
  title,
  description,
  slices,
  formatValue = formatNumber,
  height = 220,
  className,
}: {
  title: string;
  description?: ReactNode;
  slices: readonly DonutSlice[];
  formatValue?: (value: number) => string;
  height?: number;
  className?: string;
}) {
  const grouped = groupSlices(slices);
  const total = grouped.reduce((acc, s) => acc + s.value, 0);
  const rows: ChartRow[] = grouped.map((s) => ({ label: s.label, value: s.value }));
  const summary =
    total === 0
      ? 'No data in this range.'
      : `Total ${formatValue(total)}. ${grouped
          .map(
            (s) => `${s.label} ${formatValue(s.value)} (${Math.round((s.value / total) * 100)} %)`,
          )
          .join(', ')}.`;
  return (
    <ChartFigure
      title={title}
      description={description}
      summary={summary}
      rows={rows}
      xKey="label"
      xLabel="Category"
      series={[{ key: 'value', label: 'Count' }]}
      formatValue={formatValue}
      height={height}
      className={className}
      legend={false}
    >
      {({ activeIndex }) => (
        <ResponsiveContainer width="100%" height="100%">
          <PieChart accessibilityLayer={false}>
            <Tooltip
              {...(activeIndex !== null ? { active: true, defaultIndex: activeIndex } : {})}
              content={<ChartTooltipContent formatX={String} formatValue={formatValue} />}
            />
            <Pie
              data={rows}
              dataKey="value"
              nameKey="label"
              innerRadius="60%"
              outerRadius="90%"
              stroke="var(--card)"
              strokeWidth={2}
              isAnimationActive={false}
            >
              {grouped.map((slice, index) => (
                <Cell key={slice.label} fill={seriesColor(index)} />
              ))}
            </Pie>
          </PieChart>
        </ResponsiveContainer>
      )}
    </ChartFigure>
  );
}

/** Text legend for a donut (label, value, share); place it next to the chart. */
export function DonutLegend({
  slices,
  formatValue = formatNumber,
}: {
  slices: readonly DonutSlice[];
  formatValue?: (value: number) => string;
}) {
  const grouped = groupSlices(slices);
  const total = grouped.reduce((acc, s) => acc + s.value, 0);
  return (
    <ul className="grid gap-1 text-xs">
      {grouped.map((slice, index) => (
        <li key={slice.label} className="flex items-center gap-2">
          <span
            aria-hidden
            className="inline-block size-2.5 rounded-sm"
            style={{ background: seriesColor(index) }}
          />
          <span>{slice.label}</span>
          <span className="ml-auto tabular-nums text-muted-foreground">
            {formatValue(slice.value)} ({total ? Math.round((slice.value / total) * 100) : 0} %)
          </span>
        </li>
      ))}
    </ul>
  );
}
