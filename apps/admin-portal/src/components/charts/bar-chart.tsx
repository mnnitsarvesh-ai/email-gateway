'use client';

import type { ReactNode } from 'react';
import {
  Bar,
  CartesianGrid,
  BarChart as RechartsBarChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { formatNumber } from '@/lib/format';
import { ChartFigure } from './chart-figure';
import { type ChartRow, type ChartSeries, seriesColor, summarizeSeries } from './summary';
import { ChartTooltipContent } from './tooltip-content';

const AXIS = { fontSize: 12, fill: 'var(--muted-foreground)' } as const;

/** Vertical or horizontal bars, optionally stacked (2 px surface gap between segments). */
export function BarChart({
  title,
  description,
  rows,
  categoryKey,
  categoryLabel = 'Category',
  series,
  layout = 'vertical',
  stacked = false,
  formatCategory = String,
  formatValue = formatNumber,
  height,
  className,
}: {
  title: string;
  description?: ReactNode;
  rows: readonly ChartRow[];
  categoryKey: string;
  categoryLabel?: string;
  series: readonly ChartSeries[];
  /** `vertical` = columns; `horizontal` = bars along the x axis (long category names). */
  layout?: 'vertical' | 'horizontal';
  stacked?: boolean;
  formatCategory?: (value: string | number) => string;
  formatValue?: (value: number) => string;
  height?: number;
  className?: string;
}) {
  const summary = summarizeSeries(rows, categoryKey, series, formatCategory, formatValue);
  const horizontal = layout === 'horizontal';
  return (
    <ChartFigure
      title={title}
      description={description}
      summary={summary}
      rows={rows}
      xKey={categoryKey}
      xLabel={categoryLabel}
      series={series}
      formatX={formatCategory}
      formatValue={formatValue}
      height={height ?? (horizontal ? Math.max(160, rows.length * 32 + 40) : 240)}
      className={className}
    >
      {({ activeIndex }) => (
        <ResponsiveContainer width="100%" height="100%">
          <RechartsBarChart
            data={rows}
            layout={horizontal ? 'vertical' : 'horizontal'}
            accessibilityLayer={false}
            margin={{ top: 8, right: 8, bottom: 0, left: 0 }}
            barCategoryGap="25%"
          >
            <CartesianGrid
              vertical={horizontal}
              horizontal={!horizontal}
              stroke="var(--chart-grid)"
            />
            {horizontal ? (
              <>
                <XAxis
                  type="number"
                  tickFormatter={formatValue}
                  tick={AXIS}
                  tickLine={false}
                  axisLine={false}
                  allowDecimals={false}
                />
                <YAxis
                  type="category"
                  dataKey={categoryKey}
                  tickFormatter={formatCategory}
                  tick={AXIS}
                  tickLine={false}
                  axisLine={false}
                  width={140}
                />
              </>
            ) : (
              <>
                <XAxis
                  dataKey={categoryKey}
                  tickFormatter={formatCategory}
                  tick={AXIS}
                  tickLine={false}
                  axisLine={false}
                />
                <YAxis
                  tickFormatter={formatValue}
                  tick={AXIS}
                  tickLine={false}
                  axisLine={false}
                  width={48}
                  allowDecimals={false}
                />
              </>
            )}
            <Tooltip
              cursor={{ fill: 'var(--muted)' }}
              {...(activeIndex !== null ? { active: true, defaultIndex: activeIndex } : {})}
              content={<ChartTooltipContent formatX={formatCategory} formatValue={formatValue} />}
            />
            {series.map((s, index) => (
              <Bar
                key={s.key}
                dataKey={s.key}
                name={s.label}
                stackId={stacked ? 'stack' : undefined}
                fill={seriesColor(index)}
                stroke="var(--card)"
                strokeWidth={stacked ? 2 : 0}
                radius={
                  stacked && index < series.length - 1
                    ? 0
                    : horizontal
                      ? [0, 4, 4, 0]
                      : [4, 4, 0, 0]
                }
                isAnimationActive={false}
              />
            ))}
          </RechartsBarChart>
        </ResponsiveContainer>
      )}
    </ChartFigure>
  );
}
