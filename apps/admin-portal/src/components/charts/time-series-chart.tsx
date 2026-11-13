'use client';

import type { ReactNode } from 'react';
import {
  Area,
  AreaChart,
  CartesianGrid,
  Line,
  LineChart,
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

/** Line or stacked area over time buckets; gaps for missing values (never invented zeros). */
export function TimeSeriesChart({
  title,
  description,
  rows,
  xKey,
  xLabel = 'Time',
  series,
  variant = 'line',
  formatX = String,
  formatValue = formatNumber,
  height,
  className,
}: {
  title: string;
  description?: ReactNode;
  rows: readonly ChartRow[];
  xKey: string;
  xLabel?: string;
  series: readonly ChartSeries[];
  variant?: 'line' | 'stacked-area';
  formatX?: (value: string | number) => string;
  formatValue?: (value: number) => string;
  height?: number;
  className?: string;
}) {
  const summary = summarizeSeries(rows, xKey, series, formatX, formatValue);
  const data = rows as ChartRow[];
  return (
    <ChartFigure
      title={title}
      description={description}
      summary={summary}
      rows={rows}
      xKey={xKey}
      xLabel={xLabel}
      series={series}
      formatX={formatX}
      formatValue={formatValue}
      height={height}
      className={className}
    >
      {({ activeIndex }) => (
        <ResponsiveContainer width="100%" height="100%">
          {variant === 'stacked-area' ? (
            <AreaChart
              data={data}
              accessibilityLayer={false}
              margin={{ top: 8, right: 8, bottom: 0, left: 0 }}
            >
              <CartesianGrid vertical={false} stroke="var(--chart-grid)" />
              <XAxis
                dataKey={xKey}
                tickFormatter={formatX}
                tick={AXIS}
                tickLine={false}
                axisLine={false}
                minTickGap={24}
              />
              <YAxis
                tickFormatter={formatValue}
                tick={AXIS}
                tickLine={false}
                axisLine={false}
                width={48}
                allowDecimals={false}
              />
              <Tooltip
                {...(activeIndex !== null ? { active: true, defaultIndex: activeIndex } : {})}
                content={<ChartTooltipContent formatX={formatX} formatValue={formatValue} />}
              />
              {series.map((s, index) => (
                <Area
                  key={s.key}
                  dataKey={s.key}
                  name={s.label}
                  stackId="stack"
                  type="monotone"
                  stroke={seriesColor(index)}
                  strokeWidth={2}
                  fill={seriesColor(index)}
                  fillOpacity={0.25}
                  isAnimationActive={false}
                  connectNulls={false}
                />
              ))}
            </AreaChart>
          ) : (
            <LineChart
              data={data}
              accessibilityLayer={false}
              margin={{ top: 8, right: 8, bottom: 0, left: 0 }}
            >
              <CartesianGrid vertical={false} stroke="var(--chart-grid)" />
              <XAxis
                dataKey={xKey}
                tickFormatter={formatX}
                tick={AXIS}
                tickLine={false}
                axisLine={false}
                minTickGap={24}
              />
              <YAxis
                tickFormatter={formatValue}
                tick={AXIS}
                tickLine={false}
                axisLine={false}
                width={48}
              />
              <Tooltip
                {...(activeIndex !== null ? { active: true, defaultIndex: activeIndex } : {})}
                content={<ChartTooltipContent formatX={formatX} formatValue={formatValue} />}
              />
              {series.map((s, index) => (
                <Line
                  key={s.key}
                  dataKey={s.key}
                  name={s.label}
                  type="monotone"
                  stroke={seriesColor(index)}
                  strokeWidth={2}
                  dot={false}
                  activeDot={{ r: 4, stroke: 'var(--card)', strokeWidth: 2 }}
                  isAnimationActive={false}
                  connectNulls={false}
                />
              ))}
            </LineChart>
          )}
        </ResponsiveContainer>
      )}
    </ChartFigure>
  );
}
