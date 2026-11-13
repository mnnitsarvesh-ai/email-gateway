'use client';

import { TableIcon } from 'lucide-react';
import { useId, useState, type KeyboardEvent, type ReactNode } from 'react';
import { Button } from '@/components/ui/button';
import { formatNumber } from '@/lib/format';
import { cn } from '@/lib/utils';
import type { ChartRow, ChartSeries } from './summary';
import { seriesColor } from './summary';

export interface ChartRenderState {
  /** Index of the keyboard-selected point (`null` when none). */
  readonly activeIndex: number | null;
}

/**
 * Accessible chart frame (design P13): `<figure>` + `<figcaption>`, the chart region with
 * `role="img"` and a computed `aria-label`, keyboard focus with arrow keys moving the active
 * point (its values are read out below the chart), text legend, and a "View data as table"
 * toggle rendering a real captioned table.
 */
export function ChartFigure({
  title,
  description,
  summary,
  rows,
  xKey,
  xLabel,
  series,
  formatX = String,
  formatValue = formatNumber,
  height = 240,
  children,
  className,
  legend = true,
}: {
  title: string;
  description?: ReactNode;
  summary: string;
  rows: readonly ChartRow[];
  xKey: string;
  xLabel: string;
  series: readonly ChartSeries[];
  formatX?: (value: string | number) => string;
  formatValue?: (value: number) => string;
  height?: number;
  children: (state: ChartRenderState) => ReactNode;
  className?: string;
  legend?: boolean;
}) {
  const [showTable, setShowTable] = useState(false);
  const [activeIndex, setActiveIndex] = useState<number | null>(null);
  const titleId = useId();
  const tableId = useId();

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (rows.length === 0) return;
    const last = rows.length - 1;
    let next: number | null = activeIndex;
    if (event.key === 'ArrowRight' || event.key === 'ArrowDown')
      next = activeIndex === null ? 0 : Math.min(last, activeIndex + 1);
    else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp')
      next = activeIndex === null ? last : Math.max(0, activeIndex - 1);
    else if (event.key === 'Home') next = 0;
    else if (event.key === 'End') next = last;
    else if (event.key === 'Escape') next = null;
    else return;
    event.preventDefault();
    setActiveIndex(next);
  };

  const active = activeIndex !== null ? rows[activeIndex] : undefined;
  const xText = (value: unknown) =>
    typeof value === 'string' || typeof value === 'number' ? formatX(value) : '';
  const cell = (value: unknown) =>
    typeof value === 'number' ? formatValue(value) : typeof value === 'string' ? value : 'No data';

  return (
    <figure className={cn('flex flex-col gap-3', className)} aria-labelledby={titleId}>
      <figcaption className="flex flex-wrap items-start justify-between gap-2">
        <div className="grid gap-0.5">
          <span id={titleId} className="text-base font-semibold">
            {title}
          </span>
          {description ? (
            <span className="text-xs text-muted-foreground">{description}</span>
          ) : null}
        </div>
        <Button
          variant="ghost"
          size="sm"
          aria-expanded={showTable}
          aria-controls={tableId}
          onClick={() => setShowTable((v) => !v)}
        >
          <TableIcon aria-hidden />
          {showTable ? 'Hide data table' : 'View data as table'}
        </Button>
      </figcaption>
      {/* Keyboard-operable chart region (design P13): arrow keys move the active point. */}
      {/* eslint-disable jsx-a11y/no-noninteractive-element-interactions, jsx-a11y/no-noninteractive-tabindex */}
      <div
        role="application"
        aria-roledescription="chart"
        aria-label={`${title}: use the arrow keys to read each point`}
        tabIndex={0}
        onKeyDown={onKeyDown}
        onBlur={() => setActiveIndex(null)}
        className="rounded-md outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        <div
          role="img"
          aria-label={`${title}. ${summary}`}
          className="relative w-full"
          style={{ height }}
          data-testid="chart-region"
        >
          {children({ activeIndex })}
        </div>
      </div>
      {/* eslint-enable jsx-a11y/no-noninteractive-element-interactions, jsx-a11y/no-noninteractive-tabindex */}
      <p className="min-h-4 text-xs text-muted-foreground" aria-live="polite">
        {active
          ? `${formatX(active[xKey] ?? '')}: ${series.map((s) => `${s.label} ${cell(active[s.key])}`).join(', ')}`
          : rows.length > 0
            ? 'Focus the chart and use the arrow keys to read each point.'
            : ''}
      </p>
      {legend && series.length > 1 ? (
        <ul
          className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground"
          aria-label={`${title} legend`}
        >
          {series.map((s, index) => (
            <li key={s.key} className="flex items-center gap-1.5">
              <span
                aria-hidden
                className="inline-block size-2.5 rounded-sm"
                style={{ background: seriesColor(index) }}
              />
              {s.label}
            </li>
          ))}
        </ul>
      ) : null}
      <div id={tableId} hidden={!showTable} className="overflow-x-auto">
        {showTable ? (
          <table className="w-full border-collapse text-sm">
            <caption className="pb-2 text-left text-xs text-muted-foreground">
              {title}: data table
            </caption>
            <thead>
              <tr className="border-b">
                <th scope="col" className="px-2 py-1 text-left text-xs font-semibold">
                  {xLabel}
                </th>
                {series.map((s) => (
                  <th
                    key={s.key}
                    scope="col"
                    className="px-2 py-1 text-right text-xs font-semibold"
                  >
                    {s.label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row, index) => (
                <tr key={index} className="border-b last:border-0">
                  <th scope="row" className="px-2 py-1 text-left font-normal">
                    {xText(row[xKey])}
                  </th>
                  {series.map((s) => (
                    <td key={s.key} className="px-2 py-1 text-right tabular-nums">
                      {cell(row[s.key])}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
      </div>
    </figure>
  );
}
