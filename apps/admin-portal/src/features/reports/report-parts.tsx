'use client';

import type { ReactNode } from 'react';
import { BarChart, type ChartRow } from '@/components/charts';
import { formatNumber } from '@/lib/format';
import { cn } from '@/lib/utils';
import { binLabel, type HistogramBin } from './report-utils';

export interface Stat {
  readonly label: string;
  readonly value: ReactNode;
  readonly hint?: ReactNode;
}

/** A row of labelled figures (definition list). */
export function StatList({ stats, className }: { stats: readonly Stat[]; className?: string }) {
  return (
    <dl className={cn('grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5', className)}>
      {stats.map((stat) => (
        <div key={stat.label} className="grid gap-0.5 rounded-md border bg-muted/40 px-3 py-2">
          <dt className="text-xs text-muted-foreground">{stat.label}</dt>
          <dd className="text-lg font-semibold tabular-nums">{stat.value}</dd>
          {stat.hint ? <dd className="text-xs text-muted-foreground">{stat.hint}</dd> : null}
        </div>
      ))}
    </dl>
  );
}

/** A simple captioned table of `label → count` pairs (marginals of a report). */
export function CountTable({
  caption,
  labelHeader,
  rows,
  valueHeader = 'Count',
}: {
  caption: string;
  labelHeader: string;
  rows: readonly { readonly key: string; readonly label: ReactNode; readonly value: number }[];
  valueHeader?: string;
}) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-sm">
        <caption className="pb-2 text-left text-sm font-semibold">{caption}</caption>
        <thead>
          <tr className="border-b text-xs text-muted-foreground">
            <th scope="col" className="px-2 py-1.5 text-left font-semibold">
              {labelHeader}
            </th>
            <th scope="col" className="px-2 py-1.5 text-right font-semibold">
              {valueHeader}
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.key} className="border-b last:border-0">
              <th scope="row" className="px-2 py-1.5 text-left font-normal">
                {row.label}
              </th>
              <td className="px-2 py-1.5 text-right tabular-nums">{formatNumber(row.value)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Latency histogram (counts per bin; the last bin is the overflow). */
export function HistogramChart({
  title,
  description,
  histogram,
}: {
  title: string;
  description?: ReactNode;
  histogram: readonly HistogramBin[];
}) {
  const rows: ChartRow[] = histogram.map((bin) => ({
    bin: binLabel(bin, histogram),
    count: bin.count,
  }));
  return (
    <BarChart
      title={title}
      description={description}
      rows={rows}
      categoryKey="bin"
      categoryLabel="Upper bound"
      series={[{ key: 'count', label: 'Samples' }]}
    />
  );
}
