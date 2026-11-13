'use client';

import type { ReactNode } from 'react';

interface Payload {
  readonly name?: string | number;
  readonly value?: unknown;
  readonly color?: string;
  readonly dataKey?: unknown;
}

/** Tooltip body in text tokens (values never wear the series colour; a swatch carries identity). */
export function ChartTooltipContent({
  active,
  payload,
  label,
  formatX,
  formatValue,
}: {
  active?: boolean;
  payload?: readonly Payload[];
  label?: ReactNode;
  formatX: (value: string | number) => string;
  formatValue: (value: number) => string;
}) {
  if (!active || !payload || payload.length === 0) return null;
  return (
    <div className="grid gap-1 rounded-md border bg-popover px-3 py-2 text-xs text-popover-foreground shadow-sm">
      {label !== undefined && label !== null ? (
        <p className="font-medium">
          {typeof label === 'string' || typeof label === 'number' ? formatX(label) : label}
        </p>
      ) : null}
      {payload.map((entry, index) => (
        <p key={index} className="flex items-center gap-2">
          <span
            aria-hidden
            className="inline-block size-2 rounded-sm"
            style={{ background: entry.color }}
          />
          <span className="text-muted-foreground">{entry.name}</span>
          <span className="ml-auto font-medium tabular-nums">
            {typeof entry.value === 'number' ? formatValue(entry.value) : 'No data'}
          </span>
        </p>
      ))}
    </div>
  );
}
