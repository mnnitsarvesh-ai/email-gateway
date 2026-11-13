'use client';

import { formatDistanceToNowStrict } from 'date-fns';
import { useEffect, useState } from 'react';
import { formatUtc } from '@/lib/format';
import { cn } from '@/lib/utils';

/**
 * A timestamp: relative text ("5 minutes ago") or an absolute local date, with the absolute
 * UTC time in `title`; `<time dateTime>` for machines. `null` → "—" with "Never" for AT.
 */
export function DateTime({
  value,
  mode = 'relative',
  className,
  emptyLabel = 'Never',
}: {
  value: string | Date | null | undefined;
  mode?: 'relative' | 'absolute';
  className?: string;
  emptyLabel?: string;
}) {
  const [, setTick] = useState(0);
  useEffect(() => {
    if (mode !== 'relative') return;
    const timer = setInterval(() => setTick((t) => t + 1), 60_000);
    return () => clearInterval(timer);
  }, [mode]);
  if (!value) return <span className={cn('text-muted-foreground', className)}>{emptyLabel}</span>;
  const date = typeof value === 'string' ? new Date(value) : value;
  if (Number.isNaN(date.getTime())) {
    return <span className={cn('text-muted-foreground', className)}>{emptyLabel}</span>;
  }
  const utc = formatUtc(date);
  const text =
    mode === 'relative'
      ? formatDistanceToNowStrict(date, { addSuffix: true })
      : new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(
          date,
        );
  return (
    <time dateTime={date.toISOString()} title={utc} className={cn('whitespace-nowrap', className)}>
      {text}
    </time>
  );
}
