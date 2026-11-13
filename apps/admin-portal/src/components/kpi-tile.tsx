'use client';

import { InfoIcon } from 'lucide-react';
import Link from 'next/link';
import type { ReactNode } from 'react';
import { DateTime } from '@/components/domain/date-time';
import { ErrorState } from '@/components/states/error-state';
import { Card } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { formatNumber } from '@/lib/format';
import { cn } from '@/lib/utils';

/**
 * One reported number (design P13): value, label, definition tooltip, `generatedAt`, link to
 * the detailed page. `value === null` shows `emptyText` (the API returned no value for the
 * range); the tile never invents a number. Loading and error are built in.
 */
export function KpiTile({
  label,
  value,
  format = formatNumber,
  definition,
  subtitle,
  generatedAt,
  href,
  hrefLabel = 'View details',
  loading = false,
  error,
  onRetry,
  emptyText = 'No data in this range',
  icon,
  className,
}: {
  label: string;
  value: number | null | undefined;
  format?: (value: number) => string;
  definition?: string;
  subtitle?: ReactNode;
  generatedAt?: string | null;
  href?: string;
  hrefLabel?: string;
  loading?: boolean;
  error?: unknown;
  onRetry?: () => void;
  emptyText?: string;
  icon?: ReactNode;
  className?: string;
}) {
  return (
    <Card className={cn('gap-2 px-4 py-4', className)} aria-busy={loading || undefined}>
      <div className="flex items-center justify-between gap-2">
        <h3 className="flex items-center gap-1.5 text-sm font-medium text-muted-foreground">
          {icon}
          {label}
        </h3>
        {definition ? (
          <Tooltip>
            <TooltipTrigger asChild>
              <button
                type="button"
                className="inline-flex size-6 items-center justify-center rounded-sm text-muted-foreground hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
                aria-label={`Definition of ${label}`}
              >
                <InfoIcon className="size-3.5" aria-hidden />
              </button>
            </TooltipTrigger>
            <TooltipContent>{definition}</TooltipContent>
          </Tooltip>
        ) : null}
      </div>
      {loading ? (
        <div role="status" className="grid gap-2">
          <span className="sr-only">Loading {label} …</span>
          <Skeleton className="h-8 w-28" />
          <Skeleton className="h-3 w-20" />
        </div>
      ) : error ? (
        <ErrorState error={error} onRetry={onRetry} compact className="border-0 p-0" />
      ) : value === null || value === undefined ? (
        <p className="py-1 text-sm text-muted-foreground">{emptyText}</p>
      ) : (
        <p className="text-3xl font-semibold tracking-tight tabular-nums">{format(value)}</p>
      )}
      {!loading && !error && subtitle ? (
        <div className="text-xs text-muted-foreground">{subtitle}</div>
      ) : null}
      <div className="mt-auto flex flex-wrap items-center justify-between gap-2 pt-1 text-xs text-muted-foreground">
        {generatedAt ? (
          <span>
            Updated <DateTime value={generatedAt} />
          </span>
        ) : (
          <span />
        )}
        {href ? (
          <Link
            href={href}
            className="font-medium text-primary hover:underline"
            aria-label={`${hrefLabel}: ${label}`}
          >
            {hrefLabel}
          </Link>
        ) : null}
      </div>
    </Card>
  );
}
