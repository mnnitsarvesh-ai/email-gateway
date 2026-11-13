'use client';

import { DownloadIcon } from 'lucide-react';
import { useEffect, useState, type ReactNode } from 'react';
import { ErrorState } from '@/components/states/error-state';
import { Button } from '@/components/ui/button';
import { useApiQuery } from '@/lib/api/hooks';
import { ApiError } from '@/lib/api/errors';
import type { OperationId, QueryParams } from '@/lib/api/types';
import { cn } from '@/lib/utils';
import { downloadCsv, toCsv, type CsvCell } from './csv';
import { reportRetry } from './report-utils';

/** A report query (reports are cached by the api; no refetch on focus; no retry of timeouts). */
export function useReport<Id extends OperationId>(
  operationId: Id,
  query: QueryParams<Id>,
  options: { enabled?: boolean } = {},
) {
  return useApiQuery(operationId, { query }, { retry: reportRetry, enabled: options.enabled });
}

function useCountdown(seconds: number | null): number {
  const [left, setLeft] = useState(seconds ?? 0);
  useEffect(() => setLeft(seconds ?? 0), [seconds]);
  useEffect(() => {
    if (left <= 0) return;
    const timer = setTimeout(() => setLeft((s) => Math.max(0, s - 1)), 1000);
    return () => clearTimeout(timer);
  }, [left]);
  return left;
}

/**
 * Error state of a report: the API error (code, requestId) plus guidance for the two report
 * specific cases: `503 report_timeout` ("narrow the range") and `429` (countdown; Retry waits).
 */
export function ReportErrorState({
  error,
  onRetry,
  compact = false,
  className,
}: {
  error: unknown;
  onRetry: () => void;
  compact?: boolean;
  className?: string;
}) {
  const apiError = error instanceof ApiError ? error : null;
  const rateLimited = apiError?.status === 429;
  const left = useCountdown(rateLimited ? (apiError?.retryAfterSeconds ?? 30) : null);
  const timedOut = apiError?.code === 'report_timeout';
  return (
    <div className={cn('grid gap-2', className)}>
      <ErrorState
        error={error}
        compact={compact}
        onRetry={rateLimited && left > 0 ? undefined : onRetry}
      />
      {timedOut ? (
        <p className="text-sm text-muted-foreground" role="note">
          The report took too long for this range. Narrow the range (for example the last 7 days or
          fewer custom days) and try again.
        </p>
      ) : null}
      {rateLimited && left > 0 ? (
        <p className="text-sm text-muted-foreground" aria-live="polite">
          Too many report requests. You can retry in {left} s.
        </p>
      ) : null}
    </div>
  );
}

/** "Download CSV" of the displayed aggregates. */
export function CsvButton({
  filename,
  header,
  rows,
  label = 'Download CSV',
  disabled = false,
}: {
  filename: string;
  header: readonly string[];
  rows: readonly (readonly CsvCell[])[];
  label?: string;
  disabled?: boolean;
}) {
  return (
    <Button
      variant="outline"
      size="sm"
      disabled={disabled || rows.length === 0}
      onClick={() => downloadCsv(filename, toCsv(header, rows))}
    >
      <DownloadIcon aria-hidden />
      {label}
    </Button>
  );
}

/** A titled report section card. */
export function ReportSection({
  title,
  description,
  actions,
  children,
  className,
}: {
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section
      aria-label={title}
      className={cn(
        'flex flex-col gap-3 rounded-lg border bg-card p-4 shadow-xs md:p-5',
        className,
      )}
    >
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="grid gap-0.5">
          <h2 className="text-base font-semibold">{title}</h2>
          {description ? <p className="text-xs text-muted-foreground">{description}</p> : null}
        </div>
        {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
      </div>
      {children}
    </section>
  );
}
