'use client';

import { AlertTriangleIcon, LockIcon, SearchXIcon } from 'lucide-react';
import { useEffect, useState } from 'react';
import { CopyButton } from '@/components/copy-button';
import { Button } from '@/components/ui/button';
import { ApiError } from '@/lib/api/errors';
import type { OperationId } from '@/lib/api/types';
import { describeRequirement } from '@/lib/auth/permissions';
import { cn } from '@/lib/utils';

export function errorTitle(status: number): string {
  if (status === 400) return 'The request was not accepted';
  if (status === 401) return 'Your session has ended';
  if (status === 403) return 'You do not have access';
  if (status === 404) return 'Not found';
  if (status === 409) return 'Conflict';
  if (status === 413) return 'Too large';
  if (status === 422) return 'The request could not be processed';
  if (status === 429) return 'Too many requests';
  if (status === 0) return 'Cannot reach the portal';
  return 'Something went wrong';
}

/**
 * Error state (design P8): title by status, the API message, `code`, `requestId` with copy,
 * Retry; 403 lists the permissions the operation requires; 404 reads like a missing resource.
 */
export function ErrorState({
  error,
  onRetry,
  operationId,
  className,
  compact = false,
  showRequirement = true,
}: {
  error: unknown;
  onRetry?: () => void;
  /** Operation whose required permissions a 403 lists (defaults to the error's operation). */
  operationId?: OperationId;
  className?: string;
  compact?: boolean;
  /** List the operation's required permissions on a 403 (off when another rule refused). */
  showRequirement?: boolean;
}) {
  const apiError =
    error instanceof ApiError
      ? error
      : new ApiError({
          status: 500,
          code: 'client_error',
          message: 'An unexpected error occurred',
        });
  const op = operationId ?? apiError.operationId;
  const required = showRequirement && apiError.status === 403 && op ? describeRequirement(op) : [];
  const Icon =
    apiError.status === 403 ? LockIcon : apiError.status === 404 ? SearchXIcon : AlertTriangleIcon;
  const message =
    apiError.status === 404
      ? 'It does not exist, or you do not have access to it.'
      : apiError.messages.join(' ');
  return (
    <div
      role="alert"
      className={cn(
        'flex flex-col gap-2 rounded-lg border border-border bg-card p-4 text-sm',
        !compact && 'items-start md:p-6',
        className,
      )}
    >
      <div className="flex items-center gap-2 font-semibold text-foreground">
        <Icon className="size-4 text-destructive" aria-hidden />
        <span>{errorTitle(apiError.status)}</span>
      </div>
      <p className="text-muted-foreground">{message}</p>
      {required.length > 0 ? (
        <p className="text-muted-foreground">
          Requires the permission{required.length > 1 || required[0]?.includes(' ') ? 's' : ''}{' '}
          {required.map((r, i) => (
            <code
              key={i}
              className="rounded-sm bg-muted px-1 py-0.5 font-mono text-xs text-foreground"
            >
              {r}
            </code>
          ))}
          .
        </p>
      ) : null}
      <dl className="grid grid-cols-[auto_1fr] items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
        <dt>Code</dt>
        <dd className="font-mono text-foreground">{apiError.code}</dd>
        {apiError.requestId ? (
          <>
            <dt>Request ID</dt>
            <dd className="flex min-w-0 items-center gap-1 font-mono text-foreground">
              <span className="truncate">{apiError.requestId}</span>
              <CopyButton value={apiError.requestId} label="Copy request ID" />
            </dd>
          </>
        ) : null}
      </dl>
      {apiError.status === 429 && apiError.retryAfterSeconds ? (
        <RetryCountdown
          key={`${apiError.requestId ?? ''}:${apiError.retryAfterSeconds}`}
          seconds={apiError.retryAfterSeconds}
          onRetry={onRetry}
        />
      ) : onRetry && apiError.status !== 403 && apiError.status !== 404 ? (
        <Button variant="outline" size="sm" onClick={onRetry} className="mt-1">
          Retry
        </Button>
      ) : null}
    </div>
  );
}

/**
 * `429` (design P8): "Try again in N s" counting down from `Retry-After`; Retry is enabled when it
 * reaches zero (step 7.2 §2 E10).
 */
function RetryCountdown({ seconds, onRetry }: { seconds: number; onRetry?: () => void }) {
  const [left, setLeft] = useState(seconds);
  useEffect(() => {
    if (left <= 0) return;
    const timer = setTimeout(() => setLeft((s) => Math.max(0, s - 1)), 1000);
    return () => clearTimeout(timer);
  }, [left]);
  return (
    <div className="mt-1 flex flex-wrap items-center gap-2">
      <p className="text-xs text-muted-foreground" aria-live="polite">
        {left > 0 ? `Try again in ${left} s.` : 'You can try again now.'}
      </p>
      {onRetry ? (
        <Button variant="outline" size="sm" onClick={onRetry} disabled={left > 0}>
          Retry
        </Button>
      ) : null}
    </div>
  );
}
