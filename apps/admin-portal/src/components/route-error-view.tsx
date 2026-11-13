'use client';

import { ErrorState } from '@/components/states/error-state';
import { ApiError } from '@/lib/api/errors';

/** Error boundary content: API errors show their code and requestId; others a generic message. */
export function RouteErrorView({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  const shown =
    error instanceof ApiError
      ? error
      : new ApiError({
          status: 500,
          code: 'client_error',
          message: 'This page failed to render. Retry, or reload the page.',
          requestId: error.digest ?? null,
        });
  return (
    <div className="mx-auto max-w-xl py-10">
      <ErrorState error={shown} onRetry={reset} />
    </div>
  );
}
