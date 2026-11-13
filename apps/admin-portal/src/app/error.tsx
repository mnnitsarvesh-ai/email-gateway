'use client';

import { RouteErrorView } from '@/components/route-error-view';

export default function RootError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <main id="main" className="px-4 py-10">
      <RouteErrorView error={error} reset={reset} />
    </main>
  );
}
