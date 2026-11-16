'use client';

import { AlertTriangleIcon } from 'lucide-react';
import type { ReactNode } from 'react';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import type { BuilderCatalog } from './builder';
import type { BuilderCatalogState } from './use-builder-catalog';

/** The catalogue does not have the shape the builder needs: the issues, never a guess. */
export function CatalogShapeErrorState({ issues }: { issues: readonly string[] }) {
  return (
    <div role="alert" className="grid gap-2 rounded-lg border bg-card p-4 text-sm md:p-6">
      <p className="flex items-center gap-2 font-semibold">
        <AlertTriangleIcon className="size-4 text-destructive" aria-hidden />
        The policy catalogue cannot drive the builder
      </p>
      <p className="text-muted-foreground">
        The api returned a catalogue the portal does not understand (a newer or older api). The
        builder needs it for every field, operator and action it shows, so editing is not offered.
      </p>
      <ul className="grid gap-0.5 font-mono text-xs break-all" aria-label="Catalogue problems">
        {issues.slice(0, 10).map((issue) => (
          <li key={issue}>{issue}</li>
        ))}
      </ul>
    </div>
  );
}

/** Loading, error and shape-error states of the catalogue, then the content. */
export function CatalogGate({
  state,
  children,
}: {
  state: BuilderCatalogState;
  children: (catalog: BuilderCatalog) => ReactNode;
}) {
  if (state.query.isLoading) return <LoadingState label="Loading the policy catalogue" rows={6} />;
  if (state.query.error) {
    return <ErrorState error={state.query.error} onRetry={() => void state.query.refetch()} />;
  }
  if (state.shapeError) return <CatalogShapeErrorState issues={state.shapeError.issues} />;
  if (!state.catalog) return <LoadingState label="Loading the policy catalogue" rows={6} />;
  return <>{children(state.catalog)}</>;
}
