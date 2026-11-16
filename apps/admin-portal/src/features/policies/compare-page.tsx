'use client';

import { useId, useMemo } from 'react';
import { z } from 'zod';
import { NotFoundView } from '@/components/not-found-view';
import { PageHeader } from '@/components/page-header';
import { EmptyState } from '@/components/states/empty-state';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Label } from '@/components/ui/label';
import { useUrlState } from '@/hooks/use-url-state';
import { ApiError } from '@/lib/api/errors';
import { useApiQuery } from '@/lib/api/hooks';
import { RouteGate } from '@/lib/auth/route-gate';
import { Section } from '@/features/messages/controls';
import { isUuid } from '@/features/domains/kit';
import {
  DefinitionDiffView,
  diffDefinitions,
  type BuilderCatalog,
  type DiffViewMode,
} from './builder';
import { ChoiceSelect } from './builder/inputs';
import { CatalogGate } from './catalog-state';
import { policyHref } from './links';
import { useBuilderCatalog } from './use-builder-catalog';
import { useDirectoryOptions } from './use-directory-options';

/** `?from=<n>&to=<n>&view=summary|json` (design §4.6). */
const URL_SHAPE = {
  from: z.coerce.number().int().min(1).optional().catch(undefined),
  to: z.coerce.number().int().min(1).optional().catch(undefined),
  view: z.enum(['summary', 'json']).default('summary').catch('summary'),
};

/** `/policies/[policyId]/compare` (design B10, B17): the diff of two versions of a policy. */
export function PolicyComparePage({ policyId }: { policyId: string }) {
  return (
    <RouteGate gate={['PolicyManagementController_getVersion_v1']}>
      {isUuid(policyId) ? <CompareContent policyId={policyId} /> : <NotFoundView />}
    </RouteGate>
  );
}

function CompareContent({ policyId }: { policyId: string }) {
  const [url, setUrl] = useUrlState(URL_SHAPE);
  const policy = useApiQuery('PolicyManagementController_get_v1', { path: { policyId } });
  const versions = useApiQuery('PolicyManagementController_listVersions_v1', {
    path: { policyId },
    query: { limit: 100 },
  });
  const catalog = useBuilderCatalog();
  const fromId = useId();
  const toId = useId();
  const latest = policy.data?.latestVersionNo ?? null;
  const active = policy.data?.activeVersionNo ?? null;
  // Defaults: from = the active version, to = the newest one (design B10).
  const to = url.to ?? latest;
  const from = url.from ?? active ?? (latest !== null && latest > 1 ? latest - 1 : latest);
  const breadcrumbs = [
    { label: 'Policy management', href: '/policies' },
    { label: policy.data?.name ?? 'Policy', href: policyHref(policyId, 'versions') },
    { label: 'Compare versions' },
  ];

  if (policy.error instanceof ApiError && policy.error.status === 404) return <NotFoundView />;
  const options = (versions.data?.data ?? []).map((v) => ({
    value: String(v.versionNo),
    label: `v${v.versionNo} (${v.status}${v.active ? ', active' : ''})`,
  }));
  return (
    <div className="grid min-w-0 gap-4">
      <PageHeader
        title={policy.data ? `Compare versions of ${policy.data.name}` : 'Compare versions'}
        breadcrumbs={breadcrumbs}
        description="The change between two versions as readable rule summaries and as canonical JSON. It describes the documents; it never states what would happen to a message."
      />
      {policy.isLoading ? (
        <LoadingState label="Loading the policy" rows={4} />
      ) : policy.error ? (
        <ErrorState error={policy.error} onRetry={() => void policy.refetch()} />
      ) : (
        <>
          <Section title="Versions">
            <div className="grid min-w-0 grid-cols-1 gap-3 sm:grid-cols-2">
              <div className="grid min-w-0 gap-1">
                <Label id={fromId} className="text-xs text-muted-foreground">
                  From
                </Label>
                <ChoiceSelect
                  labelledBy={fromId}
                  value={from !== null ? String(from) : undefined}
                  options={options}
                  onChange={(value) => setUrl({ from: value ? Number(value) : undefined })}
                />
              </div>
              <div className="grid min-w-0 gap-1">
                <Label id={toId} className="text-xs text-muted-foreground">
                  To
                </Label>
                <ChoiceSelect
                  labelledBy={toId}
                  value={to !== null ? String(to) : undefined}
                  options={options}
                  onChange={(value) => setUrl({ to: value ? Number(value) : undefined })}
                />
              </div>
            </div>
          </Section>
          {from === null || to === null ? (
            <EmptyState title="This policy has no versions to compare" />
          ) : (
            <CatalogGate state={catalog}>
              {(builderCatalog) => (
                <VersionDiff
                  policyId={policyId}
                  from={from}
                  to={to}
                  catalog={builderCatalog}
                  view={url.view}
                  onViewChange={(view) => setUrl({ view })}
                />
              )}
            </CatalogGate>
          )}
        </>
      )}
    </div>
  );
}

function VersionDiff({
  policyId,
  from,
  to,
  catalog,
  view,
  onViewChange,
}: {
  policyId: string;
  from: number;
  to: number;
  catalog: BuilderCatalog;
  view: DiffViewMode;
  onViewChange: (view: DiffViewMode) => void;
}) {
  const { names } = useDirectoryOptions();
  const a = useApiQuery('PolicyManagementController_getVersion_v1', {
    path: { policyId, versionNo: from },
  });
  const b = useApiQuery('PolicyManagementController_getVersion_v1', {
    path: { policyId, versionNo: to },
  });
  const diff = useMemo(
    () =>
      a.data && b.data
        ? diffDefinitions(a.data.definition, b.data.definition, catalog, names)
        : null,
    [a.data, b.data, catalog, names],
  );
  if (a.isLoading || b.isLoading) return <LoadingState label="Loading the versions" rows={6} />;
  const error = a.error ?? b.error;
  if (error) {
    return (
      <ErrorState
        error={error}
        onRetry={() => {
          void a.refetch();
          void b.refetch();
        }}
      />
    );
  }
  if (!diff) return null;
  return (
    <Section title={`Changes from v${from} to v${to}`}>
      <DefinitionDiffView
        diff={diff}
        fromLabel={`v${from}`}
        toLabel={`v${to}`}
        view={view}
        onViewChange={onViewChange}
      />
    </Section>
  );
}
