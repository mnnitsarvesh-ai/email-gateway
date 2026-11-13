'use client';

import { z } from 'zod';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { CopyableId, DateTime } from '@/components/domain';
import { PageHeader } from '@/components/page-header';
import { EmptyState } from '@/components/states/empty-state';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { useUrlState } from '@/hooks/use-url-state';
import { useApiQuery, useCursorList } from '@/lib/api/hooks';
import type { ListItem } from '@/lib/api/types';
import { RouteGate } from '@/lib/auth/route-gate';
import { formatNumber, humanize } from '@/lib/format';
import { DetailList, EnumBadge, Section, YesNo } from '@/features/messages/controls';
import { PolicyEditingBanner } from './policies-page';
import { POLICY_STATUS_TONE, VERSION_STATUS_TONE } from './semantic';

type Version = ListItem<'PolicyManagementController_listVersions_v1'>;

const URL_SHAPE = { version: z.coerce.number().int().min(1).optional().catch(undefined) };

/** Policy detail (`/policies/[policyId]`): policy, versions, and a version's definition (read-only). */
export function PolicyDetail({ policyId }: { policyId: string }) {
  return (
    <RouteGate gate={['PolicyManagementController_get_v1']}>
      <PolicyDetailContent policyId={policyId} />
    </RouteGate>
  );
}

function PolicyDetailContent({ policyId }: { policyId: string }) {
  const policy = useApiQuery('PolicyManagementController_get_v1', { path: { policyId } });
  const [state, setState] = useUrlState(URL_SHAPE);
  const versions = useCursorList('PolicyManagementController_listVersions_v1', undefined, {
    path: { policyId },
    limit: 25,
    enabled: policy.isSuccess,
  });
  const breadcrumbs = [{ label: 'Policy management', href: '/policies' }, { label: 'Policy' }];
  if (policy.isLoading) {
    return (
      <div className="grid gap-4">
        <PageHeader title="Policy" breadcrumbs={breadcrumbs} />
        <LoadingState label="Loading the policy" rows={6} />
      </div>
    );
  }
  if (policy.error || !policy.data) {
    return (
      <div className="grid gap-4">
        <PageHeader title="Policy" breadcrumbs={breadcrumbs} />
        <ErrorState error={policy.error} onRetry={() => void policy.refetch()} />
      </div>
    );
  }
  const p = policy.data;
  const selected = state.version ?? p.activeVersionNo ?? p.latestVersionNo ?? undefined;
  const columns: DataTableColumn<Version>[] = [
    {
      id: 'versionNo',
      header: 'Version',
      meta: { label: 'Version' },
      cell: ({ row }) => (
        <Button
          variant="link"
          size="sm"
          className="h-auto p-0"
          aria-pressed={row.original.versionNo === selected}
          onClick={() => setState({ version: row.original.versionNo })}
        >
          v{row.original.versionNo}
          {row.original.active ? ' (active)' : ''}
        </Button>
      ),
    },
    {
      id: 'status',
      header: 'Status',
      meta: { label: 'Status' },
      cell: ({ row }) => <EnumBadge value={row.original.status} tones={VERSION_STATUS_TONE} />,
    },
    {
      id: 'rules',
      header: 'Rules',
      meta: { label: 'Rules', className: 'tabular-nums' },
      cell: ({ row }) => formatNumber(row.original.ruleCount),
    },
    {
      id: 'note',
      header: 'Change note',
      meta: { label: 'Change note', className: 'max-w-72' },
      cell: ({ row }) =>
        row.original.changeNote ?? <span className="text-muted-foreground">None</span>,
    },
    {
      id: 'published',
      header: 'Published',
      meta: { label: 'Published', className: 'whitespace-nowrap' },
      cell: ({ row }) => <DateTime value={row.original.publishedAt} emptyLabel="Not published" />,
    },
  ];
  return (
    <div className="grid gap-4">
      <PageHeader
        title={p.name}
        breadcrumbs={breadcrumbs}
        description={p.description ?? undefined}
      />
      <PolicyEditingBanner />
      <Section title="Policy">
        <DetailList
          items={[
            { label: 'Status', value: <EnumBadge value={p.status} tones={POLICY_STATUS_TONE} /> },
            { label: 'Direction', value: humanize(p.direction) },
            { label: 'Priority', value: formatNumber(p.priority) },
            {
              label: 'Active version',
              value: p.activeVersion ? (
                <span>
                  v{p.activeVersion.versionNo} · {formatNumber(p.activeVersion.ruleCount)} rules
                  {p.activeVersion.hasOverrideRules ? ' · has override rules' : ''}
                </span>
              ) : (
                <span className="text-muted-foreground">No active version</span>
              ),
            },
            {
              label: 'Versions',
              value: `${formatNumber(p.counts.published)} published, ${formatNumber(p.counts.drafts)} drafts, ${formatNumber(p.counts.superseded)} superseded (limit ${formatNumber(p.counts.limit)})`,
            },
            { label: 'Updated', value: <DateTime value={p.updatedAt} mode="absolute" /> },
            { label: 'Policy ID', value: <CopyableId value={p.id} label="policy ID" max={40} /> },
          ]}
        />
      </Section>
      <DataTable
        tableId="policy-versions"
        caption="Policy versions"
        columns={columns}
        list={versions}
        getRowId={(row) => String(row.versionNo)}
        getRowLabel={(row) => `version ${row.versionNo}`}
        emptyState={<EmptyState title="No versions" />}
        mobileCard={(row) => (
          <Button
            variant="link"
            size="sm"
            className="h-auto p-0"
            onClick={() => setState({ version: row.versionNo })}
          >
            v{row.versionNo} · {humanize(row.status)}
          </Button>
        )}
      />
      {selected ? <VersionDefinition policyId={p.id} versionNo={selected} /> : null}
    </div>
  );
}

function VersionDefinition({ policyId, versionNo }: { policyId: string; versionNo: number }) {
  const version = useApiQuery('PolicyManagementController_getVersion_v1', {
    path: { policyId, versionNo },
  });
  return (
    <Section
      title={`Definition of version ${versionNo}`}
      description="The policy DSL document as stored (read-only). Validation runs against today's DSL."
    >
      {version.isLoading ? (
        <LoadingState label="Loading the definition" rows={8} />
      ) : version.error || !version.data ? (
        <ErrorState error={version.error} onRetry={() => void version.refetch()} compact />
      ) : (
        <div className="grid gap-3">
          <DetailList
            items={[
              {
                label: 'Status',
                value: <EnumBadge value={version.data.status} tones={VERSION_STATUS_TONE} />,
              },
              { label: 'DSL version', value: version.data.dslVersion ?? 'Unknown' },
              { label: 'Valid today', value: <YesNo value={version.data.validation.valid} /> },
              {
                label: 'Definition hash',
                value: (
                  <span className="font-mono text-xs break-all">
                    {version.data.definitionSha256}
                  </span>
                ),
              },
            ]}
          />
          {version.data.validation.violations.length > 0 ? (
            <ul className="grid gap-1 text-sm" aria-label="Validation violations">
              {version.data.validation.violations.map((v, i) => (
                <li key={i}>
                  <span className="font-mono text-xs">{v.path}</span> {v.code}: {v.message}
                </li>
              ))}
            </ul>
          ) : null}
          <pre
            className="rounded-md border bg-muted/40 p-3 font-mono text-xs leading-relaxed break-words whitespace-pre-wrap"
            aria-label={`Definition of version ${versionNo}`}
            data-testid="policy-definition"
          >
            {JSON.stringify(version.data.definition, null, 2)}
          </pre>
        </div>
      )}
    </Section>
  );
}
