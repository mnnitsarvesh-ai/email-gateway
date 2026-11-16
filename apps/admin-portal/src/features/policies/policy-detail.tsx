'use client';

import { CopyPlusIcon, PencilIcon, ScrollTextIcon, Trash2Icon, WorkflowIcon } from 'lucide-react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useMemo, useState } from 'react';
import { toast } from 'sonner';
import { z } from 'zod';
import { CopyableId, DateTime, DirectionBadge } from '@/components/domain';
import { NotFoundView } from '@/components/not-found-view';
import { PageHeader } from '@/components/page-header';
import { EmptyState } from '@/components/states/empty-state';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useUrlState } from '@/hooks/use-url-state';
import { ApiError } from '@/lib/api/errors';
import { useApiMutation, useApiQuery } from '@/lib/api/hooks';
import type { SuccessBody } from '@/lib/api/types';
import { useCan } from '@/lib/auth/me';
import { RouteGate } from '@/lib/auth/route-gate';
import { formatNumber } from '@/lib/format';
import { DetailList, EnumBadge, Section } from '@/features/messages/controls';
import { isUuid } from '@/features/domains/kit';
import { PolicySummaryView, summarizeDefinition, type DirectoryNames } from './builder';
import { CatalogGate } from './catalog-state';
import { PolicyAuditTrail } from './detail/audit-trail';
import { VersionsTable } from './detail/versions-table';
import { NextEvaluationNote } from './lifecycle/dialog-shell';
import { DeletePolicyDialog, PolicyStatusSwitch, RenameDialog } from './lifecycle/policy-controls';
import {
  policiesTabHref,
  policyExecutionsHref,
  policyVersionHref,
  type PolicyDetailTab,
} from './links';
import { detailNumber, POLICY_QUERIES } from './queries';
import { POLICY_STATUS_TONE } from './semantic';
import { useBuilderCatalog } from './use-builder-catalog';
import { useDirectoryOptions } from './use-directory-options';

type Policy = SuccessBody<'PolicyManagementController_get_v1'>;

const DETAIL_TABS = ['overview', 'versions', 'audit'] as const;
const URL_SHAPE = { tab: z.enum(DETAIL_TABS).default('overview').catch('overview') };

/** Policy detail (`/policies/[policyId]?tab=overview|versions|audit`, design B9–B11, B17). */
export function PolicyDetail({ policyId }: { policyId: string }) {
  return (
    <RouteGate gate={['PolicyManagementController_get_v1']}>
      {isUuid(policyId) ? <PolicyDetailContent policyId={policyId} /> : <NotFoundView />}
    </RouteGate>
  );
}

function PolicyDetailContent({ policyId }: { policyId: string }) {
  const router = useRouter();
  const policy = useApiQuery('PolicyManagementController_get_v1', { path: { policyId } });
  const settings = useApiQuery('PolicySettingsController_get_v1');
  const [url, setUrl] = useUrlState(URL_SHAPE);
  const { names } = useDirectoryOptions();
  const canAudit = useCan('AuditLogsController_search_v1');
  const canRename = useCan('PolicyManagementController_update_v1');
  const canDelete = useCan('PolicyManagementController_remove_v1');
  const canCreateDraft = useCan('PolicyManagementController_createDraft_v1');
  const [dialog, setDialog] = useState<'rename' | 'delete' | null>(null);
  const [generation, setGeneration] = useState<string | null>(null);
  const createDraft = useApiMutation('PolicyManagementController_createDraft_v1', {
    invalidates: POLICY_QUERIES,
    successMessage: null,
  });
  const breadcrumbs = [{ label: 'Policy management', href: '/policies' }, { label: 'Policy' }];

  if (policy.error instanceof ApiError && policy.error.status === 404) return <NotFoundView />;
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
  const tabs = DETAIL_TABS.filter((tab) => tab !== 'audit' || canAudit);
  const tab: PolicyDetailTab = tabs.includes(url.tab) ? url.tab : 'overview';
  const builderVersion = p.activeVersionNo ?? p.latestVersionNo;
  const draftSource = p.activeVersionNo ?? p.latestVersionNo;

  const newDraft = async () => {
    if (!draftSource) return;
    const outcome = await createDraft.submit({
      path: { policyId: p.id },
      body: { basedOnVersionNo: draftSource },
    });
    if (outcome.ok) {
      toast.success(`Draft v${outcome.data.versionNo} created from v${draftSource}`);
      router.push(policyVersionHref(p.id, outcome.data.versionNo));
    } else if (outcome.error.code === 'policy_version_limit_reached') {
      toast.error(
        `This policy reached its limit of ${detailNumber(outcome.error, 'limit') ?? '?'} versions; delete unused drafts first.`,
      );
    } else if (outcome.error.status !== 429) {
      toast.error(`The draft could not be created (${outcome.error.code}).`);
    }
  };

  return (
    <div className="grid min-w-0 gap-4">
      <PageHeader
        title={p.name}
        breadcrumbs={[{ label: 'Policy management', href: '/policies' }, { label: p.name }]}
        description={p.description ?? undefined}
        actions={
          <>
            {builderVersion ? (
              <Button asChild size="sm">
                <Link href={policyVersionHref(p.id, builderVersion)}>
                  <WorkflowIcon aria-hidden />
                  {p.activeVersionNo
                    ? `Open v${builderVersion} in the builder`
                    : `Open v${builderVersion}`}
                </Link>
              </Button>
            ) : null}
            {canCreateDraft && draftSource ? (
              <Button
                variant="outline"
                size="sm"
                onClick={() => void newDraft()}
                disabled={createDraft.isPending}
              >
                <CopyPlusIcon aria-hidden />
                New draft
              </Button>
            ) : null}
            {canRename ? (
              <Button variant="outline" size="sm" onClick={() => setDialog('rename')}>
                <PencilIcon aria-hidden />
                Rename
              </Button>
            ) : null}
            {canDelete ? (
              <Button variant="ghost" size="sm" onClick={() => setDialog('delete')}>
                <Trash2Icon aria-hidden />
                Delete policy
              </Button>
            ) : null}
          </>
        }
      />
      <Section title="Policy">
        <PolicyStatusSwitch policy={p} />
        <DetailList
          items={[
            { label: 'Status', value: <EnumBadge value={p.status} tones={POLICY_STATUS_TONE} /> },
            {
              label: 'Direction',
              value:
                p.direction === 'any' ? (
                  <span>Any direction</span>
                ) : (
                  <DirectionBadge direction={p.direction} />
                ),
            },
            { label: 'Priority', value: `${formatNumber(p.priority)} (lower runs first)` },
            {
              label: 'Active version',
              value: p.activeVersion ? (
                <span>
                  {`v${p.activeVersion.versionNo} · ${formatNumber(p.activeVersion.ruleCount)} rules`}
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
            {
              label: 'Policy generation',
              value: settings.data ? (
                <span>
                  <span className="font-mono">{settings.data.generation}</span>
                  <span className="text-xs text-muted-foreground">
                    {' '}
                    (every change that affects evaluation increments it)
                  </span>
                </span>
              ) : (
                <span className="text-muted-foreground">Unknown</span>
              ),
            },
            { label: 'Updated', value: <DateTime value={p.updatedAt} mode="absolute" /> },
            { label: 'Policy ID', value: <CopyableId value={p.id} label="policy ID" max={40} /> },
          ]}
        />
        {generation ? <NextEvaluationNote generation={generation} /> : null}
      </Section>
      <Tabs
        value={tab}
        onValueChange={(next) => setUrl({ tab: next as PolicyDetailTab }, { push: true })}
      >
        <TabsList aria-label="Policy views">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="versions">Versions</TabsTrigger>
          {canAudit ? <TabsTrigger value="audit">Audit</TabsTrigger> : null}
        </TabsList>
        <TabsContent value="overview">
          {tab === 'overview' ? <Overview policy={p} names={names} /> : null}
        </TabsContent>
        <TabsContent value="versions">
          {tab === 'versions' ? (
            <VersionsTable policy={p} names={names} onGeneration={setGeneration} />
          ) : null}
        </TabsContent>
        {canAudit ? (
          <TabsContent value="audit">
            {tab === 'audit' ? <PolicyAuditTrail policyId={p.id} names={names} /> : null}
          </TabsContent>
        ) : null}
      </Tabs>
      {canRename ? (
        <RenameDialog
          open={dialog === 'rename'}
          onOpenChange={(open) => setDialog(open ? 'rename' : null)}
          policy={p}
        />
      ) : null}
      {canDelete ? (
        <DeletePolicyDialog
          open={dialog === 'delete'}
          onOpenChange={(open) => setDialog(open ? 'delete' : null)}
          policy={p}
          onDeleted={() => router.push(policiesTabHref('email'))}
        />
      ) : null}
    </div>
  );
}

/** The active version's readable summary and the link to the policy's executions. */
function Overview({ policy, names }: { policy: Policy; names: DirectoryNames }) {
  const catalog = useBuilderCatalog();
  const activeNo = policy.activeVersionNo;
  const active = useApiQuery(
    'PolicyManagementController_getVersion_v1',
    { path: { policyId: policy.id, versionNo: activeNo ?? 0 } },
    { enabled: activeNo !== null },
  );
  return (
    <div className="grid min-w-0 gap-4">
      <Section
        title={activeNo ? `Active version (v${activeNo})` : 'Active version'}
        description="What the policy evaluates now, as a readable summary of its definition."
        actions={
          activeNo ? (
            <Button asChild size="sm" variant="outline">
              <Link href={policyVersionHref(policy.id, activeNo)}>Open in the builder</Link>
            </Button>
          ) : null
        }
      >
        {activeNo === null ? (
          <EmptyState
            icon={ScrollTextIcon}
            title="No active version"
            description="Publish and activate a version to make this policy effective."
            action={
              policy.latestVersionNo ? (
                <Button asChild size="sm" variant="outline">
                  <Link href={policyVersionHref(policy.id, policy.latestVersionNo)}>
                    {`Open v${policy.latestVersionNo}`}
                  </Link>
                </Button>
              ) : undefined
            }
          />
        ) : (
          <CatalogGate state={catalog}>
            {(builderCatalog) =>
              active.isLoading ? (
                <LoadingState label="Loading the active version" rows={4} />
              ) : active.error || !active.data ? (
                <ErrorState error={active.error} onRetry={() => void active.refetch()} compact />
              ) : (
                <ActiveSummary
                  definition={active.data.definition}
                  catalog={builderCatalog}
                  names={names}
                />
              )
            }
          </CatalogGate>
        )}
      </Section>
      <Section title="Executions" description="The stored evaluations this policy decided.">
        <Button asChild size="sm" variant="outline" className="justify-self-start">
          <Link href={policyExecutionsHref(policy.id)}>
            Open the execution history of this policy
          </Link>
        </Button>
      </Section>
    </div>
  );
}

function ActiveSummary({
  definition,
  catalog,
  names,
}: {
  definition: unknown;
  catalog: Parameters<typeof summarizeDefinition>[1];
  names: DirectoryNames;
}) {
  const summary = useMemo(
    () => summarizeDefinition(definition, catalog, names),
    [definition, catalog, names],
  );
  return <PolicySummaryView summary={summary} />;
}
