'use client';

import { useState, type ReactNode } from 'react';
import { toast } from 'sonner';
import { CopyableId } from '@/components/domain/copyable-id';
import { DateTime } from '@/components/domain/date-time';
import { PageHeader } from '@/components/page-header';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { UnavailableState } from '@/components/states/unavailable-state';
import { Button } from '@/components/ui/button';
import { useApiMutation, useApiQuery } from '@/lib/api/hooks';
import { ApiError } from '@/lib/api/errors';
import type { SuccessBody } from '@/lib/api/types';
import { Can } from '@/lib/auth/can';
import { useMe, usePermissions } from '@/lib/auth/me';
import { RouteGate } from '@/lib/auth/route-gate';
import { formatUtc, humanize } from '@/lib/format';
import { LimitsTable, UsageSummary } from '@/features/billing/entitlements';
import { GatedTabs, type TabDefinition } from '@/features/reports/gated-tabs';
import { navGate } from '@/features/reports/nav-gate';
import { ReportSection } from '@/features/reports/report-state';
import { OrganizationSettingsPanel } from '@/features/settings/organization-settings-form';
import { ActInOrganizationDialog } from './act-in-organization';
import { DeletionPanel } from './deletion-panel';
import { EntitlementsPanel } from './entitlements-panel';
import { OrganizationStatusBadge } from './organizations-page';
import { ProfileForm } from './profile-form';
import { ReasonConfirmDialog } from './reason-confirm-dialog';

type Organization = SuccessBody<'OrganizationsController_get_v1'>;

/** `/organizations/[organizationId]` (design §1.3 row 3). */
export function OrganizationDetailPage({ organizationId }: { organizationId: string }) {
  return (
    <RouteGate gate={navGate('organizations')}>
      <OrganizationDetail organizationId={organizationId} />
    </RouteGate>
  );
}

const PLATFORM_TABS: readonly TabDefinition[] = [
  { id: 'profile', label: 'Profile', ops: ['OrganizationsController_get_v1'] },
  { id: 'usage', label: 'Usage', ops: ['OrganizationsController_getUsage_v1'] },
  {
    id: 'settings',
    label: 'Settings',
    ops: ['OrganizationConfigurationController_getSettings_v1'],
  },
  {
    id: 'entitlements',
    label: 'Features and limits',
    ops: ['OrganizationConfigurationController_listFeatures_v1'],
  },
  { id: 'deletion', label: 'Deletion', ops: ['OrganizationDeletionController_get_v1'] },
];

export function OrganizationDetail({
  organizationId,
  tenantView = false,
}: {
  organizationId: string;
  tenantView?: boolean;
}) {
  const query = useApiQuery('OrganizationsController_get_v1', { path: { id: organizationId } });
  if (query.isLoading) return <LoadingState label="Loading the organization" rows={6} />;
  if (query.error)
    return (
      <div className="grid gap-4">
        <PageHeader
          title="Organization"
          breadcrumbs={
            tenantView ? undefined : [{ label: 'Organizations', href: '/organizations' }]
          }
        />
        <ErrorState error={query.error} onRetry={() => void query.refetch()} />
      </div>
    );
  if (!query.data) return null;
  return <OrganizationView organization={query.data} tenantView={tenantView} />;
}

function OrganizationView({
  organization,
  tenantView,
}: {
  organization: Organization;
  tenantView: boolean;
}) {
  const permissions = usePermissions();
  const me = useMe();
  const [acting, setActing] = useState(false);
  const [statusOpen, setStatusOpen] = useState(false);
  const isPlatformOrg = organization.kind === 'platform';
  const tabs = PLATFORM_TABS.filter(
    (tab) => !(tab.id === 'deletion' && (tenantView || isPlatformOrg)),
  );
  const canAct =
    !tenantView &&
    permissions.has('platform:tenant_override') &&
    !isPlatformOrg &&
    organization.status === 'active' &&
    !me.data?.override;
  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={organization.name}
        breadcrumbs={
          tenantView
            ? undefined
            : [{ label: 'Organizations', href: '/organizations' }, { label: organization.name }]
        }
        description={
          <span className="flex flex-wrap items-center gap-2">
            <OrganizationStatusBadge status={organization.status} />
            <span className="font-mono text-xs">{organization.slug}</span>
            <span>
              {humanize(organization.kind)} · {organization.plan.name}
            </span>
          </span>
        }
        actions={
          <>
            {canAct ? (
              <Button variant="outline" onClick={() => setActing(true)}>
                Act in this organization
              </Button>
            ) : null}
            {!tenantView &&
            !isPlatformOrg &&
            (organization.status === 'active' || organization.status === 'suspended') ? (
              <Can op="OrganizationsController_changeStatus_v1">
                <Button
                  variant={organization.status === 'active' ? 'destructive' : 'default'}
                  onClick={() => setStatusOpen(true)}
                >
                  {organization.status === 'active' ? 'Suspend' : 'Reactivate'}
                </Button>
              </Can>
            ) : null}
          </>
        }
      />
      <GatedTabs
        tabs={tabs}
        label="Organization"
        keepParams={[]}
        render={(tab) =>
          tab === 'profile' ? (
            <ProfilePanel organization={organization} tenantView={tenantView} />
          ) : tab === 'usage' ? (
            <UsagePanel organizationId={organization.id} />
          ) : tab === 'settings' ? (
            <ReportSection title="Settings">
              <OrganizationSettingsPanel organizationId={organization.id} />
            </ReportSection>
          ) : tab === 'entitlements' ? (
            <EntitlementsPanel organizationId={organization.id} />
          ) : (
            <DeletionPanel organization={organization} />
          )
        }
      />
      {canAct ? (
        <ActInOrganizationDialog
          open={acting}
          onOpenChange={setActing}
          organization={organization}
        />
      ) : null}
      <StatusDialog organization={organization} open={statusOpen} onOpenChange={setStatusOpen} />
    </div>
  );
}

function ProfilePanel({
  organization,
  tenantView,
}: {
  organization: Organization;
  tenantView: boolean;
}) {
  const rows: [string, ReactNode][] = [
    [
      'Organization ID',
      <CopyableId key="id" value={organization.id} label="organization ID" max={40} />,
    ],
    [
      'Slug',
      <span key="slug" className="font-mono">
        {organization.slug}
      </span>,
    ],
    ['Kind', humanize(organization.kind)],
    ['Plan', `${organization.plan.name} (${organization.plan.code})`],
    ['Deployment mode', organization.deploymentMode === 'saas' ? 'SaaS (shared)' : 'Dedicated'],
    [
      'Data region',
      <span key="region" className="font-mono">
        {organization.dataRegion}
      </span>,
    ],
    ['Status reason', organization.statusReason ?? 'None'],
    [
      'Status changed',
      organization.statusChangedAt ? formatUtc(organization.statusChangedAt) : 'Never',
    ],
    ['Created', formatUtc(organization.createdAt)],
    ['Updated', <DateTime key="updated" value={organization.updatedAt} />],
  ];
  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <ReportSection title="Profile">
        <dl className="grid grid-cols-1 gap-x-6 gap-y-2 text-sm sm:grid-cols-[auto_1fr]">
          {rows.map(([label, value]) => (
            <div key={label} className="contents">
              <dt className="text-muted-foreground">{label}</dt>
              <dd className="min-w-0 break-words">{value}</dd>
            </div>
          ))}
        </dl>
      </ReportSection>
      <Can op="OrganizationsController_update_v1">
        <ReportSection
          title="Edit profile"
          description="Slug, kind, deployment mode and data region cannot be changed."
        >
          <ProfileForm organization={organization} allowPlan={!tenantView} />
        </ReportSection>
      </Can>
      <ReportSection title="Deployments" className="xl:col-span-2">
        {organization.deployments.length === 0 ? (
          <p className="text-sm text-muted-foreground">No deployment is recorded.</p>
        ) : (
          <ul className="grid gap-2 text-sm">
            {organization.deployments.map((d) => (
              <li key={`${d.region}-${d.environment}`} className="rounded-md border p-3">
                <p className="font-medium">
                  {d.deploymentMode === 'saas' ? 'SaaS' : 'Dedicated'} ·{' '}
                  <span className="font-mono">{d.region}</span> ·{' '}
                  <span className="font-mono">{d.environment}</span> · {humanize(d.status)}
                </p>
                <p className="text-xs text-muted-foreground">
                  Endpoint {d.endpointHostname ?? 'not assigned'} · MX{' '}
                  {d.mxHostname ?? 'not assigned'} · Release {d.releaseVersion ?? 'none'}
                </p>
              </li>
            ))}
          </ul>
        )}
        <UnavailableState
          step="8.3"
          title="Dedicated deployment provisioning"
          description="Provisioning, upgrading and decommissioning dedicated deployments arrives with the deployment manager."
        />
      </ReportSection>
    </div>
  );
}

function UsagePanel({ organizationId }: { organizationId: string }) {
  const usage = useApiQuery('OrganizationsController_getUsage_v1', {
    path: { id: organizationId },
  });
  if (usage.isLoading) return <LoadingState label="Loading usage" rows={6} />;
  if (usage.error) return <ErrorState error={usage.error} onRetry={() => void usage.refetch()} />;
  if (!usage.data) return null;
  return (
    <ReportSection
      title="Usage"
      description={`${formatUtc(usage.data.period.from)} to ${formatUtc(usage.data.period.to)} (last 30 days)`}
    >
      <UsageSummary usage={usage.data} />
      <LimitsTable caption="Limits and their use" limits={usage.data.limits} showUsed />
    </ReportSection>
  );
}

/** Suspend (reason required) or reactivate; legacy Idempotency-Key is handled by the hook. */
function StatusDialog({
  organization,
  open,
  onOpenChange,
}: {
  organization: Organization;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const mutation = useApiMutation('OrganizationsController_changeStatus_v1', {
    invalidates: ['OrganizationsController_get_v1', 'OrganizationsController_list_v1'],
  });
  const suspend = organization.status === 'active';
  return (
    <ReasonConfirmDialog
      open={open}
      onOpenChange={(next) => {
        if (!next) mutation.reset();
        onOpenChange(next);
      }}
      title={suspend ? `Suspend ${organization.name}?` : `Reactivate ${organization.name}?`}
      description={
        suspend
          ? 'Suspension revokes every session of the organization and stops its API keys immediately. Mail processing follows the platform rules for suspended tenants.'
          : 'Users can sign in again and API keys work again.'
      }
      confirmLabel={suspend ? 'Suspend organization' : 'Reactivate organization'}
      destructive={suspend}
      minLength={3}
      maxLength={512}
      reasonRequired={suspend}
      onConfirm={async (reason) => {
        const outcome = await mutation.submit({
          path: { id: organization.id },
          body: { status: suspend ? 'suspended' : 'active', ...(reason ? { reason } : {}) },
        });
        if (outcome.ok) {
          toast.success(suspend ? 'Organization suspended.' : 'Organization reactivated.');
        }
        return outcome.ok;
      }}
      error={mutation.error ? <ErrorState error={mutation.error} compact /> : null}
    />
  );
}

export function isMfaRequired(error: unknown): boolean {
  return error instanceof ApiError && error.status === 403 && error.code === 'mfa_required';
}
