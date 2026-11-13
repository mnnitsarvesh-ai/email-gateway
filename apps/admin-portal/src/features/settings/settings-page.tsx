'use client';

import Link from 'next/link';
import { PageHeader } from '@/components/page-header';
import { LoadingState } from '@/components/states/loading-state';
import { ErrorState } from '@/components/states/error-state';
import { UnavailableState } from '@/components/states/unavailable-state';
import { useApiQuery } from '@/lib/api/hooks';
import { Can } from '@/lib/auth/can';
import { useMe } from '@/lib/auth/me';
import { RouteGate } from '@/lib/auth/route-gate';
import { ChangePasswordForm, MfaPanel, SessionsPanel } from '@/features/account';
import { ProfileForm } from '@/features/organizations/profile-form';
import { GatedTabs, type TabDefinition } from '@/features/reports/gated-tabs';
import { navGate } from '@/features/reports/nav-gate';
import { ReportSection } from '@/features/reports/report-state';
import { AlertSettingsPanel, PreferencesPanel } from './notification-forms';
import { OrganizationSettingsPanel } from './organization-settings-form';
import { ScanSettingsPanel } from './scan-settings-panel';

export const SETTINGS_TABS: readonly TabDefinition[] = [
  {
    id: 'organization',
    label: 'Organization',
    ops: ['OrganizationConfigurationController_getSettings_v1'],
  },
  { id: 'notifications', label: 'Notifications', ops: ['NotificationsController_settings_v1'] },
  { id: 'preferences', label: 'My notifications' },
  { id: 'security', label: 'Security' },
  { id: 'scanning', label: 'Scanning', ops: ['ScanSettingsController_list_v1'] },
  { id: 'archive', label: 'Archive and retention' },
];

/** `/settings` (design §1.3 row 21): each tab gated by its operation; security is self-service. */
export function SettingsPage() {
  return (
    <RouteGate gate={navGate('settings')}>
      <div className="flex flex-col gap-4">
        <PageHeader
          title="Settings"
          description={
            <>
              Organization, notification, account security and scanning settings. Quarantine
              settings are under{' '}
              <Link
                href="/quarantine/settings"
                className="text-primary underline underline-offset-2"
              >
                Quarantine settings
              </Link>{' '}
              and policy settings under{' '}
              <Link
                href="/policies?tab=settings"
                className="text-primary underline underline-offset-2"
              >
                Policy management
              </Link>
              .
            </>
          }
        />
        <GatedTabs
          tabs={SETTINGS_TABS}
          label="Settings"
          keepParams={[]}
          render={(tab) => {
            switch (tab) {
              case 'organization':
                return <OrganizationTab />;
              case 'notifications':
                return <AlertSettingsPanel />;
              case 'preferences':
                return <PreferencesPanel />;
              case 'security':
                return <SecurityTab />;
              case 'scanning':
                return <ScanSettingsPanel />;
              default:
                return (
                  <UnavailableState
                    step="8.1"
                    title="Archive and retention settings"
                    description="Archive and retention settings arrive in 8.1 together with journaling and compliance archiving; no API exists for them yet."
                  />
                );
            }
          }}
        />
      </div>
    </RouteGate>
  );
}

function OrganizationTab() {
  const me = useMe();
  const organizationId = me.data?.organization.id;
  const organization = useApiQuery(
    'OrganizationsController_get_v1',
    { path: { id: organizationId ?? '' } },
    { enabled: Boolean(organizationId) },
  );
  if (!organizationId || organization.isLoading)
    return <LoadingState label="Loading your organization" rows={6} />;
  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <ReportSection title="Organization profile">
        {organization.error ? (
          <ErrorState
            error={organization.error}
            onRetry={() => void organization.refetch()}
            compact
          />
        ) : organization.data ? (
          <Can
            op="OrganizationsController_update_v1"
            fallback={<p className="text-sm">{organization.data.name}</p>}
          >
            <ProfileForm organization={organization.data} allowPlan={false} />
          </Can>
        ) : null}
      </ReportSection>
      <ReportSection title="Organization settings" className="xl:col-span-2">
        <OrganizationSettingsPanel organizationId={organizationId} />
      </ReportSection>
    </div>
  );
}

function SecurityTab() {
  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <ReportSection title="Password">
        <ChangePasswordForm />
      </ReportSection>
      <ReportSection title="Two-factor authentication">
        <MfaPanel />
      </ReportSection>
      <ReportSection title="Sessions" className="xl:col-span-2">
        <SessionsPanel />
      </ReportSection>
    </div>
  );
}
