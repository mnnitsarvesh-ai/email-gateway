'use client';

import Link from 'next/link';
import { PageHeader } from '@/components/page-header';
import { useApiQuery } from '@/lib/api/hooks';
import { RouteGate } from '@/lib/auth/route-gate';
import { GatedTabs, type TabDefinition } from '@/features/reports/gated-tabs';
import { CoverageTab } from './coverage-tab';
import { DetectionsTab } from './detections-tab';
import { HistoryTab } from './history-tab';
import { MailboxesTab } from './mailboxes-tab';
import { MODE_LABEL } from './model';
import { PurgeTab } from './purge-tab';
import { RemediationTab } from './remediation-tab';
import { ReportsTab } from './reports-tab';
import { SettingsTab } from './settings-tab';
import { SetupTab } from './setup-tab';

export const API_MODE_TABS: readonly TabDefinition[] = [
  { id: 'coverage', label: 'Coverage', ops: ['ApiModeController_overview_v1'] },
  { id: 'mailboxes', label: 'Mailboxes', ops: ['ApiModeController_listMailboxes_v1'] },
  { id: 'detections', label: 'Detections', ops: ['ApiModeController_listDetections_v1'] },
  // Step API-3 (docs/plan/steps/37-api-mode-clawback-reporting.md C14).
  { id: 'purge', label: 'Search & purge', ops: ['ApiModeClawbackController_list_v1'] },
  { id: 'reports', label: 'Reports', ops: ['ApiModeReportsController_list_v1'] },
  // Step API-2 R15.
  {
    id: 'remediation',
    label: 'Remediation',
    ops: ['ApiModeRemediationController_getPolicy_v1'],
  },
  { id: 'history', label: 'History', ops: ['ApiModeRemediationController_list_v1'] },
  { id: 'settings', label: 'Settings', ops: ['ApiModeSettingsController_get_v1'] },
  { id: 'setup', label: 'Setup', ops: ['ApiModeController_getConnection_v1'] },
];

/** Entitlement and activity of API mode for the organization (D1), from the overview. */
function StatusNotice() {
  const overview = useApiQuery('ApiModeController_overview_v1', undefined, {
    refetchInterval: 60_000,
  });
  const data = overview.data;
  if (!data) return null;
  if (!data.entitled) {
    return (
      <p role="status" className="rounded-md border p-3 text-sm">
        API-mode protection is not part of this organization&apos;s plan: domains stay in Inline
        mode. Mailbox coverage, feeds and detections appear once the feature is enabled.
      </p>
    );
  }
  if (!data.active) {
    return (
      <p role="status" className="rounded-md border p-3 text-sm">
        No domain is in API or Hybrid mode yet (organization mode:{' '}
        {MODE_LABEL[data.organizationMode]}
        ). Choose a mode on a{' '}
        <Link href="/domains" className="text-primary underline underline-offset-2">
          domain
        </Link>{' '}
        or for the whole organization to start protecting mailboxes without an MX change.
      </p>
    );
  }
  return null;
}

/**
 * `/api-mode` "Mailbox protection" (step API-1 D14, step API-2 R15, step API-3 C14): coverage and
 * health, mailboxes, detections with their mailbox actions, search and purge (clawbacks), reported
 * phishing, the remediation policy, the history of mailbox actions, the organization settings with
 * the report mailboxes and per-connection setup. Read-only users see every tab without the write
 * controls.
 */
export function ApiModePage() {
  return (
    <RouteGate gate={['ApiModeController_overview_v1']}>
      <div className="grid min-w-0 gap-6 [&>*]:min-w-0">
        <PageHeader
          title="Mailbox protection"
          description="API-mode protection: the gateway scans a copy of each message delivered to your Microsoft 365 or Google Workspace mailboxes, without an MX change. Mail flow is never changed, delayed or bounced."
        />
        <StatusNotice />
        <GatedTabs
          tabs={API_MODE_TABS}
          label="Mailbox protection"
          keepParams={['range', 'from', 'to', 'connection']}
          render={(tab) =>
            tab === 'coverage' ? (
              <CoverageTab />
            ) : tab === 'mailboxes' ? (
              <MailboxesTab />
            ) : tab === 'detections' ? (
              <DetectionsTab />
            ) : tab === 'purge' ? (
              <PurgeTab />
            ) : tab === 'reports' ? (
              <ReportsTab />
            ) : tab === 'remediation' ? (
              <RemediationTab />
            ) : tab === 'history' ? (
              <HistoryTab />
            ) : tab === 'settings' ? (
              <SettingsTab />
            ) : (
              <SetupTab />
            )
          }
        />
      </div>
    </RouteGate>
  );
}
