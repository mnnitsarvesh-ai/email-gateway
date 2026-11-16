'use client';

import { WorkflowIcon } from 'lucide-react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { z } from 'zod';
import { PageHeader } from '@/components/page-header';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useUrlState } from '@/hooks/use-url-state';
import type { OperationId } from '@/lib/api/types';
import { useCan, usePermissions } from '@/lib/auth/me';
import { canPerform } from '@/lib/auth/permissions';
import { RouteGate } from '@/lib/auth/route-gate';
import { ScanningTab } from './config-tabs';
import { BecTab, DlpTab } from './dlp-bec';
import { EmailPoliciesTab } from './email-policies';
import { ExecutionsTab } from './executions';
import { POLICY_BUILDER_HREF, policiesTabHref } from './links';
import { RiskTab } from './risk/risk-tab';
import { PolicySettingsTab } from './settings-tab';

export const POLICY_TABS = [
  'email',
  'executions',
  'settings',
  'risk',
  'scanning',
  'dlp',
  'bec',
] as const;
type PolicyTab = (typeof POLICY_TABS)[number];

const TAB_GATE: Record<PolicyTab, OperationId> = {
  email: 'PolicyManagementController_list_v1',
  executions: 'PolicyToolsController_history_v1',
  settings: 'PolicySettingsController_get_v1',
  risk: 'RiskProfilesController_profile_v1',
  scanning: 'ScanSettingsController_list_v1',
  dlp: 'DlpPoliciesController_list_v1',
  bec: 'BecExecutivesController_list_v1',
};
const TAB_LABEL: Record<PolicyTab, string> = {
  email: 'Email policies',
  executions: 'Executions',
  settings: 'Policy settings',
  risk: 'Risk scoring',
  scanning: 'Scanning',
  dlp: 'DLP',
  bec: 'BEC',
};

const URL_SHAPE = { tab: z.enum(POLICY_TABS).default('email').catch('email') };

/**
 * Policy management (`/policies?tab=…`, page 13; step 7.3 design B13, B17): email policies with
 * "New policy", the execution history, the editable policy settings, risk-profile drafts,
 * scanning, and the DLP and BEC tabs.
 */
export function PoliciesPage() {
  return (
    <RouteGate gate={['PolicyManagementController_list_v1']}>
      <PoliciesContent />
    </RouteGate>
  );
}

function PoliciesContent() {
  const [state] = useUrlState(URL_SHAPE);
  const router = useRouter();
  const permissions = usePermissions();
  const canCatalog = useCan('PolicyToolsController_catalog_v1');
  const visible = POLICY_TABS.filter((tab) => canPerform(TAB_GATE[tab], permissions));
  const tab = visible.includes(state.tab) ? state.tab : (visible[0] ?? 'email');
  return (
    <div className="grid gap-4">
      <PageHeader
        title="Policy management"
        description="Email policies, their execution history, policy and risk settings, scanning, DLP and BEC configuration of your organization."
        actions={
          canCatalog ? (
            <Button asChild variant="outline" size="sm">
              <Link href={POLICY_BUILDER_HREF}>
                <WorkflowIcon aria-hidden />
                Policy builder
              </Link>
            </Button>
          ) : null
        }
      />
      <Tabs
        value={tab}
        onValueChange={(next) => router.push(policiesTabHref(next), { scroll: false })}
      >
        <TabsList aria-label="Policy views">
          {visible.map((name) => (
            <TabsTrigger key={name} value={name}>
              {TAB_LABEL[name]}
            </TabsTrigger>
          ))}
        </TabsList>
        <TabsContent value="email">{tab === 'email' ? <EmailPoliciesTab /> : null}</TabsContent>
        <TabsContent value="executions">
          {tab === 'executions' ? <ExecutionsTab /> : null}
        </TabsContent>
        <TabsContent value="settings">
          {tab === 'settings' ? <PolicySettingsTab /> : null}
        </TabsContent>
        <TabsContent value="risk">{tab === 'risk' ? <RiskTab /> : null}</TabsContent>
        <TabsContent value="scanning">{tab === 'scanning' ? <ScanningTab /> : null}</TabsContent>
        <TabsContent value="dlp">{tab === 'dlp' ? <DlpTab /> : null}</TabsContent>
        <TabsContent value="bec">{tab === 'bec' ? <BecTab /> : null}</TabsContent>
      </Tabs>
    </div>
  );
}
