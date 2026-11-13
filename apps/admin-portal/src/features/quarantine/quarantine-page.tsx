'use client';

import { usePathname, useRouter } from 'next/navigation';
import { z } from 'zod';
import { PageHeader } from '@/components/page-header';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useUrlState } from '@/hooks/use-url-state';
import type { OperationId } from '@/lib/api/types';
import { usePermissions } from '@/lib/auth/me';
import { canPerform } from '@/lib/auth/permissions';
import { RouteGate } from '@/lib/auth/route-gate';
import { ApprovalsTab } from './approvals';
import { EntriesTab } from './entries-tab';
import { quarantineTabHref } from './links';
import { SelfTab } from './self-service';
import { SettingsTab } from './settings-tab';

export const QUARANTINE_TABS = ['entries', 'approvals', 'me', 'settings'] as const;
export type QuarantineTab = (typeof QUARANTINE_TABS)[number];

const TAB_GATE: Record<QuarantineTab, OperationId> = {
  entries: 'QuarantineEntriesController_search_v1',
  approvals: 'QuarantineApprovalsController_list_v1',
  me: 'QuarantineSelfController_search_v1',
  settings: 'QuarantineToolsController_getSettings_v1',
};
const TAB_LABEL: Record<QuarantineTab, string> = {
  entries: 'Entries',
  approvals: 'Approvals',
  me: 'My quarantine',
  settings: 'Settings',
};

const TAB_URL_SHAPE = { tab: z.enum(QUARANTINE_TABS).optional().catch(undefined) };

/**
 * Quarantine (`/quarantine?tab=entries|approvals|me|settings`) and the sub-routes
 * `/quarantine/approvals`, `/quarantine/me`, `/quarantine/settings` (fixed `routeTab`).
 * Tabs are shown by permission; the api decides every action.
 */
export function QuarantinePage({ routeTab }: { routeTab?: QuarantineTab }) {
  return (
    <RouteGate
      gate={['QuarantineEntriesController_search_v1', 'QuarantineSelfController_search_v1']}
    >
      <QuarantineContent routeTab={routeTab} />
    </RouteGate>
  );
}

function QuarantineContent({ routeTab }: { routeTab?: QuarantineTab }) {
  const permissions = usePermissions();
  const router = useRouter();
  const pathname = usePathname();
  const [state] = useUrlState(TAB_URL_SHAPE);
  const visible = QUARANTINE_TABS.filter((tab) => canPerform(TAB_GATE[tab], permissions));
  const fallback = visible[0] ?? 'entries';
  const tab: QuarantineTab = routeTab ?? state.tab ?? fallback;
  const tabs = visible.includes(tab) ? visible : [...visible, tab];
  const onlySelf = visible.length === 1 && visible[0] === 'me';

  // Each tab has its own filters: a tab change starts from a clean `/quarantine?tab=` URL.
  const change = (next: string) =>
    router.push(quarantineTabHref(next), { scroll: pathname !== '/quarantine' });

  return (
    <div className="grid gap-4">
      <PageHeader
        title={onlySelf ? 'My quarantine' : 'Quarantine'}
        description={
          onlySelf
            ? 'Messages addressed to you that were held because they looked dangerous or unwanted.'
            : 'Messages held per recipient by policy, with approvals, self-service and settings. Content is shown only as a sanitized text preview.'
        }
      />
      <Tabs value={tab} onValueChange={change}>
        {tabs.length > 1 ? (
          <TabsList aria-label="Quarantine views">
            {tabs.map((name) => (
              <TabsTrigger key={name} value={name}>
                {TAB_LABEL[name]}
              </TabsTrigger>
            ))}
          </TabsList>
        ) : null}
        <TabsContent value="entries">
          {tab === 'entries' ? (
            <RouteGate gate={[TAB_GATE.entries]}>
              <EntriesTab />
            </RouteGate>
          ) : null}
        </TabsContent>
        <TabsContent value="approvals">
          {tab === 'approvals' ? (
            <RouteGate gate={[TAB_GATE.approvals]}>
              <ApprovalsTab />
            </RouteGate>
          ) : null}
        </TabsContent>
        <TabsContent value="me">
          {tab === 'me' ? (
            <RouteGate gate={[TAB_GATE.me]}>
              <SelfTab />
            </RouteGate>
          ) : null}
        </TabsContent>
        <TabsContent value="settings">
          {tab === 'settings' ? (
            <RouteGate gate={[TAB_GATE.settings]}>
              <SettingsTab />
            </RouteGate>
          ) : null}
        </TabsContent>
      </Tabs>
    </div>
  );
}
