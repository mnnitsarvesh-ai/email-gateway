'use client';

import { z } from 'zod';
import { PageHeader } from '@/components/page-header';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useUrlState } from '@/hooks/use-url-state';
import type { OperationId } from '@/lib/api/types';
import { usePermissions } from '@/lib/auth/me';
import { canPerform } from '@/lib/auth/permissions';
import { RouteGate } from '@/lib/auth/route-gate';
import { ConnectorsTab } from './connectors-tab';
import { DeliveriesTab } from './deliveries-tab';
import { DestinationsTab } from './destinations-tab';
import { SuppressionsTab } from './suppressions-tab';

export const MAIL_SERVER_TABS = [
  'destinations',
  'connectors',
  'suppressions',
  'deliveries',
] as const;
type Tab = (typeof MAIL_SERVER_TABS)[number];

/** The operation each tab needs (tabs are gated individually, design §1.3 row 8). */
export const TAB_GATE: Record<Tab, OperationId> = {
  destinations: 'DomainDestinationsController_get_v1',
  connectors: 'SmtpConnectorsController_list_v1',
  suppressions: 'RecipientSuppressionsController_list_v1',
  deliveries: 'DeliveriesController_list_v1',
};

const LABEL: Record<Tab, string> = {
  destinations: 'Destination servers',
  connectors: 'SMTP connectors',
  suppressions: 'Suppressions',
  deliveries: 'Deliveries',
};

const URL_SHAPE = { tab: z.enum(MAIL_SERVER_TABS).optional().catch(undefined) };

/** `/mail-servers` (`?tab=destinations|connectors|suppressions|deliveries`). */
export function MailServersPage() {
  return (
    <RouteGate
      gate={[
        'DomainDestinationsController_get_v1',
        'SmtpConnectorsController_list_v1',
        'RecipientSuppressionsController_list_v1',
      ]}
    >
      <MailServers />
    </RouteGate>
  );
}

function MailServers() {
  const permissions = usePermissions();
  const [state, setState] = useUrlState(URL_SHAPE);
  const allowed = MAIL_SERVER_TABS.filter((tab) => canPerform(TAB_GATE[tab], permissions));
  const tab = state.tab && allowed.includes(state.tab) ? state.tab : allowed[0];
  return (
    <div className="grid min-w-0 gap-6 [&>*]:min-w-0">
      <PageHeader
        title="Mail servers"
        description="Where inbound mail is delivered, which of your servers may relay outbound mail, suppressed recipients and the delivery status of every recipient. Delivery routes have no API and are not shown."
      />
      {tab ? (
        <Tabs
          value={tab}
          onValueChange={(value) => setState({ tab: value as Tab }, { push: true })}
        >
          <TabsList aria-label="Mail server sections">
            {allowed.map((value) => (
              <TabsTrigger key={value} value={value}>
                {LABEL[value]}
              </TabsTrigger>
            ))}
          </TabsList>
          {allowed.includes('destinations') ? (
            <TabsContent value="destinations" className="min-w-0">
              {tab === 'destinations' ? <DestinationsTab /> : null}
            </TabsContent>
          ) : null}
          {allowed.includes('connectors') ? (
            <TabsContent value="connectors" className="min-w-0">
              {tab === 'connectors' ? <ConnectorsTab /> : null}
            </TabsContent>
          ) : null}
          {allowed.includes('suppressions') ? (
            <TabsContent value="suppressions" className="min-w-0">
              {tab === 'suppressions' ? <SuppressionsTab /> : null}
            </TabsContent>
          ) : null}
          {allowed.includes('deliveries') ? (
            <TabsContent value="deliveries" className="min-w-0">
              {tab === 'deliveries' ? <DeliveriesTab /> : null}
            </TabsContent>
          ) : null}
        </Tabs>
      ) : null}
    </div>
  );
}
