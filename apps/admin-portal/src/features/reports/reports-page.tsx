'use client';

import { z } from 'zod';
import { PageHeader } from '@/components/page-header';
import { RangePicker, useRangeState } from '@/components/range-picker';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useUrlState } from '@/hooks/use-url-state';
import { RouteGate } from '@/lib/auth/route-gate';
import { navGate } from './nav-gate';
import {
  DeliveryTab,
  ProcessingTab,
  ThreatsTab,
  TopDomainsTab,
  TrafficTab,
  UrlClicksTab,
} from './report-tabs';

export const REPORT_TABS = [
  'traffic',
  'threats',
  'delivery',
  'processing',
  'url-clicks',
  'top-domains',
] as const;

export const REPORTS_URL_SHAPE = {
  tab: z.enum(REPORT_TABS).default('traffic').catch('traffic'),
  granularity: z.enum(['hour', 'day']).optional().catch(undefined),
  direction: z.enum(['inbound', 'outbound', 'internal']).optional().catch(undefined),
  limit: z.coerce.number().int().min(5).max(25).default(10).catch(10),
};

const TAB_LABELS: Record<(typeof REPORT_TABS)[number], string> = {
  traffic: 'Traffic',
  threats: 'Threats',
  delivery: 'Delivery',
  processing: 'Processing',
  'url-clicks': 'URL clicks',
  'top-domains': 'Top domains',
};

/** `/reports` (design §1.3 row 18): the six report operations over one bounded range. */
export function ReportsPage() {
  return (
    <RouteGate gate={navGate('reports')}>
      <ReportsContent />
    </RouteGate>
  );
}

function ReportsContent() {
  const [range] = useRangeState();
  const [state, setState] = useUrlState(REPORTS_URL_SHAPE);
  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Reports"
        description="Aggregates computed by the api from recorded rows over a bounded UTC window (at most 31 days; longer ranges arrive with the analytics store). Downloads contain only the figures shown."
        actions={<RangePicker />}
      />
      <Tabs
        value={state.tab}
        onValueChange={(value) => setState({ tab: value as (typeof REPORT_TABS)[number] })}
      >
        <div className="overflow-x-auto">
          <TabsList aria-label="Reports">
            {REPORT_TABS.map((tab) => (
              <TabsTrigger key={tab} value={tab}>
                {TAB_LABELS[tab]}
              </TabsTrigger>
            ))}
          </TabsList>
        </div>
        <TabsContent value="traffic">
          {state.tab === 'traffic' ? (
            <TrafficTab
              range={range}
              granularity={state.granularity}
              direction={state.direction}
              onChange={(patch) => setState(patch)}
            />
          ) : null}
        </TabsContent>
        <TabsContent value="threats">
          {state.tab === 'threats' ? <ThreatsTab range={range} /> : null}
        </TabsContent>
        <TabsContent value="delivery">
          {state.tab === 'delivery' ? <DeliveryTab range={range} /> : null}
        </TabsContent>
        <TabsContent value="processing">
          {state.tab === 'processing' ? <ProcessingTab range={range} /> : null}
        </TabsContent>
        <TabsContent value="url-clicks">
          {state.tab === 'url-clicks' ? <UrlClicksTab range={range} /> : null}
        </TabsContent>
        <TabsContent value="top-domains">
          {state.tab === 'top-domains' ? (
            <TopDomainsTab
              range={range}
              limit={state.limit}
              onLimitChange={(limit) => setState({ limit })}
            />
          ) : null}
        </TabsContent>
      </Tabs>
    </div>
  );
}
