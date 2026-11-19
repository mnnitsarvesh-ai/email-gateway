'use client';

import { z } from 'zod';
import { NotFoundView } from '@/components/not-found-view';
import { PageHeader } from '@/components/page-header';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useUrlState } from '@/hooks/use-url-state';
import { useApiQuery } from '@/lib/api/hooks';
import { RouteGate } from '@/lib/auth/route-gate';
import { QueryView, isUuid } from '@/features/domains/kit';
import { GuideTab } from './guide-tab';
import { HealthTab } from './health-tab';
import {
  ConnectionStatusBadge,
  HealthBadge,
  OutboundBadge,
  PROVIDER_LABEL,
  type Catalog,
  type Connection,
} from './model';
import { SettingsTab } from './settings-tab';
import { SetupTab } from './setup-tab';
import { ValidationsTab } from './validations';

export const CONNECTION_TABS = ['setup', 'health', 'validations', 'guide', 'settings'] as const;
type Tab = (typeof CONNECTION_TABS)[number];

const TAB_LABEL: Record<Tab, string> = {
  setup: 'Setup',
  health: 'Health',
  validations: 'Validations',
  guide: 'Setup guide',
  settings: 'Settings',
};

const URL_SHAPE = { tab: z.enum(CONNECTION_TABS).optional().catch(undefined) };

function ConnectionContent({
  connection,
  catalog,
}: {
  connection: Connection;
  catalog: Catalog | undefined;
}) {
  const [state, setState] = useUrlState(URL_SHAPE);
  const tab = state.tab ?? (connection.status === 'active' ? 'health' : 'setup');
  const provider = catalog?.providers.find((p) => p.provider === connection.provider);
  return (
    <div className="grid min-w-0 gap-6 [&>*]:min-w-0">
      <PageHeader
        title={connection.displayName}
        breadcrumbs={[
          { label: 'Integrations', href: '/integrations' },
          { label: connection.displayName },
        ]}
        description={
          <span className="inline-flex flex-wrap items-center gap-2">
            <span>{PROVIDER_LABEL[connection.provider]}</span>
            <span aria-hidden>·</span>
            <span>
              {connection.tenantName
                ? `Tenant ${connection.tenantName}`
                : 'Tenant not connected yet'}
            </span>
            <ConnectionStatusBadge status={connection.status} />
            <HealthBadge status={connection.health} />
            <span className="inline-flex items-center gap-1">
              Outbound <OutboundBadge mode={connection.outboundMode} />
            </span>
          </span>
        }
      />
      {connection.status === 'disabled' ? (
        <p role="status" className="rounded-md border p-3 text-sm">
          This connection is disconnected. Its history stays visible; connect again with a new
          connection.
        </p>
      ) : null}
      <Tabs value={tab} onValueChange={(value) => setState({ tab: value as Tab }, { push: true })}>
        <TabsList aria-label="Connection sections">
          {CONNECTION_TABS.map((value) => (
            <TabsTrigger key={value} value={value}>
              {TAB_LABEL[value]}
            </TabsTrigger>
          ))}
        </TabsList>
        <TabsContent value="setup" className="min-w-0">
          {tab === 'setup' ? <SetupTab connection={connection} catalog={provider} /> : null}
        </TabsContent>
        <TabsContent value="health" className="min-w-0">
          {tab === 'health' ? <HealthTab connection={connection} /> : null}
        </TabsContent>
        <TabsContent value="validations" className="min-w-0">
          {tab === 'validations' ? <ValidationsTab connection={connection} /> : null}
        </TabsContent>
        <TabsContent value="guide" className="min-w-0">
          {tab === 'guide' ? <GuideTab connection={connection} /> : null}
        </TabsContent>
        <TabsContent value="settings" className="min-w-0">
          {tab === 'settings' ? <SettingsTab connection={connection} /> : null}
        </TabsContent>
      </Tabs>
    </div>
  );
}

function ConnectionLoader({ connectionId }: { connectionId: string }) {
  const valid = isUuid(connectionId);
  const connection = useApiQuery(
    'ProviderConnectionsController_get_v1',
    { path: { id: connectionId } },
    {
      enabled: valid,
      retry: false,
      // The worker verifies grants and binds tenants asynchronously: poll while it works (the
      // tenant is bound only after a linked domain is verified in it, D4).
      refetchInterval: (query) => {
        const c = query.state.data;
        const binding =
          c?.status === 'configuring' &&
          c.tenantId === null &&
          c.grants.some((g) => g.status === 'active') &&
          c.domains.some(
            (d) => d.providerVerification === 'unknown' || d.providerVerification === 'verified',
          );
        return c?.grants.some((g) => g.status === 'verifying') ||
          c?.status === 'connecting' ||
          binding
          ? 5000
          : false;
      },
    },
  );
  const catalog = useApiQuery('ProviderCatalogController_get_v1', undefined, {
    staleTime: 300_000,
  });
  if (!valid) return <NotFoundView />;
  return (
    <QueryView query={connection} label="connection">
      {(data) => <ConnectionContent connection={data} catalog={catalog.data} />}
    </QueryView>
  );
}

/** `/integrations/providers/[connectionId]` (`?tab=setup|health|validations|guide|settings`). */
export function ConnectionPage({ connectionId }: { connectionId: string }) {
  return (
    <RouteGate gate={['ProviderConnectionsController_get_v1']}>
      <ConnectionLoader connectionId={connectionId} />
    </RouteGate>
  );
}
