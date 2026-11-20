'use client';

import { KeyRoundIcon, PlusIcon } from 'lucide-react';
import Link from 'next/link';
import { useState } from 'react';
import { DateTime } from '@/components/domain';
import { PageHeader } from '@/components/page-header';
import { EmptyState } from '@/components/states/empty-state';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { useApiQuery } from '@/lib/api/hooks';
import { useCan } from '@/lib/auth/me';
import { RouteGate } from '@/lib/auth/route-gate';
import { FeatureOffNotice } from '../components';
import { ACTION_LABELS, labelOf } from '../model';
import { ConnectProviderDialog } from './connect-dialog';
import { CodeText, HealthBadge, IntegrationStatusBadge } from './components';
import {
  PROVIDER_LABELS,
  formatLag,
  newConnectionHref,
  providerHref,
  type ProviderSummary,
} from './model';

/** `/ato/providers`: the identity-provider integrations of the organization (step 8.5 §7). */
export function AtoProvidersPage() {
  return (
    <RouteGate gate={['AtoProvidersController_list_v1']}>
      <ProvidersContent />
    </RouteGate>
  );
}

function ProvidersContent() {
  const canConnect = useCan('AtoProvidersController_create_v1');
  const canSeeConnections = useCan('ProviderConnectionsController_list_v1');
  const [includeDisabled, setIncludeDisabled] = useState(false);
  const [connectOpen, setConnectOpen] = useState(false);
  const list = useApiQuery(
    'AtoProvidersController_list_v1',
    includeDisabled ? { query: { includeDisabled: 'true' } } : undefined,
  );
  const data = list.data;
  return (
    <div className="grid min-w-0 gap-4">
      <PageHeader
        title="Identity providers"
        breadcrumbs={[{ label: 'Account takeover', href: '/ato' }, { label: 'Identity providers' }]}
        description="Microsoft Entra ID / Microsoft 365 and Google Workspace sign-ins, risk events, OAuth consents and mailbox changes for account takeover detection, and provider-confirmed responses."
        actions={
          canConnect && data?.featureEnabled ? (
            <Button size="sm" onClick={() => setConnectOpen(true)}>
              <PlusIcon aria-hidden />
              Connect identity provider
            </Button>
          ) : null
        }
      />
      {list.isLoading ? (
        <LoadingState label="Loading identity providers" variant="table" />
      ) : list.error ? (
        <ErrorState error={list.error} onRetry={() => void list.refetch()} />
      ) : !data ? null : !data.featureEnabled ? (
        <FeatureOffNotice />
      ) : (
        <>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="text-sm text-muted-foreground">
              {data.limit.used} of {data.limit.max} identity providers in use.
            </p>
            <div className="flex items-center gap-2">
              <Switch
                id="ato-providers-include-disabled"
                checked={includeDisabled}
                onCheckedChange={(checked) => setIncludeDisabled(checked === true)}
              />
              <Label htmlFor="ato-providers-include-disabled" className="text-sm">
                Show removed
              </Label>
            </div>
          </div>
          {data.data.length === 0 ? (
            <EmptyState
              icon={KeyRoundIcon}
              title="No identity provider connected"
              description={
                <span>
                  Identity providers are read through a Microsoft 365 or Google Workspace connection
                  with the account takeover permissions.{' '}
                  {canSeeConnections ? (
                    <Link
                      href={newConnectionHref}
                      className="text-primary underline underline-offset-2"
                    >
                      Create a connection in Integrations
                    </Link>
                  ) : (
                    'An administrator creates the connection in Integrations.'
                  )}
                  , then connect it here.
                </span>
              }
            />
          ) : (
            <ul className="grid gap-3 lg:grid-cols-2" aria-label="Identity providers">
              {data.data.map((p) => (
                <ProviderCard key={p.id} provider={p} />
              ))}
            </ul>
          )}
        </>
      )}
      {canConnect ? (
        <ConnectProviderDialog open={connectOpen} onOpenChange={setConnectOpen} />
      ) : null}
    </div>
  );
}

function ProviderCard({ provider: p }: { provider: ProviderSummary }) {
  const name = p.displayName ?? p.connection?.displayName ?? PROVIDER_LABELS[p.provider];
  return (
    <li className="grid min-w-0 gap-3 rounded-lg border bg-card p-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="grid min-w-0 gap-0.5">
          <Link
            href={providerHref(p.id)}
            className="font-medium break-words text-primary underline-offset-2 hover:underline"
          >
            {name}
          </Link>
          <span className="text-xs text-muted-foreground">{PROVIDER_LABELS[p.provider]}</span>
        </div>
        <span className="flex flex-wrap gap-1">
          <IntegrationStatusBadge status={p.status} />
          <HealthBadge status={p.health.status} stale={p.health.stale} />
        </span>
      </div>
      <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm sm:grid-cols-4">
        <div>
          <dt className="text-xs text-muted-foreground">Streams</dt>
          <dd>
            {p.streams.enabled} enabled
            {p.streams.failing > 0 ? `, ${p.streams.failing} failing` : ''}
          </dd>
        </div>
        <div>
          <dt className="text-xs text-muted-foreground">Worst lag</dt>
          <dd>{formatLag(p.streams.maxLagSeconds)}</dd>
        </div>
        <div>
          <dt className="text-xs text-muted-foreground">Backfilling</dt>
          <dd>{p.streams.backfilling}</dd>
        </div>
        <div>
          <dt className="text-xs text-muted-foreground">Last check</dt>
          <dd>
            <DateTime value={p.health.checkedAt} emptyLabel="Never" />
          </dd>
        </div>
      </dl>
      <div className="grid gap-1 text-sm">
        <span className="text-xs text-muted-foreground">Actions available</span>
        <span>
          {p.capabilities.actions.length > 0
            ? p.capabilities.actions.map((a) => labelOf(ACTION_LABELS, a)).join(', ')
            : 'None'}
        </span>
      </div>
      {p.status === 'paused' && p.pausedReason ? (
        <p className="text-xs">
          Paused: <CodeText code={p.pausedReason} />
        </p>
      ) : null}
      {p.status === 'disabled' ? (
        <p className="text-xs text-muted-foreground">
          Removed <DateTime value={p.disabledAt} />
          {p.disabledReason ? (
            <>
              {' '}
              · <CodeText code={p.disabledReason} />
            </>
          ) : null}
        </p>
      ) : null}
    </li>
  );
}
