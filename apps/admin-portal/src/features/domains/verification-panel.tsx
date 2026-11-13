'use client';

import { useQueryClient } from '@tanstack/react-query';
import { RefreshCwIcon } from 'lucide-react';
import type { ReactNode } from 'react';
import { DateTime } from '@/components/domain/date-time';
import { UntrustedText } from '@/components/domain/untrusted-text';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { queryKeyFor, useApiMutation, useApiQuery } from '@/lib/api/hooks';
import { Can } from '@/lib/auth/can';
import { humanize } from '@/lib/format';
import { MutationError } from './kit';
import { DomainStatusBadge, RecordStatusBadge, type DomainStatusView } from './model';

/** Backoff of the status poll while verification is pending: 5 s, 10 s, 20 s, 40 s, then 60 s. */
export function pollDelay(updates: number): number {
  return Math.min(60_000, 5_000 * 2 ** Math.max(0, Math.min(updates - 1, 4)));
}

type Check = DomainStatusView['checks'][keyof DomainStatusView['checks']];

function CheckRow({ name, check, extra }: { name: string; check: Check; extra?: ReactNode }) {
  return (
    <li className="grid gap-1 rounded-md border p-3 text-sm">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="font-medium">{name}</span>
        <RecordStatusBadge status={check.status} />
      </div>
      <span className="text-xs text-muted-foreground">
        Last checked <DateTime value={check.lastCheckedAt} emptyLabel="never" />
        {check.lastOutcome === 'indeterminate' ? ' · no definitive DNS answer, retried' : ''}
      </span>
      {extra}
      {check.warnings.length > 0 ? (
        <ul className="grid gap-0.5 text-xs text-tone-warning-foreground">
          {check.warnings.map((warning, i) => (
            <li key={i}>
              <UntrustedText value={warning} maxLength={240} />
            </li>
          ))}
        </ul>
      ) : null}
    </li>
  );
}

/**
 * Verification and DNS check status (`GET /domains/{id}/status`), polled with backoff while the
 * domain waits for ownership proof; "Verify now" runs a fresh check (`POST /domains/{id}/verify`).
 */
export function VerificationPanel({ domainId }: { domainId: string }) {
  const queryClient = useQueryClient();
  const status = useApiQuery(
    'DomainDnsController_status_v1',
    { path: { id: domainId } },
    {
      refetchInterval: (query) =>
        query.state.data?.status === 'pending_verification'
          ? pollDelay(query.state.dataUpdateCount)
          : false,
    },
  );
  const verify = useApiMutation('DomainDnsController_verify_v1', {
    invalidates: [
      'DomainsController_get_v1',
      'DomainsController_list_v1',
      'DomainDnsController_dnsRecords_v1',
    ],
    onSuccess: (data) => {
      queryClient.setQueryData(
        queryKeyFor('DomainDnsController_status_v1', { path: { id: domainId } }),
        data,
      );
    },
  });

  if (status.isLoading) return <LoadingState label="Loading verification status" rows={4} />;
  if (status.error)
    return <ErrorState error={status.error} onRetry={() => void status.refetch()} />;
  const view = status.data;
  if (!view) return null;
  const pending = view.status === 'pending_verification' || view.status === 'failed';

  return (
    <div className="grid min-w-0 gap-4 [&>*]:min-w-0">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="grid gap-1 text-sm">
          <span className="flex flex-wrap items-center gap-2">
            <DomainStatusBadge status={view.status} />
            {view.statusReason ? (
              <span className="text-muted-foreground">{humanize(view.statusReason)}</span>
            ) : null}
          </span>
          <span className="text-xs text-muted-foreground">
            Last check <DateTime value={view.lastCheckedAt} emptyLabel="not yet run" /> · next check{' '}
            <DateTime value={view.nextCheckAt} emptyLabel="not scheduled" />
            {view.checkFailures > 0
              ? ` · ${view.checkFailures} inconclusive DNS lookups in a row`
              : ''}
          </span>
        </div>
        <Can op="DomainDnsController_verify_v1">
          <Button
            variant={pending ? 'default' : 'outline'}
            onClick={() => void verify.submit({ path: { id: domainId } })}
            disabled={verify.isPending || verify.retryAfterSeconds > 0}
          >
            <RefreshCwIcon aria-hidden className={verify.isPending ? 'animate-spin' : undefined} />
            {verify.isPending
              ? 'Checking DNS …'
              : verify.retryAfterSeconds > 0
                ? `Verify now (${verify.retryAfterSeconds} s)`
                : 'Verify now'}
          </Button>
        </Can>
      </div>
      {pending ? (
        <p className="text-sm text-muted-foreground" role="status">
          {view.status === 'failed'
            ? 'Verification failed. Check the ownership record and run Verify now: a failed domain restarts verification with the same token.'
            : 'Waiting for the ownership record. DNS changes can take minutes to hours to reach every resolver; this view refreshes automatically and the gateway keeps checking in the background.'}
        </p>
      ) : null}
      <MutationError error={verify.error} />
      <ul className="grid gap-2 md:grid-cols-2" aria-label="DNS checks">
        <CheckRow name="Ownership (TXT)" check={view.checks.ownership} />
        <CheckRow
          name="MX"
          check={view.checks.mx}
          extra={
            view.checks.mx.observed.length > 0 ? (
              <ul className="grid gap-0.5 text-xs">
                {view.checks.mx.observed.map((mx) => (
                  <li key={`${mx.priority}-${mx.host}`}>
                    <span className="tabular-nums">{mx.priority}</span>{' '}
                    <UntrustedText value={mx.host} mono />{' '}
                    {mx.pointsToGateway ? '(gateway)' : '(not the gateway)'}
                  </li>
                ))}
              </ul>
            ) : null
          }
        />
        <CheckRow
          name="SPF"
          check={view.checks.spf}
          extra={
            view.checks.spf.lookupCount !== null && view.checks.spf.lookupCount !== undefined ? (
              <span className="text-xs">
                DNS lookups in the record: {view.checks.spf.lookupCount}
              </span>
            ) : null
          }
        />
        <CheckRow
          name="DKIM"
          check={view.checks.dkim}
          extra={
            view.checks.dkim.selectors.length > 0 ? (
              <ul className="grid gap-0.5 text-xs">
                {view.checks.dkim.selectors.map((s) => (
                  <li key={s.selector}>
                    <code className="font-mono">{s.selector}</code> ({humanize(s.algorithm)}): key{' '}
                    {humanize(s.keyStatus).toLowerCase()}, record{' '}
                    {humanize(s.recordStatus).toLowerCase()}
                  </li>
                ))}
              </ul>
            ) : null
          }
        />
        <CheckRow
          name="DMARC"
          check={view.checks.dmarc}
          extra={
            <span className="text-xs">
              Stage: {humanize(view.checks.dmarc.stage)}. {view.checks.dmarc.nextStep}
            </span>
          }
        />
      </ul>
      <p className="text-xs text-muted-foreground">
        {view.readyForActivation
          ? 'Ownership is proven: the domain can be activated.'
          : view.mailFlowReady
            ? 'Mail flow is ready: the domain is active and its MX points to the gateway.'
            : view.status === 'active'
              ? 'The domain is active; mail flows once its MX record points to the gateway.'
              : 'Activation needs proven ownership only; switch the MX record after activating.'}
      </p>
    </div>
  );
}
