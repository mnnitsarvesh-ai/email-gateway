'use client';

import Link from 'next/link';
import { useMemo } from 'react';
import { DateTime, ToneBadge } from '@/components/domain';
import { EmptyState } from '@/components/states/empty-state';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { useApiMutation, useApiQuery, useCursorList } from '@/lib/api/hooks';
import { useCan } from '@/lib/auth/me';
import { humanize } from '@/lib/format';
import { CursorPager, Section } from '@/features/messages/controls';
import { SignalTable } from '../account-page';
import { pagerOf, ScrollRegion } from '../components';
import { incidentHref, type AtoAccountDetail } from '../model';
import { RequestResponseButton } from '../response-actions';
import { ProviderErrorSummary } from './components';
import {
  MAILBOX_ITEM_KIND_LABELS,
  PROVIDER_LABELS,
  TRAIT_LABELS,
  canRemoveForwarding,
  providerHref,
  providersHref,
  type MailboxItem,
  type MailboxState,
} from './model';

/** Signal categories derived from identity-provider data (§7). */
export const PROVIDER_SIGNAL_CATEGORIES = [
  'mailbox_configuration',
  'oauth_activity',
  'provider_risk',
] as const;

/**
 * "Mailbox changes" tab of an ATO account (step 8.5 §7): the mailbox state the identity providers
 * report (forwarding, inbox rules and filters, delegates; target domains only, never addresses or
 * rule keywords), the account's provider-derived signals, "Refresh now" and per-item "Remove
 * forwarding" through 8.4's response request (needs the account's active incident).
 */
export function MailboxChangesTab({ account }: { account: AtoAccountDetail }) {
  const canRefresh = useCan('AtoAccountMailboxController_refresh_v1');
  const state = useApiQuery(
    'AtoAccountMailboxController_get_v1',
    { path: { accountId: account.id } },
    { retry: false },
  );
  const refresh = useApiMutation('AtoAccountMailboxController_refresh_v1', {
    invalidates: ['AtoAccountMailboxController_get_v1'],
    successMessage: 'Refresh requested: the provider is read again at its next poll',
  });
  const data = state.data;
  const refreshable = data?.identities.some((i) => i.refreshSupported) ?? false;
  return (
    <div className="grid min-w-0 gap-4">
      <Section
        title="Mailbox state"
        description="Forwarding, inbox rules and filters, delegates and mailbox permissions reported by the identity provider (present items and items removed in the last 30 days). Forwarding targets are shown by domain only."
        actions={
          canRefresh && data ? (
            <Button
              size="sm"
              variant="outline"
              disabled={!refreshable || refresh.isPending}
              onClick={() => void refresh.submit({ path: { accountId: account.id } })}
            >
              Refresh now
            </Button>
          ) : null
        }
      >
        {state.isLoading ? (
          <LoadingState label="Loading the mailbox state" variant="table" />
        ) : state.error ? (
          <ErrorState error={state.error} onRetry={() => void state.refetch()} compact />
        ) : !data ? null : (
          <>
            {refresh.error ? <ProviderErrorSummary error={refresh.error} /> : null}
            <Sources state={data} />
            {data.items.length === 0 ? (
              <EmptyState
                title="No mailbox items reported"
                description={
                  data.integrations.length === 0 ? (
                    <span>
                      No identity provider reports this mailbox.{' '}
                      <Link
                        href={providersHref}
                        className="text-primary underline underline-offset-2"
                      >
                        Identity providers
                      </Link>
                    </span>
                  ) : (
                    'The provider reports no forwarding, rule or delegate for this mailbox.'
                  )
                }
              />
            ) : (
              <ItemTable account={account} items={data.items} />
            )}
            {data.truncated ? (
              <p className="text-xs text-muted-foreground">Only the first 500 items are shown.</p>
            ) : null}
          </>
        )}
      </Section>
      <ProviderSignals account={account} />
    </div>
  );
}

function Sources({ state }: { state: MailboxState }) {
  return (
    <ul className="grid gap-1 text-sm" aria-label="Provider identities">
      {state.identities.map((i, index) => {
        const integration = state.integrations.find((x) => x.id === i.integrationId);
        return (
          <li key={`${i.integrationId ?? i.provider}-${index}`} className="flex flex-wrap gap-2">
            <span className="font-mono text-xs">{i.userPrincipalName ?? 'unnamed identity'}</span>
            <ToneBadge
              tone={
                i.directoryStatus === 'active'
                  ? 'success'
                  : i.directoryStatus === 'unknown'
                    ? 'neutral'
                    : 'danger'
              }
            >
              {i.directoryStatus === 'unknown'
                ? 'Directory status unknown'
                : `Directory: ${humanize(i.directoryStatus)}`}
            </ToneBadge>
            {integration ? (
              <Link
                href={providerHref(integration.id)}
                className="text-xs text-primary underline underline-offset-2"
              >
                {integration.displayName ?? PROVIDER_LABELS[integration.provider]}
              </Link>
            ) : null}
            <span className="text-xs text-muted-foreground">
              {integration?.lastSweepAt ? (
                <>
                  Last read <DateTime value={integration.lastSweepAt} />
                </>
              ) : (
                'Not read yet'
              )}
              {i.refreshRequestedAt ? (
                <>
                  {' '}
                  · refresh requested <DateTime value={i.refreshRequestedAt} />
                </>
              ) : null}
              {!i.refreshSupported ? ' · refresh not available' : ''}
            </span>
          </li>
        );
      })}
    </ul>
  );
}

function ItemTable({
  account,
  items,
}: {
  account: AtoAccountDetail;
  items: readonly MailboxItem[];
}) {
  return (
    <ScrollRegion label="Mailbox items">
      <table className="w-full min-w-[48rem] text-left text-sm">
        <caption className="sr-only">Mailbox items</caption>
        <thead className="bg-muted/50 text-xs text-muted-foreground">
          <tr>
            {['Item', 'State', 'Target domain', 'Behaviour', 'Enabled', 'Seen', ''].map((h, i) => (
              <th key={h || i} scope="col" className="px-2 py-1.5 font-medium whitespace-nowrap">
                {h || <span className="sr-only">Actions</span>}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr key={item.id} className="border-t align-top">
              <th scope="row" className="px-2 py-1.5 font-normal">
                <span className="font-medium">{MAILBOX_ITEM_KIND_LABELS[item.kind]}</span>
                <span className="block text-xs text-muted-foreground">
                  {PROVIDER_LABELS[item.provider]} ·{' '}
                  {item.source === 'audit' ? 'audit log' : 'snapshot'} · last {item.lastChange}
                </span>
              </th>
              <td className="px-2 py-1.5">
                <ToneBadge tone={item.state === 'present' ? 'warning' : 'neutral'}>
                  {item.state === 'present' ? 'Present' : 'Removed'}
                </ToneBadge>
                {item.removedAt ? (
                  <span className="block text-xs text-muted-foreground">
                    <DateTime value={item.removedAt} />
                  </span>
                ) : null}
              </td>
              <td className="px-2 py-1.5 font-mono text-xs">{item.targetDomain ?? '—'}</td>
              <td className="px-2 py-1.5 text-xs">
                {item.traits.length > 0
                  ? item.traits.map((t) => TRAIT_LABELS[t] ?? humanize(t)).join(', ')
                  : '—'}
              </td>
              <td className="px-2 py-1.5">
                {item.enabled === null ? '—' : item.enabled ? 'Yes' : 'No'}
              </td>
              <td className="px-2 py-1.5 text-xs whitespace-nowrap">
                first <DateTime value={item.firstSeenAt} />
                <br />
                last <DateTime value={item.lastSeenAt} />
              </td>
              <td className="px-2 py-1.5">
                {canRemoveForwarding(item) ? (
                  <RemoveForwarding account={account} item={item} />
                ) : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </ScrollRegion>
  );
}

function RemoveForwarding({ account, item }: { account: AtoAccountDetail; item: MailboxItem }) {
  const can = useCan('AtoResponsesController_request_v1');
  if (!can) return null;
  const subject = `${MAILBOX_ITEM_KIND_LABELS[item.kind]}${item.targetDomain ? ` forwarding to ${item.targetDomain}` : ''}`;
  if (!account.activeIncident) {
    return (
      <span className="text-xs text-muted-foreground">
        Removal is requested from an active incident of this account.
      </span>
    );
  }
  return (
    <span className="grid gap-1">
      <RequestResponseButton
        incidentId={account.activeIncident.id}
        accountKind={account.kind}
        label="Remove forwarding"
        preset={{ actionType: 'remove_forwarding_rule', params: { itemId: item.id }, subject }}
      />
      {item.provider === 'microsoft_entra' && item.kind === 'forwarding' ? (
        <span className="text-xs text-muted-foreground">
          Microsoft Graph cannot change mailbox-level forwarding: the request will answer
          “unsupported” with the manual step.
        </span>
      ) : null}
      <Link
        href={incidentHref(account.activeIncident.id)}
        className="text-xs text-primary underline-offset-2 hover:underline"
      >
        Incident
      </Link>
    </span>
  );
}

function ProviderSignals({ account }: { account: AtoAccountDetail }) {
  const can = useCan('AtoAccountsController_signals_v1');
  const filters = useMemo(
    () => ({ sort: '-detectedAt' as const, category: PROVIDER_SIGNAL_CATEGORIES.join(',') }),
    [],
  );
  if (!can) return null;
  return <ProviderSignalList account={account} filters={filters} />;
}

function ProviderSignalList({
  account,
  filters,
}: {
  account: AtoAccountDetail;
  filters: { sort: '-detectedAt'; category: string };
}) {
  const list = useCursorList('AtoAccountsController_signals_v1', filters, {
    path: { accountId: account.id },
    limit: 25,
  });
  return (
    <Section
      title="Identity-provider signals"
      description="Mailbox configuration, OAuth consent and provider risk signals of the last 30 days."
      headingLevel={3}
    >
      {list.query.isLoading ? (
        <LoadingState label="Loading provider signals" variant="table" />
      ) : list.query.error ? (
        <ErrorState error={list.query.error} onRetry={() => void list.query.refetch()} compact />
      ) : list.rows.length === 0 ? (
        <EmptyState title="No identity-provider signals in this range" />
      ) : (
        <SignalTable rows={list.rows} caption="Identity-provider signals of the account" />
      )}
      <CursorPager label="Provider signal pages" state={pagerOf(list)} />
    </Section>
  );
}
