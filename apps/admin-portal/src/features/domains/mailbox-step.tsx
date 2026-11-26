'use client';

import { useQueries } from '@tanstack/react-query';
import Link from 'next/link';
import { ToneBadge } from '@/components/domain/tone-badge';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { callOperation } from '@/lib/api/call';
import type { ApiError } from '@/lib/api/errors';
import { queryKeyFor, shouldRetry, useApiQuery } from '@/lib/api/hooks';
import { useCan } from '@/lib/auth/me';
import { humanize } from '@/lib/format';
import { grantHref } from '@/features/api-mode/coverage-tab';
import { MailboxGrantBadge, type ApiModeConnection } from '@/features/api-mode/model';
import { PROVIDER_LABEL } from '@/features/integrations/providers/model';
import { intakeSourceHref } from '@/features/journaling/model';

export interface MailboxLinks {
  /** API-mode views of the provider connections linked to the domain; `null` = unknown. */
  readonly linked: readonly ApiModeConnection[] | null;
  /** A linked connection has an active mailbox grant or a verified journal source. */
  readonly ready: boolean | null;
  readonly isLoading: boolean;
  readonly error: ApiError | null;
  readonly refetch: () => void;
}

/**
 * The provider connections linked to a domain with their API-mode state (step API-1 D3):
 * `GET /api-mode/connections` (grant status and journal sources per connection) joined with the
 * linked domains of each 8.2 connection (`GET /provider-connections/{id}`). Server state only.
 */
export function useMailboxLinks(domainId: string, enabled: boolean): MailboxLinks {
  const canApiMode = useCan('ApiModeController_listConnections_v1');
  const canProvider = useCan('ProviderConnectionsController_get_v1');
  const list = useApiQuery('ApiModeController_listConnections_v1', undefined, {
    enabled: enabled && canApiMode,
  });
  const connections = list.data?.data ?? [];
  const details = useQueries({
    queries: connections.map((c) => ({
      queryKey: queryKeyFor('ProviderConnectionsController_get_v1', { path: { id: c.id } }),
      queryFn: ({ signal }: { signal: AbortSignal }) =>
        callOperation('ProviderConnectionsController_get_v1', { path: { id: c.id } }, { signal }),
      enabled: enabled && canProvider,
      retry: shouldRetry,
      staleTime: 30_000,
    })),
  });
  if (!enabled || !canApiMode || !canProvider) {
    return { linked: null, ready: null, isLoading: false, error: null, refetch: () => undefined };
  }
  const detailError = details.find((d) => d.error)?.error;
  const loading = list.isLoading || details.some((d) => d.isLoading);
  if (loading || list.error || detailError) {
    return {
      linked: null,
      ready: null,
      isLoading: loading,
      error: (list.error ?? (detailError as ApiError | undefined)) || null,
      refetch: () => void list.refetch(),
    };
  }
  const linked = connections.filter((_, index) =>
    details[index]?.data?.domains.some((domain) => domain.id === domainId),
  );
  return {
    linked,
    ready: linked.some(
      (c) => c.grant?.status === 'active' || c.journalSources.some((source) => source.verified),
    ),
    isLoading: false,
    error: null,
    refetch: () => void list.refetch(),
  };
}

/**
 * Wizard step "Mailbox protection" (API and Hybrid, D3): the linked provider connection, its
 * mailbox-access grant and its journal intake source, with links to the 8.2 connection page and
 * `/api-mode`. Informational: activation never waits for it.
 */
export function MailboxStep({ links }: { links: MailboxLinks }) {
  if (links.isLoading) return <LoadingState label="Loading the provider connections" rows={3} />;
  if (links.error) return <ErrorState error={links.error} onRetry={links.refetch} />;
  if (links.linked === null) {
    return (
      <p className="text-sm text-muted-foreground">
        Your role cannot read provider connections or mailbox protection; an administrator with
        integration and remediation read access sees the connection state here.
      </p>
    );
  }
  if (links.linked.length === 0) {
    return (
      <div className="grid gap-2 text-sm">
        <p>
          No Microsoft 365 or Google Workspace connection is linked to this domain yet. Connect your
          provider and link this domain, then add a journal copy or grant mailbox access.
        </p>
        <div className="flex flex-wrap gap-3">
          <Link href="/integrations" className="text-primary underline underline-offset-2">
            Open integrations
          </Link>
          <Link href="/api-mode" className="text-primary underline underline-offset-2">
            Open mailbox protection
          </Link>
        </div>
      </div>
    );
  }
  return (
    <ul className="grid gap-3" aria-label="Linked provider connections">
      {links.linked.map((connection) => (
        <li key={connection.id} className="grid gap-2 rounded-md border p-3 text-sm">
          <div className="flex flex-wrap items-center gap-2">
            <Link
              href={`/integrations/providers/${connection.id}`}
              className="font-medium text-primary hover:underline"
            >
              {connection.displayName}
            </Link>
            <span className="text-muted-foreground">
              {PROVIDER_LABEL[connection.provider]} · {humanize(connection.status)}
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-medium text-muted-foreground">Mailbox access</span>
            <MailboxGrantBadge status={connection.grant?.status ?? null} />
            <Link
              href={grantHref(connection.id)}
              className="text-xs text-primary underline underline-offset-2"
            >
              {connection.grant?.status === 'active' ? 'Manage' : 'Grant mailbox access'}
            </Link>
          </div>
          <div className="grid gap-1">
            <span className="text-xs font-medium text-muted-foreground">Journal copy</span>
            {connection.journalSources.length === 0 ? (
              <span>
                No journal intake source on this connection.{' '}
                <Link
                  href="/settings?tab=journaling"
                  className="text-primary underline underline-offset-2"
                >
                  Add one under Journaling
                </Link>
              </span>
            ) : (
              <ul className="grid gap-1">
                {connection.journalSources.map((source) => (
                  <li key={source.id} className="flex flex-wrap items-center gap-2">
                    <Link
                      href={intakeSourceHref(source.id)}
                      className="text-primary underline underline-offset-2"
                    >
                      {source.displayName}
                    </Link>
                    <ToneBadge tone={source.verified ? 'success' : 'warning'}>
                      {source.verified ? 'Verified' : 'Not verified yet'}
                    </ToneBadge>
                    <span className="text-xs text-muted-foreground">
                      {humanize(source.status)} · health {humanize(source.health)}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </div>
          <Link href="/api-mode" className="text-primary underline underline-offset-2">
            Open mailbox protection
          </Link>
        </li>
      ))}
    </ul>
  );
}
