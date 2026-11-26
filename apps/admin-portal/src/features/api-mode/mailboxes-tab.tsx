'use client';

import { MailboxIcon } from 'lucide-react';
import { useMemo, useState } from 'react';
import { z } from 'zod';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { DateTime } from '@/components/domain/date-time';
import { UntrustedText } from '@/components/domain/untrusted-text';
import { EmptyState } from '@/components/states/empty-state';
import { useUrlState } from '@/hooks/use-url-state';
import { useApiMutation, useApiQuery, useCursorList } from '@/lib/api/hooks';
import type { QueryParams } from '@/lib/api/types';
import { useCan } from '@/lib/auth/me';
import { humanize } from '@/lib/format';
import { FilterSelect, MutationError } from '@/features/domains/kit';
import { API_MODE_QUERIES } from './coverage-tab';
import {
  COVERAGE_STATES,
  CoverageBadge,
  FEED_STATUSES,
  FeedStatusBadge,
  MAILBOX_STATUSES,
  type Mailbox,
} from './model';

const URL_SHAPE = {
  q: z.string().max(320).optional().catch(undefined),
  connection: z.string().uuid().optional().catch(undefined),
  coverage: z.enum(COVERAGE_STATES).optional().catch(undefined),
  feedStatus: z.enum(FEED_STATUSES).optional().catch(undefined),
  status: z.enum(MAILBOX_STATUSES).optional().catch(undefined),
  domainId: z.string().uuid().optional().catch(undefined),
};

/** The list query of the URL filters (`GET /api-mode/mailboxes`, v1 cursor; D12 #10). */
export function mailboxQuery(filters: {
  q?: string;
  connection?: string;
  coverage?: string;
  feedStatus?: string;
  status?: string;
  domainId?: string;
}): QueryParams<'ApiModeController_listMailboxes_v1'> {
  return {
    ...(filters.q ? { q: filters.q.trim().toLowerCase() } : {}),
    ...(filters.connection ? { connectionId: filters.connection } : {}),
    ...(filters.coverage ? { coverage: filters.coverage } : {}),
    ...(filters.feedStatus ? { feedStatus: filters.feedStatus } : {}),
    ...(filters.status ? { status: filters.status } : {}),
    ...(filters.domainId ? { domainId: filters.domainId } : {}),
  };
}

function resyncErrorText(code: string | undefined): string | null {
  return code === 'api_mode_mailbox_access_required'
    ? 'Resync needs the active mailbox access grant of the connection.'
    : null;
}

/** Tab "Mailboxes" (D14): cursor table with filters and the resync action. */
export function MailboxesTab() {
  const [filters, setFilters] = useUrlState(URL_SHAPE);
  const canResync = useCan('ApiModeController_resyncMailbox_v1');
  const canListDomains = useCan('DomainsController_list_v1');
  const connections = useApiQuery('ApiModeController_listConnections_v1');
  const domains = useApiQuery(
    'DomainsController_list_v1',
    { query: { limit: 100 } },
    { enabled: canListDomains },
  );
  const [resyncing, setResyncing] = useState<Mailbox | null>(null);
  const resync = useApiMutation('ApiModeController_resyncMailbox_v1', {
    invalidates: API_MODE_QUERIES,
    successMessage: 'Resync requested: the feed restarts from now (no backfill).',
  });
  const query = useMemo(() => mailboxQuery(filters), [filters]);
  const list = useCursorList('ApiModeController_listMailboxes_v1', query);

  const columns = useMemo<DataTableColumn<Mailbox>[]>(
    () => [
      {
        id: 'address',
        header: 'Mailbox',
        meta: { label: 'Mailbox' },
        cell: ({ row }) => <UntrustedText value={row.original.address} mono maxLength={80} />,
      },
      {
        id: 'domain',
        header: 'Domain',
        meta: { label: 'Domain' },
        cell: ({ row }) => row.original.domain?.name ?? '—',
      },
      {
        id: 'status',
        header: 'Status',
        meta: { label: 'Status' },
        cell: ({ row }) => humanize(row.original.status),
      },
      {
        id: 'coverage',
        header: 'Coverage',
        meta: { label: 'Coverage' },
        cell: ({ row }) => <CoverageBadge coverage={row.original.coverage} />,
      },
      {
        id: 'feedStatus',
        header: 'Feed',
        meta: { label: 'Feed' },
        cell: ({ row }) => <FeedStatusBadge status={row.original.feedStatus} />,
      },
      {
        id: 'journalLastSeenAt',
        header: 'Last journal copy',
        meta: { label: 'Last journal copy' },
        cell: ({ row }) => <DateTime value={row.original.journalLastSeenAt} emptyLabel="None" />,
      },
      {
        id: 'lastSyncAt',
        header: 'Last feed sync',
        meta: { label: 'Last feed sync' },
        cell: ({ row }) => <DateTime value={row.original.lastSyncAt} emptyLabel="Never" />,
      },
      {
        id: 'lastErrorCode',
        header: 'Last error',
        meta: { label: 'Last error' },
        cell: ({ row }) =>
          row.original.lastErrorCode ? humanize(row.original.lastErrorCode) : 'None',
      },
    ],
    [],
  );

  const connectionOptions = (connections.data?.data ?? []).map((c) => ({
    value: c.id,
    label: c.displayName,
  }));
  const domainOptions = (domains.data?.data ?? []).map((d) => ({
    value: d.id,
    label: d.unicodeName,
  }));
  const isFiltered = Object.values(filters).some(Boolean);

  return (
    <>
      <DataTable
        tableId="api-mode-mailboxes"
        caption="Mailboxes protected in API mode"
        columns={columns}
        list={list}
        getRowId={(row) => row.id}
        getRowLabel={(row) => row.address}
        search={{
          value: filters.q ?? '',
          onChange: (value) => setFilters({ q: value || undefined }),
          label: 'Search mailboxes by address prefix',
          placeholder: 'Address prefix',
        }}
        filters={
          <>
            {connectionOptions.length > 1 ? (
              <FilterSelect
                label="Connection"
                value={filters.connection}
                onChange={(connection) => setFilters({ connection })}
                options={connectionOptions}
              />
            ) : null}
            <FilterSelect
              label="Coverage"
              value={filters.coverage}
              onChange={(coverage) =>
                setFilters({ coverage: coverage as (typeof COVERAGE_STATES)[number] | undefined })
              }
              options={COVERAGE_STATES.map((value) => ({ value, label: humanize(value) }))}
            />
            <FilterSelect
              label="Feed"
              value={filters.feedStatus}
              onChange={(feedStatus) =>
                setFilters({ feedStatus: feedStatus as (typeof FEED_STATUSES)[number] | undefined })
              }
              options={FEED_STATUSES.map((value) => ({ value, label: humanize(value) }))}
            />
            <FilterSelect
              label="Status"
              value={filters.status}
              onChange={(status) =>
                setFilters({ status: status as (typeof MAILBOX_STATUSES)[number] | undefined })
              }
              options={MAILBOX_STATUSES.map((value) => ({ value, label: humanize(value) }))}
            />
            {domainOptions.length > 0 ? (
              <FilterSelect
                label="Domain"
                value={filters.domainId}
                onChange={(domainId) => setFilters({ domainId })}
                options={domainOptions}
              />
            ) : null}
          </>
        }
        isFiltered={isFiltered}
        onClearFilters={() =>
          setFilters({
            q: undefined,
            connection: undefined,
            coverage: undefined,
            feedStatus: undefined,
            status: undefined,
            domainId: undefined,
          })
        }
        rowActions={
          canResync
            ? (row) => [
                {
                  label: 'Resync feed',
                  onSelect: () => setResyncing(row),
                  disabled: row.feedStatus === 'off' || row.feedStatus === 'revoked',
                },
              ]
            : undefined
        }
        emptyState={
          <EmptyState
            icon={MailboxIcon}
            title="No mailboxes yet"
            description="Mailboxes appear after the first inventory sync (mailbox access granted) or with the first journal copy addressed to them."
          />
        }
        mobileCard={(row) => (
          <div className="grid gap-1">
            <UntrustedText value={row.address} mono maxLength={60} />
            <div className="flex flex-wrap items-center gap-2">
              <CoverageBadge coverage={row.coverage} />
              <FeedStatusBadge status={row.feedStatus} />
            </div>
          </div>
        )}
      />
      <ConfirmDialog
        open={resyncing !== null}
        onOpenChange={(open) => {
          if (!open) {
            setResyncing(null);
            resync.reset();
          }
        }}
        title="Resync this mailbox feed?"
        description="The feed cursor is reset and restarts from now. Mail already in the mailbox is not fetched again (no backfill); the change is audited."
        confirmLabel="Resync"
        error={
          resync.error ? (
            <div className="grid gap-1">
              {resyncErrorText(resync.error.code) ? (
                <p className="text-xs font-medium text-destructive">
                  {resyncErrorText(resync.error.code)}
                </p>
              ) : null}
              <MutationError error={resync.error} />
            </div>
          ) : null
        }
        onConfirm={async () => {
          if (!resyncing) return false;
          const outcome = await resync.submit({ path: { mailboxId: resyncing.id } });
          return outcome.ok;
        }}
      />
    </>
  );
}
