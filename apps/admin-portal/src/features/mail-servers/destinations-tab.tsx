'use client';

import { GlobeIcon } from 'lucide-react';
import Link from 'next/link';
import { useMemo } from 'react';
import { z } from 'zod';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { EmptyState } from '@/components/states/empty-state';
import { Button } from '@/components/ui/button';
import { useUrlState } from '@/hooks/use-url-state';
import { useApiQuery, useCursorList } from '@/lib/api/hooks';
import { Can } from '@/lib/auth/can';
import { humanize } from '@/lib/format';
import { DomainStatusBadge, type DomainSummary } from '@/features/domains/model';

const URL_SHAPE = { q: z.string().max(253).optional().catch(undefined) };

/** The destinations of one domain, fetched only for the rows on the current page. */
export function DestinationsCell({ domainId }: { domainId: string }) {
  const query = useApiQuery('DomainDestinationsController_get_v1', { path: { id: domainId } });
  if (query.isLoading) return <span className="text-xs text-muted-foreground">Loading …</span>;
  if (query.error)
    return (
      <span className="text-xs text-destructive">
        Could not load ({query.error.code}
        {query.error.requestId ? `, request ${query.error.requestId}` : ''})
      </span>
    );
  const data = query.data;
  if (!data || data.servers.length === 0)
    return <span className="text-xs text-muted-foreground">None (mail is held)</span>;
  return (
    <span className="grid gap-0.5 text-xs">
      <span className="font-medium">{humanize(data.provider ?? 'custom')}</span>
      {data.servers.map((server) => (
        <code key={server.id} className="font-mono break-all">
          {server.host}:{server.port} ({server.priority})
        </code>
      ))}
    </span>
  );
}

/** Per-domain destination overview (paginated domains, destinations fetched per visible row). */
export function DestinationsTab() {
  const [filters, setFilters] = useUrlState(URL_SHAPE);
  const list = useCursorList('DomainsController_list_v1', filters.q ? { q: filters.q } : {}, {
    limit: 10,
  });
  const columns = useMemo<DataTableColumn<DomainSummary>[]>(
    () => [
      {
        id: 'name',
        header: 'Domain',
        meta: { label: 'Domain' },
        cell: ({ row }) => (
          <Link
            href={`/domains/${row.original.id}`}
            className="font-medium text-primary hover:underline"
          >
            {row.original.unicodeName}
          </Link>
        ),
      },
      {
        id: 'status',
        header: 'Status',
        meta: { label: 'Status' },
        cell: ({ row }) => <DomainStatusBadge status={row.original.status} />,
      },
      {
        id: 'destinations',
        header: 'Destination servers',
        meta: { label: 'Destination servers' },
        cell: ({ row }) => <DestinationsCell domainId={row.original.id} />,
      },
      {
        id: 'edit',
        header: () => <span className="sr-only">Edit</span>,
        meta: { label: 'Edit', hideable: false },
        cell: ({ row }) => (
          <Can op="DomainDestinationsController_replace_v1">
            <Button asChild variant="outline" size="sm">
              <Link
                href={`/domains/${row.original.id}?tab=destinations`}
                aria-label={`Edit destinations of ${row.original.unicodeName}`}
              >
                Edit
              </Link>
            </Button>
          </Can>
        ),
      },
    ],
    [],
  );
  return (
    <DataTable
      tableId="mail-servers-destinations"
      caption="Destination servers per domain"
      columns={columns}
      list={list}
      getRowId={(row) => row.id}
      getRowLabel={(row) => row.unicodeName}
      search={{
        value: filters.q ?? '',
        onChange: (value) => setFilters({ q: value || undefined }),
        label: 'Search domains by name prefix',
        placeholder: 'Search domains',
      }}
      isFiltered={Boolean(filters.q)}
      onClearFilters={() => setFilters({ q: undefined })}
      emptyState={
        <EmptyState
          icon={GlobeIcon}
          title="No domains yet"
          description="Destination servers are set per domain; add a domain first."
        />
      }
      mobileCard={(row) => (
        <div className="grid gap-1">
          <Link
            href={`/domains/${row.id}?tab=destinations`}
            className="font-medium text-primary hover:underline"
          >
            {row.unicodeName}
          </Link>
          <DestinationsCell domainId={row.id} />
        </div>
      )}
    />
  );
}
