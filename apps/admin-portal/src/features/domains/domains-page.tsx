'use client';

import { GlobeIcon, PlusIcon } from 'lucide-react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useMemo } from 'react';
import { z } from 'zod';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { DateTime } from '@/components/domain/date-time';
import { PageHeader } from '@/components/page-header';
import { EmptyState } from '@/components/states/empty-state';
import { Button } from '@/components/ui/button';
import { useUrlState } from '@/hooks/use-url-state';
import { useCursorList } from '@/lib/api/hooks';
import { Can } from '@/lib/auth/can';
import { useCan } from '@/lib/auth/me';
import { RouteGate } from '@/lib/auth/route-gate';
import { FilterSelect } from './kit';
import {
  DOMAIN_STATUSES,
  DOMAIN_STATUS_LABEL,
  DomainStatusBadge,
  type DomainSummary,
} from './model';

const URL_SHAPE = {
  q: z.string().max(253).optional().catch(undefined),
  status: z
    .enum(DOMAIN_STATUSES as [string, ...string[]])
    .optional()
    .catch(undefined),
};

function FlowFlags({ domain }: { domain: DomainSummary }) {
  return (
    <span className="flex flex-wrap gap-1 text-xs">
      <span>Inbound {domain.inboundEnabled ? 'on' : 'off'}</span>
      <span aria-hidden>·</span>
      <span>Outbound {domain.outboundEnabled ? 'on' : 'off'}</span>
    </span>
  );
}

function onboardingIncomplete(domain: DomainSummary): boolean {
  return domain.status !== 'active' && domain.status !== 'suspended';
}

/** `/domains`: the organization's domains (`GET /domains`, v0 cursor, `q` and `status`). */
export function DomainsPage() {
  return (
    <RouteGate gate={['DomainsController_list_v1']}>
      <DomainsList />
    </RouteGate>
  );
}

function DomainsList() {
  const router = useRouter();
  const [filters, setFilters] = useUrlState(URL_SHAPE);
  const canCreate = useCan('DomainsController_create_v1');
  const query = useMemo(
    () => ({
      ...(filters.q ? { q: filters.q } : {}),
      ...(filters.status ? { status: filters.status as DomainSummary['status'] } : {}),
    }),
    [filters.q, filters.status],
  );
  const list = useCursorList('DomainsController_list_v1', query);

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
        id: 'flow',
        header: 'Mail flow',
        meta: { label: 'Mail flow' },
        cell: ({ row }) => <FlowFlags domain={row.original} />,
      },
      {
        id: 'verifiedAt',
        header: 'Verified',
        meta: { label: 'Verified' },
        cell: ({ row }) => <DateTime value={row.original.verifiedAt} emptyLabel="Not yet" />,
      },
      {
        id: 'lastCheckedAt',
        header: 'Last DNS check',
        meta: { label: 'Last DNS check' },
        cell: ({ row }) => <DateTime value={row.original.lastCheckedAt} />,
      },
      {
        id: 'createdAt',
        header: 'Added',
        meta: { label: 'Added' },
        cell: ({ row }) => <DateTime value={row.original.createdAt} />,
      },
    ],
    [],
  );

  return (
    <div className="grid min-w-0 gap-6 [&>*]:min-w-0">
      <PageHeader
        title="Domains"
        description="The mail domains of your organization: ownership, DNS records, mail flow and destination servers."
        actions={
          <Can op="DomainsController_create_v1">
            <Button asChild>
              <Link href="/domains/onboarding">
                <PlusIcon aria-hidden />
                Add domain
              </Link>
            </Button>
          </Can>
        }
      />
      <DataTable
        tableId="domains"
        caption="Domains"
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
        filters={
          <FilterSelect
            label="Status"
            value={filters.status}
            onChange={(status) => setFilters({ status })}
            options={DOMAIN_STATUSES.map((value) => ({
              value,
              label: DOMAIN_STATUS_LABEL[value],
            }))}
          />
        }
        isFiltered={Boolean(filters.q || filters.status)}
        onClearFilters={() => setFilters({ q: undefined, status: undefined })}
        rowActions={(row) => [
          { label: 'Open', onSelect: () => router.push(`/domains/${row.id}`) },
          ...(canCreate && onboardingIncomplete(row)
            ? [
                {
                  label: 'Continue onboarding',
                  onSelect: () => router.push(`/domains/onboarding?domainId=${row.id}`),
                },
              ]
            : []),
        ]}
        emptyState={
          <EmptyState
            icon={GlobeIcon}
            title="No domains yet"
            description="Add a domain, prove ownership with a DNS record and point its MX to the gateway."
            action={
              canCreate ? (
                <Button asChild size="sm">
                  <Link href="/domains/onboarding">Add domain</Link>
                </Button>
              ) : undefined
            }
          />
        }
        mobileCard={(row) => (
          <div className="grid gap-1">
            <Link href={`/domains/${row.id}`} className="font-medium text-primary hover:underline">
              {row.unicodeName}
            </Link>
            <div className="flex flex-wrap items-center gap-2">
              <DomainStatusBadge status={row.status} />
              <FlowFlags domain={row} />
            </div>
          </div>
        )}
      />
    </div>
  );
}
