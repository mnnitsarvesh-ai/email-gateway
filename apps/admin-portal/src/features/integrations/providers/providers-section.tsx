'use client';

import { MailIcon, PlusIcon } from 'lucide-react';
import Link from 'next/link';
import { useMemo } from 'react';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { DateTime } from '@/components/domain/date-time';
import { EmptyState } from '@/components/states/empty-state';
import { Button } from '@/components/ui/button';
import { useCursorList } from '@/lib/api/hooks';
import { Can } from '@/lib/auth/can';
import { Section } from '@/features/domains/kit';
import {
  ConnectionStatusBadge,
  HealthBadge,
  OutboundBadge,
  PROVIDER_LABEL,
  type ConnectionRow,
} from './model';

/**
 * The "Microsoft 365 and Google Workspace" section of `/integrations` (step 8.2 §6): the
 * organization's provider connections and "Connect" (gate `ProviderConnectionsController_create_v1`).
 */
export function ProvidersSection() {
  const list = useCursorList('ProviderConnectionsController_list_v1', undefined, { limit: 25 });
  const columns = useMemo<DataTableColumn<ConnectionRow>[]>(
    () => [
      {
        id: 'name',
        header: 'Connection',
        meta: { label: 'Connection' },
        cell: ({ row }) => (
          <Link
            href={`/integrations/providers/${row.original.id}`}
            className="font-medium underline-offset-4 hover:underline"
          >
            {row.original.displayName}
          </Link>
        ),
      },
      {
        id: 'provider',
        header: 'Provider',
        meta: { label: 'Provider' },
        cell: ({ row }) => (
          <span className="inline-flex items-center gap-2">
            <MailIcon className="size-4 text-muted-foreground" aria-hidden />
            {PROVIDER_LABEL[row.original.provider]}
          </span>
        ),
      },
      {
        id: 'tenant',
        header: 'Tenant',
        meta: { label: 'Tenant' },
        cell: ({ row }) =>
          row.original.tenantName ?? <span className="text-muted-foreground">Not connected</span>,
      },
      {
        id: 'status',
        header: 'Status',
        meta: { label: 'Status' },
        cell: ({ row }) => <ConnectionStatusBadge status={row.original.status} />,
      },
      {
        id: 'health',
        header: 'Health',
        meta: { label: 'Health' },
        cell: ({ row }) => <HealthBadge status={row.original.health} />,
      },
      {
        id: 'outbound',
        header: 'Outbound',
        meta: { label: 'Outbound' },
        cell: ({ row }) => <OutboundBadge mode={row.original.outboundMode} />,
      },
      {
        id: 'domains',
        header: 'Domains',
        meta: { label: 'Domains' },
        cell: ({ row }) => row.original.domainCount,
      },
      {
        id: 'createdAt',
        header: 'Created',
        meta: { label: 'Created' },
        cell: ({ row }) => <DateTime value={row.original.createdAt} />,
      },
    ],
    [],
  );

  return (
    <Section
      title="Microsoft 365 and Google Workspace"
      description="Route Microsoft 365 (Exchange Online) and Google Workspace mail through the gateway. The gateway only reads your tenant; every change on your side is an instruction you apply yourself."
      actions={
        <Can op="ProviderConnectionsController_create_v1">
          <Button size="sm" asChild>
            <Link href="/integrations/providers/new">
              <PlusIcon aria-hidden />
              Connect
            </Link>
          </Button>
        </Can>
      }
    >
      <DataTable
        tableId="provider-connections"
        caption="Microsoft 365 and Google Workspace connections"
        columns={columns}
        list={list}
        getRowId={(row) => row.id}
        getRowLabel={(row) => row.displayName}
        emptyState={
          <EmptyState
            icon={MailIcon}
            title="No connections"
            description="Connect a Microsoft 365 tenant or a Google Workspace organization to route its mail through the gateway."
          />
        }
        mobileCard={(row) => (
          <div className="grid gap-1">
            <Link href={`/integrations/providers/${row.id}`} className="font-medium underline">
              {row.displayName}
            </Link>
            <span className="text-xs text-muted-foreground">
              {PROVIDER_LABEL[row.provider]} · {row.domainCount} domain
              {row.domainCount === 1 ? '' : 's'}
            </span>
            <span className="flex flex-wrap items-center gap-2">
              <ConnectionStatusBadge status={row.status} />
              <HealthBadge status={row.health} />
            </span>
          </div>
        )}
      />
    </Section>
  );
}
