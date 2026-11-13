'use client';

import { ScrollTextIcon } from 'lucide-react';
import Link from 'next/link';
import { useMemo } from 'react';
import { z } from 'zod';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { DateTime, DirectionBadge } from '@/components/domain';
import { EmptyState } from '@/components/states/empty-state';
import { useUrlState } from '@/hooks/use-url-state';
import { useCursorList } from '@/lib/api/hooks';
import type { ListItem, QueryParams } from '@/lib/api/types';
import { formatNumber } from '@/lib/format';
import { EnumBadge, FilterSelect, optionsOf } from '@/features/messages/controls';
import { policyHref } from './links';
import { POLICY_STATUS_TONE } from './semantic';

type PolicyRow = ListItem<'PolicyManagementController_list_v1'>;

const STATUSES = ['draft', 'active', 'disabled'] as const;
const DIRECTIONS = ['inbound', 'outbound', 'internal', 'any'] as const;

export const EMAIL_POLICIES_URL_SHAPE = {
  status: z.enum(STATUSES).optional().catch(undefined),
  direction: z.enum(DIRECTIONS).optional().catch(undefined),
};

const COLUMNS: DataTableColumn<PolicyRow>[] = [
  {
    id: 'name',
    header: 'Policy',
    meta: { label: 'Policy', className: 'max-w-80' },
    cell: ({ row }) => (
      <div className="grid">
        <Link
          href={policyHref(row.original.id)}
          className="font-medium text-primary underline-offset-2 hover:underline"
        >
          {row.original.name}
        </Link>
        {row.original.description ? (
          <span className="truncate text-xs text-muted-foreground" title={row.original.description}>
            {row.original.description}
          </span>
        ) : null}
      </div>
    ),
  },
  {
    id: 'status',
    header: 'Status',
    meta: { label: 'Status' },
    cell: ({ row }) => <EnumBadge value={row.original.status} tones={POLICY_STATUS_TONE} />,
  },
  {
    id: 'direction',
    header: 'Direction',
    meta: { label: 'Direction' },
    cell: ({ row }) =>
      row.original.direction === 'any' ? (
        <span className="text-sm">Any direction</span>
      ) : (
        <DirectionBadge direction={row.original.direction} />
      ),
  },
  {
    id: 'priority',
    header: 'Priority',
    meta: { label: 'Priority', className: 'tabular-nums' },
    cell: ({ row }) => formatNumber(row.original.priority),
  },
  {
    id: 'versions',
    header: 'Versions',
    meta: { label: 'Versions' },
    cell: ({ row }) => (
      <span className="text-xs">
        {row.original.activeVersionNo
          ? `v${row.original.activeVersionNo} active`
          : 'No active version'}
        {row.original.latestVersionNo ? ` · latest v${row.original.latestVersionNo}` : ''}
      </span>
    ),
  },
  {
    id: 'updatedAt',
    header: 'Updated',
    meta: { label: 'Updated', className: 'whitespace-nowrap' },
    cell: ({ row }) => <DateTime value={row.original.updatedAt} />,
  },
];

/** Email policies (`GET /policies`, v0 list, status and direction filters), read-only in 7.1. */
export function EmailPoliciesTab() {
  const [state, setState] = useUrlState(EMAIL_POLICIES_URL_SHAPE);
  const query = useMemo(() => {
    const q: QueryParams<'PolicyManagementController_list_v1'> = {};
    if (state.status) q.status = state.status;
    if (state.direction) q.direction = state.direction;
    return q;
  }, [state]);
  const list = useCursorList('PolicyManagementController_list_v1', query, { limit: 25 });
  const generation = (list.query.data as { generation?: string } | undefined)?.generation;
  return (
    <div className="grid gap-2">
      {generation ? (
        <p className="text-xs text-muted-foreground">
          Policy generation <span className="font-mono">{generation}</span>: every change that
          affects evaluation increments it and applies to the next evaluation only.
        </p>
      ) : null}
      <DataTable
        tableId="policies"
        caption="Email policies"
        columns={COLUMNS}
        list={list}
        getRowId={(row) => row.id}
        getRowLabel={(row) => row.name}
        isFiltered={Boolean(state.status || state.direction)}
        onClearFilters={() => setState({ status: undefined, direction: undefined })}
        filters={
          <div className="flex flex-wrap items-end gap-2">
            <FilterSelect
              label="Status"
              value={state.status}
              options={optionsOf(STATUSES)}
              onChange={(status) => setState({ status: status as typeof state.status })}
            />
            <FilterSelect
              label="Direction"
              value={state.direction}
              options={optionsOf(DIRECTIONS)}
              onChange={(direction) => setState({ direction: direction as typeof state.direction })}
            />
          </div>
        }
        emptyState={
          <EmptyState
            icon={ScrollTextIcon}
            title="No email policies yet"
            description="Without tenant policies the platform default decides. Creating policies arrives in step 7.3."
          />
        }
        mobileCard={(row) => (
          <div className="grid gap-1 text-sm">
            <Link href={policyHref(row.id)} className="font-medium text-primary hover:underline">
              {row.name}
            </Link>
            <EnumBadge value={row.status} tones={POLICY_STATUS_TONE} />
          </div>
        )}
      />
    </div>
  );
}
