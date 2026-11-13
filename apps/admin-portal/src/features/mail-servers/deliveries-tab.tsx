'use client';

import { SendIcon } from 'lucide-react';
import Link from 'next/link';
import { useMemo } from 'react';
import { z } from 'zod';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { DeliveryStatusBadge, DirectionBadge } from '@/components/domain/badges';
import { DateTime } from '@/components/domain/date-time';
import { UntrustedText } from '@/components/domain/untrusted-text';
import { RangePicker, useRangeState } from '@/components/range-picker';
import { EmptyState } from '@/components/states/empty-state';
import { useUrlState } from '@/hooks/use-url-state';
import { useCursorList } from '@/lib/api/hooks';
import type { ListItem } from '@/lib/api/types';
import { humanize } from '@/lib/format';
import { FilterSelect } from '@/features/domains/kit';

type Delivery = ListItem<'DeliveriesController_list_v1'>;
const STATUSES = [
  'pending',
  'in_progress',
  'queued',
  'deferred',
  'delivered',
  'bounced',
  'expired',
  'failed',
  'suppressed',
  'unknown',
] as const;
const DIRECTIONS = ['inbound', 'outbound', 'internal'] as const;

const URL_SHAPE = {
  dstatus: z.enum(STATUSES).optional().catch(undefined),
  direction: z.enum(DIRECTIONS).optional().catch(undefined),
};

/** Per-recipient delivery state (`GET /deliveries`, v0, newest first, range ≤ 31 days). */
export function DeliveriesTab() {
  const [filters, setFilters] = useUrlState(URL_SHAPE);
  const [range] = useRangeState();
  const list = useCursorList('DeliveriesController_list_v1', {
    from: range.from,
    to: range.to,
    ...(filters.dstatus ? { status: filters.dstatus } : {}),
    ...(filters.direction ? { direction: filters.direction } : {}),
  });
  const columns = useMemo<DataTableColumn<Delivery>[]>(
    () => [
      {
        id: 'recipient',
        header: 'Recipient',
        meta: { label: 'Recipient' },
        cell: ({ row }) => <UntrustedText value={row.original.recipient} maxLength={60} />,
      },
      {
        id: 'status',
        header: 'Status',
        meta: { label: 'Status' },
        cell: ({ row }) => <DeliveryStatusBadge status={row.original.status} />,
      },
      {
        id: 'direction',
        header: 'Direction',
        meta: { label: 'Direction' },
        cell: ({ row }) =>
          row.original.direction ? (
            <DirectionBadge direction={row.original.direction} />
          ) : (
            <span className="text-muted-foreground">Unknown</span>
          ),
      },
      {
        id: 'attempts',
        header: 'Attempts',
        meta: { label: 'Attempts', className: 'tabular-nums' },
        cell: ({ row }) => row.original.attemptCount,
      },
      {
        id: 'error',
        header: 'Last error',
        meta: { label: 'Last error' },
        cell: ({ row }) =>
          row.original.lastErrorClass ? (
            humanize(row.original.lastErrorClass)
          ) : (
            <span className="text-muted-foreground">None</span>
          ),
      },
      {
        id: 'changed',
        header: 'Status changed',
        meta: { label: 'Status changed' },
        cell: ({ row }) => <DateTime value={row.original.statusChangedAt} />,
      },
      {
        id: 'message',
        header: 'Message',
        meta: { label: 'Message' },
        cell: ({ row }) => (
          <Link
            href={`/messages/${row.original.messageId}`}
            className="text-primary hover:underline"
            aria-label={`Open message of the delivery to ${row.original.recipient}`}
          >
            Open message
          </Link>
        ),
      },
    ],
    [],
  );
  return (
    <div className="grid min-w-0 gap-3 [&>*]:min-w-0">
      <RangePicker />
      <DataTable
        tableId="deliveries"
        caption="Deliveries"
        columns={columns}
        list={list}
        getRowId={(row) => `${row.messageId}:${row.rcptSeq}`}
        getRowLabel={(row) => row.recipient}
        filters={
          <>
            <FilterSelect
              label="Delivery status"
              value={filters.dstatus}
              onChange={(dstatus) =>
                setFilters({ dstatus: dstatus as (typeof STATUSES)[number] | undefined })
              }
              options={STATUSES.map((s) => ({ value: s, label: humanize(s) }))}
            />
            <FilterSelect
              label="Direction"
              value={filters.direction}
              onChange={(direction) =>
                setFilters({ direction: direction as (typeof DIRECTIONS)[number] | undefined })
              }
              options={DIRECTIONS.map((d) => ({ value: d, label: humanize(d) }))}
            />
          </>
        }
        isFiltered={Boolean(filters.dstatus || filters.direction)}
        onClearFilters={() => setFilters({ dstatus: undefined, direction: undefined })}
        emptyState={
          <EmptyState
            icon={SendIcon}
            title="No deliveries in this range"
            description="Choose a longer range (at most 31 days)."
          />
        }
        mobileCard={(row) => (
          <div className="grid gap-1">
            <UntrustedText value={row.recipient} />
            <span className="flex flex-wrap items-center gap-2">
              <DeliveryStatusBadge status={row.status} />
              <DateTime value={row.statusChangedAt} className="text-xs" />
            </span>
            <Link
              href={`/messages/${row.messageId}`}
              className="text-xs text-primary hover:underline"
            >
              Open message
            </Link>
          </div>
        )}
      />
    </div>
  );
}
