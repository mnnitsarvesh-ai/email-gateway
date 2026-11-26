'use client';

import { ScrollTextIcon } from 'lucide-react';
import { useMemo } from 'react';
import { z } from 'zod';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { DateTime } from '@/components/domain/date-time';
import { EmptyState } from '@/components/states/empty-state';
import { Button } from '@/components/ui/button';
import { FilterSelect } from '@/features/domains/kit';
import { useUrlState } from '@/hooks/use-url-state';
import { useCursorList } from '@/lib/api/hooks';
import type { ListItem } from '@/lib/api/types';
import { formatNumber } from '@/lib/format';
import { StatusBadge } from './audit-detail';
import { formatCostMicros, userLabel } from './model';
import { useAdminRange } from './range-control';
import { USER_URL_SHAPE, UserCell } from './usage-tab';

type AuditRow = ListItem<'AssistantAdminAuditController_conversations_v1'>;
const STATUSES = ['active', 'archived', 'deleted'] as const;

const URL_SHAPE = {
  ...USER_URL_SHAPE,
  cstatus: z.enum(STATUSES).optional().catch(undefined),
};

/**
 * Conversation audit (D4, `audit:read`): conversations of the organization by their last question,
 * metadata only (no title). "Open audit" shows the turns, tool calls, confirmations, reports and
 * ratings of one conversation in a drawer.
 */
export function AuditTab({ onOpen }: { onOpen: (conversationId: string) => void }) {
  const [range] = useAdminRange();
  const [filters, setFilters] = useUrlState(URL_SHAPE);
  const list = useCursorList('AssistantAdminAuditController_conversations_v1', {
    from: range.from,
    to: range.to,
    ...(filters.user ? { userId: filters.user } : {}),
    ...(filters.cstatus ? { status: filters.cstatus } : {}),
  });
  const columns = useMemo<DataTableColumn<AuditRow>[]>(
    () => [
      {
        id: 'lastTurn',
        header: 'Last question',
        meta: { label: 'Last question', hideable: false },
        cell: ({ row }) => <DateTime value={row.original.lastTurnAt} emptyLabel="None" />,
      },
      {
        id: 'user',
        header: 'Person',
        meta: { label: 'Person' },
        cell: ({ row }) => (
          <Button
            variant="link"
            className="h-auto p-0 text-left whitespace-normal"
            onClick={() => setFilters({ user: row.original.user.id })}
          >
            <UserCell user={row.original.user} />
            <span className="sr-only"> (show only this person)</span>
          </Button>
        ),
      },
      {
        id: 'status',
        header: 'Status',
        meta: { label: 'Status' },
        cell: ({ row }) => (
          <span className="grid gap-0.5">
            <StatusBadge status={row.original.status} />
            {row.original.contentPurged ? (
              <span className="text-xs text-muted-foreground">Content deleted</span>
            ) : null}
            {row.original.underPlatformOverride ? (
              <span className="text-xs text-muted-foreground">Platform override</span>
            ) : null}
          </span>
        ),
      },
      {
        id: 'turns',
        header: 'Turns',
        meta: { label: 'Turns' },
        cell: ({ row }) => formatNumber(row.original.turnCount),
      },
      {
        id: 'tools',
        header: 'Tool calls',
        meta: { label: 'Tool calls' },
        cell: ({ row }) =>
          `${formatNumber(row.original.totals.toolCalls)} (${formatNumber(row.original.totals.deniedCalls)} refused)`,
      },
      {
        id: 'confirmations',
        header: 'Confirmed writes',
        meta: { label: 'Confirmed writes' },
        cell: ({ row }) => formatNumber(row.original.totals.confirmations.executed),
      },
      {
        id: 'tokens',
        header: 'Tokens',
        meta: { label: 'Tokens' },
        cell: ({ row }) => (
          <span className="grid gap-0.5 tabular-nums">
            {formatNumber(row.original.totals.tokens)}
            <span className="text-xs text-muted-foreground">
              est. {formatCostMicros(row.original.totals.estimatedCostMicros)}
            </span>
          </span>
        ),
      },
      {
        id: 'ratings',
        header: 'Ratings',
        meta: { label: 'Ratings' },
        cell: ({ row }) =>
          `${row.original.totals.feedback.up} up, ${row.original.totals.feedback.down} down`,
      },
      {
        id: 'open',
        header: 'Details',
        meta: { label: 'Details' },
        cell: ({ row }) => (
          <Button
            variant="outline"
            size="sm"
            onClick={() => onOpen(row.original.id)}
            aria-label={`Open audit of the conversation of ${userLabel(row.original.user)} (${row.original.id.slice(0, 8)})`}
          >
            Open audit
          </Button>
        ),
      },
    ],
    [onOpen, setFilters],
  );
  return (
    <div className="grid min-w-0 gap-3 [&>*]:min-w-0">
      <p className="text-sm text-muted-foreground">
        What people asked and what the assistant answered is private to them. This view lists what
        happened: turns, tool calls with their redacted parameters, confirmations, reports and
        ratings.
      </p>
      <DataTable<AuditRow>
        tableId="assistant-admin-audit"
        caption={`AI conversations with a question between ${range.fromDay} and ${range.toDay} (UTC)`}
        columns={columns}
        list={list}
        getRowId={(row) => row.id}
        getRowLabel={(row) => `Conversation of ${userLabel(row.user)}`}
        filters={
          <FilterSelect
            label="Status"
            value={filters.cstatus}
            onChange={(cstatus) =>
              setFilters({ cstatus: cstatus as (typeof STATUSES)[number] | undefined })
            }
            options={STATUSES.map((value) => ({
              value,
              label: value[0]!.toUpperCase() + value.slice(1),
            }))}
          />
        }
        isFiltered={Boolean(filters.cstatus || filters.user)}
        onClearFilters={() => setFilters({ cstatus: undefined, user: undefined })}
        emptyState={
          <EmptyState
            icon={ScrollTextIcon}
            title="No conversations in this range"
            description="Conversations appear here by the time of their last question."
          />
        }
        mobileCard={(row) => (
          <div className="grid gap-1 text-sm">
            <UserCell user={row.user} />
            <span className="flex flex-wrap items-center gap-2">
              <StatusBadge status={row.status} />
              <DateTime value={row.lastTurnAt} className="text-xs" emptyLabel="No question" />
            </span>
            <span className="text-xs">
              {formatNumber(row.turnCount)} turns · {formatNumber(row.totals.toolCalls)} tool calls
            </span>
            <Button
              variant="outline"
              size="sm"
              className="w-fit"
              onClick={() => onOpen(row.id)}
              aria-label={`Open audit of the conversation of ${userLabel(row.user)} (${row.id.slice(0, 8)})`}
            >
              Open audit
            </Button>
          </div>
        )}
      />
    </div>
  );
}
