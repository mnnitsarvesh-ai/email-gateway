'use client';

import { MailIcon, ShieldCheckIcon } from 'lucide-react';
import Link from 'next/link';
import { useMemo } from 'react';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import {
  DateTime,
  DirectionBadge,
  RiskScore,
  UntrustedText,
  VerdictBadge,
} from '@/components/domain';
import { PageHeader } from '@/components/page-header';
import { EmptyState } from '@/components/states/empty-state';
import { UnavailableState } from '@/components/states/unavailable-state';
import { useUrlState } from '@/hooks/use-url-state';
import { useCursorList } from '@/lib/api/hooks';
import type { ListItem } from '@/lib/api/types';
import { RouteGate } from '@/lib/auth/route-gate';
import { formatBytes, formatNumber } from '@/lib/format';
import {
  EnumBadge,
  FilterMultiSelect,
  FilterSelect,
  FilterText,
  RangeSelect,
  optionsOf,
} from './controls';
import {
  CLEARED_EXPLORER_FILTERS,
  EXPLORER_URL_SHAPE,
  MAX_VERDICTS,
  MESSAGE_ACTIONS,
  MESSAGE_DIRECTIONS,
  MESSAGE_STATUSES,
  MESSAGE_VERDICTS,
  explorerQuery,
  hasExplorerFilters,
} from './explorer-filters';
import { messageHref } from './links';
import { FINAL_ACTION_TONE, MESSAGE_STATUS_TONE } from './semantic';

type MessageRow = ListItem<'MessagesController_list_v1'>;

const COLUMNS: DataTableColumn<MessageRow>[] = [
  {
    id: 'receivedAt',
    header: 'Received',
    meta: { label: 'Received', className: 'whitespace-nowrap' },
    cell: ({ row }) => (
      <Link
        href={messageHref(row.original.id)}
        className="font-medium text-primary underline-offset-2 hover:underline focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
      >
        <DateTime value={row.original.receivedAt} />
        <span className="sr-only">, open message details</span>
      </Link>
    ),
  },
  {
    id: 'direction',
    header: 'Direction',
    meta: { label: 'Direction' },
    cell: ({ row }) => <DirectionBadge direction={row.original.direction} />,
  },
  {
    id: 'from',
    header: 'From',
    meta: { label: 'From', className: 'max-w-64' },
    cell: ({ row }) => (
      <div className="grid min-w-0">
        <UntrustedText
          value={row.original.envelopeFrom}
          maxLength={60}
          emptyLabel="(null sender)"
        />
        {row.original.headerFrom && row.original.headerFrom !== row.original.envelopeFrom ? (
          <span className="text-xs text-muted-foreground">
            Header: <UntrustedText value={row.original.headerFrom} maxLength={60} />
          </span>
        ) : null}
      </div>
    ),
  },
  {
    id: 'subject',
    header: 'Subject',
    meta: { label: 'Subject', className: 'max-w-80' },
    cell: ({ row }) => (
      <UntrustedText value={row.original.subject} maxLength={90} emptyLabel="(no subject)" />
    ),
  },
  {
    id: 'verdict',
    header: 'Verdict',
    meta: { label: 'Verdict' },
    cell: ({ row }) => <VerdictBadge verdict={row.original.finalVerdict} />,
  },
  {
    id: 'action',
    header: 'Action',
    meta: { label: 'Action' },
    cell: ({ row }) => (
      <EnumBadge value={row.original.finalAction} tones={FINAL_ACTION_TONE} emptyLabel="Pending" />
    ),
  },
  {
    id: 'status',
    header: 'Status',
    meta: { label: 'Status' },
    cell: ({ row }) => <EnumBadge value={row.original.status} tones={MESSAGE_STATUS_TONE} />,
  },
  {
    id: 'risk',
    header: 'Risk',
    meta: { label: 'Risk score' },
    cell: ({ row }) => <RiskScore score={row.original.riskScore} />,
  },
  {
    id: 'recipients',
    header: 'Recipients',
    meta: { label: 'Recipients', className: 'text-right tabular-nums' },
    cell: ({ row }) => formatNumber(row.original.recipientCount),
  },
  {
    id: 'attachments',
    header: 'Attachments',
    meta: { label: 'Attachments', className: 'text-right tabular-nums' },
    cell: ({ row }) => formatNumber(row.original.attachmentCount),
  },
  {
    id: 'size',
    header: 'Size',
    meta: { label: 'Size', className: 'text-right tabular-nums whitespace-nowrap' },
    cell: ({ row }) => formatBytes(row.original.sizeBytes),
  },
];

/** Email explorer (`/messages`, design §1.3 row 9): the v1 message list with URL filters. */
export function MessageExplorer() {
  return (
    <RouteGate gate={['MessagesController_list_v1']}>
      <MessageExplorerContent />
    </RouteGate>
  );
}

function MessageExplorerContent() {
  const [state, setState] = useUrlState(EXPLORER_URL_SHAPE);
  const query = useMemo(() => explorerQuery(state), [state]);
  const list = useCursorList('MessagesController_list_v1', query, { limit: 50 });
  const filtered = hasExplorerFilters(state);

  const filters = (
    <div className="flex flex-wrap items-end gap-2">
      <RangeSelect value={state.range} onChange={(range) => setState({ range })} maxDays={31} />
      <FilterSelect
        label="Direction"
        value={state.direction}
        options={optionsOf(MESSAGE_DIRECTIONS)}
        onChange={(direction) => setState({ direction: direction as typeof state.direction })}
      />
      <FilterSelect
        label="Status"
        value={state.status}
        options={optionsOf(MESSAGE_STATUSES)}
        onChange={(status) => setState({ status: status as typeof state.status })}
      />
      <FilterMultiSelect
        label="Verdict"
        values={state.verdict}
        max={MAX_VERDICTS}
        options={optionsOf(MESSAGE_VERDICTS)}
        onChange={(verdict) => setState({ verdict: verdict as typeof state.verdict })}
      />
      <FilterSelect
        label="Action"
        value={state.action}
        options={optionsOf(MESSAGE_ACTIONS)}
        onChange={(action) => setState({ action: action as typeof state.action })}
      />
      <FilterSelect
        label="Attachments"
        value={state.attachments}
        options={[
          { value: 'true', label: 'With attachments' },
          { value: 'false', label: 'Without attachments' },
        ]}
        onChange={(attachments) => setState({ attachments: attachments as 'true' | 'false' })}
      />
      <FilterText
        label="Sender (exact)"
        type="email"
        value={state.sender}
        onCommit={(sender) => setState({ sender })}
        placeholder="name@example.com"
        description="Exact envelope sender. Press Enter to search; the search is audited."
      />
      <FilterText
        label="Recipient (exact)"
        type="email"
        value={state.recipient}
        onCommit={(recipient) => setState({ recipient })}
        placeholder="name@example.com"
        description="Exact recipient address. Press Enter to search; the search is audited."
      />
      <FilterText
        label="Risk from"
        type="number"
        inputMode="numeric"
        value={state.riskMin === undefined ? undefined : String(state.riskMin)}
        onCommit={(value) => setState({ riskMin: value === undefined ? undefined : Number(value) })}
        className="w-24"
        description="Lowest risk score, 0 to 1000"
      />
      <FilterText
        label="Risk to"
        type="number"
        inputMode="numeric"
        value={state.riskMax === undefined ? undefined : String(state.riskMax)}
        onCommit={(value) => setState({ riskMax: value === undefined ? undefined : Number(value) })}
        className="w-24"
        description="Highest risk score, 0 to 1000"
      />
    </div>
  );

  return (
    <div className="grid gap-4">
      <PageHeader
        title="Email explorer"
        description="Message metadata of your organization from the read replica (a few seconds behind). Subjects and addresses are shown as text exactly as received; message content is never displayed here."
      />
      <p className="flex items-start gap-2 rounded-md border bg-muted/40 px-3 py-2 text-xs text-muted-foreground">
        <ShieldCheckIcon className="mt-0.5 size-4 shrink-0" aria-hidden />
        <span>
          Searches by sender or recipient are recorded in the audit log (the values are stored as
          hashes). Lists without totals: filters other than a single verdict or a recipient alone
          examine a bounded number of rows per page, so a page can be short while more results exist
          further back.
        </span>
      </p>
      <DataTable
        tableId="messages"
        caption="Messages"
        columns={COLUMNS}
        list={list}
        getRowId={(row) => row.id}
        getRowLabel={(row) => `message received ${row.receivedAt}`}
        filters={filters}
        isFiltered={filtered}
        onClearFilters={() => setState(CLEARED_EXPLORER_FILTERS)}
        sort={{
          operationId: 'MessagesController_list_v1',
          columnId: 'receivedAt',
          value: state.sort,
          onChange: (sort) => setState({ sort: (sort as typeof state.sort) ?? '-receivedAt' }),
        }}
        emptyState={
          <EmptyState
            icon={MailIcon}
            title="No mail in this range"
            description="No message was received in the selected range. Choose a longer range."
          />
        }
        mobileCard={(row) => (
          <div className="grid gap-1 text-sm">
            <Link href={messageHref(row.id)} className="font-medium text-primary hover:underline">
              <UntrustedText value={row.subject} maxLength={70} emptyLabel="(no subject)" />
            </Link>
            <UntrustedText value={row.envelopeFrom} maxLength={50} emptyLabel="(null sender)" />
            <div className="flex flex-wrap items-center gap-2">
              <VerdictBadge verdict={row.finalVerdict} />
              <DirectionBadge direction={row.direction} />
              <DateTime value={row.receivedAt} className="text-xs text-muted-foreground" />
            </div>
          </div>
        )}
      />
      <UnavailableState
        step="7.2"
        title="Saved views, column sets, bulk actions and export"
        description="Saved views, column sets, bulk actions and export arrive in step 7.2."
      />
    </div>
  );
}
