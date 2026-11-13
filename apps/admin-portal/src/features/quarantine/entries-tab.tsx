'use client';

import { ShieldCheckIcon } from 'lucide-react';
import Link from 'next/link';
import { useMemo, useState } from 'react';
import { z } from 'zod';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import {
  DateTime,
  DirectionBadge,
  QuarantineStateBadge,
  RiskScore,
  UntrustedText,
} from '@/components/domain';
import { EmptyState } from '@/components/states/empty-state';
import { ErrorState } from '@/components/states/error-state';
import { Button } from '@/components/ui/button';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { useUrlState } from '@/hooks/use-url-state';
import { useApiQuery, useCursorList } from '@/lib/api/hooks';
import type { QueryParams } from '@/lib/api/types';
import { usePermissions } from '@/lib/auth/me';
import { formatNumber, humanize } from '@/lib/format';
import { RANGE_PRESETS, resolvePreset, type RangePreset } from '@/lib/range';
import {
  FilterSelect,
  FilterText,
  RangeSelect,
  optionsOf,
  presetDays,
} from '@/features/messages/controls';
import { BulkActionBar, BulkResultNotice } from './bulk-actions';
import { entryHref } from './links';
import type { BulkResult, EntrySummary } from './types';
import { useQuarantineCatalog } from './use-catalog';

export const ENTRY_STATES = [
  'held',
  'pending_approval',
  'releasing',
  'released',
  'rejected',
  'deleted',
  'expired',
  'superseded',
] as const;
export const ENTRY_REASONS = [
  'spam',
  'bulk',
  'phishing',
  'malware',
  'bec',
  'dlp',
  'policy',
  'suspicious',
  'engine_unavailable',
  'manual',
] as const;
const ENGINES = ['rspamd', 'attachment', 'url', 'bec', 'dlp', 'sandbox', 'policy', 'none'] as const;
const LEVELS = ['none', 'low', 'medium', 'high', 'critical'] as const;
const opt = <T extends readonly [string, ...string[]]>(values: T) =>
  z.enum(values).optional().catch(undefined);
const text = (max: number) => z.string().trim().min(1).max(max).optional().catch(undefined);

/** URL state of the entries tab (every filter of `GET /quarantine/entries`). */
export const ENTRIES_URL_SHAPE = {
  range: z.enum(RANGE_PRESETS).default('7d').catch('7d'),
  state: opt(ENTRY_STATES),
  kind: opt(['quarantine', 'review'] as const),
  direction: opt(['inbound', 'outbound', 'internal'] as const),
  reason: opt(ENTRY_REASONS),
  minRiskLevel: opt(LEVELS),
  primaryEngine: opt(ENGINES),
  policyId: text(36),
  ruleId: text(48),
  sender: text(320),
  headerFrom: text(320),
  senderDomain: text(253),
  recipient: text(320),
  hasAttachments: opt(['true', 'false'] as const),
  hasHardBlock: opt(['true', 'false'] as const),
  messageId: text(36),
};

type EntriesState = {
  [K in keyof typeof ENTRIES_URL_SHAPE]: z.output<(typeof ENTRIES_URL_SHAPE)[K]>;
};
const FILTER_KEYS = Object.keys(ENTRIES_URL_SHAPE).filter(
  (k) => k !== 'range',
) as (keyof EntriesState)[];

export function entriesQuery(
  state: EntriesState,
  now = Date.now(),
): QueryParams<'QuarantineEntriesController_search_v1'> {
  const window = resolvePreset(state.range, now);
  const query: Record<string, string> = { from: window.from, to: window.to };
  for (const key of FILTER_KEYS) {
    const value = state[key];
    if (value !== undefined) query[key] = String(value);
  }
  return query as unknown as QueryParams<'QuarantineEntriesController_search_v1'>;
}

const COLUMNS: DataTableColumn<EntrySummary>[] = [
  {
    id: 'quarantinedAt',
    header: 'Quarantined',
    meta: { label: 'Quarantined', className: 'whitespace-nowrap' },
    cell: ({ row }) => (
      <Link
        href={entryHref(row.original.id)}
        className="font-medium text-primary underline-offset-2 hover:underline"
      >
        <DateTime value={row.original.quarantinedAt} />
        <span className="sr-only">, open entry</span>
      </Link>
    ),
  },
  {
    id: 'state',
    header: 'State',
    meta: { label: 'State' },
    cell: ({ row }) => <QuarantineStateBadge state={row.original.state} />,
  },
  {
    id: 'reason',
    header: 'Reason',
    meta: { label: 'Reason' },
    cell: ({ row }) => (
      <span className="text-sm">
        {humanize(row.original.reason)}
        {row.original.hardBlocks.length > 0 ? (
          <span className="block text-xs font-medium text-tone-danger-foreground">Hard block</span>
        ) : null}
      </span>
    ),
  },
  {
    id: 'recipient',
    header: 'Recipient',
    meta: { label: 'Recipient', className: 'max-w-56' },
    cell: ({ row }) => <UntrustedText value={row.original.recipient} maxLength={50} />,
  },
  {
    id: 'sender',
    header: 'Sender',
    meta: { label: 'Sender', className: 'max-w-56' },
    cell: ({ row }) => (
      <UntrustedText
        value={row.original.sender.headerFrom ?? row.original.sender.envelope}
        maxLength={50}
        emptyLabel="(null sender)"
      />
    ),
  },
  {
    id: 'subject',
    header: 'Subject',
    meta: { label: 'Subject', className: 'max-w-72' },
    cell: ({ row }) => (
      <UntrustedText value={row.original.subject} maxLength={70} emptyLabel="(not shown)" />
    ),
  },
  {
    id: 'risk',
    header: 'Risk',
    meta: { label: 'Risk' },
    cell: ({ row }) => <RiskScore score={row.original.riskScore} level={row.original.riskLevel} />,
  },
  {
    id: 'engine',
    header: 'Engine',
    meta: { label: 'Primary engine' },
    cell: ({ row }) => humanize(row.original.primaryEngine),
  },
  {
    id: 'direction',
    header: 'Direction',
    meta: { label: 'Direction' },
    cell: ({ row }) => <DirectionBadge direction={row.original.direction} />,
  },
  {
    id: 'expires',
    header: 'Expires',
    meta: { label: 'Expires', className: 'whitespace-nowrap' },
    cell: ({ row }) => <DateTime value={row.original.expiresAt} />,
  },
];

/** Entries tab of `/quarantine`: summary strip, filters, cursor list, selection and bulk actions. */
export function EntriesTab() {
  const [state, setState] = useUrlState(ENTRIES_URL_SHAPE);
  const catalog = useQuarantineCatalog();
  const maxDays = catalog.data?.limits.searchMaxRangeDays;
  const query = useMemo(() => entriesQuery(state), [state]);
  const list = useCursorList('QuarantineEntriesController_search_v1', query, {
    limit: Math.min(50, catalog.data?.limits.searchMaxPageSize ?? 50),
  });
  const permissions = usePermissions();
  const bulkAllowed = (catalog.data?.bulkActions ?? []).filter(
    (action) =>
      action !== 'approve' && action !== 'deny' && permissions.has(`quarantine:${action}`),
  );
  const [bulkResult, setBulkResult] = useState<BulkResult | null>(null);
  const filtered = FILTER_KEYS.some((key) => state[key] !== undefined);
  const advancedCount = (
    [
      'policyId',
      'ruleId',
      'headerFrom',
      'senderDomain',
      'hasAttachments',
      'hasHardBlock',
      'messageId',
      'primaryEngine',
    ] as const
  ).filter((key) => state[key] !== undefined).length;
  const clear = () => setState(Object.fromEntries(FILTER_KEYS.map((key) => [key, undefined])));

  const filters = (
    <div className="grid w-full gap-2">
      <div className="flex flex-wrap items-end gap-2">
        <RangeSelect
          value={state.range}
          onChange={(range: RangePreset) => setState({ range })}
          maxDays={maxDays}
        />
        <FilterSelect
          label="State"
          value={state.state}
          options={optionsOf(ENTRY_STATES)}
          onChange={(v) => setState({ state: v as EntriesState['state'] })}
        />
        <FilterSelect
          label="Reason"
          value={state.reason}
          options={optionsOf(ENTRY_REASONS)}
          onChange={(v) => setState({ reason: v as EntriesState['reason'] })}
        />
        <FilterSelect
          label="Kind"
          value={state.kind}
          options={optionsOf(['quarantine', 'review'])}
          onChange={(v) => setState({ kind: v as EntriesState['kind'] })}
        />
        <FilterSelect
          label="Direction"
          value={state.direction}
          options={optionsOf(['inbound', 'outbound', 'internal'])}
          onChange={(v) => setState({ direction: v as EntriesState['direction'] })}
        />
        <FilterSelect
          label="Minimum risk level"
          value={state.minRiskLevel}
          options={optionsOf(LEVELS)}
          onChange={(v) => setState({ minRiskLevel: v as EntriesState['minRiskLevel'] })}
        />
        <FilterText
          label="Sender (exact)"
          value={state.sender}
          onCommit={(sender) => setState({ sender })}
          type="email"
        />
        <FilterText
          label="Recipient (exact)"
          value={state.recipient}
          onCommit={(recipient) => setState({ recipient })}
          type="email"
        />
      </div>
      <Collapsible defaultOpen={advancedCount > 0}>
        <CollapsibleTrigger asChild>
          <Button variant="ghost" size="sm" className="justify-self-start">
            More filters{advancedCount > 0 ? ` (${advancedCount})` : ''}
          </Button>
        </CollapsibleTrigger>
        <CollapsibleContent className="flex flex-wrap items-end gap-2 pt-2">
          <FilterSelect
            label="Primary engine"
            value={state.primaryEngine}
            options={optionsOf(ENGINES)}
            onChange={(v) => setState({ primaryEngine: v as EntriesState['primaryEngine'] })}
          />
          <FilterSelect
            label="Attachments"
            value={state.hasAttachments}
            options={[
              { value: 'true', label: 'With attachments' },
              { value: 'false', label: 'Without attachments' },
            ]}
            onChange={(v) => setState({ hasAttachments: v as EntriesState['hasAttachments'] })}
          />
          <FilterSelect
            label="Hard block"
            value={state.hasHardBlock}
            options={[
              { value: 'true', label: 'Hard-blocked' },
              { value: 'false', label: 'No hard block' },
            ]}
            onChange={(v) => setState({ hasHardBlock: v as EntriesState['hasHardBlock'] })}
          />
          <FilterText
            label="Header From (exact)"
            value={state.headerFrom}
            onCommit={(headerFrom) => setState({ headerFrom })}
          />
          <FilterText
            label="Sender domain"
            value={state.senderDomain}
            onCommit={(senderDomain) => setState({ senderDomain })}
          />
          <FilterText
            label="Policy ID"
            value={state.policyId}
            onCommit={(policyId) => setState({ policyId })}
          />
          <FilterText
            label="Rule ID"
            value={state.ruleId}
            onCommit={(ruleId) => setState({ ruleId })}
          />
          <FilterText
            label="Message ID"
            value={state.messageId}
            onCommit={(messageId) => setState({ messageId })}
          />
        </CollapsibleContent>
      </Collapsible>
    </div>
  );

  return (
    <div className="grid gap-4">
      <SummaryStrip from={query.from} to={query.to} />
      {maxDays !== undefined && presetDays(state.range) > maxDays ? (
        <p className="text-xs text-muted-foreground">
          Searches are limited to {maxDays} days by the platform.
        </p>
      ) : null}
      <div role="status" aria-live="polite">
        {bulkResult ? (
          <BulkResultNotice result={bulkResult} onDismiss={() => setBulkResult(null)} />
        ) : null}
      </div>
      <DataTable
        tableId="quarantine-entries"
        caption="Quarantine entries"
        columns={COLUMNS}
        list={list}
        getRowId={(row) => row.id}
        getRowLabel={(row) => `entry for ${row.recipient}`}
        filters={filters}
        isFiltered={filtered}
        onClearFilters={clear}
        enableSelection={bulkAllowed.length > 0}
        bulkActions={(rows, clearSelection) => (
          <BulkActionBar
            ids={rows.map((row) => row.id)}
            actions={bulkAllowed}
            catalog={catalog.data}
            onDone={(result) => {
              setBulkResult(result);
              clearSelection();
            }}
          />
        )}
        emptyState={
          <EmptyState
            icon={ShieldCheckIcon}
            title="Nothing quarantined in this range"
            description="No entry was quarantined in the selected range."
          />
        }
        mobileCard={(row) => (
          <div className="grid gap-1 text-sm">
            <Link href={entryHref(row.id)} className="font-medium text-primary hover:underline">
              <UntrustedText value={row.subject} maxLength={60} emptyLabel="Open entry" />
            </Link>
            <UntrustedText value={row.recipient} maxLength={40} />
            <div className="flex flex-wrap items-center gap-2">
              <QuarantineStateBadge state={row.state} />
              <span className="text-xs">{humanize(row.reason)}</span>
              <DateTime value={row.quarantinedAt} className="text-xs text-muted-foreground" />
            </div>
          </div>
        )}
      />
      <p className="text-xs text-muted-foreground">
        Searches are recorded in the audit log (filter hash and result count only). There is no
        subject or free-text search. The list cursor is bound to the filters: changing a filter
        starts again at page 1.
      </p>
    </div>
  );
}

/** Counts by state and pending approvals in the same window (`GET /quarantine/summary`). */
function SummaryStrip({ from, to }: { from: string; to: string }) {
  const summary = useApiQuery('QuarantineToolsController_summary_v1', { query: { from, to } });
  if (summary.isLoading) {
    return (
      <div
        role="status"
        aria-busy="true"
        className="h-14 animate-pulse rounded-lg border bg-muted/40"
      >
        <span className="sr-only">Loading the quarantine summary …</span>
      </div>
    );
  }
  if (summary.error) {
    return <ErrorState error={summary.error} onRetry={() => void summary.refetch()} compact />;
  }
  const counts = Object.entries(summary.data?.counts ?? {});
  return (
    <dl
      className="flex flex-wrap gap-x-6 gap-y-2 rounded-lg border bg-card px-4 py-3 text-sm shadow-xs"
      aria-label="Quarantine summary for the selected range"
    >
      {counts.map(([stateName, count]) => (
        <div key={stateName} className="grid">
          <dt className="text-xs text-muted-foreground">{humanize(stateName)}</dt>
          <dd className="text-lg font-semibold tabular-nums">{formatNumber(count)}</dd>
        </div>
      ))}
      <div className="grid">
        <dt className="text-xs text-muted-foreground">Pending approvals</dt>
        <dd className="text-lg font-semibold tabular-nums">
          {formatNumber(summary.data?.pendingApprovals ?? 0)}
        </dd>
      </div>
    </dl>
  );
}
