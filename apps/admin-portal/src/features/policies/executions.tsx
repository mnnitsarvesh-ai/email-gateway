'use client';

import { HistoryIcon } from 'lucide-react';
import Link from 'next/link';
import { useMemo } from 'react';
import { z } from 'zod';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { DateTime, DirectionBadge } from '@/components/domain';
import { EmptyState } from '@/components/states/empty-state';
import { useUrlState } from '@/hooks/use-url-state';
import { useCursorList } from '@/lib/api/hooks';
import type { ListItem, QueryParams } from '@/lib/api/types';
import { useCan } from '@/lib/auth/me';
import { formatDuration, humanize } from '@/lib/format';
import { RANGE_PRESETS, resolvePreset } from '@/lib/range';
import {
  EnumBadge,
  FilterSelect,
  FilterText,
  RangeSelect,
  optionsOf,
} from '@/features/messages/controls';
import { messageHref } from '@/features/messages/links';
import { DISPOSITION_TONE, FINAL_ACTION_TONE } from '@/features/messages/semantic';
import { policyHref } from './links';

type Execution = ListItem<'PolicyToolsController_history_v1'>;

const DIRECTIONS = ['inbound', 'outbound', 'internal'] as const;
const DISPOSITIONS = ['allow', 'require_approval', 'quarantine', 'reject'] as const;
const SOURCES = ['tenant_rule', 'platform_default', 'floor'] as const;
const TRIGGERS = ['scanned', 'scan_failed', 'parse_failed'] as const;

export const EXECUTIONS_URL_SHAPE = {
  range: z.enum(RANGE_PRESETS).default('24h').catch('24h'),
  direction: z.enum(DIRECTIONS).optional().catch(undefined),
  disposition: z.enum(DISPOSITIONS).optional().catch(undefined),
  source: z.enum(SOURCES).optional().catch(undefined),
  trigger: z.enum(TRIGGERS).optional().catch(undefined),
  overrideApplied: z.enum(['true', 'false']).optional().catch(undefined),
  policyId: z.string().trim().min(1).max(36).optional().catch(undefined),
  ruleId: z.string().trim().min(1).max(64).optional().catch(undefined),
};
type ExecutionsState = {
  [K in keyof typeof EXECUTIONS_URL_SHAPE]: z.output<(typeof EXECUTIONS_URL_SHAPE)[K]>;
};
const FILTERS = [
  'direction',
  'disposition',
  'source',
  'trigger',
  'overrideApplied',
  'policyId',
  'ruleId',
] as const;

export function executionsQuery(
  state: ExecutionsState,
  now = Date.now(),
): QueryParams<'PolicyToolsController_history_v1'> {
  const window = resolvePreset(state.range, now);
  const query: QueryParams<'PolicyToolsController_history_v1'> = {
    from: window.from,
    to: window.to,
  };
  if (state.direction) query.direction = state.direction;
  if (state.disposition) query.disposition = state.disposition;
  if (state.source) query.source = state.source;
  if (state.trigger) query.trigger = state.trigger;
  if (state.overrideApplied) query.overrideApplied = state.overrideApplied;
  if (state.policyId) query.policyId = state.policyId;
  if (state.ruleId) query.ruleId = state.ruleId;
  return query;
}

function columns(canMessages: boolean): DataTableColumn<Execution>[] {
  return [
    {
      id: 'evaluatedAt',
      header: 'Evaluated',
      meta: { label: 'Evaluated', className: 'whitespace-nowrap' },
      cell: ({ row }) => <DateTime value={row.original.evaluatedAt} />,
    },
    {
      id: 'message',
      header: 'Message',
      meta: { label: 'Message' },
      cell: ({ row }) =>
        row.original.messageId && canMessages ? (
          <Link
            href={messageHref(row.original.messageId)}
            className="text-xs text-primary underline-offset-2 hover:underline"
          >
            Open message
          </Link>
        ) : (
          <span className="text-xs text-muted-foreground">
            {row.original.messageId ? 'Message (no access)' : 'No message'}
          </span>
        ),
    },
    {
      id: 'direction',
      header: 'Direction',
      meta: { label: 'Direction' },
      cell: ({ row }) => <DirectionBadge direction={row.original.direction} />,
    },
    {
      id: 'disposition',
      header: 'Disposition',
      meta: { label: 'Disposition' },
      cell: ({ row }) => <EnumBadge value={row.original.disposition} tones={DISPOSITION_TONE} />,
    },
    {
      id: 'finalAction',
      header: 'Final action',
      meta: { label: 'Final action' },
      cell: ({ row }) => <EnumBadge value={row.original.finalAction} tones={FINAL_ACTION_TONE} />,
    },
    {
      id: 'decisive',
      header: 'Decided by',
      meta: { label: 'Decided by' },
      cell: ({ row }) => {
        const d = row.original.decisive;
        return (
          <span className="grid text-xs">
            <span>{humanize(d.source)}</span>
            {d.policyId ? (
              <Link href={policyHref(d.policyId)} className="text-primary hover:underline">
                Policy{d.versionNo ? ` v${d.versionNo}` : ''}
              </Link>
            ) : null}
            {d.ruleId ? <span className="font-mono">{d.ruleId}</span> : null}
          </span>
        );
      },
    },
    {
      id: 'actions',
      header: 'Actions',
      meta: { label: 'Actions', className: 'max-w-64' },
      cell: ({ row }) => (
        <ul className="flex flex-wrap gap-1" aria-label="Actions">
          {row.original.actions.map((action, index) => (
            <li key={index} className="rounded-sm bg-muted px-1.5 py-0.5 font-mono text-xs">
              {action.type} · {action.status}
            </li>
          ))}
        </ul>
      ),
    },
    {
      id: 'override',
      header: 'Override',
      meta: { label: 'Override applied' },
      cell: ({ row }) => (row.original.overrideApplied ? 'Yes' : 'No'),
    },
    {
      id: 'duration',
      header: 'Duration',
      meta: { label: 'Duration', className: 'whitespace-nowrap tabular-nums' },
      cell: ({ row }) => formatDuration(row.original.durationUs / 1000),
    },
  ];
}

/** Policy execution history (`GET /policies/executions`, v0 list, bounded range). */
export function ExecutionsTab() {
  const [state, setState] = useUrlState(EXECUTIONS_URL_SHAPE);
  const query = useMemo(() => executionsQuery(state), [state]);
  const list = useCursorList('PolicyToolsController_history_v1', query, { limit: 50 });
  const canMessages = useCan('MessagesController_detail_v1');
  const cols = useMemo(() => columns(canMessages), [canMessages]);
  const filtered = FILTERS.some((key) => state[key] !== undefined);
  return (
    <DataTable
      tableId="policy-executions"
      caption="Policy executions"
      columns={cols}
      list={list}
      getRowId={(row) => `${row.inputSha256}:${row.evaluatedAt}`}
      getRowLabel={(row) => `evaluation at ${row.evaluatedAt}`}
      isFiltered={filtered}
      onClearFilters={() => setState(Object.fromEntries(FILTERS.map((key) => [key, undefined])))}
      filters={
        <div className="flex flex-wrap items-end gap-2">
          <RangeSelect value={state.range} onChange={(range) => setState({ range })} />
          <FilterSelect
            label="Direction"
            value={state.direction}
            options={optionsOf(DIRECTIONS)}
            onChange={(v) => setState({ direction: v as ExecutionsState['direction'] })}
          />
          <FilterSelect
            label="Disposition"
            value={state.disposition}
            options={optionsOf(DISPOSITIONS)}
            onChange={(v) => setState({ disposition: v as ExecutionsState['disposition'] })}
          />
          <FilterSelect
            label="Decided by"
            value={state.source}
            options={optionsOf(SOURCES)}
            onChange={(v) => setState({ source: v as ExecutionsState['source'] })}
          />
          <FilterSelect
            label="Trigger"
            value={state.trigger}
            options={optionsOf(TRIGGERS)}
            onChange={(v) => setState({ trigger: v as ExecutionsState['trigger'] })}
          />
          <FilterSelect
            label="Override"
            value={state.overrideApplied}
            options={[
              { value: 'true', label: 'Override applied' },
              { value: 'false', label: 'No override' },
            ]}
            onChange={(v) => setState({ overrideApplied: v as ExecutionsState['overrideApplied'] })}
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
        </div>
      }
      emptyState={
        <EmptyState
          icon={HistoryIcon}
          title="No evaluations in this range"
          description="No message was evaluated by the policy engine in the selected range."
        />
      }
      mobileCard={(row) => (
        <div className="grid gap-1 text-sm">
          <EnumBadge value={row.disposition} tones={DISPOSITION_TONE} />
          <span className="text-xs">{humanize(row.decisive.source)}</span>
          <DateTime value={row.evaluatedAt} className="text-xs text-muted-foreground" />
        </div>
      )}
    />
  );
}
