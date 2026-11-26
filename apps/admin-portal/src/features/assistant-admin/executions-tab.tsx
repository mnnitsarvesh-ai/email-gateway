'use client';

import { WrenchIcon } from 'lucide-react';
import { useEffect, useId, useMemo, useState, type FormEvent } from 'react';
import { z } from 'zod';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { DateTime } from '@/components/domain/date-time';
import { EmptyState } from '@/components/states/empty-state';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { decisionLabel } from '@/features/assistant/model';
import { FilterSelect } from '@/features/domains/kit';
import { useUrlState } from '@/hooks/use-url-state';
import { useCursorList } from '@/lib/api/hooks';
import type { ListItem } from '@/lib/api/types';
import { humanize } from '@/lib/format';
import { ParamsViewer, StatusBadge } from './audit-detail';
import { userLabel } from './model';
import { useAdminRange } from './range-control';
import { USER_URL_SHAPE, UserCell } from './usage-tab';

type ExecutionRow = ListItem<'AssistantAdminAuditController_executions_v1'>;

const DECISIONS = [
  'allowed',
  'denied_permission',
  'denied_unknown_tool',
  'denied_disabled',
  'denied_not_applicable',
  'denied_schema',
  'denied_ref',
  'denied_budget',
  'denied_guard',
] as const;
const STATUSES = ['succeeded', 'failed', 'refused', 'timeout', 'pending_confirmation'] as const;
const RISKS = ['read', 'read_audited', 'low', 'medium', 'high', 'critical'] as const;
const ACCESS = ['read', 'write'] as const;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const text = (max: number) => z.string().trim().min(1).max(max).optional().catch(undefined);

export const EXECUTION_URL_SHAPE = {
  ...USER_URL_SHAPE,
  tool: text(96),
  module: text(64),
  correlation: text(128),
  conversation: z.string().regex(UUID).optional().catch(undefined),
  decision: z.enum(DECISIONS).optional().catch(undefined),
  xstatus: z.enum(STATUSES).optional().catch(undefined),
  risk: z.enum(RISKS).optional().catch(undefined),
  access: z.enum(ACCESS).optional().catch(undefined),
};

/** Free-text filters (tool, module, correlation id), applied with the button or Enter. */
function TextFilters({
  values,
  onApply,
}: {
  values: { tool?: string; module?: string; correlation?: string };
  onApply: (next: { tool?: string; module?: string; correlation?: string }) => void;
}) {
  const [tool, setTool] = useState(values.tool ?? '');
  const [module, setModule] = useState(values.module ?? '');
  const [correlation, setCorrelation] = useState(values.correlation ?? '');
  const id = useId();
  useEffect(() => {
    setTool(values.tool ?? '');
    setModule(values.module ?? '');
    setCorrelation(values.correlation ?? '');
  }, [values.tool, values.module, values.correlation]);
  const submit = (event: FormEvent) => {
    event.preventDefault();
    onApply({
      tool: tool.trim() || undefined,
      module: module.trim() || undefined,
      correlation: correlation.trim() || undefined,
    });
  };
  return (
    <form
      onSubmit={submit}
      className="flex flex-wrap items-end gap-2"
      aria-label="Search tool calls"
    >
      <div className="grid gap-1">
        <Label htmlFor={`${id}-tool`} className="text-xs">
          Tool name
        </Label>
        <Input
          id={`${id}-tool`}
          value={tool}
          maxLength={96}
          onChange={(event) => setTool(event.target.value)}
          className="h-8 w-48 font-mono text-xs"
          autoComplete="off"
          spellCheck={false}
        />
      </div>
      <div className="grid gap-1">
        <Label htmlFor={`${id}-module`} className="text-xs">
          Module
        </Label>
        <Input
          id={`${id}-module`}
          value={module}
          maxLength={64}
          onChange={(event) => setModule(event.target.value)}
          className="h-8 w-36 font-mono text-xs"
          autoComplete="off"
          spellCheck={false}
        />
      </div>
      <div className="grid gap-1">
        <Label htmlFor={`${id}-correlation`} className="text-xs">
          Correlation ID
        </Label>
        <Input
          id={`${id}-correlation`}
          value={correlation}
          maxLength={128}
          onChange={(event) => setCorrelation(event.target.value)}
          className="h-8 w-56 font-mono text-xs"
          autoComplete="off"
          spellCheck={false}
        />
      </div>
      <Button type="submit" size="sm" variant="outline">
        Search
      </Button>
    </form>
  );
}

/** Tool calls search (D4 "audit view search", `audit:read`): execution metadata, ≤ 92 days. */
export function ExecutionsTab({
  onOpenConversation,
}: {
  onOpenConversation: (id: string) => void;
}) {
  const [range] = useAdminRange();
  const [filters, setFilters] = useUrlState(EXECUTION_URL_SHAPE);
  const list = useCursorList('AssistantAdminAuditController_executions_v1', {
    from: range.from,
    to: range.to,
    ...(filters.user ? { userId: filters.user } : {}),
    ...(filters.conversation ? { conversationId: filters.conversation } : {}),
    ...(filters.tool ? { tool: filters.tool } : {}),
    ...(filters.module ? { module: filters.module } : {}),
    ...(filters.correlation ? { correlationId: filters.correlation } : {}),
    ...(filters.decision ? { decision: filters.decision } : {}),
    ...(filters.xstatus ? { status: filters.xstatus } : {}),
    ...(filters.risk ? { risk: filters.risk } : {}),
    ...(filters.access ? { access: filters.access } : {}),
  });
  const columns = useMemo<DataTableColumn<ExecutionRow>[]>(
    () => [
      {
        id: 'created',
        header: 'Time',
        meta: { label: 'Time', hideable: false },
        cell: ({ row }) => <DateTime value={row.original.createdAt} />,
      },
      {
        id: 'user',
        header: 'Person',
        meta: { label: 'Person' },
        cell: ({ row }) => <UserCell user={row.original.user} />,
      },
      {
        id: 'tool',
        header: 'Tool',
        meta: { label: 'Tool' },
        cell: ({ row }) => (
          <span className="grid gap-0.5">
            <span className="font-mono text-xs break-all">{row.original.tool}</span>
            <span className="font-mono text-xs break-all text-muted-foreground">
              {row.original.method} {row.original.operationId}
            </span>
          </span>
        ),
      },
      {
        id: 'risk',
        header: 'Access and risk',
        meta: { label: 'Access and risk' },
        cell: ({ row }) => `${humanize(row.original.access)} · ${humanize(row.original.risk)}`,
      },
      {
        id: 'decision',
        header: 'Decision',
        meta: { label: 'Decision' },
        cell: ({ row }) => decisionLabel(row.original.decision),
      },
      {
        id: 'status',
        header: 'Status',
        meta: { label: 'Status' },
        cell: ({ row }) => (
          <span className="grid gap-0.5">
            <StatusBadge status={row.original.status} />
            <span className="text-xs text-muted-foreground">
              {row.original.httpStatus ? `HTTP ${row.original.httpStatus}` : ''}
              {row.original.errorCode ? ` ${row.original.errorCode}` : ''}
            </span>
          </span>
        ),
      },
      {
        id: 'params',
        header: 'Parameters',
        meta: { label: 'Parameters' },
        cell: ({ row }) => (
          <ParamsViewer value={row.original.paramsRedacted} label="Redacted parameters" />
        ),
      },
      {
        id: 'correlation',
        header: 'Correlation ID',
        meta: { label: 'Correlation ID' },
        cell: ({ row }) => (
          <span className="font-mono text-xs break-all">{row.original.correlationId}</span>
        ),
      },
      {
        id: 'conversation',
        header: 'Conversation',
        meta: { label: 'Conversation' },
        cell: ({ row }) => (
          <Button
            variant="link"
            className="h-auto p-0"
            onClick={() => onOpenConversation(row.original.conversationId)}
            aria-label={`Open audit of the conversation of this ${row.original.tool} call`}
          >
            Open audit
          </Button>
        ),
      },
    ],
    [onOpenConversation],
  );
  const filtered = Boolean(
    filters.user ||
    filters.conversation ||
    filters.tool ||
    filters.module ||
    filters.correlation ||
    filters.decision ||
    filters.xstatus ||
    filters.risk ||
    filters.access,
  );
  return (
    <div className="grid min-w-0 gap-3 [&>*]:min-w-0">
      <TextFilters values={filters} onApply={(next) => setFilters(next)} />
      {filters.conversation ? (
        <p className="text-sm">
          One conversation only (<span className="font-mono text-xs">{filters.conversation}</span>
          ).{' '}
          <Button
            variant="link"
            className="h-auto p-0"
            onClick={() => setFilters({ conversation: undefined })}
          >
            Show all
          </Button>
        </p>
      ) : null}
      <DataTable<ExecutionRow>
        tableId="assistant-admin-executions"
        caption={`AI tool calls, ${range.fromDay} to ${range.toDay} (UTC)`}
        columns={columns}
        list={list}
        getRowId={(row) => row.id}
        getRowLabel={(row) => `${row.tool} by ${userLabel(row.user)}`}
        filters={
          <>
            <FilterSelect
              label="Decision"
              value={filters.decision}
              onChange={(decision) =>
                setFilters({ decision: decision as (typeof DECISIONS)[number] | undefined })
              }
              options={DECISIONS.map((value) => ({ value, label: decisionLabel(value) }))}
            />
            <FilterSelect
              label="Status"
              value={filters.xstatus}
              onChange={(xstatus) =>
                setFilters({ xstatus: xstatus as (typeof STATUSES)[number] | undefined })
              }
              options={STATUSES.map((value) => ({ value, label: humanize(value) }))}
            />
            <FilterSelect
              label="Risk"
              value={filters.risk}
              onChange={(risk) => setFilters({ risk: risk as (typeof RISKS)[number] | undefined })}
              options={RISKS.map((value) => ({ value, label: humanize(value) }))}
            />
            <FilterSelect
              label="Access"
              value={filters.access}
              onChange={(access) =>
                setFilters({ access: access as (typeof ACCESS)[number] | undefined })
              }
              options={ACCESS.map((value) => ({ value, label: humanize(value) }))}
            />
          </>
        }
        isFiltered={filtered}
        onClearFilters={() =>
          setFilters({
            user: undefined,
            conversation: undefined,
            tool: undefined,
            module: undefined,
            correlation: undefined,
            decision: undefined,
            xstatus: undefined,
            risk: undefined,
            access: undefined,
          })
        }
        emptyState={
          <EmptyState
            icon={WrenchIcon}
            title="No tool calls match"
            description="Change the filters or choose a longer range (at most 92 days)."
          />
        }
        mobileCard={(row) => (
          <div className="grid gap-1 text-sm">
            <span className="font-mono text-xs break-all">{row.tool}</span>
            <UserCell user={row.user} />
            <span className="flex flex-wrap items-center gap-2">
              <StatusBadge status={row.status} />
              <span className="text-xs">{decisionLabel(row.decision)}</span>
            </span>
            <DateTime value={row.createdAt} className="text-xs" />
          </div>
        )}
      />
    </div>
  );
}
