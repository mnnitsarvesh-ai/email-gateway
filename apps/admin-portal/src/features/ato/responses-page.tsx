'use client';

import { ShieldCheckIcon } from 'lucide-react';
import Link from 'next/link';
import { useMemo, useState } from 'react';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { DateTime } from '@/components/domain';
import { PageHeader } from '@/components/page-header';
import { EmptyState } from '@/components/states/empty-state';
import { useCursorList } from '@/lib/api/hooks';
import { RouteGate } from '@/lib/auth/route-gate';
import { humanize } from '@/lib/format';
import { GatedTabs, type TabDefinition } from '@/features/reports/gated-tabs';
import { EnumBadge, FilterMultiSelect, FilterSelect } from '@/features/messages/controls';
import { ResponseControls } from './response-actions';
import {
  ACTION_LABELS,
  ATO_ACTION_TYPES,
  ATO_RESPONSE_STATUSES,
  KIND_LABELS,
  RESPONSE_STATUS_TONE,
  RESTRICTION_STATUS_TONE,
  atoAccountHref,
  formatMinutes,
  incidentHref,
  labelOf,
  type AtoResponse,
  type AtoRestriction,
} from './model';

export const RESPONSE_TABS: readonly TabDefinition[] = [
  { id: 'pending', label: 'Pending approvals', ops: ['AtoResponsesController_list_v1'] },
  { id: 'all', label: 'All responses', ops: ['AtoResponsesController_list_v1'] },
  { id: 'restrictions', label: 'Restrictions', ops: ['AtoRestrictionsController_list_v1'] },
];

/** `/ato/responses`: responses and approvals, pending first, and restrictions (step 8.4 §6). */
export function AtoResponsesPage() {
  return (
    <RouteGate gate={['AtoResponsesController_list_v1']}>
      <div className="grid min-w-0 gap-4">
        <PageHeader
          title="Responses"
          breadcrumbs={[{ label: 'Account takeover', href: '/ato' }, { label: 'Responses' }]}
          description="Responses to account takeover incidents. High-impact responses need a second analyst’s approval with MFA (four eyes); every decision is recorded with its reason."
        />
        <GatedTabs
          tabs={RESPONSE_TABS}
          label="Responses"
          keepParams={[]}
          render={(tab) => {
            switch (tab) {
              case 'all':
                return <ResponseList mode="all" />;
              case 'restrictions':
                return <RestrictionList />;
              default:
                return <ResponseList mode="pending" />;
            }
          }}
        />
      </div>
    </RouteGate>
  );
}

export function responseColumns(): DataTableColumn<AtoResponse>[] {
  return [
    {
      id: 'response',
      header: 'Response',
      meta: { label: 'Response', hideable: false },
      cell: ({ row }) => (
        <div className="grid gap-0.5">
          <span className="font-medium">{labelOf(ACTION_LABELS, row.original.actionType)}</span>
          <span className="text-xs text-muted-foreground">
            {humanize(row.original.impact)} impact · {humanize(row.original.provider)}
            {row.original.params.durationMinutes
              ? ` · ${formatMinutes(row.original.params.durationMinutes)}`
              : ''}
            {row.original.target.cidr ? ` · ${row.original.target.cidr}` : ''}
          </span>
        </div>
      ),
    },
    {
      id: 'status',
      header: 'Status',
      meta: { label: 'Status' },
      cell: ({ row }) => (
        <div className="grid gap-0.5">
          <EnumBadge value={row.original.status} tones={RESPONSE_STATUS_TONE} />
          {row.original.providerStatus ? (
            <span className="text-xs text-muted-foreground">
              {row.original.providerStatus === 'applied'
                ? 'Applied by the gateway'
                : row.original.providerStatus === 'unconfirmed'
                  ? 'Queued (delivery not confirmed)'
                  : humanize(row.original.providerStatus)}
            </span>
          ) : null}
          {row.original.status === 'pending_approval' && row.original.approvalExpiresAt ? (
            <span className="text-xs text-muted-foreground">
              Expires <DateTime value={row.original.approvalExpiresAt} />
            </span>
          ) : null}
        </div>
      ),
    },
    {
      id: 'account',
      header: 'Account',
      meta: { label: 'Account' },
      cell: ({ row }) => (
        <Link
          href={atoAccountHref(row.original.account.id)}
          className="text-primary underline-offset-2 hover:underline"
        >
          {labelOf(KIND_LABELS, row.original.account.kind)}
        </Link>
      ),
    },
    {
      id: 'incident',
      header: 'Incident',
      meta: { label: 'Incident' },
      cell: ({ row }) =>
        row.original.incidentId ? (
          <Link
            href={incidentHref(row.original.incidentId)}
            className="text-primary underline-offset-2 hover:underline"
          >
            Open incident
          </Link>
        ) : (
          <span className="text-muted-foreground">None</span>
        ),
    },
    {
      id: 'requested',
      header: 'Requested',
      meta: { label: 'Requested' },
      cell: ({ row }) => (
        <div className="grid gap-0.5">
          <DateTime value={row.original.createdAt} />
          <span className="text-xs text-muted-foreground">
            by {humanize(row.original.requestedBy.type)}
            {row.original.authorization === 'automation_policy' ? ' (automation)' : ''}
          </span>
          {row.original.requestReason ? (
            <span className="text-xs text-muted-foreground">{row.original.requestReason}</span>
          ) : null}
        </div>
      ),
    },
    {
      id: 'actions',
      header: 'Actions',
      meta: { label: 'Actions', hideable: false },
      cell: ({ row }) => <ResponseControls response={row.original} />,
    },
  ];
}

function ResponseList({ mode }: { mode: 'pending' | 'all' }) {
  const [statuses, setStatuses] = useState<string[]>([]);
  const [actionType, setActionType] = useState<string | undefined>(undefined);
  const filters = useMemo(
    () => ({
      sort: '-createdAt' as const,
      ...(mode === 'pending'
        ? { status: 'pending_approval' }
        : statuses.length
          ? { status: statuses.join(',') }
          : {}),
      ...(actionType ? { actionType } : {}),
    }),
    [mode, statuses, actionType],
  );
  const list = useCursorList('AtoResponsesController_list_v1', filters, { limit: 25 });
  return (
    <DataTable
      tableId={`ato-responses-${mode}`}
      caption={mode === 'pending' ? 'Responses waiting for approval' : 'Responses'}
      columns={responseColumns()}
      list={list}
      getRowId={(row) => row.id}
      getRowLabel={(row) => labelOf(ACTION_LABELS, row.actionType)}
      filters={
        <div className="flex flex-wrap items-end gap-3">
          {mode === 'all' ? (
            <FilterMultiSelect
              label="Status"
              values={statuses}
              options={ATO_RESPONSE_STATUSES.map((s) => ({ value: s, label: humanize(s) }))}
              onChange={setStatuses}
            />
          ) : null}
          <FilterSelect
            label="Response"
            value={actionType}
            options={ATO_ACTION_TYPES.map((t) => ({ value: t, label: ACTION_LABELS[t] }))}
            onChange={setActionType}
          />
        </div>
      }
      isFiltered={statuses.length > 0 || actionType !== undefined}
      onClearFilters={() => {
        setStatuses([]);
        setActionType(undefined);
      }}
      emptyState={
        <EmptyState
          icon={ShieldCheckIcon}
          title={mode === 'pending' ? 'Nothing waits for approval' : 'No responses yet'}
          description="Responses are requested from an incident or proposed by the tenant’s automation."
        />
      }
      mobileCard={(row) => (
        <div className="grid gap-1">
          <span className="font-medium">{labelOf(ACTION_LABELS, row.actionType)}</span>
          <EnumBadge value={row.status} tones={RESPONSE_STATUS_TONE} />
          <ResponseControls response={row} />
        </div>
      )}
    />
  );
}

function RestrictionList() {
  const [status, setStatus] = useState<string | undefined>('active');
  const [kind, setKind] = useState<string | undefined>(undefined);
  const filters = useMemo(
    () => ({
      sort: '-createdAt' as const,
      ...(status ? { status } : {}),
      ...(kind ? { kind } : {}),
    }),
    [status, kind],
  );
  const list = useCursorList('AtoRestrictionsController_list_v1', filters, { limit: 25 });
  const columns: DataTableColumn<AtoRestriction>[] = [
    {
      id: 'restriction',
      header: 'Restriction',
      meta: { label: 'Restriction', hideable: false },
      cell: ({ row }) => (
        <div className="grid gap-0.5">
          <span className="font-medium">
            {row.original.kind === 'send_block'
              ? 'Sending restricted'
              : 'SMTP authentication blocked'}
          </span>
          <span className="text-xs text-muted-foreground">
            {humanize(row.original.scope)}
            {row.original.kind === 'send_block' ? ` · ${humanize(row.original.mode)}` : ''}
          </span>
        </div>
      ),
    },
    {
      id: 'target',
      header: 'Target',
      meta: { label: 'Target' },
      cell: ({ row }) => (
        <span className="grid gap-0.5">
          <span>{row.original.mailboxAddress ?? row.original.connectorName ?? '—'}</span>
          {row.original.ipCidr ? (
            <span className="font-mono text-xs text-muted-foreground">{row.original.ipCidr}</span>
          ) : null}
        </span>
      ),
    },
    {
      id: 'status',
      header: 'Status',
      meta: { label: 'Status' },
      cell: ({ row }) => <EnumBadge value={row.original.status} tones={RESTRICTION_STATUS_TONE} />,
    },
    {
      id: 'window',
      header: 'Window',
      meta: { label: 'Window' },
      cell: ({ row }) => (
        <span className="grid gap-0.5 text-xs">
          <span>
            From <DateTime value={row.original.startsAt} mode="absolute" />
          </span>
          <span>
            {row.original.liftedAt ? 'Lifted ' : 'Until '}
            <DateTime value={row.original.liftedAt ?? row.original.expiresAt} mode="absolute" />
          </span>
        </span>
      ),
    },
    {
      id: 'reason',
      header: 'Reason',
      meta: { label: 'Reason' },
      cell: ({ row }) => (
        <span className="font-mono text-xs">
          {row.original.liftReason ?? row.original.reasonCode}
        </span>
      ),
    },
  ];
  return (
    <DataTable
      tableId="ato-restrictions"
      caption="SMTP restrictions"
      columns={columns}
      list={list}
      getRowId={(row) => row.id}
      filters={
        <div className="flex flex-wrap items-end gap-3">
          <FilterSelect
            label="Status"
            value={status}
            anyLabel="All"
            options={[
              { value: 'active', label: 'Active' },
              { value: 'lifted', label: 'Lifted' },
              { value: 'expired', label: 'Expired' },
            ]}
            onChange={setStatus}
          />
          <FilterSelect
            label="Kind"
            value={kind}
            options={[
              { value: 'send_block', label: 'Sending restricted' },
              { value: 'auth_block', label: 'Authentication blocked' },
            ]}
            onChange={setKind}
          />
        </div>
      }
      isFiltered={status !== 'active' || kind !== undefined}
      onClearFilters={() => {
        setStatus('active');
        setKind(undefined);
      }}
      emptyState={
        <EmptyState
          icon={ShieldCheckIcon}
          title="No restrictions"
          description="Restrictions are created by approved or automatic responses and end when lifted or expired (at most 7 days)."
        />
      }
    />
  );
}
