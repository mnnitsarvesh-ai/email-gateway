'use client';

import { CheckIcon, InboxIcon, XIcon } from 'lucide-react';
import Link from 'next/link';
import { useMemo, useState } from 'react';
import { z } from 'zod';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { CopyableId, DateTime, UntrustedText } from '@/components/domain';
import { PageHeader } from '@/components/page-header';
import { EmptyState } from '@/components/states/empty-state';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { useUrlState } from '@/hooks/use-url-state';
import { useApiMutation, useApiQuery, useCursorList } from '@/lib/api/hooks';
import type { QueryParams } from '@/lib/api/types';
import { useCan, usePermissions } from '@/lib/auth/me';
import { RouteGate } from '@/lib/auth/route-gate';
import { humanize } from '@/lib/format';
import { resolvePreset } from '@/lib/range';
import {
  CodeList,
  DetailList,
  EnumBadge,
  FilterSelect,
  Section,
  optionsOf,
} from '@/features/messages/controls';
import { BulkActionBar, BulkResultNotice } from './bulk-actions';
import { approvalDecisionBody } from './forms';
import { approvalHref, entryHref, releaseHref } from './links';
import { ReasonConfirm } from './reason-confirm';
import { APPROVAL_STATUS_TONE } from './semantic';
import type { Approval, BulkResult } from './types';
import { useQuarantineCatalog } from './use-catalog';

const STATUSES = ['pending', 'approved', 'denied', 'expired', 'cancelled'] as const;
const KINDS = ['policy_review', 'release_approval', 'release_request'] as const;
const RANGES = ['all', '7d', '30d'] as const;

export const APPROVALS_URL_SHAPE = {
  status: z
    .enum([...STATUSES, 'any'] as const)
    .default('pending')
    .catch('pending'),
  kind: z.enum(KINDS).optional().catch(undefined),
  range: z.enum(RANGES).default('all').catch('all'),
};

type ApprovalsState = {
  [K in keyof typeof APPROVALS_URL_SHAPE]: z.output<(typeof APPROVALS_URL_SHAPE)[K]>;
};

export function approvalsQuery(
  state: ApprovalsState,
  now = Date.now(),
): QueryParams<'QuarantineApprovalsController_list_v1'> {
  const query: QueryParams<'QuarantineApprovalsController_list_v1'> = {};
  if (state.status !== 'any') query.status = state.status;
  if (state.kind) query.kind = state.kind;
  if (state.range !== 'all') {
    const window = resolvePreset(state.range, now);
    query.from = window.from;
    query.to = window.to;
  }
  return query;
}

const KIND_LABEL: Record<string, string> = {
  policy_review: 'Policy review',
  release_approval: 'Release approval',
  release_request: 'Release request',
};

const COLUMNS: DataTableColumn<Approval>[] = [
  {
    id: 'requestedAt',
    header: 'Requested',
    meta: { label: 'Requested', className: 'whitespace-nowrap' },
    cell: ({ row }) => (
      <Link
        href={approvalHref(row.original.id)}
        className="font-medium text-primary underline-offset-2 hover:underline"
      >
        <DateTime value={row.original.requestedAt} />
        <span className="sr-only">, open approval request</span>
      </Link>
    ),
  },
  {
    id: 'kind',
    header: 'Kind',
    meta: { label: 'Kind' },
    cell: ({ row }) => KIND_LABEL[row.original.kind] ?? humanize(row.original.kind),
  },
  {
    id: 'status',
    header: 'Status',
    meta: { label: 'Status' },
    cell: ({ row }) => <EnumBadge value={row.original.status} tones={APPROVAL_STATUS_TONE} />,
  },
  {
    id: 'reasons',
    header: 'Approval reasons',
    meta: { label: 'Approval reasons', className: 'max-w-72' },
    cell: ({ row }) => <CodeList codes={row.original.approvalReasons} />,
  },
  {
    id: 'requestedBy',
    header: 'Requested by',
    meta: { label: 'Requested by' },
    cell: ({ row }) => (
      <span className="text-xs">
        {humanize(row.original.requestedBy.type)}
        {row.original.requestedBy.id ? (
          <span className="block font-mono text-muted-foreground">
            {row.original.requestedBy.id}
          </span>
        ) : null}
      </span>
    ),
  },
  {
    id: 'entry',
    header: 'Entry',
    meta: { label: 'Entry' },
    cell: ({ row }) => (
      <Link href={entryHref(row.original.entryId)} className="text-xs text-primary hover:underline">
        Open entry
      </Link>
    ),
  },
  {
    id: 'expires',
    header: 'Expires',
    meta: { label: 'Expires', className: 'whitespace-nowrap' },
    cell: ({ row }) => <DateTime value={row.original.expiresAt} />,
  },
];

/** Approvals tab of `/quarantine` and the `/quarantine/approvals` route. */
export function ApprovalsTab() {
  const [state, setState] = useUrlState(APPROVALS_URL_SHAPE);
  const query = useMemo(() => approvalsQuery(state), [state]);
  const list = useCursorList('QuarantineApprovalsController_list_v1', query, { limit: 50 });
  const catalog = useQuarantineCatalog();
  const permissions = usePermissions();
  const bulk = (catalog.data?.bulkActions ?? []).filter(
    (action) =>
      (action === 'approve' || action === 'deny') && permissions.has('quarantine:approve'),
  );
  const [bulkResult, setBulkResult] = useState<BulkResult | null>(null);
  const filtered = state.status !== 'pending' || state.kind !== undefined || state.range !== 'all';
  return (
    <div className="grid gap-4">
      <p className="text-sm text-muted-foreground">
        Separation of duties: nobody approves their own request or a message addressed to them.
        Approving queues a release; the release executor re-validates the message before delivery.
      </p>
      <div role="status" aria-live="polite">
        {bulkResult ? (
          <BulkResultNotice result={bulkResult} onDismiss={() => setBulkResult(null)} />
        ) : null}
      </div>
      <DataTable
        tableId="quarantine-approvals"
        caption="Approval requests"
        columns={COLUMNS}
        list={list}
        getRowId={(row) => row.id}
        getRowLabel={(row) => `approval request ${row.id}`}
        isFiltered={filtered}
        onClearFilters={() => setState({ status: 'pending', kind: undefined, range: 'all' })}
        enableSelection={bulk.length > 0 && state.status === 'pending'}
        bulkActions={(rows, clearSelection) => (
          <BulkActionBar
            ids={rows.map((row) => row.id)}
            actions={bulk}
            catalog={catalog.data}
            onDone={(result) => {
              setBulkResult(result);
              clearSelection();
            }}
          />
        )}
        filters={
          <div className="flex flex-wrap items-end gap-2">
            <FilterSelect
              label="Status"
              value={state.status}
              allowAny={false}
              options={[...optionsOf(STATUSES), { value: 'any', label: 'Any status' }]}
              onChange={(status) =>
                setState({ status: (status as ApprovalsState['status']) ?? 'pending' })
              }
            />
            <FilterSelect
              label="Kind"
              value={state.kind}
              options={KINDS.map((kind) => ({ value: kind, label: KIND_LABEL[kind] ?? kind }))}
              onChange={(kind) => setState({ kind: kind as ApprovalsState['kind'] })}
            />
            <FilterSelect
              label="Requested"
              value={state.range}
              allowAny={false}
              options={[
                { value: 'all', label: 'Any time' },
                { value: '7d', label: 'Last 7 days' },
                { value: '30d', label: 'Last 30 days' },
              ]}
              onChange={(range) => setState({ range: (range as ApprovalsState['range']) ?? 'all' })}
            />
          </div>
        }
        emptyState={
          <EmptyState
            icon={InboxIcon}
            title="No approval requests"
            description="Nothing is waiting for a decision."
          />
        }
        mobileCard={(row) => (
          <div className="grid gap-1 text-sm">
            <Link href={approvalHref(row.id)} className="font-medium text-primary hover:underline">
              {KIND_LABEL[row.kind] ?? row.kind}
            </Link>
            <div className="flex flex-wrap items-center gap-2">
              <EnumBadge value={row.status} tones={APPROVAL_STATUS_TONE} />
              <DateTime value={row.requestedAt} className="text-xs text-muted-foreground" />
            </div>
          </div>
        )}
      />
    </div>
  );
}

/** Approval request detail (`/quarantine/approvals/[approvalId]`, linked from approval e-mails). */
export function ApprovalDetail({ approvalId }: { approvalId: string }) {
  return (
    <RouteGate gate={['QuarantineApprovalsController_get_v1']}>
      <ApprovalDetailContent approvalId={approvalId} />
    </RouteGate>
  );
}

const APPROVAL_INVALIDATES = [
  'QuarantineApprovalsController_get_v1',
  'QuarantineApprovalsController_list_v1',
  'QuarantineEntriesController_detail_v1',
  'QuarantineEntriesController_search_v1',
  'QuarantineToolsController_summary_v1',
] as const;

function ApprovalDetailContent({ approvalId }: { approvalId: string }) {
  const approval = useApiQuery('QuarantineApprovalsController_get_v1', { path: { approvalId } });
  const entryId = approval.data?.entryId;
  const entry = useApiQuery(
    'QuarantineEntriesController_detail_v1',
    { path: { entryId: entryId ?? '' } },
    { enabled: Boolean(entryId), refetchOnWindowFocus: false },
  );
  const catalog = useQuarantineCatalog();
  const canApprove = useCan('QuarantineApprovalsController_approve_v1');
  const canCancel = useCan('QuarantineApprovalsController_cancel_v1');
  const [dialog, setDialog] = useState<'approve' | 'deny' | 'cancel' | null>(null);
  const [releaseId, setReleaseId] = useState<string | null>(null);
  const path = { approvalId };
  const approve = useApiMutation('QuarantineApprovalsController_approve_v1', {
    invalidates: APPROVAL_INVALIDATES,
    successMessage: 'Approved. The release is queued.',
    onSuccess: (data) => setReleaseId(data.releaseId),
  });
  const deny = useApiMutation('QuarantineApprovalsController_deny_v1', {
    invalidates: APPROVAL_INVALIDATES,
    successMessage: 'Request denied.',
  });
  const cancel = useApiMutation('QuarantineApprovalsController_cancel_v1', {
    invalidates: APPROVAL_INVALIDATES,
    successMessage: 'Request cancelled.',
  });
  const breadcrumbs = [
    { label: 'Quarantine', href: '/quarantine' },
    { label: 'Approvals', href: '/quarantine/approvals' },
    { label: 'Request' },
  ];
  if (approval.isLoading) {
    return (
      <div className="grid gap-4">
        <PageHeader title="Approval request" breadcrumbs={breadcrumbs} />
        <LoadingState label="Loading the approval request" rows={6} />
      </div>
    );
  }
  if (approval.error || !approval.data) {
    return (
      <div className="grid gap-4">
        <PageHeader title="Approval request" breadcrumbs={breadcrumbs} />
        <ErrorState error={approval.error} onRetry={() => void approval.refetch()} />
      </div>
    );
  }
  const a = approval.data;
  const pending = a.status === 'pending';
  const maxChars = catalog.data?.limits.reasonMaxChars;
  return (
    <div className="grid gap-4">
      <PageHeader
        title="Approval request"
        breadcrumbs={breadcrumbs}
        description={KIND_LABEL[a.kind]}
        actions={
          pending ? (
            <>
              {canApprove ? (
                <>
                  <Button size="sm" onClick={() => setDialog('approve')}>
                    <CheckIcon aria-hidden />
                    Approve
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => setDialog('deny')}>
                    <XIcon aria-hidden />
                    Deny
                  </Button>
                </>
              ) : null}
              {canCancel && a.kind !== 'policy_review' ? (
                <Button size="sm" variant="ghost" onClick={() => setDialog('cancel')}>
                  Cancel request
                </Button>
              ) : null}
            </>
          ) : null
        }
      />
      <div role="status" aria-live="polite">
        {releaseId ? (
          <p className="rounded-md bg-tone-success px-3 py-2 text-sm text-tone-success-foreground">
            Approved. The release executor re-validates and delivers the message.{' '}
            <Link href={releaseHref(releaseId)} className="font-medium underline">
              Follow the release status
            </Link>
          </p>
        ) : null}
      </div>
      {pending && canApprove ? (
        <p className="text-sm text-muted-foreground">
          You cannot decide a request you made yourself or one for a message addressed to you; the
          api refuses it (separation of duties). Approving and denying need an MFA session.
        </p>
      ) : null}
      <Section title="Request">
        <DetailList
          items={[
            { label: 'Status', value: <EnumBadge value={a.status} tones={APPROVAL_STATUS_TONE} /> },
            { label: 'Kind', value: KIND_LABEL[a.kind] ?? humanize(a.kind) },
            { label: 'Approval reasons', value: <CodeList codes={a.approvalReasons} /> },
            {
              label: 'Requested by',
              value: (
                <span>
                  {humanize(a.requestedBy.type)}
                  {a.requestedBy.id ? (
                    <span className="font-mono text-xs"> {a.requestedBy.id}</span>
                  ) : null}
                </span>
              ),
            },
            { label: 'Requested', value: <DateTime value={a.requestedAt} mode="absolute" /> },
            { label: 'Expires', value: <DateTime value={a.expiresAt} mode="absolute" /> },
            {
              label: 'Decided',
              value: a.decidedAt ? (
                <span>
                  <DateTime value={a.decidedAt} mode="absolute" />
                  {a.decidedBy ? (
                    <span className="font-mono text-xs"> by {a.decidedBy}</span>
                  ) : null}
                </span>
              ) : (
                <span className="text-muted-foreground">Not decided</span>
              ),
            },
            {
              label: 'Decision reason',
              value: <UntrustedText value={a.decisionReason} maxLength={512} emptyLabel="None" />,
            },
            {
              label: 'Request ID',
              value: <CopyableId value={a.id} label="approval ID" max={40} />,
            },
          ]}
        />
      </Section>
      <Section
        title="Entry"
        actions={
          <Button asChild size="sm" variant="outline">
            <Link href={entryHref(a.entryId)}>Open entry</Link>
          </Button>
        }
      >
        {entry.isLoading ? (
          <LoadingState label="Loading the entry" rows={3} />
        ) : entry.error ? (
          <ErrorState error={entry.error} onRetry={() => void entry.refetch()} compact />
        ) : entry.data ? (
          <DetailList
            items={[
              {
                label: 'Subject',
                value: (
                  <UntrustedText
                    value={entry.data.subject}
                    maxLength={256}
                    emptyLabel="(not shown)"
                  />
                ),
              },
              { label: 'Recipient', value: <UntrustedText value={entry.data.recipient} /> },
              {
                label: 'Sender',
                value: (
                  <UntrustedText
                    value={entry.data.sender.headerFrom ?? entry.data.sender.envelope}
                    emptyLabel="(null sender)"
                  />
                ),
              },
              { label: 'Reason', value: humanize(entry.data.reason) },
              { label: 'Hard blocks', value: <CodeList codes={entry.data.hardBlocks} /> },
              {
                label: 'Explanation',
                value: <p className="whitespace-pre-wrap">{entry.data.explanation.text}</p>,
              },
            ]}
          />
        ) : null}
      </Section>
      <ReasonConfirm
        open={dialog === 'approve'}
        onOpenChange={(open) => !open && setDialog(null)}
        title="Approve this request?"
        description={
          <p>The release is queued and re-validated by the release executor before delivery.</p>
        }
        confirmLabel="Approve"
        maxChars={maxChars}
        pending={approve.isPending}
        onSubmit={(reason) => approve.submit({ path, body: approvalDecisionBody(reason) })}
        onRetry={() => approve.retry()}
      />
      <ReasonConfirm
        open={dialog === 'deny'}
        onOpenChange={(open) => !open && setDialog(null)}
        title="Deny this request?"
        description={
          <p>
            {a.kind === 'policy_review'
              ? 'Denying a policy review rejects the entry: the message is not delivered.'
              : 'The entry returns to held.'}
          </p>
        }
        confirmLabel="Deny"
        destructive
        maxChars={maxChars}
        pending={deny.isPending}
        onSubmit={(reason) => deny.submit({ path, body: approvalDecisionBody(reason) })}
        onRetry={() => deny.retry()}
      />
      <ReasonConfirm
        open={dialog === 'cancel'}
        onOpenChange={(open) => !open && setDialog(null)}
        title="Cancel this request?"
        description={<p>The entry returns to held.</p>}
        confirmLabel="Cancel request"
        maxChars={maxChars}
        pending={cancel.isPending}
        onSubmit={(reason) => cancel.submit({ path, body: approvalDecisionBody(reason) })}
        onRetry={() => cancel.retry()}
      />
    </div>
  );
}
