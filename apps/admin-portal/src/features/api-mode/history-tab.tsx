'use client';

import { HistoryIcon } from 'lucide-react';
import Link from 'next/link';
import { useMemo, useState } from 'react';
import { z } from 'zod';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { CopyableId } from '@/components/domain/copyable-id';
import { DateTime } from '@/components/domain/date-time';
import { UntrustedText } from '@/components/domain/untrusted-text';
import { RangePicker, useRangeState } from '@/components/range-picker';
import { EmptyState } from '@/components/states/empty-state';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import { useUrlState } from '@/hooks/use-url-state';
import { useApiMutation, useApiQuery, useCursorList } from '@/lib/api/hooks';
import type { OperationId, QueryParams } from '@/lib/api/types';
import { useCan } from '@/lib/auth/me';
import { formatDuration, formatNumber, humanize } from '@/lib/format';
import { DetailList, FilterSelect, MutationError } from '@/features/domains/kit';
import { entryHref, releaseHref } from '@/features/quarantine/links';
import { clawbackHref } from './clawback-model';
import {
  CONTAINER_LABEL,
  POLICY_SOURCE_LABEL,
  REMEDIATION_ACTION_KINDS,
  REMEDIATION_STATUSES,
  REMEDIATION_TRIGGERS,
  RemediationStatusBadge,
  TRIGGER_LABEL,
  actionLabel,
  detectionHref,
  reasonCodeText,
  remediationErrorText,
  type Remediation,
  type RemediationDetail,
} from './remediation-model';

/** Queries a remediation request makes stale (history, detections, coverage). */
export const REMEDIATION_QUERIES: readonly OperationId[] = [
  'ApiModeRemediationController_list_v1',
  'ApiModeRemediationController_detail_v1',
  'ApiModeController_listDetections_v1',
  'ApiModeController_getDetection_v1',
  'ApiModeController_overview_v1',
];

const uuid = z.string().uuid().optional().catch(undefined);
const URL_SHAPE = {
  status: z.enum(REMEDIATION_STATUSES).optional().catch(undefined),
  action: z.enum(REMEDIATION_ACTION_KINDS).optional().catch(undefined),
  trigger: z.enum(REMEDIATION_TRIGGERS).optional().catch(undefined),
  connection: uuid,
  mailbox: uuid,
  detection: uuid,
  /** The remediation whose detail drawer is open. */
  remediation: uuid,
};

/** The list query (`GET /api-mode/remediations`, v1 cursor, ≤ 31 days; R13 #5). */
export function historyQuery(
  filters: {
    status?: string;
    action?: string;
    trigger?: string;
    connection?: string;
    mailbox?: string;
    detection?: string;
  },
  range: { from: string; to: string },
): QueryParams<'ApiModeRemediationController_list_v1'> {
  return {
    from: range.from,
    to: range.to,
    ...(filters.status ? { status: filters.status } : {}),
    ...(filters.action ? { action: filters.action } : {}),
    ...(filters.trigger ? { trigger: filters.trigger } : {}),
    ...(filters.connection ? { connectionId: filters.connection } : {}),
    ...(filters.mailbox ? { mailboxId: filters.mailbox } : {}),
    ...(filters.detection ? { detectionId: filters.detection } : {}),
  };
}

function latencyText(ms: number | null): string {
  return ms === null ? '—' : formatDuration(ms);
}

/** "Retry" of a failed action (R12): back to pending, attempts reset. */
export function RetryDialog({
  remediation,
  onOpenChange,
}: {
  remediation: Pick<Remediation, 'id' | 'action'> | null;
  onOpenChange: (open: boolean) => void;
}) {
  const retry = useApiMutation('ApiModeRemediationController_retry_v1', {
    invalidates: REMEDIATION_QUERIES,
    successMessage: 'Queued again: the mailbox worker retries the action within seconds.',
  });
  const text = remediationErrorText(retry.error);
  return (
    <ConfirmDialog
      open={remediation !== null}
      onOpenChange={(open) => {
        if (!open) retry.reset();
        onOpenChange(open);
      }}
      title="Retry this mailbox action?"
      description={`${actionLabel(remediation?.action)} goes back to the queue with its attempts reset. The request is audited.`}
      confirmLabel="Retry"
      error={
        retry.error ? (
          <div className="grid gap-1">
            {text ? <p className="text-xs font-medium text-destructive">{text}</p> : null}
            <MutationError error={retry.error} />
          </div>
        ) : null
      }
      onConfirm={async () => {
        if (!remediation) return false;
        const outcome = await retry.submit({ path: { remediationId: remediation.id } });
        return outcome.ok;
      }}
    />
  );
}

function DecisionRecord({ decision }: { decision: RemediationDetail['decision'] }) {
  if (decision === null) return <span className="text-muted-foreground">Not recorded</span>;
  if ('requestedAction' in decision) {
    return (
      <span className="grid gap-0.5 text-sm">
        <span>Requested: {actionLabel(decision.requestedAction)}</span>
        {decision.reason ? (
          <span className="text-xs">
            Reason: <UntrustedText value={decision.reason} maxLength={500} />
          </span>
        ) : null}
      </span>
    );
  }
  return (
    <DetailList
      className="rounded-md border p-2"
      items={[
        {
          label: 'Policy',
          value: `${POLICY_SOURCE_LABEL[decision.policy.scope] ?? humanize(decision.policy.scope)}${
            decision.policy.rowVersion !== null ? ` (version ${decision.policy.rowVersion})` : ''
          }`,
        },
        { label: 'Mode', value: humanize(decision.mode) },
        {
          label: 'Rule',
          value: decision.ruleId ? (
            <UntrustedText value={decision.ruleId} mono maxLength={48} />
          ) : (
            'No rule matched'
          ),
        },
        {
          label: 'Inputs',
          value: (
            <span className="text-xs">
              verdict {decision.inputs.verdict ?? 'none'} · score{' '}
              {decision.inputs.riskScore ?? 'none'} · level {decision.inputs.level ?? 'none'} ·{' '}
              {decision.inputs.verdictAuthority} verdict
              {decision.inputs.hardBlocks.length > 0
                ? ` · hard blocks ${decision.inputs.hardBlocks.join(', ')}`
                : ''}
            </span>
          ),
        },
        ...(decision.notes.length > 0
          ? [{ label: 'Notes', value: decision.notes.map(humanize).join(', ') }]
          : []),
        {
          label: 'Policy fingerprint',
          value: <span className="font-mono text-xs break-all">{decision.policy.sha256}</span>,
        },
      ]}
    />
  );
}

/** Detail drawer of one remediation (R13 #6): decision record, attempts, error, links. */
export function RemediationDrawer({
  remediationId,
  onClose,
  onOpen,
  onRetry,
}: {
  remediationId: string | undefined;
  onClose: () => void;
  onOpen: (remediationId: string) => void;
  onRetry: (remediation: RemediationDetail) => void;
}) {
  const canRetry = useCan('ApiModeRemediationController_retry_v1');
  const detail = useApiQuery(
    'ApiModeRemediationController_detail_v1',
    { path: { remediationId: remediationId ?? '' } },
    { enabled: Boolean(remediationId) },
  );
  const r = detail.data;
  return (
    <Sheet open={Boolean(remediationId)} onOpenChange={(next) => (!next ? onClose() : undefined)}>
      <SheetContent side="right" className="w-full overflow-y-auto sm:max-w-lg">
        <SheetHeader>
          <SheetTitle>Mailbox action</SheetTitle>
          <SheetDescription>
            {r ? `${actionLabel(r.action)} · ${TRIGGER_LABEL[r.trigger] ?? r.trigger}` : 'Details'}
          </SheetDescription>
        </SheetHeader>
        <div className="grid gap-4 px-4 pb-6">
          {detail.isLoading ? (
            <LoadingState label="Loading the action" rows={6} />
          ) : detail.error ? (
            <ErrorState error={detail.error} onRetry={() => void detail.refetch()} compact />
          ) : r ? (
            <>
              <DetailList
                items={[
                  { label: 'Status', value: <RemediationStatusBadge status={r.status} /> },
                  {
                    label: 'Result',
                    value: reasonCodeText(r.reasonCode) ?? (
                      <span className="text-muted-foreground">None</span>
                    ),
                  },
                  { label: 'Action', value: actionLabel(r.action) },
                  { label: 'Trigger', value: TRIGGER_LABEL[r.trigger] ?? humanize(r.trigger) },
                  {
                    label: 'Requested by',
                    value: `${humanize(r.requestedBy.type)}${r.requestedBy.userId ? ` ${r.requestedBy.userId}` : ''}`,
                  },
                  {
                    label: 'Request reason',
                    value: (
                      <UntrustedText value={r.requestReason} maxLength={500} emptyLabel="None" />
                    ),
                  },
                  {
                    label: 'Mailbox',
                    value: <UntrustedText value={r.mailbox.address} mono maxLength={80} />,
                  },
                  {
                    label: 'Attempts',
                    value: `${formatNumber(r.attempts)} (message searches ${formatNumber(r.locateAttempts)})`,
                  },
                  {
                    label: 'Last error',
                    value: r.lastErrorCode ? (
                      <span className="font-mono text-xs">
                        {r.lastErrorCode}
                        {r.lastHttpStatus ? ` (HTTP ${r.lastHttpStatus})` : ''}
                      </span>
                    ) : (
                      'None'
                    ),
                  },
                  {
                    label: 'Message location',
                    value: r.providerRefs ? (
                      <span>
                        {r.providerRefs.container
                          ? (CONTAINER_LABEL[r.providerRefs.container] ?? r.providerRefs.container)
                          : 'Unchanged'}{' '}
                        <span className="text-xs text-muted-foreground">
                          ({formatNumber(r.providerRefs.before)} message
                          {r.providerRefs.before === 1 ? '' : 's'} acted on)
                        </span>
                      </span>
                    ) : (
                      'Not acted on yet'
                    ),
                  },
                  { label: 'Decision', value: <DecisionRecord decision={r.decision} /> },
                  { label: 'Requested', value: <DateTime value={r.createdAt} mode="absolute" /> },
                  {
                    label: 'Next attempt',
                    value: <DateTime value={r.nextAttemptAt} mode="absolute" emptyLabel="None" />,
                  },
                  {
                    label: 'Completed',
                    value: <DateTime value={r.completedAt} mode="absolute" emptyLabel="Not yet" />,
                  },
                  { label: 'Latency', value: latencyText(r.latencyMs) },
                  {
                    label: 'Action ID',
                    value: <CopyableId value={r.id} label="action ID" max={40} />,
                  },
                ]}
              />
              <nav aria-label="Related" className="flex flex-wrap gap-2 text-sm">
                {r.detectionId ? (
                  <Link
                    href={detectionHref(r.detectionId)}
                    className="text-primary underline-offset-2 hover:underline"
                  >
                    Open the detection
                  </Link>
                ) : (
                  <span className="text-muted-foreground">Detection past its retention</span>
                )}
                {r.quarantineEntryId ? (
                  <Link
                    href={entryHref(r.quarantineEntryId)}
                    className="text-primary underline-offset-2 hover:underline"
                  >
                    Open the quarantine entry
                  </Link>
                ) : null}
                {r.clawbackId ? (
                  <Link
                    href={clawbackHref(r.clawbackId)}
                    className="text-primary underline-offset-2 hover:underline"
                  >
                    Open the clawback
                  </Link>
                ) : null}
                {r.releaseId ? (
                  <Link
                    href={releaseHref(r.releaseId)}
                    className="text-primary underline-offset-2 hover:underline"
                  >
                    Release status
                  </Link>
                ) : null}
                {r.reverses ? (
                  <Button
                    size="sm"
                    variant="link"
                    className="h-auto p-0"
                    onClick={() => onOpen(r.reverses!)}
                  >
                    Open the remediation it undoes
                  </Button>
                ) : null}
                {r.reversedBy ? (
                  <Button
                    size="sm"
                    variant="link"
                    className="h-auto p-0"
                    onClick={() => onOpen(r.reversedBy!)}
                  >
                    Open the reversal
                  </Button>
                ) : null}
              </nav>
              {canRetry && r.status === 'failed' ? (
                <Button size="sm" className="justify-self-start" onClick={() => onRetry(r)}>
                  Retry
                </Button>
              ) : null}
            </>
          ) : null}
        </div>
      </SheetContent>
    </Sheet>
  );
}

/** Tab "History" (R15): every mailbox action with filters, the detail drawer and Retry. */
export function HistoryTab() {
  const [filters, setFilters] = useUrlState(URL_SHAPE);
  const [range] = useRangeState();
  const canRetry = useCan('ApiModeRemediationController_retry_v1');
  const connections = useApiQuery('ApiModeController_listConnections_v1');
  const [retrying, setRetrying] = useState<Pick<Remediation, 'id' | 'action'> | null>(null);
  const { from, to } = range;
  const { status, action, trigger, connection, mailbox, detection } = filters;
  const query = useMemo(
    () => historyQuery({ status, action, trigger, connection, mailbox, detection }, { from, to }),
    [status, action, trigger, connection, mailbox, detection, from, to],
  );
  const list = useCursorList('ApiModeRemediationController_list_v1', query);

  const columns = useMemo<DataTableColumn<Remediation>[]>(
    () => [
      {
        id: 'createdAt',
        header: 'Requested',
        meta: { label: 'Requested', className: 'whitespace-nowrap' },
        cell: ({ row }) => (
          <Button
            variant="link"
            size="sm"
            className="h-auto p-0"
            onClick={() => setFilters({ remediation: row.original.id })}
          >
            <DateTime value={row.original.createdAt} />
            <span className="sr-only">, open details</span>
          </Button>
        ),
      },
      {
        id: 'action',
        header: 'Action',
        meta: { label: 'Action' },
        cell: ({ row }) => actionLabel(row.original.action),
      },
      {
        id: 'trigger',
        header: 'Trigger',
        meta: { label: 'Trigger' },
        cell: ({ row }) => TRIGGER_LABEL[row.original.trigger] ?? humanize(row.original.trigger),
      },
      {
        id: 'status',
        header: 'Status',
        meta: { label: 'Status' },
        cell: ({ row }) => (
          <span className="grid justify-items-start gap-0.5">
            <RemediationStatusBadge status={row.original.status} />
            {row.original.reasonCode ? (
              <span className="text-xs text-muted-foreground">
                {reasonCodeText(row.original.reasonCode)}
              </span>
            ) : null}
          </span>
        ),
      },
      {
        id: 'mailbox',
        header: 'Mailbox',
        meta: { label: 'Mailbox' },
        cell: ({ row }) => (
          <UntrustedText value={row.original.mailbox.address} mono maxLength={60} />
        ),
      },
      {
        id: 'attempts',
        header: 'Attempts',
        meta: { label: 'Attempts' },
        cell: ({ row }) => (
          <span className="grid text-xs">
            <span className="tabular-nums">{formatNumber(row.original.attempts)}</span>
            {row.original.lastErrorCode ? (
              <span className="font-mono text-muted-foreground">{row.original.lastErrorCode}</span>
            ) : null}
          </span>
        ),
      },
      {
        id: 'links',
        header: 'Detection and entry',
        meta: { label: 'Detection and entry' },
        cell: ({ row }) => (
          <span className="grid text-xs">
            {row.original.detectionId ? (
              <Link
                href={detectionHref(row.original.detectionId)}
                className="text-primary hover:underline"
              >
                Detection
              </Link>
            ) : (
              <span className="text-muted-foreground">Detection expired</span>
            )}
            {row.original.quarantineEntryId ? (
              <Link
                href={entryHref(row.original.quarantineEntryId)}
                className="text-primary hover:underline"
              >
                Quarantine entry
              </Link>
            ) : null}
          </span>
        ),
      },
      {
        id: 'completedAt',
        header: 'Completed',
        meta: { label: 'Completed', className: 'whitespace-nowrap' },
        cell: ({ row }) => (
          <span className="grid text-xs">
            <DateTime value={row.original.completedAt} emptyLabel="Not yet" />
            <span className="text-muted-foreground">{latencyText(row.original.latencyMs)}</span>
          </span>
        ),
      },
    ],
    [setFilters],
  );

  const connectionOptions = (connections.data?.data ?? []).map((c) => ({
    value: c.id,
    label: c.displayName,
  }));
  const isFiltered = Boolean(status || action || trigger || connection || mailbox || detection);

  return (
    <div className="grid gap-4">
      {detection || mailbox ? (
        <p className="text-sm">
          Showing the actions of one {detection ? 'detection' : 'mailbox'}.{' '}
          <Button
            size="sm"
            variant="link"
            className="h-auto p-0"
            onClick={() => setFilters({ detection: undefined, mailbox: undefined })}
          >
            Show every action
          </Button>
        </p>
      ) : null}
      <DataTable
        tableId="api-mode-remediations"
        caption="Mailbox actions of API-mode remediation"
        columns={columns}
        list={list}
        getRowId={(row) => row.id}
        getRowLabel={(row) => `${actionLabel(row.action)} ${row.mailbox.address} ${row.createdAt}`}
        filters={
          <>
            <RangePicker />
            <FilterSelect
              label="Status"
              value={status}
              onChange={(value) =>
                setFilters({ status: value as (typeof REMEDIATION_STATUSES)[number] | undefined })
              }
              options={REMEDIATION_STATUSES.map((value) => ({ value, label: humanize(value) }))}
            />
            <FilterSelect
              label="Action"
              value={action}
              onChange={(value) =>
                setFilters({
                  action: value as (typeof REMEDIATION_ACTION_KINDS)[number] | undefined,
                })
              }
              options={REMEDIATION_ACTION_KINDS.map((value) => ({
                value,
                label: actionLabel(value),
              }))}
            />
            <FilterSelect
              label="Trigger"
              value={trigger}
              onChange={(value) =>
                setFilters({ trigger: value as (typeof REMEDIATION_TRIGGERS)[number] | undefined })
              }
              options={REMEDIATION_TRIGGERS.map((value) => ({
                value,
                label: TRIGGER_LABEL[value] ?? humanize(value),
              }))}
            />
            {connectionOptions.length > 1 ? (
              <FilterSelect
                label="Connection"
                value={connection}
                onChange={(value) => setFilters({ connection: value })}
                options={connectionOptions}
              />
            ) : null}
          </>
        }
        isFiltered={isFiltered}
        onClearFilters={() =>
          setFilters({
            status: undefined,
            action: undefined,
            trigger: undefined,
            connection: undefined,
            mailbox: undefined,
            detection: undefined,
          })
        }
        rowActions={(row) => [
          { label: 'Details', onSelect: () => setFilters({ remediation: row.id }) },
          ...(canRetry && row.status === 'failed'
            ? [{ label: 'Retry', onSelect: () => setRetrying(row) }]
            : []),
        ]}
        emptyState={
          <EmptyState
            icon={HistoryIcon}
            title="No mailbox actions in this range"
            description="Actions decided by the remediation policy, requested by an administrator or by a quarantine release appear here."
          />
        }
        mobileCard={(row) => (
          <div className="grid gap-1">
            <span className="font-medium">{actionLabel(row.action)}</span>
            <UntrustedText value={row.mailbox.address} mono maxLength={60} />
            <div className="flex flex-wrap items-center gap-2">
              <RemediationStatusBadge status={row.status} />
              <DateTime value={row.createdAt} />
            </div>
          </div>
        )}
      />
      <RemediationDrawer
        remediationId={filters.remediation}
        onClose={() => setFilters({ remediation: undefined })}
        onOpen={(id) => setFilters({ remediation: id })}
        onRetry={(r) => setRetrying(r)}
      />
      <RetryDialog remediation={retrying} onOpenChange={(open) => !open && setRetrying(null)} />
    </div>
  );
}
