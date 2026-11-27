'use client';

import { ScanSearchIcon } from 'lucide-react';
import { useMemo, useState } from 'react';
import { z } from 'zod';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { VerdictBadge } from '@/components/domain/badges';
import { DateTime } from '@/components/domain/date-time';
import { UntrustedText } from '@/components/domain/untrusted-text';
import { RangePicker, useRangeState } from '@/components/range-picker';
import { EmptyState } from '@/components/states/empty-state';
import { useUrlState } from '@/hooks/use-url-state';
import { useApiQuery, useCursorList } from '@/lib/api/hooks';
import type { QueryParams } from '@/lib/api/types';
import { useCan } from '@/lib/auth/me';
import { humanize } from '@/lib/format';
import { FilterSelect } from '@/features/domains/kit';
import { ClawBackSimilarDialog } from './clawback-dialogs';
import {
  DetectionDrawer,
  RemediateDialog,
  RestoreDialog,
  RestoreResultNotice,
  canBeClawedBack,
  canBeRemediated,
  canBeRestored,
  type DetectionRef,
} from './detection-actions';
import {
  DETECTION_DIRECTIONS,
  DETECTION_SOURCES,
  DETECTION_STATUSES,
  DETECTION_VERDICTS,
  DIRECTION_LABEL,
  SOURCE_LABEL,
  VerdictRevisionBadge,
  formatLagMs,
  type Detection,
} from './model';
import {
  COPY_REMEDIATION_STATES,
  RemediationStateBadge,
  STATE_LABEL,
  actionLabel,
  type RestoreResult,
} from './remediation-model';

const URL_SHAPE = {
  verdict: z.enum(DETECTION_VERDICTS).optional().catch(undefined),
  status: z.enum(DETECTION_STATUSES).optional().catch(undefined),
  source: z.enum(DETECTION_SOURCES).optional().catch(undefined),
  connection: z.string().uuid().optional().catch(undefined),
  remediationState: z.enum(COPY_REMEDIATION_STATES).optional().catch(undefined),
  /** Step API-3 C8: inbound or internal (east-west) copies. */
  direction: z.enum(DETECTION_DIRECTIONS).optional().catch(undefined),
  /** The detection whose detail drawer is open (link target of entries and history). */
  detection: z.string().uuid().optional().catch(undefined),
};

/** The list query (`GET /api-mode/detections`, v1 cursor, ≤ 31 days; D12 #13). */
export function detectionQuery(
  filters: {
    verdict?: string;
    status?: string;
    source?: string;
    connection?: string;
    remediationState?: string;
    direction?: string;
  },
  range: { from: string; to: string },
): QueryParams<'ApiModeController_listDetections_v1'> {
  return {
    from: range.from,
    to: range.to,
    ...(filters.verdict ? { verdict: filters.verdict } : {}),
    ...(filters.status ? { status: filters.status } : {}),
    ...(filters.source ? { source: filters.source } : {}),
    ...(filters.connection ? { connectionId: filters.connection } : {}),
    ...(filters.remediationState ? { remediationState: filters.remediationState } : {}),
    ...(filters.direction ? { direction: filters.direction } : {}),
  };
}

/**
 * Subject of a copy: withheld in the list (Email explorer masking rules, ADR-0062); a plain value
 * would still be attacker-controlled text.
 */
function SubjectCell({ detection }: { detection: Detection }) {
  if (detection.subjectMasked || detection.subject === null) {
    return <span className="text-xs text-muted-foreground">Hidden (masked)</span>;
  }
  return <UntrustedText value={String(detection.subject)} maxLength={80} />;
}

/**
 * Tab "Detections" (D14; step API-2 R15; step API-3 C8, C14): copies with their verdicts (and a
 * revision badge when a late verdict revised them), direction, masked subject and sender, lag and
 * remediation state; row actions Remediate…, Restore and Claw back similar…; the detail drawer.
 */
export function DetectionsTab() {
  const [filters, setFilters] = useUrlState(URL_SHAPE);
  const [range] = useRangeState();
  const connections = useApiQuery('ApiModeController_listConnections_v1');
  const canRemediate = useCan('ApiModeRemediationController_remediate_v1');
  const canRestore = useCan('ApiModeRemediationController_restore_v1');
  const canClawback = useCan('ApiModeClawbackController_create_v1');
  const [clawing, setClawing] = useState<DetectionRef | null>(null);
  const [remediating, setRemediating] = useState<DetectionRef | null>(null);
  const [restoring, setRestoring] = useState<DetectionRef | null>(null);
  const [restored, setRestored] = useState<RestoreResult | null>(null);
  const { from, to } = range;
  const { verdict, status, source, connection, remediationState, direction } = filters;
  const query = useMemo(
    () =>
      detectionQuery(
        { verdict, status, source, connection, remediationState, direction },
        { from, to },
      ),
    [verdict, status, source, connection, remediationState, direction, from, to],
  );
  const list = useCursorList('ApiModeController_listDetections_v1', query);

  const columns = useMemo<DataTableColumn<Detection>[]>(
    () => [
      {
        id: 'receivedAt',
        header: 'Received',
        meta: { label: 'Received' },
        cell: ({ row }) => <DateTime value={row.original.receivedAt} />,
      },
      {
        id: 'mailbox',
        header: 'Mailbox',
        meta: { label: 'Mailbox' },
        cell: ({ row }) => (
          <UntrustedText value={row.original.mailboxAddress} mono maxLength={60} />
        ),
      },
      {
        id: 'verdict',
        header: 'Verdict',
        meta: { label: 'Verdict' },
        cell: ({ row }) => (
          <span className="inline-flex flex-wrap items-center gap-1">
            <VerdictBadge verdict={row.original.verdict} />
            <VerdictRevisionBadge revision={row.original.verdictRevision} />
            {row.original.verdictAuthority === 'inline' ? (
              <span className="text-xs text-muted-foreground">inline verdict</span>
            ) : null}
          </span>
        ),
      },
      {
        id: 'direction',
        header: 'Direction',
        meta: { label: 'Direction' },
        cell: ({ row }) =>
          DIRECTION_LABEL[row.original.direction] ?? humanize(row.original.direction),
      },
      {
        id: 'riskScore',
        header: 'Risk',
        meta: { label: 'Risk' },
        cell: ({ row }) =>
          row.original.riskScore === null ? (
            '—'
          ) : (
            <span className="tabular-nums">{row.original.riskScore}</span>
          ),
      },
      {
        id: 'status',
        header: 'Status',
        meta: { label: 'Status' },
        cell: ({ row }) => humanize(row.original.status),
      },
      {
        id: 'subject',
        header: 'Subject',
        meta: { label: 'Subject' },
        cell: ({ row }) => <SubjectCell detection={row.original} />,
      },
      {
        id: 'headerFrom',
        header: 'Sender',
        meta: { label: 'Sender' },
        cell: ({ row }) => (
          <UntrustedText value={row.original.headerFrom} mono maxLength={60} emptyLabel="Unknown" />
        ),
      },
      {
        id: 'source',
        header: 'Source',
        meta: { label: 'Source' },
        cell: ({ row }) => (
          <span className="grid text-xs">
            <span>{SOURCE_LABEL[row.original.source]}</span>
            <span className="text-muted-foreground">
              {[row.original.seenJournal ? 'journal' : null, row.original.seenApi ? 'feed' : null]
                .filter(Boolean)
                .join(' + ') || 'one copy'}
            </span>
          </span>
        ),
      },
      {
        id: 'lag',
        header: 'Lag',
        meta: { label: 'Lag' },
        cell: ({ row }) => <span className="tabular-nums">{formatLagMs(row.original.lagMs)}</span>,
      },
      {
        id: 'remediation',
        header: 'Remediation',
        meta: { label: 'Remediation' },
        cell: ({ row }) => (
          <span className="grid justify-items-start gap-0.5">
            <RemediationStateBadge state={row.original.remediationState} />
            {row.original.remediationAction ? (
              <span className="text-xs text-muted-foreground">
                {actionLabel(row.original.remediationAction)}
              </span>
            ) : null}
          </span>
        ),
      },
    ],
    [],
  );

  const connectionOptions = (connections.data?.data ?? []).map((c) => ({
    value: c.id,
    label: c.displayName,
  }));

  return (
    <div className="grid gap-4">
      <div role="status" aria-live="polite">
        {restored ? <RestoreResultNotice result={restored} /> : null}
      </div>
      <DataTable
        tableId="api-mode-detections"
        caption="Detections of API-mode copies"
        columns={columns}
        list={list}
        getRowId={(row) => row.id}
        getRowLabel={(row) => `${row.mailboxAddress} ${row.receivedAt}`}
        filters={
          <>
            <RangePicker />
            <FilterSelect
              label="Verdict"
              value={filters.verdict}
              onChange={(verdict) =>
                setFilters({ verdict: verdict as (typeof DETECTION_VERDICTS)[number] | undefined })
              }
              options={DETECTION_VERDICTS.map((value) => ({ value, label: humanize(value) }))}
            />
            <FilterSelect
              label="Status"
              value={filters.status}
              onChange={(status) =>
                setFilters({ status: status as (typeof DETECTION_STATUSES)[number] | undefined })
              }
              options={DETECTION_STATUSES.map((value) => ({ value, label: humanize(value) }))}
            />
            <FilterSelect
              label="Source"
              value={filters.source}
              onChange={(source) =>
                setFilters({ source: source as (typeof DETECTION_SOURCES)[number] | undefined })
              }
              options={DETECTION_SOURCES.map((value) => ({ value, label: SOURCE_LABEL[value] }))}
            />
            <FilterSelect
              label="Remediation"
              value={filters.remediationState}
              onChange={(state) =>
                setFilters({
                  remediationState: state as (typeof COPY_REMEDIATION_STATES)[number] | undefined,
                })
              }
              options={COPY_REMEDIATION_STATES.map((value) => ({
                value,
                label: STATE_LABEL[value],
              }))}
            />
            <FilterSelect
              label="Direction"
              value={filters.direction}
              onChange={(value) =>
                setFilters({
                  direction: value as (typeof DETECTION_DIRECTIONS)[number] | undefined,
                })
              }
              options={DETECTION_DIRECTIONS.map((value) => ({
                value,
                label: DIRECTION_LABEL[value],
              }))}
            />
            {connectionOptions.length > 1 ? (
              <FilterSelect
                label="Connection"
                value={filters.connection}
                onChange={(connection) => setFilters({ connection })}
                options={connectionOptions}
              />
            ) : null}
          </>
        }
        isFiltered={Boolean(
          verdict || status || source || connection || remediationState || direction,
        )}
        onClearFilters={() =>
          setFilters({
            verdict: undefined,
            status: undefined,
            source: undefined,
            connection: undefined,
            remediationState: undefined,
            direction: undefined,
          })
        }
        rowActions={(row) => [
          { label: 'Details', onSelect: () => setFilters({ detection: row.id }) },
          ...(canRemediate
            ? [
                {
                  label: 'Remediate…',
                  onSelect: () => setRemediating(row),
                  disabled: !canBeRemediated(row),
                },
              ]
            : []),
          ...(canRestore
            ? [
                {
                  label: row.remediationAction === 'tag' ? 'Remove tag' : 'Restore',
                  onSelect: () => setRestoring(row),
                  disabled: !canBeRestored(row),
                },
              ]
            : []),
          ...(canClawback
            ? [
                {
                  label: 'Claw back similar…',
                  onSelect: () => setClawing(row),
                  disabled: !canBeClawedBack(row),
                },
              ]
            : []),
        ]}
        emptyState={
          <EmptyState
            icon={ScanSearchIcon}
            title="No detections in this range"
            description="Copies scanned in detect mode appear here with their verdict; nothing is delivered or bounced by API mode."
          />
        }
        mobileCard={(row) => (
          <div className="grid gap-1">
            <UntrustedText value={row.mailboxAddress} mono maxLength={60} />
            <div className="flex flex-wrap items-center gap-2">
              <VerdictBadge verdict={row.verdict} />
              <RemediationStateBadge state={row.remediationState} />
              <DateTime value={row.receivedAt} />
            </div>
          </div>
        )}
      />
      <DetectionDrawer
        detectionId={filters.detection}
        onClose={() => setFilters({ detection: undefined })}
        onRemediate={setRemediating}
        onRestore={setRestoring}
        onClawback={setClawing}
      />
      <ClawBackSimilarDialog
        detection={clawing}
        onOpenChange={(open) => !open && setClawing(null)}
      />
      <RemediateDialog
        detection={remediating}
        onOpenChange={(open) => !open && setRemediating(null)}
      />
      <RestoreDialog
        detection={restoring}
        onOpenChange={(open) => !open && setRestoring(null)}
        onResult={(result) => {
          setRestored(result);
          setRestoring(null);
        }}
      />
    </div>
  );
}
