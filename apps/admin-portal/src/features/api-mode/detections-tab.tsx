'use client';

import { ScanSearchIcon } from 'lucide-react';
import { useMemo } from 'react';
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
import { humanize } from '@/lib/format';
import { FilterSelect } from '@/features/domains/kit';
import {
  DETECTION_SOURCES,
  DETECTION_STATUSES,
  DETECTION_VERDICTS,
  SOURCE_LABEL,
  formatLagMs,
  type Detection,
} from './model';

const URL_SHAPE = {
  verdict: z.enum(DETECTION_VERDICTS).optional().catch(undefined),
  status: z.enum(DETECTION_STATUSES).optional().catch(undefined),
  source: z.enum(DETECTION_SOURCES).optional().catch(undefined),
  connection: z.string().uuid().optional().catch(undefined),
};

/** The list query (`GET /api-mode/detections`, v1 cursor, ≤ 31 days; D12 #13). */
export function detectionQuery(
  filters: { verdict?: string; status?: string; source?: string; connection?: string },
  range: { from: string; to: string },
): QueryParams<'ApiModeController_listDetections_v1'> {
  return {
    from: range.from,
    to: range.to,
    ...(filters.verdict ? { verdict: filters.verdict } : {}),
    ...(filters.status ? { status: filters.status } : {}),
    ...(filters.source ? { source: filters.source } : {}),
    ...(filters.connection ? { connectionId: filters.connection } : {}),
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

/** Tab "Detections" (D14): copies with their verdicts, masked subject and sender, lag. */
export function DetectionsTab() {
  const [filters, setFilters] = useUrlState(URL_SHAPE);
  const [range] = useRangeState();
  const connections = useApiQuery('ApiModeController_listConnections_v1');
  const { from, to } = range;
  const query = useMemo(() => detectionQuery(filters, { from, to }), [filters, from, to]);
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
            {row.original.verdictAuthority === 'inline' ? (
              <span className="text-xs text-muted-foreground">inline verdict</span>
            ) : null}
          </span>
        ),
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
    ],
    [],
  );

  const connectionOptions = (connections.data?.data ?? []).map((c) => ({
    value: c.id,
    label: c.displayName,
  }));

  return (
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
        filters.verdict || filters.status || filters.source || filters.connection,
      )}
      onClearFilters={() =>
        setFilters({
          verdict: undefined,
          status: undefined,
          source: undefined,
          connection: undefined,
        })
      }
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
            <DateTime value={row.receivedAt} />
          </div>
        </div>
      )}
    />
  );
}
