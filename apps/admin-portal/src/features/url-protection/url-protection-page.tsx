'use client';

import Link from 'next/link';
import { useMemo } from 'react';
import { z } from 'zod';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { DateTime } from '@/components/domain/date-time';
import { ToneBadge } from '@/components/domain/tone-badge';
import { UntrustedText } from '@/components/domain/untrusted-text';
import { PageHeader } from '@/components/page-header';
import { RangePicker, useRangeState } from '@/components/range-picker';
import { EmptyState } from '@/components/states/empty-state';
import { LoadingState } from '@/components/states/loading-state';
import { useUrlState } from '@/hooks/use-url-state';
import { useCursorList } from '@/lib/api/hooks';
import type { ListItem } from '@/lib/api/types';
import { RouteGate } from '@/lib/auth/route-gate';
import type { Tone } from '@/lib/design/tokens';
import { formatUtc, humanize } from '@/lib/format';
import { SelectFilter, TextFilter, validateUuid } from '@/features/reports/filters';
import { GatedTabs, type TabDefinition } from '@/features/reports/gated-tabs';
import { navGate } from '@/features/reports/nav-gate';
import { ReportErrorState, ReportSection, useReport } from '@/features/reports/report-state';
import { CLICK_DECISIONS, UrlClicksChart } from '@/features/reports/report-tabs';
import { EngineSettingsReadOnly } from '@/features/settings/scan-settings-panel';

type ClickRow = ListItem<'UrlProtectionController_clicks_v1'>;

export const SCAN_VERDICT_TONE: Record<string, Tone> = {
  clean: 'success',
  suspicious: 'warning',
  malicious: 'danger',
  unknown: 'neutral',
};

/** Verdict of the URL and attachment engines (`clean | suspicious | malicious | unknown`). */
export function ScanVerdictBadge({ verdict }: { verdict: string | null }) {
  return verdict ? (
    <ToneBadge tone={SCAN_VERDICT_TONE[verdict] ?? 'neutral'}>{humanize(verdict)}</ToneBadge>
  ) : (
    <ToneBadge tone="neutral">No verdict</ToneBadge>
  );
}

const DECISION_TONE: Record<ClickRow['decision'], Tone> = {
  allowed: 'success',
  warned: 'warning',
  blocked: 'danger',
  continued: 'orange',
  expired: 'neutral',
  not_found: 'neutral',
};

const TABS: readonly TabDefinition[] = [
  { id: 'clicks', label: 'Clicks', ops: ['UrlProtectionController_clicks_v1'] },
  { id: 'report', label: 'Click report', ops: ['ReportsController_urlClicks_v1'] },
  { id: 'settings', label: 'URL engine settings', ops: ['ScanSettingsController_list_v1'] },
];

export const CLICKS_URL_SHAPE = {
  decision: z.enum(CLICK_DECISIONS).optional().catch(undefined),
  verdict: z.enum(['clean', 'suspicious', 'malicious', 'unknown']).optional().catch(undefined),
  messageId: z.string().uuid().optional().catch(undefined),
};

/** `/url-protection` (design §1.3 row 16). */
export function UrlProtectionPage() {
  return (
    <RouteGate gate={navGate('url-protection')}>
      <div className="flex flex-col gap-4">
        <PageHeader
          title="URL protection"
          description="Time-of-click decisions on rewritten links. Hosts are shown as text, never as links."
          actions={<RangePicker />}
        />
        <GatedTabs
          tabs={TABS}
          label="URL protection"
          render={(tab) =>
            tab === 'clicks' ? (
              <Clicks />
            ) : tab === 'report' ? (
              <ClickReport />
            ) : (
              <EngineSettingsReadOnly engine="url" />
            )
          }
        />
      </div>
    </RouteGate>
  );
}

function Clicks() {
  const [range] = useRangeState();
  const [state, setState] = useUrlState(CLICKS_URL_SHAPE);
  const list = useCursorList('UrlProtectionController_clicks_v1', {
    from: range.from,
    to: range.to,
    sort: '-clickedAt',
    ...(state.decision ? { decision: state.decision } : {}),
    ...(state.verdict ? { verdict: state.verdict } : {}),
    ...(state.messageId ? { messageId: state.messageId } : {}),
  });
  const columns = useMemo<DataTableColumn<ClickRow>[]>(
    () => [
      {
        id: 'clickedAt',
        header: 'Clicked',
        meta: { label: 'Clicked' },
        cell: ({ row }) => <DateTime value={row.original.clickedAt} />,
      },
      {
        id: 'decision',
        header: 'Decision',
        meta: { label: 'Decision' },
        cell: ({ row }) => (
          <ToneBadge tone={DECISION_TONE[row.original.decision]}>
            {humanize(row.original.decision)}
          </ToneBadge>
        ),
      },
      {
        id: 'verdict',
        header: 'Verdict',
        meta: { label: 'Verdict' },
        cell: ({ row }) => <ScanVerdictBadge verdict={row.original.verdict} />,
      },
      {
        id: 'host',
        header: 'Host',
        meta: { label: 'Host' },
        cell: ({ row }) => (
          <UntrustedText
            value={row.original.host}
            maxLength={48}
            copy
            copyLabel="Copy host"
            emptyLabel="Unknown"
          />
        ),
      },
      {
        id: 'registrableDomain',
        header: 'Registrable domain',
        meta: { label: 'Registrable domain' },
        cell: ({ row }) => (
          <UntrustedText value={row.original.registrableDomain} maxLength={48} emptyLabel="None" />
        ),
      },
      {
        id: 'reasonCodes',
        header: 'Reasons',
        meta: { label: 'Reasons' },
        cell: ({ row }) =>
          row.original.reasonCodes.length ? (
            <span className="font-mono text-xs">{row.original.reasonCodes.join(', ')}</span>
          ) : (
            <span className="text-muted-foreground">None</span>
          ),
      },
      {
        id: 'clientNetwork',
        header: 'Client network',
        meta: { label: 'Client network' },
        cell: ({ row }) => (
          <span className="font-mono text-xs">{row.original.clientNetwork ?? 'Unknown'}</span>
        ),
      },
      {
        id: 'message',
        header: 'Message',
        meta: { label: 'Message' },
        cell: ({ row }) =>
          row.original.messageId ? (
            <Link
              href={`/messages/${row.original.messageId}/scans`}
              className="text-primary hover:underline"
              aria-label={`Scan details of the message (URL ${row.original.urlSeq})`}
            >
              Scan details
            </Link>
          ) : (
            <span className="text-muted-foreground">Unknown</span>
          ),
      },
    ],
    [],
  );
  return (
    <DataTable<ClickRow>
      tableId="url-clicks"
      caption="URL clicks"
      columns={columns}
      list={list}
      getRowId={(row) => row.id}
      getRowLabel={(row) => `click at ${formatUtc(row.clickedAt)}`}
      isFiltered={Boolean(state.decision || state.verdict || state.messageId)}
      onClearFilters={() =>
        setState({ decision: undefined, verdict: undefined, messageId: undefined })
      }
      emptyState={
        <EmptyState
          title="No clicks in this range"
          description="Nobody clicked a rewritten link in the selected range."
        />
      }
      filters={
        <>
          <SelectFilter
            label="Decision"
            value={state.decision}
            onChange={(decision) => setState({ decision })}
            options={CLICK_DECISIONS.map((value) => ({ value, label: humanize(value) }))}
          />
          <SelectFilter
            label="Verdict"
            value={state.verdict}
            onChange={(verdict) => setState({ verdict })}
            options={(['clean', 'suspicious', 'malicious', 'unknown'] as const).map((value) => ({
              value,
              label: humanize(value),
            }))}
          />
          <TextFilter
            label="Message ID"
            value={state.messageId}
            onChange={(messageId) => setState({ messageId })}
            validate={validateUuid}
            mono
          />
        </>
      }
      mobileCard={(row) => (
        <div className="grid gap-1 text-sm">
          <UntrustedText value={row.host} maxLength={40} emptyLabel="Unknown host" />
          <span className="flex items-center gap-2">
            <ToneBadge tone={DECISION_TONE[row.decision]}>{humanize(row.decision)}</ToneBadge>
            <DateTime value={row.clickedAt} />
          </span>
        </div>
      )}
    />
  );
}

function ClickReport() {
  const [range] = useRangeState();
  const report = useReport('ReportsController_urlClicks_v1', {
    from: range.from,
    to: range.to,
    granularity: range.granularity,
  });
  return (
    <ReportSection title="Click report">
      {report.isLoading ? (
        <LoadingState label="Loading the click report" rows={6} />
      ) : report.error ? (
        <ReportErrorState error={report.error} onRetry={() => void report.refetch()} />
      ) : report.data ? (
        <UrlClicksChart report={report.data} />
      ) : null}
    </ReportSection>
  );
}
