'use client';

import type { UseQueryResult } from '@tanstack/react-query';
import { useId, type ReactNode } from 'react';
import { TimeSeriesChart, type ChartRow, type ChartSeries } from '@/components/charts';
import { DateTime } from '@/components/domain/date-time';
import { EmptyState } from '@/components/states/empty-state';
import { LoadingState } from '@/components/states/loading-state';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { TopDomains } from '@/features/dashboard/dashboard-page';
import type { ApiError } from '@/lib/api/errors';
import { formatDuration, formatNumber, formatPercent, humanize } from '@/lib/format';
import type { ResolvedRange } from '@/lib/range';
import { csvFilename, type CsvCell } from './csv';
import { CountTable, HistogramChart, StatList } from './report-parts';
import { CsvButton, ReportErrorState, ReportSection, useReport } from './report-state';
import {
  ACTION_LABELS,
  VERDICT_LABELS,
  bucketLabel,
  hourAllowed,
  percentileReading,
  type DeliveryReport,
  type ProcessingReport,
  type ThreatsReport,
  type TrafficReport,
  type UrlClicksReport,
} from './report-utils';

/** Loading / error / body of one report query. */
function ReportBody<T>({
  query,
  label,
  children,
}: {
  query: UseQueryResult<T, ApiError>;
  label: string;
  children: (data: T) => ReactNode;
}) {
  if (query.isLoading) return <LoadingState label={`Loading ${label}`} rows={8} />;
  if (query.error)
    return <ReportErrorState error={query.error} onRetry={() => void query.refetch()} />;
  if (!query.data) return null;
  return <>{children(query.data)}</>;
}

function Updated({ at }: { at: string }) {
  return (
    <span>
      Updated <DateTime value={at} />
    </span>
  );
}

const axisLabel = (granularity: 'hour' | 'day') =>
  granularity === 'hour' ? 'Hour (UTC)' : 'Day (UTC)';

/* ------------------------------------------------------------------------------------------ */
/* Traffic                                                                                     */
/* ------------------------------------------------------------------------------------------ */

const DIRECTIONS = ['inbound', 'outbound', 'internal'] as const;
/** Eight verdict series (the palette has eight hues); `unknown` and `none` are in the table. */
const TRAFFIC_VERDICTS = [
  'clean',
  'spam',
  'bulk',
  'phishing',
  'malware',
  'bec',
  'suspicious',
  'dlp_violation',
] as const;
const ALL_VERDICTS = [...TRAFFIC_VERDICTS, 'unknown', 'none'] as const;

export function trafficCsv(report: TrafficReport): { header: string[]; rows: CsvCell[][] } {
  return {
    header: ['bucket_start', 'total', ...DIRECTIONS, ...ALL_VERDICTS],
    rows: report.buckets.map((b) => [
      b.start,
      b.total,
      ...DIRECTIONS.map((d) => b[d]),
      ...ALL_VERDICTS.map((v) => b.verdicts[v]),
    ]),
  };
}

export function TrafficTab({
  range,
  granularity,
  direction,
  onChange,
}: {
  range: ResolvedRange;
  granularity: 'hour' | 'day' | undefined;
  direction: 'inbound' | 'outbound' | 'internal' | undefined;
  onChange: (patch: {
    granularity?: 'hour' | 'day' | undefined;
    direction?: 'inbound' | 'outbound' | 'internal' | undefined;
  }) => void;
}) {
  const hourOk = hourAllowed(range);
  const effective: 'hour' | 'day' =
    granularity === 'hour' ? (hourOk ? 'hour' : 'day') : (granularity ?? range.granularity);
  const query = useReport('ReportsController_traffic_v1', {
    from: range.from,
    to: range.to,
    granularity: effective,
    ...(direction ? { direction } : {}),
  });
  const granularityId = useId();
  const directionId = useId();
  return (
    <div className="grid gap-4">
      <div className="flex flex-wrap items-end gap-3" role="group" aria-label="Traffic filters">
        <div className="grid gap-1.5">
          <Label htmlFor={granularityId}>Granularity</Label>
          <Select
            value={effective}
            onValueChange={(value) => onChange({ granularity: value as 'hour' | 'day' })}
          >
            <SelectTrigger id={granularityId} size="sm" className="min-w-32">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="hour" disabled={!hourOk}>
                Hour{hourOk ? '' : ' (ranges ≤ 7 days)'}
              </SelectItem>
              <SelectItem value="day">Day</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="grid gap-1.5">
          <Label htmlFor={directionId}>Direction</Label>
          <Select
            value={direction ?? 'all'}
            onValueChange={(value) =>
              onChange({
                direction: value === 'all' ? undefined : (value as (typeof DIRECTIONS)[number]),
              })
            }
          >
            <SelectTrigger id={directionId} size="sm" className="min-w-36">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All directions</SelectItem>
              {DIRECTIONS.map((d) => (
                <SelectItem key={d} value={d}>
                  {humanize(d)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>
      <ReportBody query={query} label="the traffic report">
        {(report) => {
          const csv = trafficCsv(report);
          const directionRows: ChartRow[] = report.buckets.map((b) => ({
            bucket: bucketLabel(b.start, report.granularity),
            inbound: b.inbound,
            outbound: b.outbound,
            internal: b.internal,
          }));
          const verdictRows: ChartRow[] = report.buckets.map((b) => {
            const row: ChartRow = { bucket: bucketLabel(b.start, report.granularity) };
            for (const v of TRAFFIC_VERDICTS) row[v] = b.verdicts[v];
            return row;
          });
          return (
            <ReportSection
              title="Traffic"
              description={<Updated at={report.generatedAt} />}
              actions={
                <CsvButton
                  filename={csvFilename('traffic', report.from, report.to)}
                  header={csv.header}
                  rows={csv.rows}
                />
              }
            >
              <StatList
                stats={[
                  { label: 'Total', value: formatNumber(report.totals.total) },
                  ...DIRECTIONS.map((d) => ({
                    label: humanize(d),
                    value: formatNumber(report.totals[d]),
                  })),
                ]}
              />
              {report.totals.total === 0 ? (
                <EmptyState
                  title="No mail in this range"
                  description="No message was received in the selected range."
                />
              ) : (
                <div className="grid gap-6 xl:grid-cols-2">
                  <TimeSeriesChart
                    title="Messages by direction"
                    rows={directionRows}
                    xKey="bucket"
                    xLabel={axisLabel(report.granularity)}
                    series={DIRECTIONS.map((d) => ({ key: d, label: humanize(d) }))}
                    variant="stacked-area"
                  />
                  <TimeSeriesChart
                    title="Messages by verdict"
                    description="Final verdicts; messages without a verdict yet and unknown verdicts are listed in the table below."
                    rows={verdictRows}
                    xKey="bucket"
                    xLabel={axisLabel(report.granularity)}
                    series={TRAFFIC_VERDICTS.map((v) => ({
                      key: v,
                      label: VERDICT_LABELS[v] ?? v,
                    }))}
                    variant="stacked-area"
                  />
                </div>
              )}
              <CountTable
                caption="Verdict totals"
                labelHeader="Verdict"
                rows={ALL_VERDICTS.map((v) => ({
                  key: v,
                  label: VERDICT_LABELS[v] ?? v,
                  value: report.totals.verdicts[v],
                }))}
              />
            </ReportSection>
          );
        }}
      </ReportBody>
    </div>
  );
}

/* ------------------------------------------------------------------------------------------ */
/* Threats                                                                                     */
/* ------------------------------------------------------------------------------------------ */

const VERDICT_KEYS = Object.keys(VERDICT_LABELS) as (keyof ThreatsReport['messages']['verdicts'])[];
const ACTION_KEYS = Object.keys(ACTION_LABELS) as (keyof ThreatsReport['messages']['actions'])[];

/** The verdict × action matrix; pairs the api does not list are zero (it lists non-zero pairs). */
export function outcomeMatrix(report: ThreatsReport): number[][] {
  return VERDICT_KEYS.map((verdict) =>
    ACTION_KEYS.map(
      (action) =>
        report.outcomes.find((o) => o.verdict === verdict && o.action === action)?.count ?? 0,
    ),
  );
}

export function ThreatsTab({ range }: { range: ResolvedRange }) {
  const query = useReport('ReportsController_threats_v1', { from: range.from, to: range.to });
  return (
    <ReportBody query={query} label="the threats report">
      {(report) => {
        const matrix = outcomeMatrix(report);
        const usedVerdicts = VERDICT_KEYS.filter((_, i) => (matrix[i] ?? []).some((c) => c > 0));
        const usedActions = ACTION_KEYS.filter((_, j) => matrix.some((row) => (row[j] ?? 0) > 0));
        const csvRows: CsvCell[][] = report.outcomes.map((o) => [o.verdict, o.action, o.count]);
        return (
          <ReportSection
            title="Threats"
            description={<Updated at={report.generatedAt} />}
            actions={
              <CsvButton
                filename={csvFilename('threat-outcomes', report.from, report.to)}
                header={['verdict', 'action', 'count']}
                rows={csvRows}
              />
            }
          >
            <StatList
              stats={[
                { label: 'Messages', value: formatNumber(report.messages.total) },
                {
                  label: 'Quarantine entries',
                  value: formatNumber(report.quarantine.total),
                  hint: 'One per recipient',
                },
                { label: 'Malware', value: formatNumber(report.messages.verdicts.malware) },
                { label: 'Phishing', value: formatNumber(report.messages.verdicts.phishing) },
                { label: 'Spam', value: formatNumber(report.messages.verdicts.spam) },
              ]}
            />
            {report.messages.total === 0 ? (
              <EmptyState
                title="No mail in this range"
                description="No message was received in the selected range."
              />
            ) : (
              <>
                <div className="overflow-x-auto">
                  <table className="w-full border-collapse text-sm">
                    <caption className="pb-2 text-left text-sm font-semibold">
                      Outcomes: final verdict × final action (messages)
                    </caption>
                    <thead>
                      <tr className="border-b text-xs text-muted-foreground">
                        <th scope="col" className="px-2 py-1.5 text-left font-semibold">
                          Verdict
                        </th>
                        {usedActions.map((action) => (
                          <th
                            key={action}
                            scope="col"
                            className="px-2 py-1.5 text-right font-semibold"
                          >
                            {ACTION_LABELS[action]}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {usedVerdicts.map((verdict) => {
                        const i = VERDICT_KEYS.indexOf(verdict);
                        return (
                          <tr key={verdict} className="border-b last:border-0">
                            <th scope="row" className="px-2 py-1.5 text-left font-normal">
                              {VERDICT_LABELS[verdict]}
                            </th>
                            {usedActions.map((action) => (
                              <td key={action} className="px-2 py-1.5 text-right tabular-nums">
                                {formatNumber(matrix[i]?.[ACTION_KEYS.indexOf(action)] ?? 0)}
                              </td>
                            ))}
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
                <div className="grid gap-6 md:grid-cols-2">
                  <CountTable
                    caption="Messages by final verdict"
                    labelHeader="Verdict"
                    rows={VERDICT_KEYS.map((v) => ({
                      key: v,
                      label: VERDICT_LABELS[v],
                      value: report.messages.verdicts[v],
                    }))}
                  />
                  <CountTable
                    caption="Messages by final action"
                    labelHeader="Action"
                    rows={ACTION_KEYS.map((a) => ({
                      key: a,
                      label: ACTION_LABELS[a],
                      value: report.messages.actions[a],
                    }))}
                  />
                  <CountTable
                    caption="Quarantine entries by reason"
                    labelHeader="Reason"
                    rows={Object.entries(report.quarantine.reasons).map(([key, value]) => ({
                      key,
                      label: humanize(key),
                      value,
                    }))}
                  />
                  <CountTable
                    caption="Quarantine entries by primary engine"
                    labelHeader="Engine"
                    rows={Object.entries(report.quarantine.primaryEngines).map(([key, value]) => ({
                      key,
                      label: key === 'rspamd' ? 'Rspamd' : humanize(key),
                      value,
                    }))}
                  />
                </div>
              </>
            )}
          </ReportSection>
        );
      }}
    </ReportBody>
  );
}

/* ------------------------------------------------------------------------------------------ */
/* Delivery                                                                                    */
/* ------------------------------------------------------------------------------------------ */

const DELIVERY_STATUSES = [
  'pending',
  'in_progress',
  'queued',
  'deferred',
  'delivered',
  'bounced',
  'expired',
  'failed',
  'suppressed',
  'unknown',
] as const;
/** Charted statuses (eight hues); `pending` and `unknown` stay in the table and the CSV. */
const CHARTED_DELIVERY = [
  'delivered',
  'queued',
  'in_progress',
  'deferred',
  'bounced',
  'failed',
  'expired',
  'suppressed',
] as const;

export function deliveryCsv(report: DeliveryReport): { header: string[]; rows: CsvCell[][] } {
  return {
    header: ['bucket_start', 'total', ...DELIVERY_STATUSES, 'success_rate'],
    rows: report.buckets.map((b) => [
      b.start,
      b.total,
      ...DELIVERY_STATUSES.map((s) => b.statuses[s]),
      b.successRate,
    ]),
  };
}

export function DeliveryTab({ range }: { range: ResolvedRange }) {
  const query = useReport('ReportsController_delivery_v1', {
    from: range.from,
    to: range.to,
    granularity: range.granularity,
  });
  return (
    <ReportBody query={query} label="the delivery report">
      {(report) => {
        const csv = deliveryCsv(report);
        const p50 = percentileReading(report.latency.p50UpperBoundMs, report.latency.histogram);
        const p95 = percentileReading(report.latency.p95UpperBoundMs, report.latency.histogram);
        const rows: ChartRow[] = report.buckets.map((b) => {
          const row: ChartRow = { bucket: bucketLabel(b.start, report.granularity) };
          for (const s of CHARTED_DELIVERY) row[s] = b.statuses[s];
          return row;
        });
        return (
          <ReportSection
            title="Delivery"
            description={
              <>
                Deliveries (one per recipient) of the messages received in the range ·{' '}
                <Updated at={report.generatedAt} />
              </>
            }
            actions={
              <CsvButton
                filename={csvFilename('delivery', report.from, report.to)}
                header={csv.header}
                rows={csv.rows}
              />
            }
          >
            <StatList
              stats={[
                { label: 'Deliveries', value: formatNumber(report.totals.total) },
                {
                  label: 'Success rate',
                  value:
                    report.totals.successRate === null
                      ? 'No completed deliveries in range'
                      : formatPercent(report.totals.successRate),
                  hint: 'Delivered ÷ (delivered + bounced + failed + expired)',
                },
                { label: 'Delivered with a time', value: formatNumber(report.latency.delivered) },
                { label: 'Latency p50', value: p50.kind === 'none' ? 'No samples' : p50.text },
                {
                  label: 'Latency p95',
                  value: p95.kind === 'none' ? 'No samples' : p95.text,
                  hint:
                    report.latency.averageMs === null
                      ? undefined
                      : `Average ${formatDuration(report.latency.averageMs)}`,
                },
              ]}
            />
            {report.totals.total === 0 ? (
              <EmptyState
                title="No deliveries in this range"
                description="No delivery was recorded for messages received in the selected range."
              />
            ) : (
              <div className="grid gap-6 xl:grid-cols-2">
                <TimeSeriesChart
                  title="Delivery statuses over time"
                  description="Pending and unknown deliveries are listed in the table below."
                  rows={rows}
                  xKey="bucket"
                  xLabel={axisLabel(report.granularity)}
                  series={CHARTED_DELIVERY.map((s) => ({ key: s, label: humanize(s) }))}
                  variant="stacked-area"
                />
                <HistogramChart
                  title="Delivery latency"
                  description="Time from receipt to delivery of delivered recipients; percentiles are histogram upper bounds."
                  histogram={report.latency.histogram}
                />
              </div>
            )}
            <BucketTable
              caption="Success rate per bucket"
              granularity={report.granularity}
              buckets={report.buckets.map((b) => ({
                start: b.start,
                cells: [
                  formatNumber(b.total),
                  formatNumber(b.statuses.delivered),
                  b.successRate === null ? 'No completed deliveries' : formatPercent(b.successRate),
                ],
              }))}
              headers={['Deliveries', 'Delivered', 'Success rate']}
            />
          </ReportSection>
        );
      }}
    </ReportBody>
  );
}

function BucketTable({
  caption,
  granularity,
  headers,
  buckets,
}: {
  caption: string;
  granularity: 'hour' | 'day';
  headers: readonly string[];
  buckets: readonly { start: string; cells: readonly ReactNode[] }[];
}) {
  return (
    <details className="rounded-md border px-3 py-2">
      <summary className="cursor-pointer text-sm font-medium">{caption}</summary>
      <div className="mt-2 max-h-80 overflow-auto">
        <table className="w-full border-collapse text-sm">
          <caption className="sr-only">{caption}</caption>
          <thead>
            <tr className="border-b text-xs text-muted-foreground">
              <th scope="col" className="px-2 py-1.5 text-left font-semibold">
                {axisLabel(granularity)}
              </th>
              {headers.map((h) => (
                <th key={h} scope="col" className="px-2 py-1.5 text-right font-semibold">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {buckets.map((b) => (
              <tr key={b.start} className="border-b last:border-0">
                <th scope="row" className="px-2 py-1.5 text-left font-normal">
                  {bucketLabel(b.start, granularity)}
                </th>
                {b.cells.map((cell, i) => (
                  <td key={i} className="px-2 py-1.5 text-right tabular-nums">
                    {cell}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </details>
  );
}

/* ------------------------------------------------------------------------------------------ */
/* Processing                                                                                  */
/* ------------------------------------------------------------------------------------------ */

const ROUND_STATUSES = ['pending', 'running', 'completed', 'failed', 'timed_out'] as const;

export function processingCsv(report: ProcessingReport): { header: string[]; rows: CsvCell[][] } {
  return {
    header: ['bucket_start', 'rounds', ...ROUND_STATUSES, 'average_ms', 'p95_upper_bound_ms'],
    rows: report.buckets.map((b) => [
      b.start,
      b.rounds,
      ...ROUND_STATUSES.map((s) => b.statuses[s]),
      b.averageMs,
      b.p95UpperBoundMs,
    ]),
  };
}

export function ProcessingTab({ range }: { range: ResolvedRange }) {
  const query = useReport('ReportsController_processing_v1', {
    from: range.from,
    to: range.to,
    granularity: range.granularity,
  });
  return (
    <ReportBody query={query} label="the processing report">
      {(report) => {
        const csv = processingCsv(report);
        const overflow = percentileReading(null, report.totals.histogram);
        const overflowText = overflow.kind === 'overflow' ? overflow.text : 'Beyond the last bound';
        const p50 = percentileReading(report.totals.p50UpperBoundMs, report.totals.histogram);
        const p95 = percentileReading(report.totals.p95UpperBoundMs, report.totals.histogram);
        const rows: ChartRow[] = report.buckets.map((b) => {
          const row: ChartRow = { bucket: bucketLabel(b.start, report.granularity) };
          for (const s of ROUND_STATUSES) row[s] = b.statuses[s];
          return row;
        });
        return (
          <ReportSection
            title="Processing"
            description={
              <>
                {report.definition}. · <Updated at={report.generatedAt} />
              </>
            }
            actions={
              <CsvButton
                filename={csvFilename('processing', report.from, report.to)}
                header={csv.header}
                rows={csv.rows}
              />
            }
          >
            <StatList
              stats={[
                { label: 'Initial scan rounds', value: formatNumber(report.totals.rounds) },
                { label: 'Completed', value: formatNumber(report.totals.statuses.completed) },
                {
                  label: 'Time to verdict p50',
                  value: p50.kind === 'none' ? 'No samples' : p50.text,
                },
                {
                  label: 'Time to verdict p95',
                  value: p95.kind === 'none' ? 'No samples' : p95.text,
                },
                {
                  label: 'Average',
                  value:
                    report.totals.averageMs === null
                      ? 'No samples'
                      : formatDuration(report.totals.averageMs),
                },
              ]}
            />
            <p className="text-xs text-muted-foreground">
              Percentiles are histogram upper bounds (the database has no percentile function and
              the histogram is exact). A percentile beyond the last bound reads “&gt; last bound”.
            </p>
            {report.totals.rounds === 0 ? (
              <EmptyState
                title="No scan rounds in this range"
                description="No message was scanned in the selected range."
              />
            ) : (
              <div className="grid gap-6 xl:grid-cols-2">
                <TimeSeriesChart
                  title="Scan rounds by status"
                  rows={rows}
                  xKey="bucket"
                  xLabel={axisLabel(report.granularity)}
                  series={ROUND_STATUSES.map((s) => ({ key: s, label: humanize(s) }))}
                  variant="stacked-area"
                />
                <HistogramChart
                  title="Time to verdict"
                  description="Completed initial scan rounds per latency bin."
                  histogram={report.totals.histogram}
                />
              </div>
            )}
            <BucketTable
              caption="Latency per bucket"
              granularity={report.granularity}
              headers={['Rounds', 'Average', 'p95 (upper bound)']}
              buckets={report.buckets.map((b) => ({
                start: b.start,
                cells: [
                  formatNumber(b.rounds),
                  b.averageMs === null ? 'No samples' : formatDuration(b.averageMs),
                  b.p95UpperBoundMs === null
                    ? b.statuses.completed > 0
                      ? overflowText
                      : 'No samples'
                    : `≤ ${formatDuration(b.p95UpperBoundMs)}`,
                ],
              }))}
            />
          </ReportSection>
        );
      }}
    </ReportBody>
  );
}

/* ------------------------------------------------------------------------------------------ */
/* URL clicks                                                                                  */
/* ------------------------------------------------------------------------------------------ */

export const CLICK_DECISIONS = [
  'allowed',
  'warned',
  'blocked',
  'continued',
  'expired',
  'not_found',
] as const;

export function urlClickRows(report: UrlClicksReport): ChartRow[] {
  return report.buckets.map((b) => {
    const row: ChartRow = { bucket: bucketLabel(b.start, report.granularity) };
    for (const d of CLICK_DECISIONS) row[d] = b.decisions[d];
    return row;
  });
}

export const CLICK_SERIES: readonly ChartSeries[] = CLICK_DECISIONS.map((d) => ({
  key: d,
  label: humanize(d),
}));

/** Clicks per decision over time (shared with the URL protection page). */
export function UrlClicksChart({ report }: { report: UrlClicksReport }) {
  if (report.totals.total === 0) {
    return (
      <EmptyState
        title="No clicks in this range"
        description="No rewritten link was clicked in the selected range."
      />
    );
  }
  return (
    <TimeSeriesChart
      title="Clicks by decision"
      rows={urlClickRows(report)}
      xKey="bucket"
      xLabel={axisLabel(report.granularity)}
      series={CLICK_SERIES}
      variant="stacked-area"
    />
  );
}

export function UrlClicksTab({ range }: { range: ResolvedRange }) {
  const query = useReport('ReportsController_urlClicks_v1', {
    from: range.from,
    to: range.to,
    granularity: range.granularity,
  });
  return (
    <ReportBody query={query} label="the URL click report">
      {(report) => (
        <ReportSection
          title="URL clicks"
          description={
            <>
              Time-of-click decisions on rewritten links · <Updated at={report.generatedAt} />
            </>
          }
          actions={
            <CsvButton
              filename={csvFilename('url-clicks', report.from, report.to)}
              header={['bucket_start', 'total', ...CLICK_DECISIONS]}
              rows={report.buckets.map((b) => [
                b.start,
                b.total,
                ...CLICK_DECISIONS.map((d) => b.decisions[d]),
              ])}
            />
          }
        >
          <StatList
            stats={[
              { label: 'Clicks', value: formatNumber(report.totals.total) },
              ...CLICK_DECISIONS.slice(0, 4).map((d) => ({
                label: humanize(d),
                value: formatNumber(report.totals.decisions[d]),
              })),
            ]}
          />
          <UrlClicksChart report={report} />
        </ReportSection>
      )}
    </ReportBody>
  );
}

/* ------------------------------------------------------------------------------------------ */
/* Top domains                                                                                 */
/* ------------------------------------------------------------------------------------------ */

export const TOP_DOMAIN_LIMITS = [5, 10, 15, 20, 25] as const;

export function TopDomainsTab({
  range,
  limit,
  onLimitChange,
}: {
  range: ResolvedRange;
  limit: number;
  onLimitChange: (limit: number) => void;
}) {
  const query = useReport('ReportsController_topDomains_v1', {
    from: range.from,
    to: range.to,
    limit,
  });
  const limitId = useId();
  return (
    <div className="grid gap-4">
      <div className="grid w-fit gap-1.5">
        <Label htmlFor={limitId}>Domains shown</Label>
        <Select value={String(limit)} onValueChange={(value) => onLimitChange(Number(value))}>
          <SelectTrigger id={limitId} size="sm" className="min-w-24">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {TOP_DOMAIN_LIMITS.map((n) => (
              <SelectItem key={n} value={String(n)}>
                {n}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <ReportBody query={query} label="the top domains report">
        {(report) => (
          <ReportSection
            title="Top attacked domains"
            description={
              <>
                Inbound messages with a threat verdict (
                {report.threatVerdicts.map((v) => VERDICT_LABELS[v] ?? v).join(', ')}) per domain ·{' '}
                <Updated at={report.generatedAt} />
              </>
            }
            actions={
              <CsvButton
                filename={csvFilename('top-domains', report.from, report.to)}
                header={['domain', 'deleted', 'inbound', 'threats', ...report.threatVerdicts]}
                rows={report.domains.map((d) => [
                  d.name,
                  d.deleted,
                  d.inbound,
                  d.threats,
                  ...report.threatVerdicts.map((v) => d.verdicts[v]),
                ])}
              />
            }
          >
            <TopDomains report={report} />
          </ReportSection>
        )}
      </ReportBody>
    </div>
  );
}
