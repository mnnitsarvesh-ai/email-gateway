'use client';

import { InboxIcon } from 'lucide-react';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import { BarChart, TimeSeriesChart, type ChartRow } from '@/components/charts';
import { DateTime } from '@/components/domain/date-time';
import { ToneBadge } from '@/components/domain/tone-badge';
import { KpiTile } from '@/components/kpi-tile';
import { PageHeader } from '@/components/page-header';
import { RangePicker, useRangeState } from '@/components/range-picker';
import { EmptyState } from '@/components/states/empty-state';
import { LoadingState } from '@/components/states/loading-state';
import { PlatformHealthCard } from '@/features/shell/platform-health-card';
import { RouteGate } from '@/lib/auth/route-gate';
import { formatDuration, formatNumber, formatPercent } from '@/lib/format';
import { navGate } from '@/features/reports/nav-gate';
import { ReportErrorState, ReportSection, useReport } from '@/features/reports/report-state';
import {
  THREAT_VERDICTS,
  VERDICT_LABELS,
  bucketLabel,
  hrefWithRange,
  percentileReading,
  reportWindow,
  spamBlocked,
  type TopDomainsReport,
  type TrafficReport,
} from '@/features/reports/report-utils';

export const SPAM_BLOCKED_DEFINITION =
  'Messages whose final verdict is spam or bulk and whose final action is quarantine, discard or reject (GET /reports/threats, outcomes).';

/** `/dashboard` (design §1.4): 12 widgets over one bounded range, each loading on its own. */
export function DashboardPage() {
  return (
    <RouteGate gate={navGate('dashboard')}>
      <DashboardContent />
    </RouteGate>
  );
}

function DashboardContent() {
  const [range] = useRangeState();
  const searchParams = useSearchParams();
  const win = reportWindow(range);
  const traffic = useReport('ReportsController_traffic_v1', win);
  const threats = useReport('ReportsController_threats_v1', { from: win.from, to: win.to });
  const delivery = useReport('ReportsController_delivery_v1', win);
  const processing = useReport('ReportsController_processing_v1', win);
  const topDomains = useReport('ReportsController_topDomains_v1', {
    from: win.from,
    to: win.to,
    limit: 10,
  });
  const link = (tab: string) => hrefWithRange('/reports', searchParams, { tab });

  const trafficTile = (
    label: string,
    key: 'total' | 'inbound' | 'outbound' | 'internal',
    definition: string,
  ) => (
    <KpiTile
      label={label}
      value={traffic.data?.totals[key]}
      definition={definition}
      generatedAt={traffic.data?.generatedAt}
      href={link('traffic')}
      loading={traffic.isLoading}
      error={traffic.error}
      onRetry={() => void traffic.refetch()}
    />
  );

  const threatsData = threats.data;
  const threatsTile = (
    label: string,
    value: number | undefined,
    definition: string,
    subtitle?: string,
  ) => (
    <KpiTile
      label={label}
      value={value}
      definition={definition}
      subtitle={subtitle}
      generatedAt={threatsData?.generatedAt}
      href={link('threats')}
      loading={threats.isLoading}
      error={threats.error}
      onRetry={() => void threats.refetch()}
    />
  );

  const p95 = processing.data
    ? percentileReading(processing.data.totals.p95UpperBoundMs, processing.data.totals.histogram)
    : null;
  const average = processing.data?.totals.averageMs ?? null;

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Dashboard"
        description={`Mail flow and threats for your organization, ${range.label.toLowerCase()}. Every figure comes from the reports API.`}
        actions={<RangePicker />}
      />

      <section
        aria-label="Key figures"
        className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4 2xl:grid-cols-5"
      >
        {trafficTile(
          'Total emails processed',
          'total',
          'Messages received in the range, all directions (GET /reports/traffic, totals.total).',
        )}
        {trafficTile(
          'Inbound emails',
          'inbound',
          'Messages received from outside your organization (totals.inbound).',
        )}
        {trafficTile(
          'Outbound emails',
          'outbound',
          'Messages sent by your organization to outside recipients (totals.outbound).',
        )}
        {trafficTile(
          'Internal emails',
          'internal',
          'Messages between addresses of your organization (totals.internal).',
        )}
        {threatsTile(
          'Spam blocked',
          threatsData ? spamBlocked(threatsData.outcomes) : undefined,
          SPAM_BLOCKED_DEFINITION,
        )}
        {threatsTile(
          'Malware detected',
          threatsData?.messages.verdicts.malware,
          'Messages whose final verdict is malware (GET /reports/threats, messages.verdicts.malware).',
        )}
        {threatsTile(
          'Phishing detected',
          threatsData?.messages.verdicts.phishing,
          'Messages whose final verdict is phishing (messages.verdicts.phishing).',
        )}
        {threatsTile(
          'Quarantined emails',
          threatsData?.messages.actions.quarantine,
          'Messages whose final action is quarantine (messages.actions.quarantine). Quarantine entries are per recipient (quarantine.total).',
          threatsData
            ? `${formatNumber(threatsData.quarantine.total)} quarantine ${threatsData.quarantine.total === 1 ? 'entry' : 'entries'} (one per recipient)`
            : undefined,
        )}
        <KpiTile
          label="Delivery success rate"
          value={delivery.data ? delivery.data.totals.successRate : undefined}
          format={formatPercent}
          emptyText="No completed deliveries in range"
          definition="Delivered ÷ (delivered + bounced + failed + expired) of the deliveries of messages received in the range (GET /reports/delivery). In-flight, deferred and suppressed deliveries do not count."
          subtitle={
            delivery.data
              ? `${formatNumber(delivery.data.totals.statuses.delivered)} delivered of ${formatNumber(delivery.data.totals.total)} deliveries`
              : undefined
          }
          generatedAt={delivery.data?.generatedAt}
          href={link('delivery')}
          loading={delivery.isLoading}
          error={delivery.error}
          onRetry={() => void delivery.refetch()}
        />
        <KpiTile
          label="Time to verdict (p95)"
          value={processing.data ? (p95 && p95.kind !== 'none' ? p95.ms : null) : undefined}
          format={(ms) =>
            p95?.kind === 'overflow' ? `> ${formatDuration(ms)}` : `≤ ${formatDuration(ms)}`
          }
          emptyText="No completed scan rounds in range"
          definition={`${processing.data?.definition ?? 'Time from receipt to completion of the initial scan round.'} The 95th percentile is reported as a histogram upper bound.`}
          subtitle={
            processing.data
              ? average !== null
                ? `Average ${formatDuration(average)}`
                : 'No average (no completed rounds)'
              : undefined
          }
          generatedAt={processing.data?.generatedAt}
          href={link('processing')}
          loading={processing.isLoading}
          error={processing.error}
          onRetry={() => void processing.refetch()}
        />
      </section>

      <div className="grid gap-6 xl:grid-cols-2">
        <ReportSection
          title="Threat trends"
          description={
            traffic.data ? (
              <>
                Threat verdicts per {traffic.data.granularity} · Updated{' '}
                <DateTime value={traffic.data.generatedAt} />
              </>
            ) : (
              'Threat verdicts over time'
            )
          }
          actions={
            <Link
              className="text-sm font-medium text-primary hover:underline"
              href={link('traffic')}
            >
              Open traffic report
            </Link>
          }
        >
          {traffic.isLoading ? (
            <LoadingState label="Loading threat trends" rows={6} />
          ) : traffic.error ? (
            <ReportErrorState
              error={traffic.error}
              onRetry={() => void traffic.refetch()}
              compact
            />
          ) : traffic.data ? (
            <ThreatTrends report={traffic.data} />
          ) : null}
        </ReportSection>

        <ReportSection
          title="Top attacked domains"
          description={
            topDomains.data ? (
              <>
                Inbound messages with a threat verdict per domain · Updated{' '}
                <DateTime value={topDomains.data.generatedAt} />
              </>
            ) : (
              'Inbound messages with a threat verdict per domain'
            )
          }
          actions={
            <Link
              className="text-sm font-medium text-primary hover:underline"
              href={link('top-domains')}
            >
              Open top domains report
            </Link>
          }
        >
          {topDomains.isLoading ? (
            <LoadingState label="Loading top attacked domains" rows={6} />
          ) : topDomains.error ? (
            <ReportErrorState
              error={topDomains.error}
              onRetry={() => void topDomains.refetch()}
              compact
            />
          ) : topDomains.data ? (
            <TopDomains report={topDomains.data} />
          ) : null}
        </ReportSection>
      </div>

      <PlatformHealthCard />
    </div>
  );
}

/** Widget 11: stacked area of the threat verdicts per bucket (table fallback in ChartFigure). */
export function ThreatTrends({ report }: { report: TrafficReport }) {
  const threatTotal = THREAT_VERDICTS.reduce((sum, v) => sum + report.totals.verdicts[v], 0);
  if (report.totals.total === 0) {
    return (
      <EmptyState
        icon={InboxIcon}
        title="No mail in this range"
        description="No message was received in the selected range."
      />
    );
  }
  if (threatTotal === 0) {
    return (
      <EmptyState
        title="No threats in this range"
        description={`${formatNumber(report.totals.total)} messages were received; none had a threat verdict.`}
      />
    );
  }
  const rows: ChartRow[] = report.buckets.map((bucket) => {
    const row: ChartRow = { bucket: bucketLabel(bucket.start, report.granularity) };
    for (const verdict of THREAT_VERDICTS) row[verdict] = bucket.verdicts[verdict];
    return row;
  });
  return (
    <TimeSeriesChart
      title="Threat verdicts over time"
      description="Spam, phishing, malware, BEC, suspicious and DLP violations, stacked."
      rows={rows}
      xKey="bucket"
      xLabel={report.granularity === 'hour' ? 'Hour (UTC)' : 'Day (UTC)'}
      series={THREAT_VERDICTS.map((key) => ({ key, label: VERDICT_LABELS[key] ?? key }))}
      variant="stacked-area"
    />
  );
}

/** Widget 12: horizontal stacked bars per domain plus a table with links to the domains. */
export function TopDomains({ report }: { report: TopDomainsReport }) {
  const unattributed = report.unattributed;
  const note =
    unattributed.inbound > 0 ? (
      <p className="text-xs text-muted-foreground" role="note">
        {formatNumber(unattributed.inbound)} inbound{' '}
        {unattributed.inbound === 1 ? 'message' : 'messages'} ({formatNumber(unattributed.threats)}{' '}
        with a threat verdict) could not be attributed to one of your domains.
      </p>
    ) : null;
  if (report.domains.length === 0) {
    return (
      <div className="grid gap-2">
        <EmptyState
          title="No attacked domains in this range"
          description="No inbound message with a threat verdict was attributed to one of your domains."
        />
        {note}
      </div>
    );
  }
  const verdicts = report.threatVerdicts;
  const rows: ChartRow[] = report.domains.map((domain) => {
    const row: ChartRow = { domain: domain.deleted ? `${domain.name} (deleted)` : domain.name };
    for (const verdict of verdicts) row[verdict] = domain.verdicts[verdict];
    return row;
  });
  return (
    <div className="grid gap-4">
      <BarChart
        title="Threats per domain"
        description="Inbound messages with a threat verdict, stacked by verdict."
        rows={rows}
        categoryKey="domain"
        categoryLabel="Domain"
        series={verdicts.map((key) => ({ key, label: VERDICT_LABELS[key] ?? key }))}
        layout="horizontal"
        stacked
      />
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-sm">
          <caption className="sr-only">Top attacked domains</caption>
          <thead>
            <tr className="border-b text-xs text-muted-foreground">
              <th scope="col" className="px-2 py-1.5 text-left font-semibold">
                Domain
              </th>
              <th scope="col" className="px-2 py-1.5 text-right font-semibold">
                Threats
              </th>
              <th scope="col" className="px-2 py-1.5 text-right font-semibold">
                Inbound
              </th>
            </tr>
          </thead>
          <tbody>
            {report.domains.map((domain) => (
              <tr key={domain.domainId} className="border-b last:border-0">
                <th scope="row" className="px-2 py-1.5 text-left font-normal">
                  <span className="inline-flex flex-wrap items-center gap-2">
                    {domain.deleted ? (
                      <>
                        <span className="break-all">{domain.name}</span>
                        <ToneBadge tone="neutral">Deleted</ToneBadge>
                      </>
                    ) : (
                      <Link
                        href={`/domains/${domain.domainId}`}
                        className="break-all text-primary hover:underline"
                      >
                        {domain.name}
                      </Link>
                    )}
                  </span>
                </th>
                <td className="px-2 py-1.5 text-right tabular-nums">
                  {formatNumber(domain.threats)}
                </td>
                <td className="px-2 py-1.5 text-right tabular-nums">
                  {formatNumber(domain.inbound)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {note}
    </div>
  );
}
