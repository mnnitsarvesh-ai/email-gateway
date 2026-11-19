'use client';

import Link from 'next/link';
import { z } from 'zod';
import { BarChart, type ChartRow } from '@/components/charts';
import { DateTime } from '@/components/domain';
import { KpiTile } from '@/components/kpi-tile';
import { PageHeader } from '@/components/page-header';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { UnavailableState } from '@/components/states/unavailable-state';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { useUrlState } from '@/hooks/use-url-state';
import { useApiQuery } from '@/lib/api/hooks';
import { RouteGate } from '@/lib/auth/route-gate';
import { formatNumber, humanize } from '@/lib/format';
import { DetailList, Section } from '@/features/messages/controls';
import { FeatureOffNotice } from './components';
import {
  OVERVIEW_RANGES,
  atoIncidentsHref,
  atoResponsesHref,
  countryName,
  type AtoOverview,
  type OverviewRange,
} from './model';

const URL_SHAPE = { range: z.enum(OVERVIEW_RANGES).default('7d') };
const RANGE_LABELS: Record<OverviewRange, string> = {
  '24h': 'Last 24 hours',
  '7d': 'Last 7 days',
  '30d': 'Last 30 days',
};

/** `/ato`: the account takeover dashboard (step 8.4 §6, brief §11). */
export function AtoDashboardPage() {
  return (
    <RouteGate gate={['AtoOverviewController_overview_v1']}>
      <AtoDashboardContent />
    </RouteGate>
  );
}

function RangeChooser({
  value,
  onChange,
}: {
  value: OverviewRange;
  onChange: (value: OverviewRange) => void;
}) {
  return (
    <div className="grid gap-1">
      <Label htmlFor="ato-range" className="text-xs text-muted-foreground">
        Range
      </Label>
      <Select value={value} onValueChange={(next) => onChange(next as OverviewRange)}>
        <SelectTrigger id="ato-range" size="sm" className="min-w-40">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {OVERVIEW_RANGES.map((range) => (
            <SelectItem key={range} value={range}>
              {RANGE_LABELS[range]}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}

function AtoDashboardContent() {
  const [state, setState] = useUrlState(URL_SHAPE);
  const overview = useApiQuery('AtoOverviewController_overview_v1', {
    query: { range: state.range },
  });
  const data = overview.data;
  return (
    <div className="grid min-w-0 gap-4">
      <PageHeader
        title="Account takeover"
        description="Compromised-account detection over portal sign-ins, SMTP authentication and outbound mail: risky accounts, incidents, responses awaiting approval and where sign-ins come from."
        actions={<RangeChooser value={state.range} onChange={(range) => setState({ range })} />}
      />
      {overview.isLoading ? (
        <LoadingState label="Loading the account takeover overview" variant="tile" rows={8} />
      ) : overview.error ? (
        <ErrorState error={overview.error} onRetry={() => void overview.refetch()} />
      ) : data ? (
        data.monitoring.featureEnabled ? (
          <Overview data={data} />
        ) : (
          <FeatureOffNotice />
        )
      ) : null}
    </div>
  );
}

function Overview({ data }: { data: AtoOverview }) {
  const tile = (
    label: string,
    value: number,
    definition: string,
    href?: string,
    subtitle?: string,
  ) => (
    <KpiTile
      label={label}
      value={value}
      definition={definition}
      generatedAt={data.generatedAt}
      href={href}
      subtitle={subtitle}
    />
  );
  const trendRows: ChartRow[] = data.incidents.trend.map((bucket) => ({
    bucket: bucket.bucketStart,
    low: bucket.low,
    medium: bucket.medium,
    high: bucket.high,
    critical: bucket.critical,
  }));
  const bucketLabel = (value: string | number) => {
    const date = new Date(String(value));
    return Number.isNaN(date.getTime())
      ? String(value)
      : data.range === '24h'
        ? date.toISOString().slice(11, 16)
        : date.toISOString().slice(0, 10);
  };
  const countryRows: ChartRow[] = data.geography.topCountries.map((c) => ({
    country: c.countryCode,
    successfulAuth: c.successfulAuth,
    newCountrySignals: c.newCountrySignals,
  }));
  return (
    <div className="grid min-w-0 gap-4">
      <div
        role="group"
        className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4"
        aria-label="Key figures"
      >
        {tile(
          'Monitored accounts',
          data.accounts.monitored,
          'Mailboxes, portal users and SMTP connectors the detection engine tracks (active accounts).',
          '/ato/accounts',
          `${formatNumber(data.accounts.byKind.mailbox)} mailboxes · ${formatNumber(data.accounts.byKind.gateway_user)} users · ${formatNumber(data.accounts.byKind.smtp_connector)} connectors`,
        )}
        {tile(
          'High-risk accounts',
          data.accounts.highRisk,
          'Accounts whose current risk level is high or critical.',
          '/ato/accounts?level=high,critical',
          `${formatNumber(data.accounts.criticalRisk)} critical`,
        )}
        {tile(
          'Critical incidents',
          data.incidents.critical,
          'Active account takeover incidents with severity critical.',
          atoIncidentsHref({ severity: 'critical' }),
          `${formatNumber(data.incidents.active)} active · ${formatNumber(data.incidents.openedInRange)} opened in range`,
        )}
        {tile(
          'Suspicious sign-ins',
          data.logins.suspiciousInRange,
          'Authentication signals (failed-sign-in patterns, new or impossible locations, risky IPs) in the range.',
          undefined,
          `${formatNumber(data.logins.failedInRange)} failed sign-ins in range`,
        )}
        {tile(
          'Suspicious outbound activity',
          data.outbound.suspiciousInRange,
          'Outbound behaviour and content signals (volume, recipients, phishing or malware sent) in the range.',
        )}
        {tile(
          'Restricted accounts',
          data.outbound.restrictedAccounts,
          'Accounts with an active SMTP sending or authentication restriction.',
          '/ato/responses?tab=restrictions',
        )}
        {tile(
          'Mail held by ATO policy',
          data.outbound.policyHeldInRange,
          'Messages in the range that a tenant policy over account takeover facts held, quarantined or rejected.',
        )}
        {tile(
          'Pending approvals',
          data.responses.pendingApproval,
          'Responses waiting for a second analyst’s approval.',
          atoResponsesHref('pending_approval'),
          `${formatNumber(data.responses.executedInRange)} executed · ${formatNumber(data.responses.failedInRange)} failed in range`,
        )}
      </div>

      <div className="grid min-w-0 gap-4 xl:grid-cols-2">
        <Section
          title="Incident trend"
          description={`Account takeover incidents opened per ${data.range === '24h' ? 'hour' : 'day'} by severity.`}
        >
          {trendRows.length > 0 ? (
            <BarChart
              title="Incidents opened by severity"
              rows={trendRows}
              categoryKey="bucket"
              categoryLabel={data.range === '24h' ? 'Hour (UTC)' : 'Day (UTC)'}
              formatCategory={bucketLabel}
              stacked
              series={[
                { key: 'critical', label: 'Critical' },
                { key: 'high', label: 'High' },
                { key: 'medium', label: 'Medium' },
                { key: 'low', label: 'Low' },
              ]}
            />
          ) : (
            <p className="text-sm text-muted-foreground">No incidents opened in this range.</p>
          )}
          <DetailList
            items={[
              {
                label: 'Remediated',
                value: formatNumber(data.incidents.resolvedInRange.remediated),
              },
              {
                label: 'False positives',
                value: formatNumber(data.incidents.resolvedInRange.falsePositive),
              },
              {
                label: 'Other resolutions',
                value: formatNumber(data.incidents.resolvedInRange.other),
              },
            ]}
          />
        </Section>

        <Section
          title="Geographic anomalies"
          description="Countries of successful sign-ins and new-country signals in the range."
        >
          {data.geography.available ? (
            <>
              {countryRows.length > 0 ? (
                <BarChart
                  title="Sign-ins by country"
                  rows={countryRows}
                  categoryKey="country"
                  categoryLabel="Country"
                  formatCategory={(value) => countryName(String(value))}
                  layout="horizontal"
                  series={[
                    { key: 'successfulAuth', label: 'Successful sign-ins' },
                    { key: 'newCountrySignals', label: 'New-country signals' },
                  ]}
                />
              ) : (
                <p className="text-sm text-muted-foreground">No located sign-ins in this range.</p>
              )}
              <DetailList
                items={[
                  {
                    label: 'Impossible travel',
                    value: formatNumber(data.geography.impossibleTravelInRange),
                  },
                ]}
              />
            </>
          ) : (
            <UnavailableState
              step={null}
              title="Geography unavailable"
              description={
                data.geography.reason === 'capabilities_unknown'
                  ? 'The detection worker has not reported its capabilities recently, so it is unknown whether locations can be resolved.'
                  : 'No GeoIP City database is configured. Locations, new-country and impossible-travel detection need the operator-provided MaxMind GeoLite2 City and ASN databases; until they are mounted these rules are unavailable (never guessed).'
              }
            />
          )}
        </Section>
      </div>

      <Section title="Monitoring" description="How detection runs for this organization.">
        <DetailList
          items={[
            { label: 'Mode', value: humanize(data.monitoring.mode) },
            {
              label: 'Learning period',
              value: data.monitoring.learning ? (
                <span>
                  Learning until <DateTime value={data.monitoring.learningEndsAt} mode="absolute" />{' '}
                  (baseline-relative rules are informational)
                </span>
              ) : (
                'Complete'
              ),
            },
            {
              label: 'Range',
              value: (
                <span>
                  <DateTime value={data.from} mode="absolute" /> –{' '}
                  <DateTime value={data.to} mode="absolute" />
                </span>
              ),
            },
            {
              label: 'Active incidents',
              value: (
                <Link
                  href={atoIncidentsHref()}
                  className="text-primary underline-offset-2 hover:underline"
                >
                  {formatNumber(data.incidents.active)} active (critical{' '}
                  {formatNumber(data.incidents.activeBySeverity.critical)}, high{' '}
                  {formatNumber(data.incidents.activeBySeverity.high)}, medium{' '}
                  {formatNumber(data.incidents.activeBySeverity.medium)}, low{' '}
                  {formatNumber(data.incidents.activeBySeverity.low)})
                </Link>
              ),
            },
          ]}
        />
      </Section>
    </div>
  );
}
