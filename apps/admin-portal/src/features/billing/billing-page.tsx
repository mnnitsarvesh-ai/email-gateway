'use client';

import { useId } from 'react';
import { z } from 'zod';
import { DateTime } from '@/components/domain/date-time';
import { PageHeader } from '@/components/page-header';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { UnavailableState } from '@/components/states/unavailable-state';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useUrlState } from '@/hooks/use-url-state';
import { useApiQuery } from '@/lib/api/hooks';
import { RouteGate } from '@/lib/auth/route-gate';
import { formatNumber, formatUtc } from '@/lib/format';
import { GatedTabs, type TabDefinition } from '@/features/reports/gated-tabs';
import { navGate } from '@/features/reports/nav-gate';
import { StatList } from '@/features/reports/report-parts';
import { ReportSection } from '@/features/reports/report-state';
import { FeaturesTable, LimitsTable, UsageSummary } from './entitlements';

const TABS: readonly TabDefinition[] = [
  { id: 'plan', label: 'Plan and entitlements', ops: ['BillingController_plan_v1'] },
  { id: 'metered', label: 'Monthly usage', ops: ['BillingController_usage_v1'] },
  { id: 'current', label: 'Current usage', ops: ['UsageController_get_v1'] },
];

export const PRICING_UNAVAILABLE =
  'Pricing, invoices and payment methods are not managed by the platform';

/** `/billing` (design §1.3 row 22): plan, entitlements and metered usage; never prices. */
export function BillingPage() {
  return (
    <RouteGate gate={navGate('billing')}>
      <div className="flex flex-col gap-4">
        <PageHeader
          title="Usage and billing"
          description="Your plan, its limits and features, and the usage the platform measures."
        />
        <GatedTabs
          tabs={TABS}
          label="Usage and billing"
          keepParams={[]}
          render={(tab) =>
            tab === 'plan' ? <PlanTab /> : tab === 'metered' ? <MeteredTab /> : <CurrentUsageTab />
          }
        />
      </div>
    </RouteGate>
  );
}

function PlanTab() {
  const plan = useApiQuery('BillingController_plan_v1');
  if (plan.isLoading) return <LoadingState label="Loading your plan" rows={6} />;
  if (plan.error) return <ErrorState error={plan.error} onRetry={() => void plan.refetch()} />;
  if (!plan.data) return null;
  const data = plan.data;
  return (
    <div className="grid gap-4">
      <ReportSection
        title={`Plan: ${data.plan.name}`}
        description={<span className="font-mono">{data.plan.code}</span>}
      >
        <p className="text-sm text-muted-foreground">
          {data.plan.description ?? 'This plan has no description.'}
        </p>
        <p className="text-xs text-muted-foreground">{data.note}</p>
      </ReportSection>
      {data.pricing === null ? (
        <UnavailableState
          step={null}
          title="Pricing and invoices"
          description={`${PRICING_UNAVAILABLE}. No step of the plan delivers them; contact your provider for commercial terms.`}
        />
      ) : null}
      <div className="grid gap-4 xl:grid-cols-2">
        <ReportSection title="Limits">
          <LimitsTable caption="Limits of your plan" limits={data.limits} />
        </ReportSection>
        <ReportSection title="Features">
          <FeaturesTable caption="Features of your plan" features={data.features} />
        </ReportSection>
      </div>
    </div>
  );
}

const MONTH = /^(\d{4})-(0[1-9]|1[0-2])$/;
export const BILLING_URL_SHAPE = {
  month: z.string().regex(MONTH).optional().catch(undefined),
};

function MeteredTab() {
  const [state, setState] = useUrlState(BILLING_URL_SHAPE);
  const monthId = useId();
  const usage = useApiQuery('BillingController_usage_v1', {
    query: state.month ? { month: state.month } : {},
  });
  return (
    <div className="grid gap-4">
      <div className="grid w-fit gap-1.5">
        <Label htmlFor={monthId}>Month (UTC)</Label>
        <Input
          id={monthId}
          type="month"
          className="w-48"
          value={state.month ?? usage.data?.month ?? ''}
          onChange={(event) => {
            const value = event.target.value;
            setState({ month: MONTH.test(value) ? value : undefined });
          }}
        />
        <p className="text-xs text-muted-foreground">
          Defaults to the current month, counted up to now. Months older than the message retention
          are not available.
        </p>
      </div>
      {usage.isLoading ? (
        <LoadingState label="Loading the monthly usage" rows={6} />
      ) : usage.error ? (
        <ErrorState error={usage.error} onRetry={() => void usage.refetch()} />
      ) : usage.data ? (
        <ReportSection
          title={`Usage in ${usage.data.month}`}
          description={
            <>
              {formatUtc(usage.data.from)} to {formatUtc(usage.data.to)} · Updated{' '}
              <DateTime value={usage.data.generatedAt} />
            </>
          }
        >
          <StatList
            stats={[
              { label: 'Messages', value: formatNumber(usage.data.messages.total) },
              { label: 'Inbound', value: formatNumber(usage.data.messages.inbound) },
              { label: 'Outbound', value: formatNumber(usage.data.messages.outbound) },
              { label: 'Internal', value: formatNumber(usage.data.messages.internal) },
              { label: 'Users', value: formatNumber(usage.data.users), hint: 'Current' },
              { label: 'Domains', value: formatNumber(usage.data.domains), hint: 'Current' },
              { label: 'Active API keys', value: formatNumber(usage.data.apiKeys) },
            ]}
          />
          <LimitsTable caption="Limits and their use" limits={usage.data.limits} showUsed />
        </ReportSection>
      ) : null}
    </div>
  );
}

function CurrentUsageTab() {
  const usage = useApiQuery('UsageController_get_v1');
  if (usage.isLoading) return <LoadingState label="Loading the current usage" rows={6} />;
  if (usage.error) return <ErrorState error={usage.error} onRetry={() => void usage.refetch()} />;
  if (!usage.data) return null;
  return (
    <ReportSection
      title="Current usage"
      description={`Rolling period ${formatUtc(usage.data.period.from)} to ${formatUtc(usage.data.period.to)}`}
    >
      <UsageSummary usage={usage.data} />
      <LimitsTable caption="Limits and their use" limits={usage.data.limits} showUsed />
    </ReportSection>
  );
}
