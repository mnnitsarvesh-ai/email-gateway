'use client';

import { BarChart3Icon, XIcon } from 'lucide-react';
import { useMemo } from 'react';
import { z } from 'zod';
import { BarChart } from '@/components/charts';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { EmptyState } from '@/components/states/empty-state';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { ReportSection } from '@/features/reports/report-state';
import { useUrlState } from '@/hooks/use-url-state';
import { useApiQuery, useCursorList } from '@/lib/api/hooks';
import type { ListItem, SuccessBody } from '@/lib/api/types';
import { useCan } from '@/lib/auth/me';
import { formatNumber } from '@/lib/format';
import { KEY_SOURCE_LABEL, formatCostMicros, userLabel, type AdminUser } from './model';
import { useAdminRange } from './range-control';

type UsageRow = ListItem<'AssistantAdminController_usageByUser_v1'>;
type UserTotal = SuccessBody<'AssistantAdminController_usageByUser_v1'>['totals']['users'][number];

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const USER_URL_SHAPE = { user: z.string().regex(UUID).optional().catch(undefined) };

/** A person: display name and address (null outside the organization), public id as fallback. */
export function UserCell({ user }: { user: AdminUser }) {
  return (
    <span className="grid min-w-0 gap-0.5">
      <span className="truncate font-medium">{userLabel(user)}</span>
      {user.email && user.displayName ? (
        <span className="truncate text-xs text-muted-foreground">{user.email}</span>
      ) : null}
    </span>
  );
}

/** "Estimated cost" cell: the formatted estimate, `—` without a price. */
function Cost({ micros }: { micros: number | null }) {
  return micros === null ? (
    <span className="text-muted-foreground">
      —<span className="sr-only"> (no price known)</span>
    </span>
  ) : (
    <span className="tabular-nums">{formatCostMicros(micros)}</span>
  );
}

const tokens = (value: number) => <span className="tabular-nums">{formatNumber(value)}</span>;

/** Tokens per UTC day of the whole organization (`GET /assistant/usage`, summed over models). */
export function dailyTokens(
  usage: SuccessBody<'AssistantUsageController_get_v1'> | undefined,
): { day: string; tokens: number }[] {
  const byDay = new Map<string, number>();
  for (const row of usage?.rows ?? []) {
    const total = row.inputTokens + row.outputTokens + row.cacheReadTokens + row.cacheWriteTokens;
    byDay.set(row.day, (byDay.get(row.day) ?? 0) + total);
  }
  return [...byDay.entries()]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([day, value]) => ({ day, tokens: value }));
}

function TokensChart({ from, to }: { from: string; to: string }) {
  const usage = useApiQuery('AssistantUsageController_get_v1', { query: { from, to } });
  const rows = useMemo(() => dailyTokens(usage.data), [usage.data]);
  if (usage.isLoading) return <LoadingState label="Loading the daily tokens" rows={3} />;
  if (usage.error)
    return <ErrorState error={usage.error} onRetry={() => void usage.refetch()} compact />;
  if (rows.length === 0)
    return <p className="text-sm text-muted-foreground">No tokens were used in this range.</p>;
  return (
    <BarChart
      title="Tokens per day"
      description="All people of the organization, every model (UTC days)."
      rows={rows}
      categoryKey="day"
      categoryLabel="Day (UTC)"
      series={[{ key: 'tokens', label: 'Tokens' }]}
      height={220}
    />
  );
}

/** Usage tab (D1): tokens and estimated cost per person and UTC day, with totals. */
export function UsageTab() {
  const [range] = useAdminRange();
  const [filters, setFilters] = useUrlState(USER_URL_SHAPE);
  const canChart = useCan('AssistantUsageController_get_v1');
  const list = useCursorList(
    'AssistantAdminController_usageByUser_v1',
    {
      from: range.fromDay,
      to: range.toDay,
      ...(filters.user ? { userId: filters.user } : {}),
    },
    { limit: 50 },
  );
  const totals = list.query.data?.totals;
  const columns = useMemo<DataTableColumn<UsageRow>[]>(
    () => [
      {
        id: 'day',
        header: 'Day (UTC)',
        meta: { label: 'Day (UTC)', hideable: false },
        cell: ({ row }) => <span className="whitespace-nowrap">{row.original.day}</span>,
      },
      {
        id: 'user',
        header: 'Person',
        meta: { label: 'Person' },
        cell: ({ row }) => <UserCell user={row.original.user} />,
      },
      {
        id: 'keySource',
        header: 'Key',
        meta: { label: 'Key' },
        cell: ({ row }) => KEY_SOURCE_LABEL[row.original.keySource],
      },
      {
        id: 'turns',
        header: 'Questions',
        meta: { label: 'Questions' },
        cell: ({ row }) => tokens(row.original.turns),
      },
      {
        id: 'input',
        header: 'Input',
        meta: { label: 'Input tokens' },
        cell: ({ row }) => tokens(row.original.inputTokens),
      },
      {
        id: 'output',
        header: 'Output',
        meta: { label: 'Output tokens' },
        cell: ({ row }) => tokens(row.original.outputTokens),
      },
      {
        id: 'cacheRead',
        header: 'Cache read',
        meta: { label: 'Cache read tokens' },
        cell: ({ row }) => tokens(row.original.cacheReadTokens),
      },
      {
        id: 'cacheWrite',
        header: 'Cache write',
        meta: { label: 'Cache write tokens' },
        cell: ({ row }) => tokens(row.original.cacheWriteTokens),
      },
      {
        id: 'total',
        header: 'Total tokens',
        meta: { label: 'Total tokens' },
        cell: ({ row }) => tokens(row.original.totalTokens),
      },
      {
        id: 'cost',
        header: 'Estimated cost',
        meta: { label: 'Estimated cost (USD)' },
        cell: ({ row }) => <Cost micros={row.original.estimatedCostMicros} />,
      },
    ],
    [],
  );
  const userColumns = useMemo<DataTableColumn<UserTotal>[]>(
    () => [
      {
        id: 'user',
        header: 'Person',
        meta: { label: 'Person', hideable: false },
        cell: ({ row }) => (
          <Button
            variant="link"
            className="h-auto p-0 text-left whitespace-normal"
            onClick={() => setFilters({ user: row.original.user.id })}
          >
            <UserCell user={row.original.user} />
            <span className="sr-only"> (show only this person)</span>
          </Button>
        ),
      },
      {
        id: 'turns',
        header: 'Questions',
        meta: { label: 'Questions' },
        cell: ({ row }) => tokens(row.original.turns),
      },
      {
        id: 'total',
        header: 'Total tokens',
        meta: { label: 'Total tokens' },
        cell: ({ row }) => tokens(row.original.totalTokens),
      },
      {
        id: 'cost',
        header: 'Estimated cost',
        meta: { label: 'Estimated cost (USD)' },
        cell: ({ row }) => <Cost micros={row.original.estimatedCostMicros} />,
      },
    ],
    [setFilters],
  );

  return (
    <div className="grid min-w-0 gap-4 [&>*]:min-w-0">
      {filters.user ? (
        <p className="flex flex-wrap items-center gap-2 text-sm">
          Showing one person only.
          <Button variant="outline" size="sm" onClick={() => setFilters({ user: undefined })}>
            <XIcon aria-hidden />
            Show everyone
          </Button>
        </p>
      ) : null}
      <section
        aria-label="Usage totals"
        className="grid gap-3 rounded-lg border bg-card p-4 sm:grid-cols-3"
      >
        <div className="grid gap-0.5">
          <span className="text-xs text-muted-foreground">Questions</span>
          <span className="text-xl font-semibold tabular-nums">
            {totals ? formatNumber(totals.overall.turns) : '…'}
          </span>
        </div>
        <div className="grid gap-0.5">
          <span className="text-xs text-muted-foreground">Total tokens</span>
          <span className="text-xl font-semibold tabular-nums">
            {totals ? formatNumber(totals.overall.totalTokens) : '…'}
          </span>
        </div>
        <div className="grid gap-0.5">
          <span className="text-xs text-muted-foreground">Estimated cost (USD, estimate)</span>
          <span className="text-xl font-semibold tabular-nums">
            {totals ? formatCostMicros(totals.overall.estimatedCostMicros) : '…'}
          </span>
        </div>
        <p className="text-xs text-muted-foreground sm:col-span-3">
          {range.fromDay} to {range.toDay} (UTC). Costs are estimates from the platform&apos;s price
          list, not an invoice; — means no price is known for the model.
        </p>
      </section>
      {canChart && !filters.user ? (
        <ReportSection title="Tokens per day">
          <TokensChart from={range.fromDay} to={range.toDay} />
        </ReportSection>
      ) : null}
      <ReportSection title="Usage per person and day">
        <DataTable<UsageRow>
          tableId="assistant-admin-usage"
          caption={`AI assistant usage per person and day, ${range.fromDay} to ${range.toDay} (UTC)`}
          columns={columns}
          list={list}
          getRowId={(row) => `${row.day}|${row.user.id}|${row.keySource}`}
          getRowLabel={(row) => `${userLabel(row.user)} on ${row.day}`}
          emptyState={
            <EmptyState
              icon={BarChart3Icon}
              title="No questions in this range"
              description="Usage appears here after people ask the AI assistant."
            />
          }
          mobileCard={(row) => (
            <div className="grid gap-1 text-sm">
              <UserCell user={row.user} />
              <span className="text-xs text-muted-foreground">
                {row.day} · {KEY_SOURCE_LABEL[row.keySource]}
              </span>
              <span>
                {formatNumber(row.turns)} questions · {formatNumber(row.totalTokens)} tokens ·{' '}
                <Cost micros={row.estimatedCostMicros} />
              </span>
            </div>
          )}
        />
      </ReportSection>
      {totals && totals.users.length > 0 ? (
        <ReportSection
          title="Totals per person"
          description="The whole range for each person on this page."
        >
          <DataTable<UserTotal>
            tableId="assistant-admin-usage-users"
            caption="AI assistant usage totals per person"
            columns={userColumns}
            list={{
              rows: totals.users,
              page: 1,
              hasNext: false,
              hasPrevious: false,
              isShortPage: false,
              next: () => undefined,
              previous: () => undefined,
              query: {
                isLoading: false,
                isFetching: list.query.isFetching,
                error: null,
                refetch: () => list.query.refetch(),
              },
            }}
            getRowId={(row) => row.user.id}
            toolbar={false}
            pagination={false}
          />
        </ReportSection>
      ) : null}
    </div>
  );
}
