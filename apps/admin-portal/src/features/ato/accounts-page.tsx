'use client';

import { UsersIcon } from 'lucide-react';
import Link from 'next/link';
import { useMemo } from 'react';
import { z } from 'zod';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { DateTime } from '@/components/domain';
import { PageHeader } from '@/components/page-header';
import { EmptyState } from '@/components/states/empty-state';
import { LoadingState } from '@/components/states/loading-state';
import { useUrlState } from '@/hooks/use-url-state';
import { useApiQuery, useCursorList } from '@/lib/api/hooks';
import type { QueryParams } from '@/lib/api/types';
import { RouteGate } from '@/lib/auth/route-gate';
import {
  EnumBadge,
  FilterMultiSelect,
  FilterSelect,
  FilterText,
} from '@/features/messages/controls';
import { AtoScore, FeatureOffNotice, KindLabel } from './components';
import {
  ATO_ACCOUNT_KINDS,
  ATO_RISK_LEVELS,
  KIND_LABELS,
  LEVEL_TONE,
  accountLabel,
  atoAccountHref,
  incidentHref,
  type AtoAccount,
} from './model';

const SORTS = ['-riskScore', '-lastSignalAt', 'address'] as const;

export const ACCOUNTS_URL_SHAPE = {
  kind: z.array(z.enum(ATO_ACCOUNT_KINDS)).max(3).default([]),
  level: z.array(z.enum(ATO_RISK_LEVELS)).max(4).default([]),
  minScore: z.coerce.number().int().min(0).max(100).optional(),
  incident: z.enum(['yes', 'no']).optional(),
  protected: z.enum(['yes', 'no']).optional(),
  q: z.string().trim().min(2).max(320).optional(),
  sort: z.enum(SORTS).default('-riskScore'),
};

type Filters = QueryParams<'AtoAccountsController_list_v1'>;

/** The list query of the URL state (comma lists, booleans as `true`/`false`). */
export function accountsQuery(state: {
  kind: readonly string[];
  level: readonly string[];
  minScore?: number;
  incident?: 'yes' | 'no';
  protected?: 'yes' | 'no';
  q?: string;
  sort: (typeof SORTS)[number];
}): Filters {
  return {
    sort: state.sort,
    ...(state.kind.length > 0 ? { kind: state.kind.join(',') } : {}),
    ...(state.level.length > 0 ? { level: state.level.join(',') } : {}),
    ...(state.minScore !== undefined ? { minScore: String(state.minScore) } : {}),
    ...(state.incident ? { hasActiveIncident: state.incident === 'yes' ? 'true' : 'false' } : {}),
    ...(state.protected ? { protected: state.protected === 'yes' ? 'true' : 'false' } : {}),
    ...(state.q ? { q: state.q } : {}),
  };
}

/** `/ato/accounts`: the account risk explorer (step 8.4 §6). */
export function AtoAccountsPage() {
  return (
    <RouteGate gate={['AtoAccountsController_list_v1']}>
      <AccountsContent />
    </RouteGate>
  );
}

function AccountsContent() {
  const [state, setState] = useUrlState(ACCOUNTS_URL_SHAPE);
  // The feature gate: lists answer empty data while ATO is off (D17); the attention read says so.
  const settings = useApiQuery('AtoSettingsController_get_v1', undefined, { retry: false });
  const filters = useMemo(() => accountsQuery(state), [state]);
  const list = useCursorList('AtoAccountsController_list_v1', filters, { limit: 25 });
  const filtered =
    state.kind.length > 0 ||
    state.level.length > 0 ||
    state.minScore !== undefined ||
    state.incident !== undefined ||
    state.protected !== undefined ||
    state.q !== undefined;

  const columns: DataTableColumn<AtoAccount>[] = [
    {
      id: 'account',
      header: 'Account',
      meta: { label: 'Account', hideable: false },
      cell: ({ row }) => (
        <div className="grid min-w-0 gap-0.5">
          <Link
            href={atoAccountHref(row.original.id)}
            className="truncate font-medium text-primary underline-offset-2 hover:underline"
          >
            {accountLabel(row.original)}
          </Link>
          <KindLabel kind={row.original.kind} />
        </div>
      ),
    },
    {
      id: 'riskScore',
      header: 'Risk',
      meta: { label: 'Risk' },
      cell: ({ row }) => <AtoScore score={row.original.riskScore} level={row.original.riskLevel} />,
    },
    {
      id: 'lastSignalAt',
      header: 'Last signal',
      meta: { label: 'Last signal' },
      cell: ({ row }) => <DateTime value={row.original.lastSignalAt} emptyLabel="None" />,
    },
    {
      id: 'incident',
      header: 'Active incident',
      meta: { label: 'Active incident' },
      cell: ({ row }) =>
        row.original.activeIncident ? (
          <Link
            href={incidentHref(row.original.activeIncident.id)}
            className="inline-flex items-center gap-1.5 text-primary underline-offset-2 hover:underline"
          >
            <EnumBadge value={row.original.activeIncident.severity} tones={LEVEL_TONE} />
            <span className="text-xs">{row.original.activeIncident.status.replace('_', ' ')}</span>
            <span className="sr-only">Open the incident</span>
          </Link>
        ) : (
          <span className="text-muted-foreground">None</span>
        ),
    },
    {
      id: 'override',
      header: 'Override',
      meta: { label: 'Override' },
      cell: ({ row }) =>
        row.original.override ? (
          <span className="text-xs">
            {row.original.override.verdict === 'benign' ? 'Benign' : 'Compromised'} until{' '}
            <DateTime value={row.original.override.expiresAt} />
          </span>
        ) : (
          <span className="text-muted-foreground">None</span>
        ),
    },
    {
      id: 'protected',
      header: 'Protected',
      meta: { label: 'Protected' },
      cell: ({ row }) => (row.original.protected ? 'Yes' : 'No'),
    },
  ];

  if (settings.isLoading) return <LoadingState label="Loading accounts" variant="table" />;
  const featureOff = settings.data?.featureEnabled === false;

  return (
    <div className="grid min-w-0 gap-4">
      <PageHeader
        title="Accounts"
        breadcrumbs={[{ label: 'Account takeover', href: '/ato' }, { label: 'Accounts' }]}
        description="Monitored mailboxes, portal users and SMTP connectors ordered by their account takeover risk. Scores are computed by the detection engine from stored signals."
      />
      {featureOff ? <FeatureOffNotice /> : null}
      <DataTable
        tableId="ato-accounts"
        caption="Monitored accounts"
        columns={columns}
        list={list}
        getRowId={(row) => row.id}
        getRowLabel={accountLabel}
        filters={
          <div className="flex flex-wrap items-end gap-3">
            <FilterSelect
              label="Sort by"
              allowAny={false}
              value={state.sort}
              options={[
                { value: '-riskScore', label: 'Highest risk first' },
                { value: '-lastSignalAt', label: 'Latest signal first' },
                { value: 'address', label: 'Address (A–Z)' },
              ]}
              onChange={(sort) =>
                setState({ sort: (sort as (typeof SORTS)[number]) ?? '-riskScore' })
              }
            />
            <FilterMultiSelect
              label="Kind"
              values={state.kind}
              options={ATO_ACCOUNT_KINDS.map((k) => ({ value: k, label: KIND_LABELS[k] }))}
              onChange={(kind) => setState({ kind: kind as typeof state.kind })}
            />
            <FilterMultiSelect
              label="Risk level"
              values={state.level}
              options={ATO_RISK_LEVELS.map((l) => ({
                value: l,
                label: l.charAt(0).toUpperCase() + l.slice(1),
              }))}
              onChange={(level) => setState({ level: level as typeof state.level })}
            />
            <FilterText
              label="Minimum score"
              type="number"
              inputMode="numeric"
              value={state.minScore === undefined ? undefined : String(state.minScore)}
              onCommit={(value) => {
                const n = value === undefined ? undefined : Number(value);
                setState({
                  minScore:
                    n === undefined || !Number.isInteger(n) || n < 0 || n > 100 ? undefined : n,
                });
              }}
              className="w-32"
            />
            <FilterSelect
              label="Active incident"
              value={state.incident}
              options={[
                { value: 'yes', label: 'With an incident' },
                { value: 'no', label: 'Without' },
              ]}
              onChange={(incident) => setState({ incident: incident as 'yes' | 'no' | undefined })}
            />
            <FilterSelect
              label="Protected"
              value={state.protected}
              options={[
                { value: 'yes', label: 'Protected' },
                { value: 'no', label: 'Not protected' },
              ]}
              onChange={(value) => setState({ protected: value as 'yes' | 'no' | undefined })}
            />
            <FilterText
              label="Address starts with"
              value={state.q}
              placeholder="at least 2 characters"
              onCommit={(q) => setState({ q: q && q.trim().length >= 2 ? q.trim() : undefined })}
              className="w-56"
            />
          </div>
        }
        isFiltered={filtered}
        onClearFilters={() =>
          setState({
            kind: [],
            level: [],
            minScore: undefined,
            incident: undefined,
            protected: undefined,
            q: undefined,
          })
        }
        emptyState={
          <EmptyState
            icon={UsersIcon}
            title="No monitored accounts"
            description="Accounts appear when the detection engine sees sign-ins, SMTP authentication or outbound mail."
          />
        }
        mobileCard={(row) => (
          <div className="grid gap-1">
            <Link
              href={atoAccountHref(row.id)}
              className="font-medium text-primary underline-offset-2 hover:underline"
            >
              {accountLabel(row)}
            </Link>
            <KindLabel kind={row.kind} />
            <AtoScore score={row.riskScore} level={row.riskLevel} />
          </div>
        )}
      />
    </div>
  );
}
