'use client';

import { LayersIcon } from 'lucide-react';
import Link from 'next/link';
import { useMemo } from 'react';
import { z } from 'zod';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { DateTime } from '@/components/domain/date-time';
import { PageHeader } from '@/components/page-header';
import { EmptyState } from '@/components/states/empty-state';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Card } from '@/components/ui/card';
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { useUrlState } from '@/hooks/use-url-state';
import { useCursorList } from '@/lib/api/hooks';
import { RouteGate } from '@/lib/auth/route-gate';
import { formatNumber, humanize } from '@/lib/format';
import {
  MODE_EXPLANATION,
  MODE_LABEL,
  PROTECTION_MODES,
  ProtectionModeBadge,
  type ProtectionMode,
} from '@/features/api-mode/model';
import {
  CAPABILITY_LABEL,
  SCOPE_KIND_LABEL,
  SupportBadge,
  capabilityNoteText,
  gapInfo,
  type Capability,
  type CoverageItem,
  type ProtectionCoverage,
} from '@/features/api-mode/parity-model';
import { MODE_TEXT } from '@/features/api-mode/remediation-model';
import { DomainStatusBadge, type DomainStatus } from '@/features/domains/model';
import { FilterSelect, Section } from '@/features/domains/kit';
import { PROVIDER_LABEL } from '@/features/integrations/providers/model';

/**
 * `/protection-by-mode` "Protection by mode" (step API-4 A10, API4-15): what Inline, API and
 * Hybrid cover (the api's static capability matrix with notes) and each domain's actual
 * coverage — inline facts, API facts and gaps with links to the page that fixes them — with
 * cursor paging and the totals per mode. Counts and codes only; the api computes every value.
 */

const URL_SHAPE = {
  mode: z
    .enum(PROTECTION_MODES as [ProtectionMode, ...ProtectionMode[]])
    .optional()
    .catch(undefined),
};

export function ProtectionByModePage() {
  return (
    <RouteGate gate={['ApiModeOnboardingController_protectionCoverage_v1']}>
      <ProtectionByMode />
    </RouteGate>
  );
}

function Totals({ view }: { view: ProtectionCoverage }) {
  return (
    <ul className="grid gap-3 sm:grid-cols-3" aria-label="Domains by protection mode">
      {PROTECTION_MODES.map((mode) => (
        <li key={mode}>
          <Card className="gap-1 px-4 py-4">
            <h3 className="text-sm font-medium text-muted-foreground">{MODE_LABEL[mode]}</h3>
            <p className="text-xl font-semibold tabular-nums">
              {formatNumber(view.totals[mode])} domain{view.totals[mode] === 1 ? '' : 's'}
            </p>
            <p className="text-xs text-muted-foreground">{MODE_EXPLANATION[mode]}</p>
          </Card>
        </li>
      ))}
    </ul>
  );
}

function CapabilityMatrix({ capabilities }: { capabilities: readonly Capability[] }) {
  return (
    // Keyboard users must be able to scroll the matrix on narrow screens (WCAG 2.1.1).
    <div
      className="relative overflow-x-auto"
      role="group"
      aria-label="Capability matrix"
      // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex -- a scrollable region
      tabIndex={0}
    >
      <Table>
        <TableCaption className="sr-only">What each protection mode covers</TableCaption>
        <TableHeader>
          <TableRow>
            <TableHead>Capability</TableHead>
            <TableHead>Inline</TableHead>
            <TableHead>API</TableHead>
            <TableHead>Hybrid</TableHead>
            <TableHead>Note</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {capabilities.map((c) => (
            <TableRow key={c.code}>
              <TableCell className="text-sm font-medium">
                {CAPABILITY_LABEL[c.code] ?? humanize(c.code)}
              </TableCell>
              <TableCell>
                <SupportBadge value={c.inline} />
              </TableCell>
              <TableCell>
                <SupportBadge value={c.api} />
              </TableCell>
              <TableCell>
                <SupportBadge value={c.hybrid} />
              </TableCell>
              <TableCell className="min-w-48 text-xs text-muted-foreground">
                {capabilityNoteText(c.noteCode) ?? '—'}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

function InlineFacts({ item }: { item: CoverageItem }) {
  if (!item.inline.applies) return <span className="text-xs text-muted-foreground">Not used</span>;
  const mx = item.inline.mxPointsToGateway;
  return (
    <span className="grid text-xs">
      <span>
        Inbound {item.inline.inboundEnabled ? 'on' : 'off'} · outbound{' '}
        {item.inline.outboundEnabled ? 'on' : 'off'}
      </span>
      <span className="text-muted-foreground">
        MX {mx === null ? 'not checked yet' : mx ? 'at the gateway' : 'not at the gateway'}
      </span>
    </span>
  );
}

function ApiFacts({ item }: { item: CoverageItem }) {
  const api = item.api;
  if (!api) return <span className="text-xs text-muted-foreground">Not used</span>;
  return (
    <span className="grid text-xs">
      <span>
        {api.connection
          ? `${PROVIDER_LABEL[api.connection.provider]} · ${humanize(api.connection.health)} · mailbox access ${api.connection.mailboxAccess}`
          : 'No connection'}
      </span>
      <span className="text-muted-foreground">
        Journal {api.intake.journal} · feeds {api.intake.feeds}
      </span>
      <span className="text-muted-foreground">
        {SCOPE_KIND_LABEL[api.scope]}: {formatNumber(api.mailboxes.inScope)} in scope,{' '}
        {formatNumber(api.mailboxes.covered)} covered, {formatNumber(api.mailboxes.gap)} with a gap
        {api.mailboxes.total !== null ? ` (of ${formatNumber(api.mailboxes.total)})` : ''}
      </span>
      <span className="text-muted-foreground">
        {MODE_TEXT[api.remediation.mode]}
        {api.remediation.detectOnlyUntil ? (
          <>
            {' '}
            until <DateTime value={api.remediation.detectOnlyUntil} />
          </>
        ) : null}{' '}
        · policies {api.policyEvaluation ? 'evaluated' : 'off'}
      </span>
      <span className="text-muted-foreground">
        Last copy <DateTime value={api.lastCopyAt} emptyLabel="none yet" />
      </span>
    </span>
  );
}

function Gaps({ item }: { item: CoverageItem }) {
  if (item.gaps.length === 0) return <span className="text-xs text-success">No gaps</span>;
  return (
    <ul className="grid gap-1 text-xs" aria-label={`Gaps of ${item.name}`}>
      {item.gaps.map((code) => {
        const gap = gapInfo(code, item);
        return (
          <li key={code}>
            {gap.text}.{' '}
            <Link href={gap.href} className="text-primary underline underline-offset-2">
              {gap.fix}
              <span className="sr-only"> for {item.name}</span>
            </Link>
          </li>
        );
      })}
    </ul>
  );
}

function ProtectionByMode() {
  const [filters, setFilters] = useUrlState(URL_SHAPE);
  const query = useMemo(
    () => (filters.mode ? { effectiveMode: filters.mode } : {}),
    [filters.mode],
  );
  const list = useCursorList('ApiModeOnboardingController_protectionCoverage_v1', query, {
    limit: 25,
  });
  const view = list.query.data;
  const columns = useMemo<DataTableColumn<CoverageItem>[]>(
    () => [
      {
        id: 'name',
        header: 'Domain',
        meta: { label: 'Domain' },
        cell: ({ row }) => (
          <span className="grid gap-0.5">
            <Link
              href={`/domains/${row.original.domainId}`}
              className="font-medium underline-offset-4 hover:underline"
            >
              {row.original.name}
            </Link>
            <DomainStatusBadge status={row.original.status as DomainStatus} />
          </span>
        ),
      },
      {
        id: 'mode',
        header: 'Mode',
        meta: { label: 'Mode' },
        cell: ({ row }) => (
          <ProtectionModeBadge
            mode={row.original.effectiveMode}
            inherited={row.original.inherited}
          />
        ),
      },
      {
        id: 'inline',
        header: 'Inline',
        meta: { label: 'Inline' },
        cell: ({ row }) => <InlineFacts item={row.original} />,
      },
      {
        id: 'api',
        header: 'API',
        meta: { label: 'API' },
        cell: ({ row }) => <ApiFacts item={row.original} />,
      },
      {
        id: 'gaps',
        header: 'Gaps',
        meta: { label: 'Gaps' },
        cell: ({ row }) => <Gaps item={row.original} />,
      },
    ],
    [],
  );
  return (
    <div className="grid min-w-0 gap-6 [&>*]:min-w-0">
      <PageHeader
        title="Protection by mode"
        breadcrumbs={[{ label: 'Domains', href: '/domains' }, { label: 'Protection by mode' }]}
        description="What Inline (MX), API (no MX change) and Hybrid protection cover, and what each of your domains actually has."
      />
      {list.query.isLoading && !view ? (
        <LoadingState label="Loading protection by mode" rows={6} />
      ) : list.query.error && !view ? (
        <ErrorState error={list.query.error} onRetry={() => void list.query.refetch()} />
      ) : view ? (
        <>
          {!view.entitled ? (
            <p role="status" className="rounded-md border p-3 text-sm">
              API-mode protection is not part of this organization&apos;s plan: every domain uses
              Inline. The matrix shows what API and Hybrid would add.
            </p>
          ) : null}
          <p className="text-sm">
            Organization mode: <ProtectionModeBadge mode={view.organizationMode} />
          </p>
          <Totals view={view} />
          <Section
            title="What each mode covers"
            description="Yes, partial or no for each capability; the note explains partial and missing cells."
          >
            <CapabilityMatrix capabilities={view.capabilities} />
          </Section>
        </>
      ) : null}
      <DataTable
        tableId="protection-by-mode"
        caption="Coverage of each domain"
        columns={columns}
        list={list}
        getRowId={(row) => row.domainId}
        getRowLabel={(row) => row.name}
        filters={
          <FilterSelect
            label="Mode"
            value={filters.mode}
            onChange={(mode) => setFilters({ mode: mode as ProtectionMode | undefined })}
            options={PROTECTION_MODES.map((value) => ({ value, label: MODE_LABEL[value] }))}
          />
        }
        isFiltered={Boolean(filters.mode)}
        onClearFilters={() => setFilters({ mode: undefined })}
        emptyState={
          <EmptyState
            icon={LayersIcon}
            title="No domain in this mode"
            description="Add a domain or change the filter."
          />
        }
        mobileCard={(row) => (
          <div className="grid gap-1">
            <span className="font-medium">{row.name}</span>
            <ProtectionModeBadge mode={row.effectiveMode} inherited={row.inherited} />
            <Gaps item={row} />
          </div>
        )}
      />
    </div>
  );
}
