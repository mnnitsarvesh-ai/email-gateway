'use client';

import { GavelIcon, SearchIcon, UnlockIcon } from 'lucide-react';
import Link from 'next/link';
import { useMemo, useState } from 'react';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { CopyableId, DateTime, UntrustedText } from '@/components/domain';
import { NotFoundView } from '@/components/not-found-view';
import { PageHeader } from '@/components/page-header';
import { EmptyState } from '@/components/states/empty-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { useApiMutation, useApiQuery, useCursorList } from '@/lib/api/hooks';
import { RouteGate } from '@/lib/auth/route-gate';
import { humanize } from '@/lib/format';
import { isUuid } from '@/features/domains/kit';
import { DetailList, EnumBadge, FilterSelect, Section } from '@/features/messages/controls';
import { ArchiveQueryError, Notice, ReasonDialog } from '@/features/archive/components';
import {
  HOLD_STATUS_TONE,
  caseHref,
  formatCriteriaInstant,
  holdSearchHref,
  legalHoldHref,
  stringList,
  useArchiveAccess,
  type LegalHold,
} from '@/features/archive/model';

const HOLD_GATE = ['LegalHoldsController_list_v1'] as const;

/** The criteria of a hold (`archive-hold/1`, A12) as a definition list; custodians in clear. */
export function HoldCriteria({ hold }: { hold: Pick<LegalHold, 'criteria' | 'criteriaVersion'> }) {
  const c = hold.criteria as Record<string, unknown>;
  const custodians = stringList(c.custodians);
  const directions = stringList(c.directions);
  return (
    <DetailList
      items={[
        { label: 'Criteria version', value: hold.criteriaVersion ?? 'Legacy (step 5.3)' },
        {
          label: 'Custodians',
          value:
            custodians.length === 0 ? (
              <span>Every party (no custodian restriction)</span>
            ) : (
              <ul className="grid max-h-48 gap-0.5 overflow-y-auto" aria-label="Custodians">
                {custodians.map((address) => (
                  <li key={address}>
                    <UntrustedText value={address} mono maxLength={120} />
                  </li>
                ))}
              </ul>
            ),
        },
        { label: 'Received from', value: formatCriteriaInstant(c.from) ?? 'Any time' },
        { label: 'Received to', value: formatCriteriaInstant(c.to) ?? 'Any time' },
        {
          label: 'Directions',
          value: directions.length > 0 ? directions.map(humanize).join(', ') : 'Every direction',
        },
      ]}
    />
  );
}

/** Legal holds of the organization (`/legal-holds`, step 8.1 A12, A28). */
export function LegalHoldsPage() {
  return (
    <RouteGate gate={HOLD_GATE}>
      <LegalHoldsContent />
    </RouteGate>
  );
}

function LegalHoldsContent() {
  const [status, setStatus] = useState<string | undefined>('active');
  const filters = useMemo(
    () => ({ sort: '-id' as const, ...(status ? { status } : {}) }),
    [status],
  );
  const list = useCursorList('LegalHoldsController_list_v1', filters, { limit: 25 });
  const columns: DataTableColumn<LegalHold>[] = [
    {
      id: 'name',
      header: 'Hold',
      meta: { label: 'Hold', hideable: false },
      cell: ({ row }) => (
        <Link
          href={legalHoldHref(row.original.id)}
          className="font-medium text-primary underline-offset-2 hover:underline"
        >
          <UntrustedText value={row.original.name} maxLength={80} />
        </Link>
      ),
    },
    {
      id: 'status',
      header: 'Status',
      meta: { label: 'Status' },
      cell: ({ row }) => <EnumBadge value={row.original.status} tones={HOLD_STATUS_TONE} />,
    },
    {
      id: 'custodians',
      header: 'Custodians',
      meta: { label: 'Custodians' },
      cell: ({ row }) => {
        const n = stringList((row.original.criteria as Record<string, unknown>).custodians).length;
        return n === 0 ? 'Every party' : String(n);
      },
    },
    {
      id: 'case',
      header: 'Case',
      meta: { label: 'Case' },
      cell: ({ row }) =>
        row.original.caseId ? (
          <Link
            href={caseHref(row.original.caseId)}
            className="text-primary underline-offset-2 hover:underline"
          >
            Open case
          </Link>
        ) : (
          <span className="text-muted-foreground">No case (legacy)</span>
        ),
    },
    {
      id: 'createdAt',
      header: 'Placed',
      meta: { label: 'Placed' },
      cell: ({ row }) => <DateTime value={row.original.createdAt} />,
    },
    {
      id: 'releasedAt',
      header: 'Released',
      meta: { label: 'Released' },
      cell: ({ row }) => <DateTime value={row.original.releasedAt} emptyLabel="—" />,
    },
  ];
  return (
    <div className="grid min-w-0 gap-4">
      <PageHeader
        title="Legal holds"
        description="Holds prevent disposal of the archived mail they cover, whatever its retention. Holds are placed inside eDiscovery cases and are immutable: change one by placing a new hold and releasing the old."
      />
      <DataTable
        tableId="legal-holds"
        caption="Legal holds"
        columns={columns}
        list={list}
        getRowId={(row) => row.id}
        getRowLabel={(row) => row.name}
        filters={
          <FilterSelect
            label="Status"
            value={status}
            anyLabel="All"
            options={[
              { value: 'active', label: 'Active' },
              { value: 'released', label: 'Released' },
            ]}
            onChange={setStatus}
          />
        }
        isFiltered={status !== 'active'}
        onClearFilters={() => setStatus('active')}
        emptyState={
          <EmptyState
            icon={GavelIcon}
            title="No legal hold"
            description="Place holds from an eDiscovery case (Compliance → eDiscovery)."
          />
        }
      />
    </div>
  );
}

/** One legal hold (`/legal-holds/[holdId]`). */
export function LegalHoldDetailPage({ holdId }: { holdId: string }) {
  return (
    <RouteGate gate={HOLD_GATE}>
      {isUuid(holdId) ? <LegalHoldDetail holdId={holdId} /> : <NotFoundView />}
    </RouteGate>
  );
}

function LegalHoldDetail({ holdId }: { holdId: string }) {
  const access = useArchiveAccess();
  const hold = useApiQuery('LegalHoldsController_get_v1', { path: { holdId } });
  const [releaseOpen, setReleaseOpen] = useState(false);
  const crumbs = [{ label: 'Legal holds', href: '/legal-holds' }, { label: 'Legal hold' }];
  if (hold.isLoading) return <LoadingState label="Loading the legal hold" rows={6} />;
  if (hold.error || !hold.data) {
    return (
      <div className="grid gap-4">
        <PageHeader title="Legal hold" breadcrumbs={crumbs} />
        <ArchiveQueryError error={hold.error} onRetry={() => void hold.refetch()} />
      </div>
    );
  }
  const h = hold.data;
  return (
    <div className="grid min-w-0 gap-4">
      <PageHeader
        title={h.name}
        breadcrumbs={crumbs}
        description="Holds are evaluated when a record’s retention ends and at every disposal: a record a hold covers is kept."
        actions={
          <>
            {access.search ? (
              <Button asChild variant="outline" size="sm">
                <Link href={holdSearchHref(h.id)}>
                  <SearchIcon aria-hidden />
                  Records under this hold
                </Link>
              </Button>
            ) : null}
            {access.legalHold && h.status === 'active' ? (
              <Button variant="destructive" size="sm" onClick={() => setReleaseOpen(true)}>
                <UnlockIcon aria-hidden />
                Release hold
              </Button>
            ) : null}
          </>
        }
      />
      <Section title="Hold">
        <DetailList
          items={[
            { label: 'Hold', value: <CopyableId value={h.id} label="hold ID" /> },
            { label: 'Status', value: <EnumBadge value={h.status} tones={HOLD_STATUS_TONE} /> },
            { label: 'Reason', value: <UntrustedText value={h.reason} maxLength={1000} /> },
            {
              label: 'Case',
              value: h.caseId ? (
                <Link
                  href={caseHref(h.caseId)}
                  className="text-primary underline underline-offset-2"
                >
                  Open the eDiscovery case
                </Link>
              ) : (
                'No case (legacy hold)'
              ),
            },
            { label: 'Placed', value: <DateTime value={h.createdAt} mode="absolute" /> },
            {
              label: 'Released',
              value: <DateTime value={h.releasedAt} mode="absolute" emptyLabel="Not released" />,
            },
            {
              label: 'Release reason',
              hidden: !h.releaseReason,
              value: <UntrustedText value={h.releaseReason} maxLength={1000} />,
            },
          ]}
        />
      </Section>
      <Section
        title="Criteria"
        description="Snapshotted when the hold was placed; never changed afterwards."
      >
        <HoldCriteria hold={h} />
      </Section>
      <Notice>
        <span>
          “Records under this hold” searches the archive with this hold as a filter (informational:
          the hold itself is enforced in the archive database at every disposal).
        </span>
      </Notice>
      <ReleaseHoldDialog holdId={h.id} open={releaseOpen} onOpenChange={setReleaseOpen} />
    </div>
  );
}

/** Release a hold (MFA, reason). */
export function ReleaseHoldDialog({
  holdId,
  open,
  onOpenChange,
}: {
  holdId: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const release = useApiMutation('LegalHoldsController_release_v1', {
    successMessage: 'Legal hold released',
    invalidates: [
      'LegalHoldsController_get_v1',
      'LegalHoldsController_list_v1',
      'EdiscoveryCasesController_get_v1',
    ],
  });
  return (
    <ReasonDialog
      open={open}
      onOpenChange={onOpenChange}
      title="Release this legal hold?"
      description={
        <p>
          Records it held become eligible for disposal at their next retention check. The release is
          recorded in the audit log and needs a session signed in with MFA.
        </p>
      }
      confirmLabel="Release hold"
      destructive
      maxChars={4096}
      pending={release.isPending}
      onSubmit={(reason) => release.submit({ path: { holdId }, body: { reason } })}
      onRetry={() => release.retry()}
    />
  );
}
