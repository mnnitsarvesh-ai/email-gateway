'use client';

import { EyeOffIcon, TagIcon } from 'lucide-react';
import { useMemo, useState } from 'react';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { DateTime, DirectionBadge, UntrustedText, VerdictBadge } from '@/components/domain';
import { NotFoundView } from '@/components/not-found-view';
import { PageHeader } from '@/components/page-header';
import { EmptyState } from '@/components/states/empty-state';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { useApiMutation, useApiQuery, useCursorList } from '@/lib/api/hooks';
import type { RequestBody } from '@/lib/api/types';
import { RouteGate } from '@/lib/auth/route-gate';
import { formatNumber, humanize } from '@/lib/format';
import { isUuid } from '@/features/domains/kit';
import {
  DetailList,
  EnumBadge,
  FilterSelect,
  Section,
  optionsOf,
} from '@/features/messages/controls';
import {
  ArchiveErrorSummary,
  ArchiveQueryError,
  ArchiveRecipients,
  ArchiveSubject,
  RateLimited,
} from '@/features/archive/components';
import { useArchiveReveal } from '@/features/archive/hooks';
import {
  REVIEW_MAX_ITEMS,
  REVIEW_TAGS,
  REVIEW_TAG_TONE,
  JOB_STATUS_TONE,
  archiveMessageHref,
  caseHref,
  formatCriteriaInstant,
  stringList,
  useArchiveAccess,
  type ReviewTag,
  type SearchHit,
} from '@/features/archive/model';
import Link from 'next/link';
import { CompletenessBanner } from './case-page';
import { JOB_POLL_MS, isActiveJob } from './model';

/** One case search with its hits (`/ediscovery/[caseId]/searches/[searchId]`, A18, A28). */
export function CaseSearchPage({ caseId, searchId }: { caseId: string; searchId: string }) {
  return (
    <RouteGate gate={['EdiscoverySearchesController_get_v1']}>
      {isUuid(caseId) && isUuid(searchId) ? (
        <CaseSearchContent caseId={caseId} searchId={searchId} />
      ) : (
        <NotFoundView />
      )}
    </RouteGate>
  );
}

/** A hit whose archived record is no longer available (disposed after the search). */
function Gone() {
  return <span className="text-xs text-muted-foreground">No longer archived</span>;
}

export function reviewBody(
  tag: ReviewTag,
  messageIds: readonly string[],
): RequestBody<'EdiscoverySearchesController_review_v1'> {
  return { tag, messageIds: [...messageIds] };
}

const ENUM_CRITERIA = new Set([
  'directions',
  'categories',
  'sources',
  'statuses',
  'verdicts',
  'finalActions',
]);

/** Criteria of a stored search, for display (values masked by the api without message:reveal). */
function CriteriaSummary({ criteria }: { criteria: Record<string, unknown> }) {
  const items: { label: string; value: string }[] = [];
  const from = formatCriteriaInstant(criteria.from);
  const to = formatCriteriaInstant(criteria.to);
  if (from || to) items.push({ label: 'Received', value: `${from ?? '…'} to ${to ?? '…'}` });
  if (criteria.custodians === 'case')
    items.push({ label: 'Custodians', value: 'The case’s custodians' });
  for (const [key, value] of Object.entries(criteria)) {
    if (key === 'from' || key === 'to' || (key === 'custodians' && value === 'case')) continue;
    if (Array.isArray(value)) {
      const list = stringList(value);
      items.push({
        label: humanize(key),
        value: (ENUM_CRITERIA.has(key) ? list.map(humanize) : list).join(', '),
      });
    } else if (
      typeof value === 'string' ||
      typeof value === 'number' ||
      typeof value === 'boolean'
    ) {
      items.push({ label: humanize(key), value: String(value) });
    }
  }
  return (
    <DetailList
      items={items.map((item) => ({
        label: item.label,
        value: <UntrustedText value={item.value} maxLength={300} />,
      }))}
    />
  );
}

function CaseSearchContent({ caseId, searchId }: { caseId: string; searchId: string }) {
  const access = useArchiveAccess();
  const search = useApiQuery(
    'EdiscoverySearchesController_get_v1',
    { path: { caseId, searchId } },
    {
      refetchInterval: (query) =>
        query.state.data && isActiveJob(query.state.data.status) ? JOB_POLL_MS : false,
    },
  );
  const [reviewTag, setReviewTag] = useState<string | undefined>(undefined);
  const completed = search.data?.status === 'completed';
  const filters = useMemo(
    () => ({ sort: '-id' as const, ...(reviewTag ? { reviewTag } : {}) }),
    [reviewTag],
  );
  const hits = useCursorList('EdiscoverySearchesController_hits_v1', filters, {
    path: { caseId, searchId },
    limit: 50,
    enabled: completed,
  });
  const reveal = useArchiveReveal(`${searchId}:${reviewTag ?? ''}`);
  const [tag, setTag] = useState<ReviewTag>('relevant');
  const review = useApiMutation('EdiscoverySearchesController_review_v1', {
    successMessage: null,
    invalidates: ['EdiscoverySearchesController_hits_v1'],
  });
  const crumbs = [
    { label: 'eDiscovery', href: '/ediscovery' },
    { label: 'Case', href: caseHref(caseId, 'searches') },
    { label: 'Search' },
  ];
  if (search.isLoading) return <LoadingState label="Loading the search" rows={6} />;
  if (search.error || !search.data) {
    return (
      <div className="grid gap-4">
        <PageHeader title="Case search" breadcrumbs={crumbs} />
        <ArchiveQueryError error={search.error} onRetry={() => void search.refetch()} />
      </div>
    );
  }
  const s = search.data;
  const columns: DataTableColumn<SearchHit>[] = [
    {
      id: 'receivedAt',
      header: 'Received',
      meta: { label: 'Received', hideable: false },
      cell: ({ row }) => (
        <Link
          href={archiveMessageHref(row.original.messageId)}
          className="font-medium text-primary underline-offset-2 hover:underline"
        >
          <DateTime value={row.original.receivedAt} />
          <span className="sr-only">, open archived message</span>
        </Link>
      ),
    },
    {
      id: 'reviewTag',
      header: 'Review',
      meta: { label: 'Review tag' },
      cell: ({ row }) => <EnumBadge value={row.original.reviewTag} tones={REVIEW_TAG_TONE} />,
    },
    {
      id: 'direction',
      header: 'Direction',
      meta: { label: 'Direction' },
      cell: ({ row }) =>
        row.original.message ? (
          <DirectionBadge direction={row.original.message.direction} />
        ) : (
          <Gone />
        ),
    },
    {
      id: 'from',
      header: 'From',
      meta: { label: 'From' },
      cell: ({ row }) =>
        row.original.message ? (
          <UntrustedText value={row.original.message.envelopeFrom} maxLength={60} />
        ) : (
          <Gone />
        ),
    },
    {
      id: 'recipients',
      header: 'Recipients',
      meta: { label: 'Recipients' },
      cell: ({ row }) =>
        row.original.message ? (
          <ArchiveRecipients
            row={row.original.message}
            revealed={reveal.values.get(row.original.messageId)}
          />
        ) : (
          <Gone />
        ),
    },
    {
      id: 'subject',
      header: 'Subject',
      meta: { label: 'Subject', className: 'min-w-48' },
      cell: ({ row }) =>
        row.original.message ? (
          <ArchiveSubject
            row={row.original.message}
            revealed={reveal.values.get(row.original.messageId)}
          />
        ) : (
          <Gone />
        ),
    },
    {
      id: 'verdict',
      header: 'Verdict',
      meta: { label: 'Verdict' },
      cell: ({ row }) => (
        <span className="flex flex-wrap gap-1">
          <VerdictBadge verdict={row.original.message?.verdict} />
          {row.original.message?.malicious ? (
            <EnumBadge value="malicious" tones={{ malicious: 'danger' }} />
          ) : null}
        </span>
      ),
    },
    {
      id: 'reviewedAt',
      header: 'Reviewed',
      meta: { label: 'Reviewed' },
      cell: ({ row }) => <DateTime value={row.original.reviewedAt} emptyLabel="—" />,
    },
  ];
  return (
    <div className="grid min-w-0 gap-4">
      <PageHeader
        title="Case search"
        breadcrumbs={crumbs}
        description={
          <>
            Requested <DateTime value={s.createdAt} mode="absolute" /> · {formatNumber(s.hitCount)}{' '}
            hits. Opening the hits is recorded in the audit log.
          </>
        }
      />
      <CompletenessBanner search={s} />
      <Section title="Search">
        <DetailList
          items={[
            { label: 'Status', value: <EnumBadge value={s.status} tones={JOB_STATUS_TONE} /> },
            {
              label: 'Started',
              value: <DateTime value={s.startedAt} mode="absolute" emptyLabel="Not yet" />,
            },
            {
              label: 'Completed',
              value: <DateTime value={s.completedAt} mode="absolute" emptyLabel="Not yet" />,
            },
            {
              label: 'Criteria SHA-256',
              value: <span className="font-mono text-xs break-all">{s.criteriaSha256}</span>,
            },
          ]}
        />
        <CriteriaSummary criteria={s.criteria} />
      </Section>
      {completed ? (
        <>
          {access.reveal && reveal.values.size > 0 ? (
            <Button
              variant="outline"
              size="sm"
              className="justify-self-start"
              onClick={reveal.hide}
            >
              <EyeOffIcon aria-hidden />
              Hide revealed values
            </Button>
          ) : null}
          <p className="sr-only" aria-live="polite">
            {reveal.announcement}
          </p>
          {reveal.error ? (
            reveal.error.status === 429 ? (
              <RateLimited seconds={reveal.retryAfterSeconds} what="reveals" />
            ) : (
              <ErrorState error={reveal.error} compact />
            )
          ) : null}
          <ArchiveErrorSummary error={review.error} />
          <DataTable
            tableId="ediscovery-hits"
            caption="Search hits"
            columns={columns}
            list={hits}
            getRowId={(row) => row.messageId}
            getRowLabel={(row) => `hit received ${row.receivedAt}`}
            enableSelection
            filters={
              <FilterSelect
                label="Review tag"
                value={reviewTag}
                anyLabel="All"
                options={optionsOf(REVIEW_TAGS)}
                onChange={setReviewTag}
              />
            }
            isFiltered={reviewTag !== undefined}
            onClearFilters={() => setReviewTag(undefined)}
            rowActions={
              access.reveal
                ? (row) => [
                    {
                      label: reveal.values.has(row.messageId)
                        ? 'Revealed'
                        : 'Reveal subject and recipients',
                      disabled:
                        reveal.values.has(row.messageId) ||
                        reveal.pending ||
                        reveal.retryAfterSeconds > 0,
                      onSelect: () => void reveal.reveal([row.messageId]),
                    },
                  ]
                : undefined
            }
            bulkActions={(rows, clear) => (
              <div className="flex flex-wrap items-end gap-2">
                <FilterSelect
                  label="Tag as"
                  value={tag}
                  allowAny={false}
                  options={optionsOf(REVIEW_TAGS)}
                  onChange={(next) => setTag((next as ReviewTag | undefined) ?? 'relevant')}
                />
                <Button
                  size="sm"
                  disabled={review.isPending || rows.length === 0 || rows.length > REVIEW_MAX_ITEMS}
                  onClick={() =>
                    void review
                      .submit({
                        path: { caseId, searchId },
                        body: reviewBody(
                          tag,
                          rows.map((r) => r.messageId),
                        ),
                      })
                      .then((outcome) => {
                        if (outcome.ok) clear();
                      })
                  }
                >
                  <TagIcon aria-hidden />
                  {review.isPending
                    ? 'Tagging …'
                    : `Tag ${rows.length} hit${rows.length === 1 ? '' : 's'} as ${humanize(tag).toLowerCase()}`}
                </Button>
              </div>
            )}
            emptyState={
              <EmptyState
                title={reviewTag ? 'No hit with this tag' : 'No hit'}
                description="The search found no archived message for these criteria."
              />
            }
          />
          {review.data ? (
            <p role="status" className="text-xs text-muted-foreground">
              Tagged {formatNumber(review.data.updated)} hit(s) as{' '}
              {humanize(review.data.tag).toLowerCase()}
              {review.data.notFound > 0 ? `; ${review.data.notFound} not found` : ''}. Recorded in
              the audit log.
            </p>
          ) : null}
        </>
      ) : null}
    </div>
  );
}
