'use client';

import { ArchiveIcon, EyeIcon, EyeOffIcon, SearchXIcon, ShieldCheckIcon } from 'lucide-react';
import Link from 'next/link';
import { useMemo } from 'react';
import { DataTable } from '@/components/data-table';
import { PageHeader } from '@/components/page-header';
import { EmptyState } from '@/components/states/empty-state';
import { ErrorState } from '@/components/states/error-state';
import { Button } from '@/components/ui/button';
import { useUrlState } from '@/hooks/use-url-state';
import { ApiError } from '@/lib/api/errors';
import { useApiQuery } from '@/lib/api/hooks';
import { RouteGate } from '@/lib/auth/route-gate';
import {
  ArchiveCard,
  IndexLagBanner,
  Notice,
  RateLimited,
  SearchUnavailable,
  archiveColumns,
} from './components';
import { useArchiveReveal, useCountdown, useArchiveSearch } from './hooks';
import { ARCHIVE_PAGE_SIZE, explainArchiveError, retentionHref, useArchiveAccess } from './model';
import { ArchiveFilters } from './search-filters';
import {
  ARCHIVE_URL_SHAPE,
  CLEARED_ARCHIVE_FILTERS,
  archiveSearchQuery,
  hasArchiveFilters,
  permittedArchiveState,
  type ArchiveSearchPatch,
} from './search-state';

export const ARCHIVE_TABLE_ID = 'archive-messages';

/** Archive search (`/archive`, step 8.1 A17, A28). */
export function ArchiveSearchPage() {
  return (
    <RouteGate gate={['ArchiveMessagesController_list_v1']}>
      <ArchiveSearchContent />
    </RouteGate>
  );
}

function ArchiveSearchContent() {
  const access = useArchiveAccess();
  const [urlState, setUrlState] = useUrlState(ARCHIVE_URL_SHAPE);
  const holdsAllowed = access.legalHold || access.ediscovery;
  const { state, ignored } = useMemo(
    () => permittedArchiveState(urlState, { reveal: access.reveal, holds: holdsAllowed }),
    [urlState, access.reveal, holdsAllowed],
  );
  const stateKey = JSON.stringify(state);
  const query = useMemo(
    () => archiveSearchQuery(state, Date.now()),
    // eslint-disable-next-line react-hooks/exhaustive-deps -- the window is fixed per state
    [stateKey],
  );
  const list = useArchiveSearch(query, { limit: ARCHIVE_PAGE_SIZE, enabled: access.ready });
  const holds = useApiQuery(
    'LegalHoldsController_list_v1',
    { query: { status: 'active', limit: '100' } },
    { enabled: holdsAllowed },
  );
  const holdOptions = useMemo(
    () => (holds.data?.data ?? []).map((h) => ({ id: h.id, name: h.name })),
    [holds.data],
  );
  const reveal = useArchiveReveal(stateKey);
  const columns = useMemo(() => archiveColumns(reveal.values), [reveal.values]);
  const error = list.query.error;
  const rateLimitSeconds = useCountdown(
    error instanceof ApiError && error.status === 429 ? (error.retryAfterSeconds ?? 60) : 0,
    error,
  );
  const setState = (patch: ArchiveSearchPatch) => setUrlState(patch);
  const masked = list.rows.filter(
    (row) => !reveal.values.has(row.messageId) && (row.subjectMasked || row.recipients.length > 0),
  );

  return (
    <div className="grid min-w-0 gap-4">
      <PageHeader
        title="Archive"
        description="Search the journaled and archived mail of your organization. Results are metadata only and masked; message content stays encrypted in the archive and is opened only from a record’s details."
        actions={
          access.read ? (
            <Button asChild variant="outline" size="sm">
              <Link href={retentionHref()}>Retention and lock</Link>
            </Button>
          ) : null
        }
      />
      <Notice icon={ShieldCheckIcon}>
        <span>
          Every search is recorded in the audit log (filter values as hashes). Lists have no totals.
          Subjects and recipient addresses are masked for everyone; revealing them is a separate,
          audited action.
        </span>
      </Notice>
      {ignored.length > 0 ? (
        <Notice tone="warning">
          <span>
            This link contains filters that need permissions you do not have; they were not applied:{' '}
            {ignored.join(', ')}.
          </span>
        </Notice>
      ) : null}
      <IndexLagBanner seconds={list.indexLagSeconds} />
      {access.reveal ? (
        <div className="grid gap-2 rounded-md border bg-card px-3 py-2">
          <div className="flex flex-wrap items-center gap-3">
            {reveal.values.size > 0 ? (
              <Button variant="outline" size="sm" onClick={reveal.hide}>
                <EyeOffIcon aria-hidden />
                Hide again
              </Button>
            ) : null}
            <Button
              variant="outline"
              size="sm"
              disabled={masked.length === 0 || reveal.pending || reveal.retryAfterSeconds > 0}
              onClick={() => void reveal.reveal(masked.map((row) => row.messageId))}
            >
              <EyeIcon aria-hidden />
              {reveal.pending ? 'Revealing …' : 'Reveal this page'}
            </Button>
            <p className="text-xs text-muted-foreground">
              Reveals the subjects and recipients of the messages on this page, one audited reveal
              per message. Revealed values are shown on this page only and forgotten when you change
              the search or leave.
            </p>
          </div>
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
        </div>
      ) : null}
      <DataTable
        tableId={ARCHIVE_TABLE_ID}
        caption="Archived messages"
        columns={columns}
        list={list}
        getRowId={(row) => row.messageId}
        getRowLabel={(row) => `archived message received ${row.receivedAt}`}
        filters={
          <ArchiveFilters
            state={state}
            setState={setState}
            can={{ reveal: access.reveal, holds: holdsAllowed }}
            holdOptions={holdsAllowed ? holdOptions : undefined}
            ingestSource
          />
        }
        isFiltered={hasArchiveFilters(state)}
        onClearFilters={() => setState(CLEARED_ARCHIVE_FILTERS)}
        sort={{
          operationId: 'ArchiveMessagesController_list_v1',
          columnId: 'receivedAt',
          value: state.sort,
          onChange: (sort) => setState({ sort: (sort as typeof state.sort) ?? '-receivedAt' }),
        }}
        errorState={(failure) => {
          if (!(failure instanceof ApiError)) return null;
          if (failure.code === 'archive_search_unavailable') {
            return (
              <div className="m-3">
                <SearchUnavailable error={failure} onRetry={() => void list.query.refetch()} />
              </div>
            );
          }
          if (failure.status === 429) {
            return (
              <div className="m-3">
                <RateLimited seconds={rateLimitSeconds} what="searches" />
              </div>
            );
          }
          if (
            failure.code === 'archive_filter_forbidden' ||
            failure.code === 'archive_search_range_invalid'
          ) {
            return (
              <div className="m-3 grid gap-2">
                <p className="text-sm">{explainArchiveError(failure).join(' ')}</p>
                <ErrorState error={failure} showRequirement={false} compact />
              </div>
            );
          }
          return null;
        }}
        emptyState={
          <EmptyState
            icon={hasArchiveFilters(state) ? SearchXIcon : ArchiveIcon}
            title="No archived mail in this range"
            description="No archived message matches. Choose a longer range or change the filters. Archiving captures mail only while journaling is enabled in Settings → Journaling."
          />
        }
        mobileCard={(row) => <ArchiveCard row={row} revealed={reveal.values.get(row.messageId)} />}
      />
    </div>
  );
}
