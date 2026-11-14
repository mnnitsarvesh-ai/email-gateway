'use client';

import type { VisibilityState } from '@tanstack/react-table';
import { InfoIcon, MailIcon, SearchXIcon, ShieldCheckIcon } from 'lucide-react';
import { useCallback, useEffect, useId, useMemo, useState, type ReactNode } from 'react';
import { CopyButton } from '@/components/copy-button';
import { DataTable, readColumnVisibility, writeColumnVisibility } from '@/components/data-table';
import { PageHeader } from '@/components/page-header';
import { EmptyState } from '@/components/states/empty-state';
import { ErrorState } from '@/components/states/error-state';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { useUrlState } from '@/hooks/use-url-state';
import { ApiError } from '@/lib/api/errors';
import { shouldRetry, useCursorList } from '@/lib/api/hooks';
import { usePermissions } from '@/lib/auth/me';
import { RouteGate } from '@/lib/auth/route-gate';
import {
  EXPLORER_COLUMN_IDS,
  MessageCard,
  columnsOfVisibility,
  explorerColumns,
  visibilityOfColumns,
} from './columns';
import { ExplorerFilters, type ExplorerCapabilities } from './explorer-filters';
import {
  CLEARED_EXPLORER_FILTERS,
  EXPLORER_URL_SHAPE,
  explorerQuery,
  hasExplorerFilters,
  permittedState,
  type ExplorerPatch,
} from './explorer-state';
import { applyDefinition, definitionFromState, type SavedView } from './saved-view-definition';
import { SavedViewsMenu } from './saved-views-menu';
import { useSubjectReveal } from './use-subject-reveal';

/** The column-visibility preference key of the explorer's table (7.1 P2). */
export const EXPLORER_TABLE_ID = 'messages';
export const EXPLORER_PAGE_SIZE = 50;

const SEARCH_REFUSALS = new Set(['message_search_too_broad', 'message_search_timeout']);

/** `422 message_search_too_broad` / `503 message_search_timeout` (subject-prefix searches). */
export function isSearchRefusal(error: unknown): error is ApiError {
  return error instanceof ApiError && SEARCH_REFUSALS.has(error.code);
}

/** Retries of the list: never a refused search (a timeout would only repeat the timeout). */
function listRetry(failureCount: number, error: unknown): boolean {
  return !isSearchRefusal(error) && shouldRetry(failureCount, error);
}

/** Email Explorer (`/messages`, step 7.2 §2 E10; page 9). */
export function MessageExplorer() {
  return (
    <RouteGate gate={['MessagesController_list_v1']}>
      <MessageExplorerContent />
    </RouteGate>
  );
}

function MessageExplorerContent() {
  const [urlState, setUrlState] = useUrlState(EXPLORER_URL_SHAPE);
  const permissions = usePermissions();
  const has = useCallback((permission: string) => permissions.has(permission), [permissions]);
  const can: ExplorerCapabilities = {
    reveal: permissions.has('message:reveal'),
    delivery: permissions.has('delivery:read'),
    quarantine: permissions.has('quarantine:read'),
    domains: permissions.has('domain:read'),
  };
  const { state, ignored } = useMemo(() => permittedState(urlState, has), [urlState, has]);
  // The applied view (`view`) is not part of the query: saving a view must not move the window.
  const { view: viewId, ...queryState } = state;
  const queryKey = JSON.stringify(queryState);
  const query = useMemo(
    () => explorerQuery(state, Date.now()),
    // eslint-disable-next-line react-hooks/exhaustive-deps -- the window is fixed per state
    [queryKey],
  );
  const list = useCursorList('MessagesController_list_v1', query, {
    limit: EXPLORER_PAGE_SIZE,
    queryOptions: { refetchOnWindowFocus: false, retry: listRetry },
  });
  const setState = useCallback(
    (patch: ExplorerPatch, options?: { push?: boolean }) => setUrlState(patch, options),
    [setUrlState],
  );

  // Column set: the viewer's preference (localStorage), replaced when a saved view is applied.
  const [visibility, setVisibility] = useState<VisibilityState>({});
  useEffect(() => setVisibility(readColumnVisibility(EXPLORER_TABLE_ID)), []);
  const changeVisibility = useCallback((next: VisibilityState) => {
    setVisibility(next);
    writeColumnVisibility(EXPLORER_TABLE_ID, next);
  }, []);

  // Subject reveal: component state only (never the URL or storage), off by default.
  const [showSubjects, setShowSubjects] = useState(false);
  const reveal = useSubjectReveal(list.rows, can.reveal && showSubjects);
  const columns = useMemo(() => explorerColumns(reveal.revealed), [reveal.revealed]);

  const definition = useMemo(
    () => definitionFromState(state, columnsOfVisibility(visibility)),
    [state, visibility],
  );
  const [viewNotice, setViewNotice] = useState<string | null>(null);
  const applyView = (view: SavedView) => {
    const applied = applyDefinition(view, has, EXPLORER_COLUMN_IDS, Date.now());
    setState(applied.patch, { push: true });
    changeVisibility(visibilityOfColumns(applied.columns));
    setViewNotice(
      applied.skipped.length > 0
        ? `Some settings of this view no longer apply and were left out: ${applied.skipped.join('; ')}.`
        : null,
    );
  };

  const error = list.query.error;
  const searchStatus = isSearchRefusal(error) ? <SearchRefusal error={error} /> : null;

  return (
    <div className="grid min-w-0 gap-4">
      <PageHeader
        title="Email explorer"
        description="Message metadata of your organization from the read replica (a few seconds behind). Subjects and recipient addresses are masked; message content is never displayed here."
        actions={
          <SavedViewsMenu
            viewId={viewId}
            definition={definition}
            onApply={applyView}
            onSaved={(view) => setState({ view: view.id })}
            onDeleted={(id) => {
              if (viewId === id) setState({ view: undefined });
            }}
          />
        }
      />
      <p className="flex items-start gap-2 rounded-md border bg-muted/40 px-3 py-2 text-xs text-muted-foreground">
        <ShieldCheckIcon className="mt-0.5 size-4 shrink-0" aria-hidden />
        <span>
          Searches by sender, recipient, subject or Message-ID are recorded in the audit log (the
          values as hashes). Lists have no totals: a search combined with other filters examines a
          bounded number of rows per page, so a page can be short while more results exist further
          back.
        </span>
      </p>
      {ignored.length > 0 ? (
        <Notice>
          This link contains filters that need permissions you do not have; they were not applied:{' '}
          {ignored.join(', ')}.
        </Notice>
      ) : null}
      {viewNotice ? <Notice>{viewNotice}</Notice> : null}
      {can.reveal ? (
        <SubjectRevealControl
          checked={showSubjects}
          onCheckedChange={setShowSubjects}
          pending={reveal.pending}
          error={reveal.error}
          onRetry={reveal.retry}
          revealedCount={reveal.revealed.size}
        />
      ) : null}
      <DataTable
        tableId={EXPLORER_TABLE_ID}
        caption="Messages"
        columns={columns}
        list={list}
        getRowId={(row) => row.id}
        getRowLabel={(row) => `message received ${row.receivedAt}`}
        filters={
          <ExplorerFilters
            state={state}
            setState={(patch) => setState(patch)}
            can={can}
            searchStatus={searchStatus}
          />
        }
        isFiltered={hasExplorerFilters(state)}
        onClearFilters={() => setState(CLEARED_EXPLORER_FILTERS)}
        sort={{
          operationId: 'MessagesController_list_v1',
          columnId: 'receivedAt',
          value: state.sort,
          onChange: (sort) => setState({ sort: (sort as typeof state.sort) ?? '-receivedAt' }),
        }}
        columnVisibility={visibility}
        onColumnVisibilityChange={changeVisibility}
        errorState={(failure) => {
          if (isSearchRefusal(failure)) {
            return (
              <EmptyState
                icon={SearchXIcon}
                title="The search was refused"
                description="Change the search above; the results appear here when it is accepted."
              />
            );
          }
          if (failure instanceof ApiError && failure.code === 'message_filter_forbidden') {
            return <FilterForbidden error={failure} />;
          }
          return null;
        }}
        emptyState={
          <EmptyState
            icon={MailIcon}
            title="No mail in this range"
            description="No message was received in the selected time range. Choose a longer range."
          />
        }
        mobileCard={(row) => <MessageCard row={row} revealed={reveal.revealed} />}
      />
    </div>
  );
}

function Notice({ children }: { children: ReactNode }) {
  return (
    <p
      role="status"
      className="flex items-start gap-2 rounded-md border border-tone-warning bg-tone-warning px-3 py-2 text-xs text-tone-warning-foreground"
    >
      <InfoIcon className="mt-0.5 size-4 shrink-0" aria-hidden />
      <span>{children}</span>
    </p>
  );
}

/** The "Show subjects" switch (message:reveal holders only; §2 E10). */
function SubjectRevealControl({
  checked,
  onCheckedChange,
  pending,
  error,
  onRetry,
  revealedCount,
}: {
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
  pending: boolean;
  error: ApiError | null;
  onRetry: () => void;
  revealedCount: number;
}) {
  const id = useId();
  return (
    <div className="grid gap-2 rounded-md border bg-card px-3 py-2">
      <div className="flex flex-wrap items-center gap-3">
        <Switch id={id} checked={checked} onCheckedChange={onCheckedChange} />
        <Label htmlFor={id}>Show subjects</Label>
        <p className="text-xs text-muted-foreground" id={`${id}-hint`}>
          Reveals the subjects of each page you load. Each revealed page is recorded in the audit
          log (one entry per message). Subjects are shown only on this page and forgotten when you
          switch this off or leave.
        </p>
      </div>
      <p className="sr-only" aria-live="polite">
        {pending
          ? 'Revealing subjects …'
          : checked && revealedCount > 0
            ? `${revealedCount} subjects revealed.`
            : ''}
      </p>
      {error ? <ErrorState error={error} onRetry={onRetry} compact /> : null}
    </div>
  );
}

/** A refused search, next to the search (§2 E10). */
function SearchRefusal({ error }: { error: ApiError }) {
  return (
    <div
      role="alert"
      className="grid gap-1 rounded-md border border-destructive/40 bg-tone-danger px-3 py-2 text-xs text-tone-danger-foreground"
    >
      <p className="font-semibold">
        {error.code === 'message_search_timeout'
          ? 'The search took too long'
          : 'The search matches too many messages'}
      </p>
      <p>{error.messages.join(' ')}</p>
      <p className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <span>
          Code <span className="font-mono">{error.code}</span>
        </span>
        {error.requestId ? (
          <span className="inline-flex items-center gap-1">
            Request ID <span className="font-mono">{error.requestId}</span>
            <CopyButton value={error.requestId} label="Copy request ID" />
          </span>
        ) : null}
      </p>
    </div>
  );
}

/** `403 message_filter_forbidden` (not reachable through the controls; still explained). */
function FilterForbidden({ error }: { error: ApiError }) {
  const permission = typeof error.details.permission === 'string' ? error.details.permission : null;
  const filter = typeof error.details.filter === 'string' ? error.details.filter : null;
  return (
    <div className="m-3 grid gap-2">
      <ErrorState error={error} showRequirement={false} compact />
      {filter || permission ? (
        <p className="text-xs text-muted-foreground">
          {filter ? (
            <>
              The filter <span className="font-mono">{filter}</span>
            </>
          ) : (
            'A filter'
          )}{' '}
          needs the permission{' '}
          <span className="font-mono">{permission ?? 'that the api names'}</span>. Remove it or ask
          an administrator.
        </p>
      ) : null}
    </div>
  );
}
