'use client';

import { InboxIcon, SendIcon, UserCheckIcon } from 'lucide-react';
import Link from 'next/link';
import { useEffect, useId, useMemo, useState } from 'react';
import { z } from 'zod';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { DateTime, QuarantineStateBadge, UntrustedText } from '@/components/domain';
import { FormErrorSummary } from '@/components/form';
import { PageHeader } from '@/components/page-header';
import { EmptyState } from '@/components/states/empty-state';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { useUrlState } from '@/hooks/use-url-state';
import { useApiMutation, useApiQuery, useCursorList } from '@/lib/api/hooks';
import type { ListItem, QueryParams } from '@/lib/api/types';
import { RouteGate } from '@/lib/auth/route-gate';
import { humanize } from '@/lib/format';
import { RANGE_PRESETS, resolvePreset } from '@/lib/range';
import { FilterSelect, RangeSelect, Section, optionsOf } from '@/features/messages/controls';
import { ENTRY_REASONS, ENTRY_STATES } from './entries-tab';
import { EntryMetadata, EntryStateNotices, ReleaseOutcomeNotice } from './entry-parts';
import { preferencesBody, requestReleaseBody, selfReleaseBody } from './forms';
import { selfEntryHref } from './links';
import { PreviewSection } from './preview-panel';
import { ReasonConfirm, explainQuarantineError } from './reason-confirm';
import type { EntryAction, ReleaseOutcome, SelfEntryDetailBody } from './types';
import { useQuarantineCatalog } from './use-catalog';

type SelfEntry = ListItem<'QuarantineSelfController_search_v1'>;

export const SELF_URL_SHAPE = {
  range: z.enum(RANGE_PRESETS).default('30d').catch('30d'),
  state: z.enum(ENTRY_STATES).optional().catch(undefined),
  reason: z.enum(ENTRY_REASONS).optional().catch(undefined),
};
type SelfState = { [K in keyof typeof SELF_URL_SHAPE]: z.output<(typeof SELF_URL_SHAPE)[K]> };

export function selfQuery(
  state: SelfState,
  now = Date.now(),
): QueryParams<'QuarantineSelfController_search_v1'> {
  const window = resolvePreset(state.range, now);
  return {
    from: window.from,
    to: window.to,
    ...(state.state ? { state: state.state } : {}),
    ...(state.reason ? { reason: state.reason } : {}),
  };
}

const COLUMNS: DataTableColumn<SelfEntry>[] = [
  {
    id: 'receivedAt',
    header: 'Received',
    meta: { label: 'Received', className: 'whitespace-nowrap' },
    cell: ({ row }) => (
      <Link
        href={selfEntryHref(row.original.id)}
        className="font-medium text-primary hover:underline"
      >
        <DateTime value={row.original.receivedAt} />
        <span className="sr-only">, open message</span>
      </Link>
    ),
  },
  {
    id: 'subject',
    header: 'Subject',
    meta: { label: 'Subject', className: 'max-w-80' },
    cell: ({ row }) => (
      <UntrustedText value={row.original.subject} maxLength={80} emptyLabel="(no subject)" />
    ),
  },
  {
    id: 'sender',
    header: 'From',
    meta: { label: 'From', className: 'max-w-64' },
    cell: ({ row }) => (
      <UntrustedText
        value={row.original.sender.headerFrom ?? row.original.sender.envelope}
        maxLength={60}
        emptyLabel="(null sender)"
      />
    ),
  },
  {
    id: 'reason',
    header: 'Reason',
    meta: { label: 'Reason' },
    cell: ({ row }) => humanize(row.original.reason),
  },
  {
    id: 'state',
    header: 'State',
    meta: { label: 'State' },
    cell: ({ row }) => <QuarantineStateBadge state={row.original.state} />,
  },
  {
    id: 'expires',
    header: 'Expires',
    meta: { label: 'Expires', className: 'whitespace-nowrap' },
    cell: ({ row }) => <DateTime value={row.original.expiresAt} />,
  },
];

/** "My quarantine" (`/quarantine/me`, `quarantine:self`; linked from digests). */
export function SelfTab() {
  const [state, setState] = useUrlState(SELF_URL_SHAPE);
  const catalog = useQuarantineCatalog();
  const query = useMemo(() => selfQuery(state), [state]);
  const list = useCursorList('QuarantineSelfController_search_v1', query, { limit: 25 });
  const selfService = catalog.data?.selfService;
  return (
    <div className="grid gap-4">
      {selfService && !selfService.enabled ? (
        <p className="rounded-md border bg-muted/40 px-3 py-2 text-sm">
          Your organization has turned off self-service quarantine access, so this list stays empty.
        </p>
      ) : null}
      <DataTable
        tableId="quarantine-self"
        caption="My quarantined messages"
        columns={COLUMNS}
        list={list}
        getRowId={(row) => row.id}
        getRowLabel={(row) => `message received ${row.receivedAt}`}
        isFiltered={Boolean(state.state || state.reason)}
        onClearFilters={() => setState({ state: undefined, reason: undefined })}
        filters={
          <div className="flex flex-wrap items-end gap-2">
            <RangeSelect
              value={state.range}
              onChange={(range) => setState({ range })}
              maxDays={catalog.data?.limits.searchMaxRangeDays}
            />
            <FilterSelect
              label="State"
              value={state.state}
              options={optionsOf(ENTRY_STATES)}
              onChange={(v) => setState({ state: v as SelfState['state'] })}
            />
            <FilterSelect
              label="Reason"
              value={state.reason}
              options={optionsOf(ENTRY_REASONS)}
              onChange={(v) => setState({ reason: v as SelfState['reason'] })}
            />
          </div>
        }
        emptyState={
          <EmptyState
            icon={InboxIcon}
            title="No quarantined messages for you"
            description="Messages addressed to you that were held appear here."
          />
        }
        mobileCard={(row) => (
          <div className="grid gap-1 text-sm">
            <Link href={selfEntryHref(row.id)} className="font-medium text-primary hover:underline">
              <UntrustedText value={row.subject} maxLength={60} emptyLabel="(no subject)" />
            </Link>
            <div className="flex flex-wrap items-center gap-2">
              <QuarantineStateBadge state={row.state} />
              <span className="text-xs">{humanize(row.reason)}</span>
            </div>
          </div>
        )}
      />
      <PreferencesCard />
    </div>
  );
}

/** Digest preference (`GET/PUT /quarantine/me/preferences`). */
export function PreferencesCard() {
  const preferences = useApiQuery('QuarantineSelfController_preferences_v1');
  const save = useApiMutation('QuarantineSelfController_putPreferences_v1', {
    invalidates: ['QuarantineSelfController_preferences_v1'],
    successMessage: 'Preference saved.',
  });
  const [optOut, setOptOut] = useState(false);
  const id = useId();
  useEffect(() => {
    if (preferences.data) setOptOut(preferences.data.digestOptOut);
  }, [preferences.data]);
  return (
    <Section
      title="Quarantine digest"
      description="The periodic e-mail that lists your held messages."
    >
      {preferences.isLoading ? (
        <LoadingState label="Loading your preferences" rows={2} />
      ) : preferences.error ? (
        <ErrorState error={preferences.error} onRetry={() => void preferences.refetch()} compact />
      ) : preferences.data ? (
        <form
          className="grid gap-3"
          aria-label="Digest preference"
          onSubmit={(event) => {
            event.preventDefault();
            void save.submit({ body: preferencesBody(optOut) });
          }}
        >
          {save.error ? (
            <FormErrorSummary messages={save.error.messages} requestId={save.error.requestId} />
          ) : null}
          <div className="flex items-center gap-3">
            <Switch
              id={id}
              checked={optOut}
              disabled={!preferences.data.allowOptOut && !preferences.data.digestOptOut}
              onCheckedChange={setOptOut}
            />
            <Label htmlFor={id}>Do not send me the quarantine digest</Label>
          </div>
          {!preferences.data.allowOptOut ? (
            <p className="text-xs text-muted-foreground">
              Your organization does not allow opting out of the digest.
            </p>
          ) : null}
          <Button
            type="submit"
            size="sm"
            className="justify-self-start"
            disabled={save.isPending || optOut === preferences.data.digestOptOut}
          >
            {save.isPending ? 'Saving …' : 'Save preference'}
          </Button>
        </form>
      ) : null}
    </Section>
  );
}

/** One of my quarantined messages (`/quarantine/me/[entryId]`, linked from digests). */
export function SelfEntryDetail({ entryId }: { entryId: string }) {
  return (
    <RouteGate gate={['QuarantineSelfController_detail_v1']}>
      <SelfEntryDetailContent entryId={entryId} />
    </RouteGate>
  );
}

function SelfEntryDetailContent({ entryId }: { entryId: string }) {
  const detail = useApiQuery(
    'QuarantineSelfController_detail_v1',
    { path: { entryId } },
    { refetchOnWindowFocus: false },
  );
  const breadcrumbs = [{ label: 'My quarantine', href: '/quarantine/me' }, { label: 'Message' }];
  if (detail.isLoading) {
    return (
      <div className="grid gap-4">
        <PageHeader title="Quarantined message" breadcrumbs={breadcrumbs} />
        <LoadingState label="Loading the message" rows={6} />
      </div>
    );
  }
  if (detail.error || !detail.data) {
    return (
      <div className="grid gap-4">
        <PageHeader title="Quarantined message" breadcrumbs={breadcrumbs} />
        <ErrorState error={detail.error} onRetry={() => void detail.refetch()} />
      </div>
    );
  }
  return <SelfEntryView entry={detail.data} breadcrumbs={breadcrumbs} />;
}

const SELF_INVALIDATES = [
  'QuarantineSelfController_detail_v1',
  'QuarantineSelfController_search_v1',
] as const;

function SelfEntryView({
  entry,
  breadcrumbs,
}: {
  entry: SelfEntryDetailBody;
  breadcrumbs: { label: string; href?: string }[];
}) {
  const allowed = new Set<EntryAction>(entry.allowedActions);
  const catalog = useQuarantineCatalog();
  const [dialog, setDialog] = useState<'release' | 'request_release' | null>(null);
  const [outcome, setOutcome] = useState<ReleaseOutcome | null>(null);
  const path = { entryId: entry.id };
  const release = useApiMutation('QuarantineSelfController_release_v1', {
    invalidates: SELF_INVALIDATES,
    successMessage: null,
    onSuccess: (data) => setOutcome(data),
  });
  const request = useApiMutation('QuarantineSelfController_requestRelease_v1', {
    invalidates: SELF_INVALIDATES,
    successMessage: null,
    onSuccess: (data) => setOutcome(data),
  });
  const maxChars = catalog.data?.limits.reasonMaxChars;
  return (
    <div className="grid gap-4">
      <PageHeader
        title="Quarantined message"
        breadcrumbs={breadcrumbs}
        description="A message addressed to you that was held. Release it only when you trust it."
        actions={
          <>
            {allowed.has('release') ? (
              <Button size="sm" onClick={() => setDialog('release')}>
                <SendIcon aria-hidden />
                Release to my inbox
              </Button>
            ) : null}
            {allowed.has('request_release') ? (
              <Button size="sm" variant="outline" onClick={() => setDialog('request_release')}>
                <UserCheckIcon aria-hidden />
                Request release
              </Button>
            ) : null}
          </>
        }
      />
      <div role="status" aria-live="polite">
        {outcome ? <ReleaseOutcomeNotice outcome={outcome} self /> : null}
      </div>
      <EntryStateNotices entry={entry} self />
      <EntryMetadata entry={entry} self />
      {allowed.has('preview') ? <PreviewSection entryId={entry.id} self /> : null}
      <ReasonConfirm
        open={dialog === 'release'}
        onOpenChange={(open) => !open && setDialog(null)}
        title="Release this message to your inbox?"
        description={
          <p>
            The platform checks the message again before delivering it. Only release mail you
            expected.
          </p>
        }
        confirmLabel="Release"
        reasonLabel="Why do you trust this message?"
        maxChars={maxChars}
        pending={release.isPending}
        onSubmit={(reason) =>
          release.submit({ path, body: selfReleaseBody(reason, entry.rowVersion) })
        }
        onRetry={() => release.retry()}
      />
      <ReasonConfirm
        open={dialog === 'request_release'}
        onOpenChange={(open) => !open && setDialog(null)}
        title="Ask an administrator to release this message?"
        description={<p>An administrator decides; you receive an e-mail with the decision.</p>}
        confirmLabel="Request release"
        reasonLabel="Why do you need this message?"
        maxChars={maxChars}
        pending={request.isPending}
        onSubmit={(reason) => request.submit({ path, body: requestReleaseBody(reason) })}
        onRetry={() => request.retry()}
      />
      {release.error && !dialog ? (
        <p className="text-sm">{explainQuarantineError(release.error).join(' ')}</p>
      ) : null}
    </div>
  );
}
