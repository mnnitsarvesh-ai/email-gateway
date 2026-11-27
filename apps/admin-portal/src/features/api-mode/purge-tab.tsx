'use client';

import { useQueryClient } from '@tanstack/react-query';
import { PlusIcon, SearchIcon } from 'lucide-react';
import { useEffect, useId, useMemo, useState } from 'react';
import { z } from 'zod';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { DateTime } from '@/components/domain/date-time';
import { RangePicker, useRangeState } from '@/components/range-picker';
import { EmptyState } from '@/components/states/empty-state';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import { Textarea } from '@/components/ui/textarea';
import { useUrlState } from '@/hooks/use-url-state';
import { useApiMutation, useApiQuery, useCursorList } from '@/lib/api/hooks';
import type { QueryParams } from '@/lib/api/types';
import { useCan } from '@/lib/auth/me';
import { formatNumber, humanize } from '@/lib/format';
import { FilterSelect, FormDialog, MutationError } from '@/features/domains/kit';
import { ClawbackDetailView } from './clawback-detail';
import {
  APPROVAL_STATUSES,
  ApprovalBadge,
  CLAWBACK_POLL_MS,
  CLAWBACK_QUERIES,
  CLAWBACK_STATUSES,
  CLAWBACK_TRIGGERS,
  ClawbackProgress,
  ClawbackStatusBadge,
  POLLED_CLAWBACK_STATUSES,
  REASON_MAX_CHARS,
  RestoreStatusBadge,
  SEARCH_KIND_LABEL,
  TRIGGER_TEXT,
  clawbackErrorText,
  createBodyOf,
  localValue,
  validateSearch,
  type Clawback,
  type SearchDraft,
  type SearchKind,
} from './clawback-model';

const URL_SHAPE = {
  status: z.enum(CLAWBACK_STATUSES).optional().catch(undefined),
  trigger: z.enum(CLAWBACK_TRIGGERS).optional().catch(undefined),
  approvalStatus: z.enum(APPROVAL_STATUSES).optional().catch(undefined),
  /** The clawback whose detail view is open. */
  clawback: z.string().uuid().optional().catch(undefined),
};

/** The list query (`GET /api-mode/clawbacks`, v1 cursor, ≤ 93 days; C14 #2). */
export function clawbackQuery(
  filters: { status?: string; trigger?: string; approvalStatus?: string },
  range: { from: string; to: string },
): QueryParams<'ApiModeClawbackController_list_v1'> {
  return {
    from: range.from,
    to: range.to,
    ...(filters.status ? { status: filters.status } : {}),
    ...(filters.trigger ? { trigger: filters.trigger } : {}),
    ...(filters.approvalStatus ? { approvalStatus: filters.approvalStatus } : {}),
  };
}

const KINDS: readonly SearchKind[] = ['message_id', 'attachment', 'url', 'sender_subject'];
const DAY_MS = 86_400_000;

function emptyDraft(): SearchDraft {
  const now = Date.now();
  return {
    kind: 'message_id',
    messageId: '',
    attachmentSha256: '',
    url: '',
    sender: '',
    subject: '',
    from: localValue(now - 7 * DAY_MS),
    to: localValue(now + 60_000),
    directions: ['inbound', 'internal'],
    reason: '',
  };
}

/**
 * "New search" (C14 #1): one key — Message-ID, attachment SHA-256, URL, or sender + subject with
 * a window of at most 7 days — a window within the platform limit and a reason. The api normalizes
 * and hashes the input; the mailbox-worker materializes the hit list a few seconds later.
 */
export function NewSearchDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated: (clawbackId: string) => void;
}) {
  const base = useId();
  const settings = useApiQuery('ApiModeSettingsController_get_v1', undefined, { enabled: open });
  const maxWindowDays = settings.data?.platform.clawbackMaxWindowDays ?? 31;
  const [draft, setDraft] = useState<SearchDraft>(emptyDraft);
  const [hints, setHints] = useState<string[]>([]);
  const create = useApiMutation('ApiModeClawbackController_create_v1', {
    invalidates: CLAWBACK_QUERIES,
    successMessage: 'Search started: the hit list is ready for review in a few seconds.',
    onSuccess: (data) => onCreated(data.id),
  });
  const set = (patch: Partial<SearchDraft>) => setDraft((d) => ({ ...d, ...patch }));
  const close = (next: boolean) => {
    if (!next) {
      setDraft(emptyDraft());
      setHints([]);
      create.reset();
    }
    onOpenChange(next);
  };
  const errorText = clawbackErrorText(create.error);
  return (
    <FormDialog
      open={open}
      onOpenChange={close}
      wide
      title="New search"
      description="Search the recorded copies of your organization's mailboxes. Nothing changes in a mailbox until you review the hit list and submit a purge."
    >
      <form
        className="grid gap-4"
        aria-label="New search"
        onSubmit={(event) => {
          event.preventDefault();
          const problems = validateSearch(draft, { maxWindowDays });
          setHints(problems);
          if (problems.length > 0) return;
          void create.submit({ body: createBodyOf(draft) }).then((outcome) => {
            if (outcome.ok) close(false);
          });
        }}
      >
        <fieldset className="grid gap-2">
          <legend className="text-sm font-medium">Search by</legend>
          <RadioGroup
            value={draft.kind}
            onValueChange={(kind) => set({ kind: kind as SearchKind })}
            className="grid gap-2 sm:grid-cols-2"
          >
            {KINDS.map((kind) => (
              <div key={kind} className="flex items-center gap-2">
                <RadioGroupItem id={`${base}-${kind}`} value={kind} />
                <Label htmlFor={`${base}-${kind}`} className="font-normal">
                  {SEARCH_KIND_LABEL[kind]}
                </Label>
              </div>
            ))}
          </RadioGroup>
        </fieldset>
        {draft.kind === 'message_id' ? (
          <div className="grid gap-2">
            <Label htmlFor={`${base}-mid`}>Message-ID</Label>
            <Input
              id={`${base}-mid`}
              value={draft.messageId}
              maxLength={998}
              placeholder="<abc123@mail.example.com>"
              onChange={(event) => set({ messageId: event.target.value })}
            />
            <p className="text-xs text-muted-foreground">
              The Internet Message-ID header of the message, with or without angle brackets.
            </p>
          </div>
        ) : draft.kind === 'attachment' ? (
          <div className="grid gap-2">
            <Label htmlFor={`${base}-sha`}>Attachment SHA-256</Label>
            <Textarea
              id={`${base}-sha`}
              rows={3}
              value={draft.attachmentSha256}
              onChange={(event) => set({ attachmentSha256: event.target.value })}
            />
            <p className="text-xs text-muted-foreground">
              64 hexadecimal characters each; up to 20, separated by spaces or new lines.
            </p>
          </div>
        ) : draft.kind === 'url' ? (
          <div className="grid gap-2">
            <Label htmlFor={`${base}-url`}>URL</Label>
            <Input
              id={`${base}-url`}
              value={draft.url}
              maxLength={8192}
              placeholder="https://login.example.com/reset"
              onChange={(event) => set({ url: event.target.value })}
            />
            <p className="text-xs text-muted-foreground">
              Normalized like URL protection: tracking parameters and case of the host do not
              matter.
            </p>
          </div>
        ) : (
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="grid gap-2">
              <Label htmlFor={`${base}-sender`}>Sender address</Label>
              <Input
                id={`${base}-sender`}
                value={draft.sender}
                maxLength={320}
                onChange={(event) => set({ sender: event.target.value })}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor={`${base}-subject`}>Subject</Label>
              <Input
                id={`${base}-subject`}
                value={draft.subject}
                maxLength={998}
                onChange={(event) => set({ subject: event.target.value })}
              />
            </div>
            <p className="text-xs text-muted-foreground sm:col-span-2">
              Matched on the normalized subject (prefixes such as Re: and Fwd: and case ignored);
              the window spans at most 7 days.
            </p>
          </div>
        )}
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="grid gap-2">
            <Label htmlFor={`${base}-from`}>Received from (UTC)</Label>
            <Input
              id={`${base}-from`}
              type="datetime-local"
              value={draft.from}
              onChange={(event) => set({ from: event.target.value })}
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor={`${base}-to`}>Received until (UTC)</Label>
            <Input
              id={`${base}-to`}
              type="datetime-local"
              value={draft.to}
              onChange={(event) => set({ to: event.target.value })}
            />
          </div>
          <p className="text-xs text-muted-foreground sm:col-span-2">
            At most {maxWindowDays} days, within the 186 days copies are kept.
          </p>
        </div>
        <fieldset className="grid gap-2">
          <legend className="text-sm font-medium">Mail directions</legend>
          <div className="flex flex-wrap gap-4">
            {(['inbound', 'internal'] as const).map((direction) => (
              <div key={direction} className="flex items-center gap-2">
                <Checkbox
                  id={`${base}-dir-${direction}`}
                  checked={draft.directions.includes(direction)}
                  onCheckedChange={(checked) =>
                    set({
                      directions:
                        checked === true
                          ? (['inbound', 'internal'] as const).filter(
                              (d) => d === direction || draft.directions.includes(d),
                            )
                          : draft.directions.filter((d) => d !== direction),
                    })
                  }
                />
                <Label htmlFor={`${base}-dir-${direction}`} className="font-normal">
                  {direction === 'inbound' ? 'Inbound' : 'Internal (east-west)'}
                </Label>
              </div>
            ))}
          </div>
        </fieldset>
        <div className="grid gap-2">
          <Label htmlFor={`${base}-reason`}>Reason (required)</Label>
          <Textarea
            id={`${base}-reason`}
            rows={2}
            maxLength={REASON_MAX_CHARS}
            value={draft.reason}
            onChange={(event) => set({ reason: event.target.value })}
          />
          <p className="text-xs text-muted-foreground">
            Stored with the search and in the audit log.
          </p>
        </div>
        {hints.length > 0 ? (
          <ul role="alert" className="grid gap-1 text-sm font-medium text-destructive">
            {hints.map((hint) => (
              <li key={hint}>{hint}</li>
            ))}
          </ul>
        ) : null}
        {create.error ? (
          <div role="alert" className="grid gap-1">
            {errorText ? <p className="text-sm font-medium text-destructive">{errorText}</p> : null}
            <MutationError error={create.error} />
          </div>
        ) : null}
        <div className="flex flex-wrap gap-2">
          <Button type="submit" size="sm" disabled={create.isPending}>
            <SearchIcon aria-hidden />
            {create.isPending ? 'Searching …' : 'Search'}
          </Button>
          <Button type="button" size="sm" variant="ghost" onClick={() => close(false)}>
            Cancel
          </Button>
        </div>
      </form>
    </FormDialog>
  );
}

/** Reloads the clawback list while one of its rows is still moving (searching, queued, running). */
function usePollWhileActive(rows: readonly Clawback[]): void {
  const queryClient = useQueryClient();
  const active = rows.some((r) => POLLED_CLAWBACK_STATUSES.includes(r.status));
  useEffect(() => {
    if (!active) return;
    const timer = setInterval(() => {
      void queryClient.invalidateQueries({ queryKey: ['ApiModeClawbackController_list_v1'] });
    }, CLAWBACK_POLL_MS);
    return () => clearInterval(timer);
  }, [active, queryClient]);
}

/**
 * Tab "Search & purge" (C14 #1–#10): automatic and manual clawbacks with filters, progress and
 * badges; "New search"; the detail view `?clawback=` with preview, submit, approval, cancel and
 * restore.
 */
export function PurgeTab() {
  const [filters, setFilters] = useUrlState(URL_SHAPE);
  const [range] = useRangeState();
  const canCreate = useCan('ApiModeClawbackController_create_v1');
  const [creating, setCreating] = useState(false);
  const { from, to } = range;
  const { status, trigger, approvalStatus } = filters;
  const query = useMemo(
    () => clawbackQuery({ status, trigger, approvalStatus }, { from, to }),
    [status, trigger, approvalStatus, from, to],
  );
  const list = useCursorList('ApiModeClawbackController_list_v1', query, {
    enabled: !filters.clawback,
  });
  usePollWhileActive(list.rows);

  const columns = useMemo<DataTableColumn<Clawback>[]>(
    () => [
      {
        id: 'createdAt',
        header: 'Created',
        meta: { label: 'Created', className: 'whitespace-nowrap' },
        cell: ({ row }) => (
          <Button
            variant="link"
            size="sm"
            className="h-auto p-0"
            onClick={() => setFilters({ clawback: row.original.id })}
          >
            <DateTime value={row.original.createdAt} />
            <span className="sr-only">, open the clawback</span>
          </Button>
        ),
      },
      {
        id: 'trigger',
        header: 'Trigger',
        meta: { label: 'Trigger' },
        cell: ({ row }) => TRIGGER_TEXT[row.original.trigger] ?? humanize(row.original.trigger),
      },
      {
        id: 'status',
        header: 'Status',
        meta: { label: 'Status' },
        cell: ({ row }) => (
          <span className="grid justify-items-start gap-0.5">
            <ClawbackStatusBadge status={row.original.status} />
            {row.original.cancelRequested && row.original.status !== 'cancelled' ? (
              <span className="text-xs text-muted-foreground">Cancel requested</span>
            ) : null}
            {row.original.lastErrorCode ? (
              <span className="font-mono text-xs text-muted-foreground">
                {row.original.lastErrorCode}
              </span>
            ) : null}
          </span>
        ),
      },
      {
        id: 'approval',
        header: 'Approval',
        meta: { label: 'Approval' },
        cell: ({ row }) => <ApprovalBadge status={row.original.approval.status} />,
      },
      {
        id: 'mailboxes',
        header: 'Eligible',
        meta: { label: 'Eligible mailboxes and messages' },
        cell: ({ row }) =>
          row.original.status === 'searching' ? (
            <span className="text-xs text-muted-foreground">Searching …</span>
          ) : (
            <span className="grid text-xs tabular-nums">
              <span>{formatNumber(row.original.counts.mailboxesEligible)} mailboxes</span>
              <span className="text-muted-foreground">
                {formatNumber(row.original.counts.targetsEligible)} of{' '}
                {formatNumber(row.original.counts.targetsTotal)} messages
              </span>
            </span>
          ),
      },
      {
        id: 'progress',
        header: 'Progress',
        meta: { label: 'Progress' },
        cell: ({ row }) => (
          <ClawbackProgress
            counts={row.original.counts}
            label={`Progress of the clawback created ${row.original.createdAt}`}
          />
        ),
      },
      {
        id: 'restore',
        header: 'Restore',
        meta: { label: 'Restore' },
        cell: ({ row }) => <RestoreStatusBadge status={row.original.restore.status} />,
      },
    ],
    [setFilters],
  );

  if (filters.clawback) {
    return (
      <ClawbackDetailView
        clawbackId={filters.clawback}
        onBack={() => setFilters({ clawback: undefined })}
        onOpen={(id) => setFilters({ clawback: id })}
      />
    );
  }

  const isFiltered = Boolean(status || trigger || approvalStatus);
  return (
    <div className="grid gap-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <p className="max-w-3xl text-sm text-muted-foreground">
          Late verdicts, threat intelligence, user reports and administrator searches find every
          copy of a message across mailboxes. Automatic clawbacks follow the remediation policy;
          searches wait for your review. Purges above the approval threshold need a second person.
        </p>
        {canCreate ? (
          <Button size="sm" onClick={() => setCreating(true)}>
            <PlusIcon aria-hidden />
            New search
          </Button>
        ) : null}
      </div>
      <DataTable
        tableId="api-mode-clawbacks"
        caption="Clawbacks and purges"
        columns={columns}
        list={list}
        getRowId={(row) => row.id}
        getRowLabel={(row) => `${TRIGGER_TEXT[row.trigger]} ${row.createdAt}`}
        filters={
          <>
            <RangePicker />
            <FilterSelect
              label="Status"
              value={status}
              onChange={(value) =>
                setFilters({ status: value as (typeof CLAWBACK_STATUSES)[number] | undefined })
              }
              options={CLAWBACK_STATUSES.map((value) => ({ value, label: humanize(value) }))}
            />
            <FilterSelect
              label="Trigger"
              value={trigger}
              onChange={(value) =>
                setFilters({ trigger: value as (typeof CLAWBACK_TRIGGERS)[number] | undefined })
              }
              options={CLAWBACK_TRIGGERS.map((value) => ({ value, label: TRIGGER_TEXT[value] }))}
            />
            <FilterSelect
              label="Approval"
              value={approvalStatus}
              onChange={(value) =>
                setFilters({
                  approvalStatus: value as (typeof APPROVAL_STATUSES)[number] | undefined,
                })
              }
              options={APPROVAL_STATUSES.map((value) => ({ value, label: humanize(value) }))}
            />
          </>
        }
        isFiltered={isFiltered}
        onClearFilters={() =>
          setFilters({ status: undefined, trigger: undefined, approvalStatus: undefined })
        }
        rowActions={(row) => [{ label: 'Open', onSelect: () => setFilters({ clawback: row.id }) }]}
        emptyState={
          <EmptyState
            icon={SearchIcon}
            title="No clawbacks in this range"
            description="Automatic clawbacks of late verdicts and threat intelligence, report clawbacks and your searches appear here."
          />
        }
        mobileCard={(row) => (
          <div className="grid gap-1">
            <span className="font-medium">{TRIGGER_TEXT[row.trigger]}</span>
            <div className="flex flex-wrap items-center gap-2">
              <ClawbackStatusBadge status={row.status} />
              <DateTime value={row.createdAt} />
            </div>
            <ClawbackProgress counts={row.counts} label={`Progress of ${row.createdAt}`} />
          </div>
        )}
      />
      <NewSearchDialog
        open={creating}
        onOpenChange={setCreating}
        onCreated={(id) => setFilters({ clawback: id })}
      />
    </div>
  );
}
