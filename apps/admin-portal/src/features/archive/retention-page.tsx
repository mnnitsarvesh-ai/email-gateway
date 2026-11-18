'use client';

import { PencilIcon, PlusIcon, RefreshCwIcon } from 'lucide-react';
import Link from 'next/link';
import { useMemo, useState, type ReactNode } from 'react';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { CopyableId, DateTime, UntrustedText } from '@/components/domain';
import { PageHeader } from '@/components/page-header';
import { EmptyState } from '@/components/states/empty-state';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import { ApiError } from '@/lib/api/errors';
import { useApiMutation, useApiQuery, useCursorList } from '@/lib/api/hooks';
import type { RequestBody } from '@/lib/api/types';
import { RouteGate } from '@/lib/auth/route-gate';
import { formatBytes, humanize } from '@/lib/format';
import { FormDialog } from '@/features/domains/kit';
import { EnumBadge, FilterMultiSelect, optionsOf } from '@/features/messages/controls';
import { GatedTabs, type TabDefinition } from '@/features/reports/gated-tabs';
import {
  ArchiveErrorSummary,
  ArchiveRecipients,
  ConflictDialog,
  Notice,
  ReasonDialog,
  SearchUnavailable,
} from './components';
import { useArchiveSearch } from './hooks';
import {
  ARCHIVE_CATEGORIES,
  ARCHIVE_DIRECTIONS,
  ARCHIVE_SOURCES,
  CAPTURE_ISSUE_STATUSES,
  CAPTURE_STATUS_TONE,
  DISPOSAL_REASONS,
  DISPOSAL_STATES,
  DISPOSAL_STATE_TONE,
  archiveMessageHref,
  archiveSettingsHref,
  conflictVersion,
  explainArchiveError,
  useArchiveAccess,
  type CaptureIssue,
  type Disposal,
  type RetentionPolicy,
} from './model';
import { archiveSearchQuery, DEFAULT_ARCHIVE_STATE } from './search-state';

export const RETENTION_TABS: readonly TabDefinition[] = [
  { id: 'policies', label: 'Retention policies', ops: ['ArchiveRetentionController_list_v1'] },
  { id: 'review', label: 'Review queue', ops: ['ArchiveMessagesController_list_v1'] },
  { id: 'disposals', label: 'Disposal log', ops: ['ArchiveAdminController_disposals_v1'] },
  { id: 'capture', label: 'Capture issues', ops: ['ArchiveAdminController_captureIssues_v1'] },
];

/** Retention and review (`/archive/retention`, step 8.1 A11, A13, A14, A28). */
export function RetentionPage() {
  return (
    <RouteGate gate={['ArchiveRetentionController_list_v1']}>
      <div className="grid min-w-0 gap-4">
        <PageHeader
          title="Retention and review"
          breadcrumbs={[{ label: 'Archive', href: '/archive' }, { label: 'Retention and review' }]}
          description="How long archived mail is kept, records waiting for a disposal decision, the disposal log and messages the archive could not capture."
        />
        <GatedTabs
          tabs={RETENTION_TABS}
          label="Retention and review"
          keepParams={[]}
          render={(tab) => {
            switch (tab) {
              case 'review':
                return <ReviewQueue />;
              case 'disposals':
                return <DisposalLog />;
              case 'capture':
                return <CaptureIssues />;
              default:
                return <PoliciesTab />;
            }
          }}
        />
      </div>
    </RouteGate>
  );
}

// ---- policies ------------------------------------------------------------------------------

export interface PolicyDraft {
  name: string;
  retentionDays: string;
  onExpiry: 'delete' | 'review';
  priority: string;
  directions: string[];
  categories: string[];
  sources: string[];
}

export function policyDraftOf(policy?: RetentionPolicy): PolicyDraft {
  const criteria = (policy?.criteria ?? {}) as Record<string, unknown>;
  const list = (key: string) =>
    Array.isArray(criteria[key])
      ? (criteria[key] as unknown[]).filter((v): v is string => typeof v === 'string')
      : [];
  return {
    name: policy?.name ?? '',
    retentionDays: policy ? String(policy.retentionDays) : '2555',
    onExpiry: policy?.onExpiry ?? 'delete',
    priority: policy ? String(policy.priority) : '100',
    directions: list('directions'),
    categories: list('categories'),
    sources: list('sources'),
  };
}

/** Validation of a policy draft (`field → message`). */
export function policyDraftErrors(draft: PolicyDraft): Record<string, string> {
  const errors: Record<string, string> = {};
  const name = draft.name.trim();
  if (!name) errors.name = 'Enter a name';
  else if (name.length > 128) errors.name = 'Use at most 128 characters';
  const days = Number(draft.retentionDays);
  if (!Number.isInteger(days) || days < 1 || days > 36_500) {
    errors.retentionDays = 'Enter whole days between 1 and 36 500 (your plan may allow fewer)';
  }
  const priority = Number(draft.priority);
  if (!Number.isInteger(priority) || priority < 0 || priority > 10_000) {
    errors.priority = 'Enter a priority between 0 and 10 000';
  }
  return errors;
}

type PolicyBody = RequestBody<'ArchiveRetentionController_create_v1'>;

export function policyBody(draft: PolicyDraft): PolicyBody {
  const criteria: NonNullable<PolicyBody['criteria']> = {};
  if (draft.directions.length > 0) criteria.directions = draft.directions as never;
  if (draft.categories.length > 0) criteria.categories = draft.categories as never;
  if (draft.sources.length > 0) criteria.sources = draft.sources as never;
  return {
    name: draft.name.trim(),
    retentionDays: Number(draft.retentionDays),
    onExpiry: draft.onExpiry,
    priority: Number(draft.priority),
    criteria,
  };
}

function criteriaSummary(policy: RetentionPolicy): string {
  const c = policy.criteria as Record<string, unknown>;
  const parts: string[] = [];
  for (const key of ['directions', 'categories', 'sources'] as const) {
    if (Array.isArray(c[key]) && (c[key] as unknown[]).length > 0) {
      parts.push(`${humanize(key)}: ${(c[key] as string[]).map(humanize).join(', ')}`);
    }
  }
  for (const key of ['policyRuleRefs', 'domainIds', 'departmentIds'] as const) {
    if (Array.isArray(c[key]) && (c[key] as unknown[]).length > 0) {
      parts.push(`${(c[key] as unknown[]).length} ${humanize(key).toLowerCase()}`);
    }
  }
  return parts.length > 0 ? parts.join(' · ') : 'Every record';
}

function PoliciesTab() {
  const access = useArchiveAccess();
  const list = useCursorList(
    'ArchiveRetentionController_list_v1',
    { sort: 'priority' },
    { limit: 50 },
  );
  const settings = useApiQuery('ArchiveAdminController_get_v1');
  const [editing, setEditing] = useState<RetentionPolicy | 'new' | null>(null);
  const [deleting, setDeleting] = useState<RetentionPolicy | null>(null);
  const remove = useApiMutation('ArchiveRetentionController_delete_v1', {
    successMessage: 'Retention policy deleted',
    invalidates: ['ArchiveRetentionController_list_v1'],
  });
  const defaultId = settings.data?.defaultRetentionPolicyId ?? null;
  const columns: DataTableColumn<RetentionPolicy>[] = [
    {
      id: 'name',
      header: 'Name',
      meta: { label: 'Name', hideable: false },
      cell: ({ row }) => (
        <span className="flex flex-wrap items-center gap-2">
          <UntrustedText value={row.original.name} maxLength={80} />
          {row.original.id === defaultId ? (
            <EnumBadge value="default" tones={{ default: 'info' }} />
          ) : null}
        </span>
      ),
    },
    {
      id: 'retentionDays',
      header: 'Keep for',
      meta: { label: 'Keep for' },
      cell: ({ row }) => `${row.original.retentionDays} days`,
    },
    {
      id: 'onExpiry',
      header: 'At expiry',
      meta: { label: 'At expiry' },
      cell: ({ row }) => humanize(row.original.onExpiry),
    },
    {
      id: 'priority',
      header: 'Priority',
      meta: { label: 'Priority' },
      cell: ({ row }) => row.original.priority,
    },
    {
      id: 'criteria',
      header: 'Applies to',
      meta: { label: 'Applies to', className: 'min-w-48' },
      cell: ({ row }) => <span className="text-xs">{criteriaSummary(row.original)}</span>,
    },
    {
      id: 'updatedAt',
      header: 'Updated',
      meta: { label: 'Updated' },
      cell: ({ row }) => <DateTime value={row.original.updatedAt} />,
    },
  ];
  return (
    <div className="grid gap-3">
      <Notice>
        <span>
          The first matching policy by priority (lowest first) sets a record’s retention when it is
          captured; records no policy matches use the default policy of the{' '}
          <Link href={archiveSettingsHref} className="underline underline-offset-2">
            archive settings
          </Link>
          . Retention never shrinks for records already captured: a longer policy protects them, a
          shorter one applies to new captures only. Your plan limits the longest retention
          (archive_retention_days).
        </span>
      </Notice>
      <DataTable
        tableId="archive-retention-policies"
        caption="Retention policies"
        columns={columns}
        list={list}
        getRowId={(row) => row.id}
        getRowLabel={(row) => row.name}
        filters={
          access.manage ? (
            <Button size="sm" onClick={() => setEditing('new')}>
              <PlusIcon aria-hidden />
              New retention policy
            </Button>
          ) : null
        }
        rowActions={
          access.manage
            ? (row) => [
                { label: 'Edit', onSelect: () => setEditing(row) },
                {
                  label: 'Delete',
                  destructive: true,
                  disabled: row.id === defaultId,
                  onSelect: () => setDeleting(row),
                },
              ]
            : undefined
        }
        emptyState={
          <EmptyState
            title="No retention policy yet"
            description="Archiving needs a default retention policy. Create one, then choose it in the archive settings."
          />
        }
      />
      {editing ? (
        <PolicyDialog
          policy={editing === 'new' ? undefined : editing}
          onClose={() => setEditing(null)}
        />
      ) : null}
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => {
          if (!open) {
            setDeleting(null);
            remove.reset();
          }
        }}
        title="Delete this retention policy?"
        description={
          <p>
            New captures no longer use it. Records already captured keep their stored retention date
            (it never shrinks).
          </p>
        }
        confirmLabel="Delete"
        destructive
        pending={remove.isPending}
        error={<ArchiveErrorSummary error={remove.error} />}
        onConfirm={async () => {
          if (!deleting) return false;
          const outcome = await remove.submit({ path: { policyId: deleting.id } });
          return outcome.ok;
        }}
      />
    </div>
  );
}

function PolicyDialog({ policy, onClose }: { policy?: RetentionPolicy; onClose: () => void }) {
  const [draft, setDraft] = useState<PolicyDraft>(() => policyDraftOf(policy));
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [rowVersion, setRowVersion] = useState(policy?.rowVersion ?? 0);
  const [conflict, setConflict] = useState<number | null>(null);
  const create = useApiMutation('ArchiveRetentionController_create_v1', {
    successMessage: 'Retention policy created',
    invalidates: ['ArchiveRetentionController_list_v1'],
  });
  const update = useApiMutation('ArchiveRetentionController_update_v1', {
    successMessage: 'Retention policy saved',
    invalidates: ['ArchiveRetentionController_list_v1', 'ArchiveRetentionController_get_v1'],
  });
  const mutation = policy ? update : create;
  const set = (patch: Partial<PolicyDraft>) => setDraft((d) => ({ ...d, ...patch }));
  const save = async (version: number) => {
    const body = policyBody(draft);
    const outcome = policy
      ? await update.submit({
          path: { policyId: policy.id },
          body: { ...body, expectedRowVersion: version },
        })
      : await create.submit({ body });
    if (outcome.ok) {
      onClose();
      return;
    }
    const current = conflictVersion(outcome.error);
    if (outcome.error.code === 'archive_retention_policy_conflict' && current !== null) {
      setConflict(current);
      return;
    }
    if (outcome.error.code === 'archive_retention_exceeds_limit') {
      setErrors({ retentionDays: explainArchiveError(outcome.error).join(' ') });
    } else if (outcome.error.code === 'archive_retention_policy_name_taken') {
      setErrors({ name: explainArchiveError(outcome.error).join(' ') });
    }
  };
  const submit = async () => {
    const found = policyDraftErrors(draft);
    setErrors(found);
    if (Object.keys(found).length === 0) await save(rowVersion);
  };
  const shownError =
    mutation.error &&
    ![
      'archive_retention_exceeds_limit',
      'archive_retention_policy_name_taken',
      'archive_retention_policy_conflict',
    ].includes(mutation.error.code)
      ? mutation.error
      : null;
  return (
    <FormDialog
      open
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
      title={policy ? 'Edit retention policy' : 'New retention policy'}
      wide
    >
      <form
        className="grid gap-4"
        noValidate
        aria-label={policy ? 'Edit retention policy' : 'New retention policy'}
        onSubmit={(event) => {
          event.preventDefault();
          void submit();
        }}
      >
        <ArchiveErrorSummary error={shownError} />
        <Field id="policy-name" label="Name (required)" error={errors.name}>
          <Input
            id="policy-name"
            value={draft.name}
            maxLength={128}
            onChange={(e) => set({ name: e.target.value })}
            aria-invalid={errors.name ? true : undefined}
          />
        </Field>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field
            id="policy-days"
            label="Keep for (days, required)"
            error={errors.retentionDays}
            help="At most your plan’s archive retention and the platform maximum."
          >
            <Input
              id="policy-days"
              inputMode="numeric"
              value={draft.retentionDays}
              onChange={(e) => set({ retentionDays: e.target.value })}
              aria-invalid={errors.retentionDays ? true : undefined}
            />
          </Field>
          <Field
            id="policy-priority"
            label="Priority"
            error={errors.priority}
            help="Lowest number wins."
          >
            <Input
              id="policy-priority"
              inputMode="numeric"
              value={draft.priority}
              onChange={(e) => set({ priority: e.target.value })}
              aria-invalid={errors.priority ? true : undefined}
            />
          </Field>
        </div>
        <fieldset className="grid gap-2">
          <legend className="text-sm font-medium">At the end of the retention</legend>
          <RadioGroup
            value={draft.onExpiry}
            onValueChange={(value) => set({ onExpiry: value as PolicyDraft['onExpiry'] })}
            className="grid gap-2"
            aria-label="At the end of the retention"
          >
            <div className="flex items-center gap-2">
              <RadioGroupItem value="delete" id="policy-expiry-delete" />
              <Label htmlFor="policy-expiry-delete" className="font-normal">
                Dispose automatically (unless a legal hold covers the record)
              </Label>
            </div>
            <div className="flex items-center gap-2">
              <RadioGroupItem value="review" id="policy-expiry-review" />
              <Label htmlFor="policy-expiry-review" className="font-normal">
                Keep for review: an administrator decides in the review queue
              </Label>
            </div>
          </RadioGroup>
        </fieldset>
        <div className="grid gap-3 sm:grid-cols-3">
          <CriteriaChecks
            legend="Directions"
            values={ARCHIVE_DIRECTIONS}
            selected={draft.directions}
            onChange={(directions) => set({ directions })}
          />
          <CriteriaChecks
            legend="Categories"
            values={ARCHIVE_CATEGORIES}
            selected={draft.categories}
            onChange={(categories) => set({ categories })}
          />
          <CriteriaChecks
            legend="Captured by"
            values={ARCHIVE_SOURCES}
            selected={draft.sources}
            onChange={(sources) => set({ sources })}
          />
        </div>
        <p className="text-xs text-muted-foreground">
          Nothing chosen in a group means every value of that group matches.
        </p>
        <div className="flex justify-end gap-2">
          <Button type="button" variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" disabled={mutation.isPending || mutation.retryAfterSeconds > 0}>
            {policy ? <PencilIcon aria-hidden /> : <PlusIcon aria-hidden />}
            {mutation.isPending ? 'Saving …' : policy ? 'Save policy' : 'Create policy'}
          </Button>
        </div>
      </form>
      <ConflictDialog
        open={conflict !== null}
        onOpenChange={(open) => {
          if (!open) setConflict(null);
        }}
        what="retention policy"
        onReload={() => {
          setConflict(null);
          onClose();
        }}
        onOverwrite={async () => {
          if (conflict === null) return;
          const version = conflict;
          setConflict(null);
          setRowVersion(version);
          await save(version);
        }}
      />
    </FormDialog>
  );
}

function Field({
  id,
  label,
  error,
  help,
  children,
}: {
  id: string;
  label: string;
  error?: string;
  help?: string;
  children: ReactNode;
}) {
  return (
    <div className="grid gap-1">
      <Label htmlFor={id}>{label}</Label>
      {children}
      {help ? <p className="text-xs text-muted-foreground">{help}</p> : null}
      {error ? <p className="text-xs font-medium text-destructive">{error}</p> : null}
    </div>
  );
}

function CriteriaChecks({
  legend,
  values,
  selected,
  onChange,
}: {
  legend: string;
  values: readonly string[];
  selected: readonly string[];
  onChange: (values: string[]) => void;
}) {
  return (
    <fieldset className="grid gap-1">
      <legend className="text-sm font-medium">{legend}</legend>
      {values.map((value) => {
        const id = `policy-${legend}-${value}`.replace(/\s+/g, '-').toLowerCase();
        return (
          <div key={value} className="flex min-h-7 items-center gap-2">
            <Checkbox
              id={id}
              checked={selected.includes(value)}
              onCheckedChange={(next) =>
                onChange(next === true ? [...selected, value] : selected.filter((v) => v !== value))
              }
            />
            <Label htmlFor={id} className="font-normal">
              {humanize(value)}
            </Label>
          </div>
        );
      })}
    </fieldset>
  );
}

// ---- review queue --------------------------------------------------------------------------

function ReviewQueue() {
  const access = useArchiveAccess();
  const query = useMemo(
    () =>
      archiveSearchQuery(
        { ...DEFAULT_ARCHIVE_STATE, range: '365d', status: ['expiry_review'] },
        Date.now(),
      ),
    [],
  );
  const list = useArchiveSearch(query, { limit: 25 });
  const [disposing, setDisposing] = useState<string | null>(null);
  const dispose = useApiMutation('ArchiveMessagesController_dispose_v1', {
    successMessage: 'Disposal requested',
    invalidates: ['ArchiveMessagesController_list_v1'],
  });
  type Row = (typeof list.rows)[number];
  const columns: DataTableColumn<Row>[] = [
    {
      id: 'receivedAt',
      header: 'Received',
      meta: { label: 'Received', hideable: false },
      cell: ({ row }) => (
        <Link
          href={archiveMessageHref(row.original.messageId)}
          className="text-primary underline-offset-2 hover:underline"
        >
          <DateTime value={row.original.receivedAt} />
          <span className="sr-only">, open archived message</span>
        </Link>
      ),
    },
    {
      id: 'from',
      header: 'From',
      meta: { label: 'From' },
      cell: ({ row }) => <UntrustedText value={row.original.envelopeFrom} maxLength={60} />,
    },
    {
      id: 'recipients',
      header: 'Recipients',
      meta: { label: 'Recipients' },
      cell: ({ row }) => <ArchiveRecipients row={row.original} />,
    },
    {
      id: 'retainUntil',
      header: 'Retention ended',
      meta: { label: 'Retention ended' },
      cell: ({ row }) => <DateTime value={row.original.retainUntil} />,
    },
    {
      id: 'legalHold',
      header: 'Held',
      meta: { label: 'Held past expiry' },
      cell: ({ row }) => (row.original.legalHold ? 'Yes' : 'No'),
    },
  ];
  return (
    <div className="grid gap-3">
      <Notice>
        <span>
          Records whose policy says “keep for review” wait here after their retention ended (search
          over the last 365 days). Disposal re-checks legal holds and crypto-shreds the record; it
          needs archive:manage and a session signed in with MFA.
        </span>
      </Notice>
      <DataTable
        tableId="archive-review-queue"
        caption="Records waiting for review"
        columns={columns}
        list={list}
        getRowId={(row) => row.messageId}
        getRowLabel={(row) => `archived message received ${row.receivedAt}`}
        rowActions={
          access.manage
            ? (row) => [
                {
                  label: 'Dispose',
                  destructive: true,
                  onSelect: () => setDisposing(row.messageId),
                },
              ]
            : undefined
        }
        errorState={(failure) =>
          failure instanceof ApiError && failure.code === 'archive_search_unavailable' ? (
            <div className="m-3">
              <SearchUnavailable error={failure} onRetry={() => void list.query.refetch()} />
            </div>
          ) : null
        }
        emptyState={
          <EmptyState
            title="Nothing to review"
            description="No record is waiting for a disposal decision."
          />
        }
      />
      <ReasonDialog
        open={disposing !== null}
        onOpenChange={(open) => {
          if (!open) setDisposing(null);
        }}
        title="Dispose this archived message?"
        description={
          <p>
            Crypto-shreds the record at once, then deletes every object version, replica copy, index
            document and the row. Legal holds are checked again first. This cannot be undone.
          </p>
        }
        confirmLabel="Dispose"
        destructive
        maxChars={4096}
        pending={dispose.isPending}
        onSubmit={(reason) =>
          disposing
            ? dispose.submit({ path: { messageId: disposing }, body: { reason } })
            : Promise.resolve({ ok: true })
        }
        onRetry={() => dispose.retry()}
      />
    </div>
  );
}

// ---- disposal log --------------------------------------------------------------------------

function DisposalLog() {
  const [reason, setReason] = useState<string[]>([]);
  const [state, setState] = useState<string[]>([]);
  const filters = useMemo(
    () => ({
      sort: '-requestedAt' as const,
      ...(reason.length > 0 ? { reason: reason.join(',') } : {}),
      ...(state.length > 0 ? { state: state.join(',') } : {}),
    }),
    [reason, state],
  );
  const list = useCursorList('ArchiveAdminController_disposals_v1', filters, { limit: 25 });
  const columns: DataTableColumn<Disposal>[] = [
    {
      id: 'requestedAt',
      header: 'Requested',
      meta: { label: 'Requested', hideable: false },
      cell: ({ row }) => <DateTime value={row.original.requestedAt} />,
    },
    {
      id: 'messageId',
      header: 'Message',
      meta: { label: 'Message' },
      cell: ({ row }) => <CopyableId value={row.original.messageId} label="message ID" />,
    },
    {
      id: 'receivedAt',
      header: 'Received',
      meta: { label: 'Received' },
      cell: ({ row }) => <DateTime value={row.original.receivedAt} mode="absolute" />,
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
      cell: ({ row }) => <EnumBadge value={row.original.state} tones={DISPOSAL_STATE_TONE} />,
    },
    {
      id: 'sha256',
      header: 'Original SHA-256',
      meta: { label: 'Original SHA-256', className: 'max-w-48' },
      cell: ({ row }) => (
        <span className="block truncate font-mono text-xs" title={row.original.sha256}>
          {row.original.sha256}
        </span>
      ),
    },
    {
      id: 'size',
      header: 'Size',
      meta: { label: 'Size' },
      cell: ({ row }) => formatBytes(row.original.sizeBytes),
    },
    {
      id: 'completedAt',
      header: 'Completed',
      meta: { label: 'Completed' },
      cell: ({ row }) => <DateTime value={row.original.completedAt} emptyLabel="In progress" />,
    },
  ];
  return (
    <DataTable
      tableId="archive-disposals"
      caption="Disposal log"
      columns={columns}
      list={list}
      getRowId={(row) => `${row.messageId}-${row.requestedAt}`}
      filters={
        <div className="flex flex-wrap gap-2">
          <FilterMultiSelect
            label="Reason"
            values={reason}
            options={optionsOf(DISPOSAL_REASONS)}
            onChange={setReason}
          />
          <FilterMultiSelect
            label="State"
            values={state}
            options={optionsOf(DISPOSAL_STATES)}
            onChange={setState}
          />
        </div>
      }
      isFiltered={reason.length > 0 || state.length > 0}
      onClearFilters={() => {
        setReason([]);
        setState([]);
      }}
      emptyState={
        <EmptyState
          title="No disposal yet"
          description="Disposals are logged here (append-only) with the original’s SHA-256; no content is kept."
        />
      }
    />
  );
}

// ---- capture issues ------------------------------------------------------------------------

function CaptureIssues() {
  const [status, setStatus] = useState<string[]>([]);
  const filters = useMemo(
    () => ({
      sort: '-receivedAt' as const,
      ...(status.length > 0 ? { status: status.join(',') } : {}),
    }),
    [status],
  );
  const list = useCursorList('ArchiveAdminController_captureIssues_v1', filters, { limit: 25 });
  const [retrying, setRetrying] = useState<CaptureIssue | null>(null);
  const retry = useApiMutation('ArchiveAdminController_retry_v1', {
    successMessage: 'Capture queued again',
    invalidates: ['ArchiveAdminController_captureIssues_v1', 'ArchiveAdminController_status_v1'],
  });
  const columns: DataTableColumn<CaptureIssue>[] = [
    {
      id: 'receivedAt',
      header: 'Received',
      meta: { label: 'Received', hideable: false },
      cell: ({ row }) => <DateTime value={row.original.receivedAt} />,
    },
    {
      id: 'messageId',
      header: 'Message',
      meta: { label: 'Message' },
      cell: ({ row }) => <CopyableId value={row.original.messageId} label="message ID" />,
    },
    {
      id: 'status',
      header: 'Status',
      meta: { label: 'Status' },
      cell: ({ row }) => <EnumBadge value={row.original.status} tones={CAPTURE_STATUS_TONE} />,
    },
    {
      id: 'code',
      header: 'Code',
      meta: { label: 'Code' },
      cell: ({ row }) => <span className="font-mono text-xs">{row.original.code ?? '—'}</span>,
    },
    {
      id: 'attempts',
      header: 'Attempts',
      meta: { label: 'Attempts' },
      cell: ({ row }) => row.original.attempts,
    },
    {
      id: 'sources',
      header: 'Requested by',
      meta: { label: 'Requested by' },
      cell: ({ row }) =>
        [
          row.original.sources.journal ? 'Journal' : null,
          row.original.sources.policy ? 'Policy' : null,
        ]
          .filter(Boolean)
          .join(', '),
    },
    {
      id: 'nextCheckAt',
      header: 'Next check',
      meta: { label: 'Next check' },
      cell: ({ row }) => <DateTime value={row.original.nextCheckAt} />,
    },
  ];
  return (
    <div className="grid gap-3">
      <Notice>
        <span>
          Messages the archive could not capture: failed captures can be retried; lost ones (the
          message or its original no longer exists) cannot.
        </span>
      </Notice>
      <DataTable
        tableId="archive-capture-issues"
        caption="Capture issues"
        columns={columns}
        list={list}
        getRowId={(row) => row.messageId}
        filters={
          <FilterMultiSelect
            label="Status"
            values={status}
            options={optionsOf(CAPTURE_ISSUE_STATUSES)}
            onChange={setStatus}
          />
        }
        isFiltered={status.length > 0}
        onClearFilters={() => setStatus([])}
        rowActions={(row) => [
          {
            label: 'Retry capture',
            disabled: row.status !== 'failed',
            onSelect: () => setRetrying(row),
          },
        ]}
        emptyState={
          <EmptyState
            icon={RefreshCwIcon}
            title="No capture issue"
            description="Every message due for archiving was captured."
          />
        }
      />
      <ConfirmDialog
        open={retrying !== null}
        onOpenChange={(open) => {
          if (!open) {
            setRetrying(null);
            retry.reset();
          }
        }}
        title="Retry this capture?"
        description={
          <p>The capture is queued again and attempted at once by the archive worker.</p>
        }
        confirmLabel="Retry capture"
        pending={retry.isPending}
        error={<ArchiveErrorSummary error={retry.error} />}
        onConfirm={async () => {
          if (!retrying) return false;
          const outcome = await retry.submit({ path: { messageId: retrying.messageId } });
          return outcome.ok;
        }}
      />
    </div>
  );
}
