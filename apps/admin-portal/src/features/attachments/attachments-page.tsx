'use client';

import { PlusIcon } from 'lucide-react';
import Link from 'next/link';
import { useMemo, useState } from 'react';
import { toast } from 'sonner';
import { z } from 'zod';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { CopyableId } from '@/components/domain/copyable-id';
import { DateTime } from '@/components/domain/date-time';
import { ToneBadge } from '@/components/domain/tone-badge';
import { UntrustedText } from '@/components/domain/untrusted-text';
import { FormErrorSummary, applyApiErrors, useZodForm } from '@/components/form';
import { PageHeader } from '@/components/page-header';
import { EmptyState } from '@/components/states/empty-state';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Form, FormField, FormItem, FormMessage } from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import { RangePicker, useRangeState } from '@/components/range-picker';
import { useUrlState } from '@/hooks/use-url-state';
import { useApiMutation, useApiQuery, useCursorList } from '@/lib/api/hooks';
import type { ListItem, SuccessBody } from '@/lib/api/types';
import { Can } from '@/lib/auth/can';
import { useCan } from '@/lib/auth/me';
import { RouteGate } from '@/lib/auth/route-gate';
import type { Tone } from '@/lib/design/tokens';
import { formatBytes, formatNumber, formatUtc, humanize } from '@/lib/format';
import { ReasonConfirmDialog } from '@/features/organizations/reason-confirm-dialog';
import { SelectFilter } from '@/features/reports/filters';
import { GatedTabs, type TabDefinition } from '@/features/reports/gated-tabs';
import { navGate } from '@/features/reports/nav-gate';
import { EngineSettingsReadOnly } from '@/features/settings/scan-settings-panel';
import { TextField } from '@/features/threat-intel/form-fields';
import { ScanVerdictBadge } from '@/features/url-protection/url-protection-page';
import { RESCAN_STATES, rescanBody, rescanSchema } from './schemas';

type AttachmentRow = ListItem<'AttachmentsController_search_v1'>;
type RescanJob = ListItem<'AttachmentRescansController_list_v1'>;

const TABS: readonly TabDefinition[] = [
  { id: 'search', label: 'Hash search', ops: ['AttachmentsController_search_v1'] },
  { id: 'settings', label: 'Attachment engine settings', ops: ['ScanSettingsController_list_v1'] },
  { id: 'rescans', label: 'Platform rescans', ops: ['AttachmentRescansController_list_v1'] },
];

const SHA256 = /^[0-9a-f]{64}$/;
export const ATTACHMENTS_URL_SHAPE = {
  sha256: z.string().regex(SHA256).optional().catch(undefined),
  status: z
    .enum(['pending', 'running', 'completed', 'cancelled', 'failed', 'skipped'])
    .optional()
    .catch(undefined),
};

/** `/attachments` (design §1.3 row 17). */
export function AttachmentsPage() {
  return (
    <RouteGate gate={navGate('attachments')}>
      <div className="flex flex-col gap-4">
        <PageHeader
          title="Attachment analysis"
          description="Find every attachment of your organization with a given SHA-256. Attachments are never downloaded from here."
          actions={<RangePicker />}
        />
        <GatedTabs
          tabs={TABS}
          label="Attachment analysis"
          render={(tab) =>
            tab === 'search' ? (
              <HashSearch />
            ) : tab === 'settings' ? (
              <EngineSettingsReadOnly engine="attachment" />
            ) : (
              <Rescans />
            )
          }
        />
      </div>
    </RouteGate>
  );
}

/* ------------------------------------------------------------------------------------------ */

function HashSearch() {
  const [range] = useRangeState();
  const [state, setState] = useUrlState(ATTACHMENTS_URL_SHAPE);
  const [text, setText] = useState(state.sha256 ?? '');
  const [error, setError] = useState<string | null>(null);
  const list = useCursorList(
    'AttachmentsController_search_v1',
    { sha256: state.sha256 ?? '', from: range.from, to: range.to, sort: '-receivedAt' },
    { enabled: Boolean(state.sha256) },
  );
  const columns = useMemo<DataTableColumn<AttachmentRow>[]>(
    () => [
      {
        id: 'receivedAt',
        header: 'Received',
        meta: { label: 'Received' },
        cell: ({ row }) => <DateTime value={row.original.receivedAt} />,
      },
      {
        id: 'filename',
        header: 'File name',
        meta: { label: 'File name' },
        cell: ({ row }) => (
          <UntrustedText value={row.original.filename} maxLength={60} emptyLabel="(no name)" />
        ),
      },
      {
        id: 'size',
        header: 'Size',
        meta: { label: 'Size' },
        cell: ({ row }) => formatBytes(row.original.sizeBytes),
      },
      {
        id: 'type',
        header: 'Detected type',
        meta: { label: 'Detected type' },
        cell: ({ row }) => (
          <span className="font-mono text-xs">{row.original.detectedContentType ?? 'Unknown'}</span>
        ),
      },
      {
        id: 'verdict',
        header: 'Verdict',
        meta: { label: 'Verdict' },
        cell: ({ row }) => <ScanVerdictBadge verdict={row.original.verdict} />,
      },
      {
        id: 'message',
        header: 'Message',
        meta: { label: 'Message' },
        cell: ({ row }) => (
          <Link
            href={`/messages/${row.original.messageId}/scans`}
            className="text-primary hover:underline"
            aria-label={`Scan details of the message (part ${row.original.partIndex})`}
          >
            Scan details
          </Link>
        ),
      },
    ],
    [],
  );
  const search = () => {
    const value = text.trim().toLowerCase();
    if (!SHA256.test(value)) {
      setError('Enter the 64 hexadecimal characters of a SHA-256 hash.');
      return;
    }
    setError(null);
    setState({ sha256: value });
  };
  return (
    <div className="grid gap-4">
      <form
        className="flex flex-wrap items-end gap-2 rounded-lg border bg-card p-3"
        aria-label="Search attachments by hash"
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          search();
        }}
      >
        <div className="grid min-w-0 flex-1 gap-1">
          <Label htmlFor="attachment-sha256">
            SHA-256 <span className="text-xs font-normal text-muted-foreground">(required)</span>
          </Label>
          <Input
            id="attachment-sha256"
            value={text}
            onChange={(event) => setText(event.target.value)}
            className="font-mono text-xs"
            spellCheck={false}
            autoComplete="off"
            aria-invalid={error ? true : undefined}
            aria-describedby={error ? 'attachment-sha256-error' : 'attachment-sha256-hint'}
          />
          {error ? (
            <p id="attachment-sha256-error" className="text-xs font-medium text-destructive">
              {error}
            </p>
          ) : (
            <p id="attachment-sha256-hint" className="text-xs text-muted-foreground">
              Searches are audited. The range is at most 31 days.
            </p>
          )}
        </div>
        <Button type="submit">Search</Button>
      </form>
      {state.sha256 ? (
        <DataTable<AttachmentRow>
          tableId="attachment-search"
          caption="Attachments with this hash"
          columns={columns}
          list={list}
          getRowId={(row) => `${row.messageId}:${row.partIndex}`}
          getRowLabel={(row) => `attachment part ${row.partIndex}`}
          emptyState={
            <EmptyState
              title="No attachment with this hash in the range"
              description="Try a longer range (at most 31 days)."
            />
          }
          mobileCard={(row) => (
            <div className="grid gap-1 text-sm">
              <UntrustedText value={row.filename} maxLength={40} emptyLabel="(no name)" />
              <span className="flex items-center gap-2">
                <ScanVerdictBadge verdict={row.verdict} /> <DateTime value={row.receivedAt} />
              </span>
              <Link
                href={`/messages/${row.messageId}/scans`}
                className="text-primary hover:underline"
              >
                Scan details
              </Link>
            </div>
          )}
        />
      ) : (
        <div className="rounded-lg border bg-card">
          <EmptyState
            title="Search by SHA-256"
            description="Enter a hash to list the messages that carried that attachment."
          />
        </div>
      )}
      <p className="text-sm text-muted-foreground" role="note">
        There is no endpoint for a tenant-wide list of malicious attachments. See the malware count
        in the{' '}
        <Link href="/reports?tab=threats" className="text-primary underline underline-offset-2">
          threats report
        </Link>{' '}
        and the{' '}
        <Link
          href="/messages?verdict=malware&hasAttachments=true"
          className="text-primary underline underline-offset-2"
        >
          malware messages with attachments
        </Link>{' '}
        in the email explorer.
      </p>
    </div>
  );
}

/* ------------------------------------------------------------------------------------------ */

const JOB_TONE: Record<RescanJob['status'], Tone> = {
  pending: 'info',
  running: 'info',
  completed: 'success',
  cancelled: 'neutral',
  failed: 'danger',
  skipped: 'neutral',
};

function JobStatus({ status }: { status: RescanJob['status'] }) {
  return <ToneBadge tone={JOB_TONE[status]}>{humanize(status)}</ToneBadge>;
}

function Rescans() {
  const [state, setState] = useUrlState(ATTACHMENTS_URL_SHAPE);
  const [requesting, setRequesting] = useState(false);
  const [openJob, setOpenJob] = useState<string | null>(null);
  const [cancelling, setCancelling] = useState<RescanJob | null>(null);
  const canCancel = useCan('AttachmentRescansController_cancel_v1');
  const list = useCursorList(
    'AttachmentRescansController_list_v1',
    state.status ? { status: state.status } : {},
  );
  const cancel = useApiMutation('AttachmentRescansController_cancel_v1', {
    successMessage: 'Rescan job cancelled.',
    invalidates: ['AttachmentRescansController_list_v1', 'AttachmentRescansController_get_v1'],
  });
  const columns = useMemo<DataTableColumn<RescanJob>[]>(
    () => [
      {
        id: 'createdAt',
        header: 'Created',
        meta: { label: 'Created' },
        cell: ({ row }) => <DateTime value={row.original.createdAt} />,
      },
      {
        id: 'status',
        header: 'Status',
        meta: { label: 'Status' },
        cell: ({ row }) => <JobStatus status={row.original.status} />,
      },
      {
        id: 'trigger',
        header: 'Trigger',
        meta: { label: 'Trigger' },
        cell: ({ row }) => humanize(row.original.trigger),
      },
      {
        id: 'window',
        header: 'Window',
        meta: { label: 'Window' },
        cell: ({ row }) =>
          `${formatUtc(row.original.windowStart)} – ${formatUtc(row.original.windowEnd)}`,
      },
      {
        id: 'counts',
        header: 'Requested / selected',
        meta: { label: 'Requested / selected' },
        cell: ({ row }) =>
          `${formatNumber(row.original.requestedCount)} / ${formatNumber(row.original.selectedCount)}`,
      },
      {
        id: 'organization',
        header: 'Organization',
        meta: { label: 'Organization' },
        cell: ({ row }) =>
          row.original.organizationId ? (
            <CopyableId value={row.original.organizationId} label="organization ID" />
          ) : (
            'All'
          ),
      },
      {
        id: 'details',
        header: () => <span className="sr-only">Details</span>,
        meta: { label: 'Details', hideable: false },
        cell: ({ row }) => (
          <Button
            variant="outline"
            size="sm"
            onClick={() => setOpenJob(row.original.jobId)}
            aria-label={`Details of rescan job ${row.original.jobId.slice(0, 8)}`}
          >
            Details
          </Button>
        ),
      },
    ],
    [],
  );
  return (
    <div className="grid gap-3">
      <div className="flex justify-end">
        <Can op="AttachmentRescansController_request_v1">
          <Button onClick={() => setRequesting(true)}>
            <PlusIcon aria-hidden />
            Request rescan
          </Button>
        </Can>
      </div>
      <DataTable<RescanJob>
        tableId="attachment-rescans"
        caption="Attachment rescan jobs"
        columns={columns}
        list={list}
        getRowId={(row) => row.jobId}
        getRowLabel={(row) => `rescan job ${row.jobId.slice(0, 8)}`}
        rowActions={
          canCancel
            ? (row) =>
                row.status === 'pending' || row.status === 'running'
                  ? [{ label: 'Cancel job', destructive: true, onSelect: () => setCancelling(row) }]
                  : []
            : undefined
        }
        isFiltered={Boolean(state.status)}
        onClearFilters={() => setState({ status: undefined })}
        emptyState={<EmptyState title="No rescan jobs" />}
        filters={
          <SelectFilter
            label="Status"
            value={state.status}
            onChange={(status) => setState({ status })}
            options={(
              ['pending', 'running', 'completed', 'cancelled', 'failed', 'skipped'] as const
            ).map((value) => ({ value, label: humanize(value) }))}
          />
        }
        mobileCard={(row) => (
          <div className="grid gap-1 text-sm">
            <span className="flex items-center gap-2">
              <JobStatus status={row.status} /> <DateTime value={row.createdAt} />
            </span>
            <Button
              variant="outline"
              size="sm"
              className="justify-self-start"
              onClick={() => setOpenJob(row.jobId)}
            >
              Details
            </Button>
          </div>
        )}
      />
      <RequestRescanDialog open={requesting} onOpenChange={setRequesting} />
      <JobSheet jobId={openJob} onClose={() => setOpenJob(null)} />
      <ReasonConfirmDialog
        open={cancelling !== null}
        onOpenChange={(open) => {
          if (!open) {
            setCancelling(null);
            cancel.reset();
          }
        }}
        title="Cancel this rescan job?"
        description="Messages already rescanned keep their new results; the rest are not rescanned."
        confirmLabel="Cancel job"
        destructive
        reasonRequired={false}
        reasonHint="Optional, up to 512 characters; recorded in the audit log."
        onConfirm={async (reason) => {
          if (!cancelling) return false;
          const outcome = await cancel.submit({
            path: { jobId: cancelling.jobId },
            body: reason ? { reason } : {},
          });
          return outcome.ok;
        }}
        error={cancel.error ? <ErrorState error={cancel.error} compact /> : null}
      />
    </div>
  );
}

function JobSheet({ jobId, onClose }: { jobId: string | null; onClose: () => void }) {
  const job = useApiQuery(
    'AttachmentRescansController_get_v1',
    { path: { jobId: jobId ?? '' } },
    { enabled: jobId !== null },
  );
  const d = job.data;
  return (
    <Sheet open={jobId !== null} onOpenChange={(open) => (!open ? onClose() : undefined)}>
      <SheetContent side="right" className="w-full overflow-y-auto sm:max-w-lg">
        <SheetHeader>
          <SheetTitle>Rescan job</SheetTitle>
          <SheetDescription>
            {jobId ? <span className="font-mono text-xs">{jobId}</span> : null}
          </SheetDescription>
        </SheetHeader>
        <div className="px-4 pb-4">
          {job.isLoading ? (
            <LoadingState label="Loading the job" rows={6} />
          ) : job.error ? (
            <ErrorState error={job.error} onRetry={() => void job.refetch()} compact />
          ) : d ? (
            <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-2 text-sm">
              {(
                [
                  ['Status', <JobStatus key="s" status={d.status} />],
                  ['Trigger', humanize(d.trigger)],
                  ['Organization', d.organizationId ?? 'All organizations'],
                  ['Window', `${formatUtc(d.windowStart)} – ${formatUtc(d.windowEnd)}`],
                  ['States', d.states.length ? d.states.map(humanize).join(', ') : 'None'],
                  [
                    'Component',
                    d.component
                      ? `${d.component} ${d.fromVersion ?? ''} → ${d.toVersion ?? ''}`
                      : 'None',
                  ],
                  ['Most messages', formatNumber(d.maxMessages)],
                  ['Selected', formatNumber(d.selectedCount)],
                  ['Requested', formatNumber(d.requestedCount)],
                  ['Skipped', formatNumber(d.skippedCount)],
                  ['Reason', d.reason ?? 'None'],
                  ['Last error', d.lastError ?? 'None'],
                  ['Started', d.startedAt ? formatUtc(d.startedAt) : 'Not started'],
                  ['Completed', d.completedAt ? formatUtc(d.completedAt) : 'Not completed'],
                ] as const
              ).map(([label, value]) => (
                <div key={label} className="contents">
                  <dt className="text-muted-foreground">{label}</dt>
                  <dd className="break-words">{value}</dd>
                </div>
              ))}
            </dl>
          ) : null}
        </div>
      </SheetContent>
    </Sheet>
  );
}

type DryRun = Extract<SuccessBody<'AttachmentRescansController_request_v1'>, { dryRun: true }>;

/** Request a rescan: a dry run first (estimate), then the real request after confirmation. */
function RequestRescanDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const [messages, setMessages] = useState<string[]>([]);
  const [estimate, setEstimate] = useState<DryRun | null>(null);
  const form = useZodForm(rescanSchema, {
    defaultValues: {
      windowHours: 24,
      states: ['scanned'],
      organizationId: '',
      maxMessages: '',
      reason: '',
    },
  });
  const mutation = useApiMutation('AttachmentRescansController_request_v1', {
    invalidates: ['AttachmentRescansController_list_v1'],
  });
  const close = () => {
    setEstimate(null);
    setMessages([]);
    mutation.reset();
    onOpenChange(false);
  };
  const run = (dryRun: boolean) =>
    form.handleSubmit(async (values) => {
      setMessages([]);
      const outcome = await mutation.submit({ body: rescanBody(values, dryRun) });
      if (!outcome.ok) {
        setMessages(applyApiErrors(form, outcome.error));
        return;
      }
      if ('dryRun' in outcome.data) setEstimate(outcome.data);
      else {
        toast.success(
          `Rescan job queued for about ${formatNumber(outcome.data.estimatedMessages)} messages.`,
        );
        form.reset();
        close();
      }
    });
  return (
    <Dialog open={open} onOpenChange={(next) => (!next ? close() : onOpenChange(next))}>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle>Request an attachment rescan</DialogTitle>
          <DialogDescription>
            Rescans attachments of recent messages with the current signatures. Start with an
            estimate.
          </DialogDescription>
        </DialogHeader>
        <Form {...form}>
          <form
            onSubmit={(event) => void run(true)(event)}
            className="grid gap-4"
            noValidate
            aria-label="Request rescan"
          >
            <FormErrorSummary messages={messages} requestId={mutation.error?.requestId} />
            <div className="grid gap-4 sm:grid-cols-2">
              <TextField
                control={form.control}
                name="windowHours"
                label="Window (hours)"
                type="number"
                required
                hint="1 to 168 hours back from now."
              />
              <TextField
                control={form.control}
                name="maxMessages"
                label="Most messages"
                type="number"
                hint="Optional, 1 to 50,000."
              />
            </div>
            <FormField
              control={form.control}
              name="states"
              render={({ field }) => (
                <FormItem>
                  <fieldset className="grid gap-2">
                    <legend className="text-sm font-medium">Message states</legend>
                    {RESCAN_STATES.map((s) => (
                      <div key={s} className="flex items-center gap-2">
                        <Checkbox
                          id={`rescan-state-${s}`}
                          checked={field.value.includes(s)}
                          onCheckedChange={(checked) =>
                            field.onChange(
                              checked === true
                                ? [...field.value, s]
                                : field.value.filter((v) => v !== s),
                            )
                          }
                        />
                        <label htmlFor={`rescan-state-${s}`} className="text-sm">
                          {humanize(s)}
                        </label>
                      </div>
                    ))}
                  </fieldset>
                  <FormMessage />
                </FormItem>
              )}
            />
            <TextField
              control={form.control}
              name="organizationId"
              label="Only this organization (ID)"
              mono
              hint="Optional; empty rescans every organization."
            />
            <TextField
              control={form.control}
              name="reason"
              label="Reason"
              required
              multiline
              hint="Recorded with the job and in the audit log."
            />
            {estimate ? (
              <p
                role="status"
                className="rounded-md bg-tone-info px-3 py-2 text-sm text-tone-info-foreground"
              >
                Estimate: about {formatNumber(estimate.estimatedMessages)} messages between{' '}
                {formatUtc(estimate.windowStart)} and {formatUtc(estimate.windowEnd)} (at most{' '}
                {formatNumber(estimate.maxMessages)}).
              </p>
            ) : null}
            <DialogFooter>
              <Button variant="outline" onClick={close}>
                Cancel
              </Button>
              {estimate ? (
                <Button
                  type="button"
                  variant="destructive"
                  disabled={mutation.isPending}
                  onClick={() => void run(false)()}
                >
                  {mutation.isPending ? 'Requesting …' : 'Start rescan'}
                </Button>
              ) : (
                <Button
                  type="submit"
                  disabled={mutation.isPending || mutation.retryAfterSeconds > 0}
                >
                  {mutation.isPending ? 'Estimating …' : 'Estimate'}
                </Button>
              )}
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}
