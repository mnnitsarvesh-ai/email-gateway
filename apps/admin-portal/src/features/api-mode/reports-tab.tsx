'use client';

import { useQueryClient } from '@tanstack/react-query';
import { FlagIcon } from 'lucide-react';
import Link from 'next/link';
import { useId, useMemo, useState } from 'react';
import { z } from 'zod';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { VerdictBadge } from '@/components/domain/badges';
import { CopyableId } from '@/components/domain/copyable-id';
import { DateTime } from '@/components/domain/date-time';
import { UntrustedText } from '@/components/domain/untrusted-text';
import { RangePicker, useRangeState } from '@/components/range-picker';
import { EmptyState } from '@/components/states/empty-state';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import { Textarea } from '@/components/ui/textarea';
import { useUrlState } from '@/hooks/use-url-state';
import { useApiMutation, useApiQuery, useCursorList } from '@/lib/api/hooks';
import type { OperationId, QueryParams } from '@/lib/api/types';
import { useCan } from '@/lib/auth/me';
import { formatNumber, humanize } from '@/lib/format';
import { DetailList, FilterSelect, FormDialog, MutationError } from '@/features/domains/kit';
import { ReportClawbackDialog } from './clawback-dialogs';
import {
  AssessmentBadge,
  FEEDBACK_TEXT,
  IDENTIFICATION_TEXT,
  OPEN_REPORT_STATUSES,
  REJECT_REASON_TEXT,
  REPORT_ASSESSMENTS,
  REPORT_STATUSES,
  REPORT_VERDICTS,
  ReportStatusBadge,
  VERDICT_TEXT,
  clawbackErrorText,
  clawbackHref,
  type Report,
  type ReportDetail,
  type ReportVerdict,
} from './clawback-model';
import { detectionHref } from './remediation-model';

/** Queries a triage makes stale. */
export const REPORT_QUERIES: readonly OperationId[] = [
  'ApiModeReportsController_list_v1',
  'ApiModeReportsController_detail_v1',
  'ApiModeController_overview_v1',
];

const URL_SHAPE = {
  status: z.enum(REPORT_STATUSES).optional().catch(undefined),
  assessment: z.enum(REPORT_ASSESSMENTS).optional().catch(undefined),
  verdict: z.enum(REPORT_VERDICTS).optional().catch(undefined),
  reporter: z.string().max(320).optional().catch(undefined),
  /** The report whose detail drawer is open. */
  report: z.string().uuid().optional().catch(undefined),
};

/** The list query (`GET /api-mode/reports`, v1 cursor; C14 #11). */
export function reportQuery(
  filters: { status?: string; assessment?: string; verdict?: string; reporter?: string },
  range: { from: string; to: string },
): QueryParams<'ApiModeReportsController_list_v1'> {
  return {
    from: range.from,
    to: range.to,
    ...(filters.status ? { status: filters.status } : {}),
    ...(filters.assessment ? { assessment: filters.assessment } : {}),
    ...(filters.verdict ? { analystVerdict: filters.verdict } : {}),
    ...(filters.reporter ? { reporter: filters.reporter.trim().toLowerCase() } : {}),
  };
}

type TriageTarget = { report: ReportDetail; status: 'resolved' | 'rejected' } | null;

/** "Resolve…" and "Reject…" (C11.4): verdict, note, reporter feedback and the group option. */
export function TriageDialog({
  target,
  feedbackDefault,
  onOpenChange,
}: {
  target: TriageTarget;
  feedbackDefault: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const base = useId();
  const queryClient = useQueryClient();
  const resolve = target?.status === 'resolved';
  const [verdict, setVerdict] = useState<ReportVerdict | ''>('');
  const [note, setNote] = useState('');
  const [notify, setNotify] = useState(feedbackDefault);
  const [group, setGroup] = useState(true);
  const [hint, setHint] = useState<string | null>(null);
  const triage = useApiMutation('ApiModeReportsController_triage_v1', {
    invalidates: REPORT_QUERIES,
    successMessage: null,
  });
  const close = (open: boolean) => {
    if (!open) {
      setVerdict('');
      setNote('');
      setNotify(feedbackDefault);
      setGroup(true);
      setHint(null);
      triage.reset();
    }
    onOpenChange(open);
  };
  const errorText = clawbackErrorText(triage.error);
  const report = target?.report;
  return (
    <FormDialog
      open={target !== null}
      onOpenChange={close}
      title={resolve ? 'Resolve the report' : 'Reject the report'}
      description={
        resolve
          ? 'Your verdict is stored and audited. A clawback is a separate step ("Claw back this message…").'
          : 'A rejected report gets no verdict and no feedback e-mail.'
      }
    >
      {report ? (
        <form
          className="grid gap-4"
          aria-label={resolve ? 'Resolve the report' : 'Reject the report'}
          onSubmit={(event) => {
            event.preventDefault();
            if (resolve && !verdict) return setHint('Choose a verdict.');
            setHint(null);
            void triage
              .submit({
                path: { reportId: report.id },
                body: resolve
                  ? {
                      status: 'resolved',
                      verdict: verdict as ReportVerdict,
                      ...(note.trim() ? { note: note.trim() } : {}),
                      notifyReporter: notify,
                      applyToGroup: group,
                      expectedRowVersion: report.rowVersion,
                    }
                  : {
                      status: 'rejected',
                      ...(note.trim() ? { note: note.trim() } : {}),
                      expectedRowVersion: report.rowVersion,
                    },
              })
              .then(async (outcome) => {
                if (outcome.ok) close(false);
                else if (outcome.error.code === 'api_mode_report_state_conflict')
                  await queryClient.invalidateQueries({
                    queryKey: ['ApiModeReportsController_detail_v1'],
                  });
              });
          }}
        >
          {resolve ? (
            <fieldset className="grid gap-2">
              <legend className="text-sm font-medium">Verdict</legend>
              <RadioGroup
                value={verdict}
                onValueChange={(value) => setVerdict(value as ReportVerdict)}
                className="grid gap-2 sm:grid-cols-2"
              >
                {REPORT_VERDICTS.map((value) => (
                  <div key={value} className="flex items-center gap-2">
                    <RadioGroupItem id={`${base}-${value}`} value={value} />
                    <Label htmlFor={`${base}-${value}`} className="font-normal">
                      {VERDICT_TEXT[value]}
                    </Label>
                  </div>
                ))}
              </RadioGroup>
            </fieldset>
          ) : null}
          <div className="grid gap-2">
            <Label htmlFor={`${base}-note`}>Note (optional)</Label>
            <Textarea
              id={`${base}-note`}
              rows={2}
              maxLength={1000}
              value={note}
              onChange={(event) => setNote(event.target.value)}
            />
            <p className="text-xs text-muted-foreground">
              Internal; never sent to the reporter (at most 1000 characters).
            </p>
          </div>
          {resolve ? (
            <div className="grid gap-2">
              <div className="flex items-center gap-2">
                <Checkbox
                  id={`${base}-notify`}
                  checked={notify}
                  onCheckedChange={(checked) => setNotify(checked === true)}
                />
                <Label htmlFor={`${base}-notify`} className="font-normal">
                  Notify the reporter
                </Label>
              </div>
              <p className="pl-6 text-xs text-muted-foreground">
                A fixed message per verdict, without the reported message&apos;s subject or content.
              </p>
              {report.groupSize > 1 ? (
                <div className="flex items-center gap-2">
                  <Checkbox
                    id={`${base}-group`}
                    checked={group}
                    onCheckedChange={(checked) => setGroup(checked === true)}
                  />
                  <Label htmlFor={`${base}-group`} className="font-normal">
                    Apply to all {formatNumber(report.groupSize)} reports of this message
                  </Label>
                </div>
              ) : null}
            </div>
          ) : null}
          {hint ? (
            <p role="alert" className="text-sm font-medium text-destructive">
              {hint}
            </p>
          ) : null}
          {triage.error ? (
            <div role="alert" className="grid gap-1">
              {errorText ? (
                <p className="text-sm font-medium text-destructive">{errorText}</p>
              ) : null}
              <MutationError error={triage.error} />
            </div>
          ) : null}
          <div className="flex flex-wrap gap-2">
            <Button
              type="submit"
              size="sm"
              variant={resolve ? 'default' : 'destructive'}
              disabled={triage.isPending}
            >
              {resolve ? 'Resolve' : 'Reject'}
            </Button>
            <Button type="button" size="sm" variant="ghost" onClick={() => close(false)}>
              Cancel
            </Button>
          </div>
        </form>
      ) : null}
    </FormDialog>
  );
}

function OriginalKeys({ original }: { original: NonNullable<ReportDetail['original']> }) {
  return (
    <div className="grid gap-2 rounded-md border p-2">
      <p className="text-xs text-muted-foreground">
        Taken from the reported message: untrusted text, shown as data.
      </p>
      <DetailList
        items={[
          {
            label: 'Sender',
            value: <UntrustedText value={original.sender} mono emptyLabel="Unknown" />,
          },
          {
            label: 'Subject key',
            value: (
              <UntrustedText value={original.subjectKey} maxLength={128} emptyLabel="Unknown" />
            ),
          },
          {
            label: 'Date',
            value: <DateTime value={original.date} mode="absolute" emptyLabel="Unknown" />,
          },
          {
            label: 'Message-ID (hash)',
            value: original.messageIdHash ? (
              <span className="font-mono text-xs break-all">{original.messageIdHash}</span>
            ) : (
              'Not found'
            ),
          },
          {
            label: 'Attachments and URLs',
            value: `${formatNumber(original.attachmentCount)} attachment hashes · ${formatNumber(original.urlCount)} URL hashes`,
          },
          ...(original.extraOriginals > 0
            ? [
                {
                  label: 'Further attached messages',
                  value: `${formatNumber(original.extraOriginals)} (only the first is used)`,
                },
              ]
            : []),
        ]}
      />
    </div>
  );
}

/** Detail drawer of one report (`?report=`; C14 #12) with the triage actions. */
export function ReportDrawer({
  reportId,
  onClose,
  onOpen,
  onTriage,
  onClawback,
}: {
  reportId: string | undefined;
  onClose: () => void;
  onOpen: (reportId: string) => void;
  onTriage: (target: NonNullable<TriageTarget>) => void;
  onClawback: (reportId: string) => void;
}) {
  const queryClient = useQueryClient();
  const canTriage = useCan('ApiModeReportsController_triage_v1');
  const canClawback = useCan('ApiModeReportsController_clawback_v1');
  const detail = useApiQuery(
    'ApiModeReportsController_detail_v1',
    { path: { reportId: reportId ?? '' } },
    { enabled: Boolean(reportId) },
  );
  const review = useApiMutation('ApiModeReportsController_triage_v1', {
    invalidates: REPORT_QUERIES,
    successMessage: 'Review started.',
  });
  const r = detail.data;
  const reviewError = clawbackErrorText(review.error);
  const startReview = (report: ReportDetail) =>
    void review
      .submit({
        path: { reportId: report.id },
        body: { status: 'in_review', expectedRowVersion: report.rowVersion },
      })
      .then(async (outcome) => {
        if (!outcome.ok && outcome.error.code === 'api_mode_report_state_conflict')
          await queryClient.invalidateQueries({ queryKey: ['ApiModeReportsController_detail_v1'] });
      });
  return (
    <Sheet open={Boolean(reportId)} onOpenChange={(next) => (!next ? onClose() : undefined)}>
      <SheetContent side="right" className="w-full overflow-y-auto sm:max-w-xl">
        <SheetHeader>
          <SheetTitle>Reported message</SheetTitle>
          <SheetDescription>
            {r ? `Reported by ${r.reporterAddress}` : 'A message a user reported'}
          </SheetDescription>
        </SheetHeader>
        <div className="grid gap-4 px-4 pb-6">
          {detail.isLoading ? (
            <LoadingState label="Loading the report" rows={6} />
          ) : detail.error ? (
            <ErrorState error={detail.error} onRetry={() => void detail.refetch()} compact />
          ) : r ? (
            <>
              <DetailList
                items={[
                  { label: 'Status', value: <ReportStatusBadge status={r.status} /> },
                  ...(r.rejectReason
                    ? [
                        {
                          label: 'Rejected because',
                          value: REJECT_REASON_TEXT[r.rejectReason] ?? humanize(r.rejectReason),
                        },
                      ]
                    : []),
                  {
                    label: 'Reporter',
                    value: (
                      <span className="grid gap-0.5">
                        <UntrustedText value={r.reporter.address} mono maxLength={80} />
                        <span className="text-xs text-muted-foreground">
                          {r.reporter.userId
                            ? 'Organization user'
                            : r.reporter.mailboxId
                              ? 'Organization mailbox'
                              : 'Not resolved to a mailbox or user'}
                        </span>
                      </span>
                    ),
                  },
                  {
                    label: 'Report mailbox',
                    value: <UntrustedText value={r.reportMailbox.address} mono maxLength={80} />,
                  },
                  { label: 'Reported', value: <DateTime value={r.reportedAt} mode="absolute" /> },
                  {
                    label: 'Identified by',
                    value: r.identification
                      ? (IDENTIFICATION_TEXT[r.identification] ?? humanize(r.identification))
                      : 'Not parsed yet',
                  },
                  {
                    label: 'Original message',
                    value: r.original ? (
                      <OriginalKeys original={r.original} />
                    ) : (
                      <span className="text-muted-foreground">Not identified</span>
                    ),
                  },
                  {
                    label: 'Original detection',
                    value: r.originalDetectionId ? (
                      <Link
                        href={detectionHref(r.originalDetectionId)}
                        className="text-primary underline-offset-2 hover:underline"
                      >
                        Open the detection
                      </Link>
                    ) : r.originalIngested ? (
                      'Not in a mailbox: the attached original was scanned on its own'
                    ) : (
                      <span className="text-muted-foreground">No copy found in a mailbox</span>
                    ),
                  },
                  {
                    label: 'Scan',
                    value: (
                      <span className="flex flex-wrap items-center gap-2">
                        <VerdictBadge verdict={r.scan.verdict} />
                        {r.scan.riskScore !== null ? (
                          <span className="text-xs tabular-nums">score {r.scan.riskScore}</span>
                        ) : null}
                        {r.scan.level ? (
                          <span className="text-xs">level {r.scan.level}</span>
                        ) : null}
                      </span>
                    ),
                  },
                  { label: 'Assessment', value: <AssessmentBadge assessment={r.assessment} /> },
                  {
                    label: 'Analyst verdict',
                    value: r.analyst.verdict ? (
                      <span className="grid gap-0.5">
                        <span>{VERDICT_TEXT[r.analyst.verdict]}</span>
                        {r.analyst.triagedAt ? (
                          <span className="text-xs text-muted-foreground">
                            <DateTime value={r.analyst.triagedAt} />
                          </span>
                        ) : null}
                      </span>
                    ) : (
                      'None yet'
                    ),
                  },
                  ...(r.analyst.note
                    ? [
                        {
                          label: 'Note',
                          value: <UntrustedText value={r.analyst.note} maxLength={1000} />,
                        },
                      ]
                    : []),
                  {
                    label: 'Feedback to the reporter',
                    value: `Acknowledgement: ${FEEDBACK_TEXT[r.feedback.acknowledgement] ?? r.feedback.acknowledgement} · Result: ${FEEDBACK_TEXT[r.feedback.result] ?? r.feedback.result}`,
                  },
                  {
                    label: 'Clawback',
                    value: r.clawbackId ? (
                      <Link
                        href={clawbackHref(r.clawbackId)}
                        className="text-primary underline-offset-2 hover:underline"
                      >
                        Open the clawback
                      </Link>
                    ) : (
                      'None'
                    ),
                  },
                  {
                    label: 'Report ID',
                    value: <CopyableId value={r.id} label="report ID" max={40} />,
                  },
                ]}
              />
              <section aria-label="Reports of the same message" className="grid gap-2">
                <h3 className="text-sm font-semibold">
                  Reports of the same message ({formatNumber(r.group.size)})
                </h3>
                {r.group.members.length <= 1 ? (
                  <p className="text-sm text-muted-foreground">Only this report.</p>
                ) : (
                  <ul className="grid gap-1 text-sm">
                    {r.group.members.map((m) => (
                      <li key={m.id} className="flex flex-wrap items-center gap-2">
                        {m.id === r.id ? (
                          <span className="text-xs font-medium">This report</span>
                        ) : (
                          <Button
                            size="sm"
                            variant="link"
                            className="h-auto p-0"
                            onClick={() => onOpen(m.id)}
                          >
                            <UntrustedText value={m.reporterAddress} mono maxLength={60} />
                          </Button>
                        )}
                        <ReportStatusBadge status={m.status} />
                        <DateTime value={m.reportedAt} />
                      </li>
                    ))}
                  </ul>
                )}
              </section>
              <section aria-label="Triage history" className="grid gap-2">
                <h3 className="text-sm font-semibold">Triage history</h3>
                {r.history.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No triage yet.</p>
                ) : (
                  <ol className="grid gap-1 text-sm">
                    {r.history.map((h, i) => (
                      <li key={`${h.at}-${i}`} className="flex flex-wrap items-center gap-2">
                        <DateTime value={h.at} />
                        <span>
                          {h.from ? humanize(h.from) : 'new'} → {h.to ? humanize(h.to) : '—'}
                          {h.verdict
                            ? ` (${VERDICT_TEXT[h.verdict as ReportVerdict] ?? humanize(h.verdict)})`
                            : ''}
                          {h.reopened ? ' · reopened' : ''}
                        </span>
                        <span className="text-xs text-muted-foreground">
                          {humanize(h.actor.type)}
                        </span>
                      </li>
                    ))}
                  </ol>
                )}
              </section>
              {review.error ? (
                <div role="alert" className="grid gap-1">
                  {reviewError ? (
                    <p className="text-sm font-medium text-destructive">{reviewError}</p>
                  ) : null}
                  <MutationError error={review.error} />
                </div>
              ) : null}
              <div className="flex flex-wrap gap-2">
                {canTriage && (r.status === 'pending_triage' || r.status === 'resolved') ? (
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={review.isPending}
                    onClick={() => startReview(r)}
                  >
                    {r.status === 'resolved' ? 'Reopen for review' : 'Start review'}
                  </Button>
                ) : null}
                {canTriage && OPEN_REPORT_STATUSES.includes(r.status) ? (
                  <>
                    <Button size="sm" onClick={() => onTriage({ report: r, status: 'resolved' })}>
                      Resolve…
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => onTriage({ report: r, status: 'rejected' })}
                    >
                      Reject…
                    </Button>
                  </>
                ) : null}
                {canClawback && r.original && r.status !== 'rejected' && !r.clawbackId ? (
                  <Button size="sm" variant="outline" onClick={() => onClawback(r.id)}>
                    Claw back this message…
                  </Button>
                ) : null}
              </div>
            </>
          ) : null}
        </div>
      </SheetContent>
    </Sheet>
  );
}

/** Tab "Reports" (C11, C14 #11–#14): the triage queue, the drawer and the triage actions. */
export function ReportsTab() {
  const [filters, setFilters] = useUrlState(URL_SHAPE);
  const [range] = useRangeState();
  const settings = useApiQuery('ApiModeSettingsController_get_v1');
  const [triaging, setTriaging] = useState<TriageTarget>(null);
  const [clawing, setClawing] = useState<string | null>(null);
  const [reporterDraft, setReporterDraft] = useState(filters.reporter ?? '');
  const { from, to } = range;
  const { status, assessment, verdict, reporter } = filters;
  const query = useMemo(
    () => reportQuery({ status, assessment, verdict, reporter }, { from, to }),
    [status, assessment, verdict, reporter, from, to],
  );
  const list = useCursorList('ApiModeReportsController_list_v1', query);
  const reporterId = useId();

  const columns = useMemo<DataTableColumn<Report>[]>(
    () => [
      {
        id: 'reportedAt',
        header: 'Reported',
        meta: { label: 'Reported', className: 'whitespace-nowrap' },
        cell: ({ row }) => (
          <Button
            variant="link"
            size="sm"
            className="h-auto p-0"
            onClick={() => setFilters({ report: row.original.id })}
          >
            <DateTime value={row.original.reportedAt} />
            <span className="sr-only">, open the report</span>
          </Button>
        ),
      },
      {
        id: 'reporter',
        header: 'Reporter',
        meta: { label: 'Reporter' },
        cell: ({ row }) => (
          <UntrustedText value={row.original.reporterAddress} mono maxLength={60} />
        ),
      },
      {
        id: 'status',
        header: 'Status',
        meta: { label: 'Status' },
        cell: ({ row }) => <ReportStatusBadge status={row.original.status} />,
      },
      {
        id: 'assessment',
        header: 'Assessment',
        meta: { label: 'Assessment' },
        cell: ({ row }) => <AssessmentBadge assessment={row.original.assessment} />,
      },
      {
        id: 'scan',
        header: 'Scan verdict',
        meta: { label: 'Scan verdict' },
        cell: ({ row }) => <VerdictBadge verdict={row.original.scan.verdict} />,
      },
      {
        id: 'verdict',
        header: 'Analyst verdict',
        meta: { label: 'Analyst verdict' },
        cell: ({ row }) =>
          row.original.analystVerdict ? (
            VERDICT_TEXT[row.original.analystVerdict]
          ) : (
            <span className="text-xs text-muted-foreground">None</span>
          ),
      },
      {
        id: 'group',
        header: 'Group',
        meta: { label: 'Reports of the same message' },
        cell: ({ row }) => (
          <span className="tabular-nums">{formatNumber(row.original.groupSize)}</span>
        ),
      },
      {
        id: 'clawback',
        header: 'Clawback',
        meta: { label: 'Clawback' },
        cell: ({ row }) =>
          row.original.clawbackId ? (
            <Link
              href={clawbackHref(row.original.clawbackId)}
              className="text-xs text-primary hover:underline"
            >
              Open
            </Link>
          ) : (
            <span className="text-xs text-muted-foreground">None</span>
          ),
      },
    ],
    [setFilters],
  );

  const isFiltered = Boolean(status || assessment || verdict || reporter);
  return (
    <div className="grid gap-4">
      <p className="max-w-3xl text-sm text-muted-foreground">
        Messages your users forwarded to a report mailbox. Each report is identified, scanned and
        waits for your triage; reports never act by themselves. A clawback from a report follows the
        approval rules of Search &amp; purge.
      </p>
      <DataTable
        tableId="api-mode-reports"
        caption="Reported messages"
        columns={columns}
        list={list}
        getRowId={(row) => row.id}
        getRowLabel={(row) => `${row.reporterAddress} ${row.reportedAt}`}
        filters={
          <>
            <RangePicker />
            <FilterSelect
              label="Status"
              value={status}
              onChange={(value) =>
                setFilters({ status: value as (typeof REPORT_STATUSES)[number] | undefined })
              }
              options={REPORT_STATUSES.map((value) => ({ value, label: humanize(value) }))}
            />
            <FilterSelect
              label="Assessment"
              value={assessment}
              onChange={(value) =>
                setFilters({
                  assessment: value as (typeof REPORT_ASSESSMENTS)[number] | undefined,
                })
              }
              options={REPORT_ASSESSMENTS.map((value) => ({ value, label: humanize(value) }))}
            />
            <FilterSelect
              label="Verdict"
              value={verdict}
              onChange={(value) =>
                setFilters({ verdict: value as (typeof REPORT_VERDICTS)[number] | undefined })
              }
              options={REPORT_VERDICTS.map((value) => ({ value, label: VERDICT_TEXT[value] }))}
            />
            <form
              className="flex items-center gap-1"
              onSubmit={(event) => {
                event.preventDefault();
                setFilters({ reporter: reporterDraft.trim() || undefined });
              }}
            >
              <Label htmlFor={reporterId} className="sr-only">
                Reporter address
              </Label>
              <Input
                id={reporterId}
                value={reporterDraft}
                placeholder="Reporter address"
                className="h-8 w-48"
                onChange={(event) => setReporterDraft(event.target.value)}
              />
              <Button type="submit" size="sm" variant="outline">
                Filter
              </Button>
            </form>
          </>
        }
        isFiltered={isFiltered}
        onClearFilters={() => {
          setReporterDraft('');
          setFilters({
            status: undefined,
            assessment: undefined,
            verdict: undefined,
            reporter: undefined,
          });
        }}
        rowActions={(row) => [{ label: 'Details', onSelect: () => setFilters({ report: row.id }) }]}
        emptyState={
          <EmptyState
            icon={FlagIcon}
            title="No reports in this range"
            description="Designate a report mailbox under Settings; messages your users forward to it appear here."
          />
        }
        mobileCard={(row) => (
          <div className="grid gap-1">
            <UntrustedText value={row.reporterAddress} mono maxLength={60} />
            <div className="flex flex-wrap items-center gap-2">
              <ReportStatusBadge status={row.status} />
              <DateTime value={row.reportedAt} />
            </div>
          </div>
        )}
      />
      <ReportDrawer
        reportId={filters.report}
        onClose={() => setFilters({ report: undefined })}
        onOpen={(id) => setFilters({ report: id })}
        onTriage={setTriaging}
        onClawback={setClawing}
      />
      {triaging ? (
        <TriageDialog
          key={`${triaging.report.id}-${triaging.status}`}
          target={triaging}
          feedbackDefault={settings.data?.settings.reportFeedbackEnabled ?? true}
          onOpenChange={(open) => !open && setTriaging(null)}
        />
      ) : null}
      <ReportClawbackDialog reportId={clawing} onOpenChange={(open) => !open && setClawing(null)} />
    </div>
  );
}
