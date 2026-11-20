'use client';

import { FileTextIcon } from 'lucide-react';
import Link from 'next/link';
import { useId, useMemo, useState } from 'react';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { DateTime } from '@/components/domain';
import { NotFoundView } from '@/components/not-found-view';
import { PageHeader } from '@/components/page-header';
import { EmptyState } from '@/components/states/empty-state';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { ApiError } from '@/lib/api/errors';
import { useApiMutation, useApiQuery, useCursorList } from '@/lib/api/hooks';
import { useCan, useMe } from '@/lib/auth/me';
import { RouteGate } from '@/lib/auth/route-gate';
import { humanize } from '@/lib/format';
import { CursorPager, DetailList, EnumBadge, Section } from '@/features/messages/controls';
import { AtoErrorSummary, AtoReasonDialog, pagerOf } from '@/features/ato/components';
import { categoryLabel, categoryUi } from './categories';
import {
  INCIDENT_SEVERITIES,
  RESOLUTION_LABELS,
  SEVERITY_TONE,
  STATUS_LABELS,
  STATUS_TONE,
  TRANSITION_LABELS,
  incidentReportHref,
  type IncidentDetail,
  type IncidentMessage,
  type IncidentSeverity,
  type ResolutionCode,
} from './model';

/** `/incidents/[incidentId]`: generic incident layout plus the category's panels (§6, D24). */
export function IncidentPage({ incidentId }: { incidentId: string }) {
  return (
    <RouteGate gate={['IncidentsController_get_v1']}>
      <IncidentContent incidentId={incidentId} />
    </RouteGate>
  );
}

const INVALIDATES = [
  'IncidentsController_get_v1',
  'IncidentsController_list_v1',
  'IncidentsController_timeline_v1',
  'AtoOverviewController_attention_v1',
  'AtoOverviewController_overview_v1',
  'AtoAccountsController_get_v1',
  'AtoAccountsController_list_v1',
] as const;

function IncidentContent({ incidentId }: { incidentId: string }) {
  const query = useApiQuery(
    'IncidentsController_get_v1',
    { path: { incidentId } },
    { retry: false },
  );
  if (query.isLoading) return <LoadingState label="Loading the incident" />;
  if (query.error instanceof ApiError && query.error.status === 404) return <NotFoundView />;
  if (query.error) return <ErrorState error={query.error} onRetry={() => void query.refetch()} />;
  if (!query.data) return null;
  return <IncidentView incident={query.data} />;
}

function IncidentView({ incident }: { incident: IncidentDetail }) {
  const ui = categoryUi(incident.category);
  const canReport = useCan('IncidentsController_report_v1');
  const subjectText = incident.subject.display ?? incident.subject.id;
  const subjectHref = ui?.subjectHref(incident.subject.id) ?? null;
  return (
    <div className="grid min-w-0 gap-4">
      <PageHeader
        title={`${categoryLabel(incident.category)}: ${subjectText}`}
        breadcrumbs={[{ label: 'Incidents', href: '/incidents' }, { label: subjectText }]}
        description={
          <span className="flex flex-wrap items-center gap-2">
            <EnumBadge value={incident.severity} tones={SEVERITY_TONE} />
            <EnumBadge value={incident.status} tones={STATUS_TONE} />
            <span>
              Detected <DateTime value={incident.detectedAt} mode="absolute" />
            </span>
          </span>
        }
        actions={
          canReport ? (
            <Button asChild variant="outline" size="sm">
              <Link href={incidentReportHref(incident.id)}>
                <FileTextIcon aria-hidden />
                Report
              </Link>
            </Button>
          ) : null
        }
      />
      <div className="grid min-w-0 gap-4 xl:grid-cols-2">
        <Section title="Summary">
          <DetailList
            items={[
              { label: 'Category', value: categoryLabel(incident.category) },
              {
                label: ui?.subjectLabel ?? 'Subject',
                value: subjectHref ? (
                  <Link
                    href={subjectHref}
                    className="text-primary underline-offset-2 hover:underline"
                  >
                    {subjectText}
                  </Link>
                ) : (
                  subjectText
                ),
              },
              {
                label: 'Severity',
                value: <EnumBadge value={incident.severity} tones={SEVERITY_TONE} />,
              },
              { label: 'Status', value: <EnumBadge value={incident.status} tones={STATUS_TONE} /> },
              {
                label: 'Origin',
                value: incident.origin === 'manual' ? 'Opened manually' : 'Detection',
              },
              {
                label: 'Detected',
                value: <DateTime value={incident.detectedAt} mode="absolute" />,
              },
              { label: 'Reason codes', value: incident.reasonCodes.join(', ') || '—' },
              {
                label: 'Escalated',
                value: <DateTime value={incident.escalatedAt} emptyLabel="No" mode="absolute" />,
              },
              {
                label: 'Resolution',
                hidden: !incident.resolution?.code,
                value: incident.resolution?.code ? (
                  <span className="grid gap-0.5">
                    <span>{RESOLUTION_LABELS[incident.resolution.code]}</span>
                    <span className="text-xs text-muted-foreground">
                      {incident.resolution.note}
                    </span>
                  </span>
                ) : null,
              },
            ]}
          />
        </Section>
        <WorkflowSection incident={incident} />
      </div>
      {ui ? <ui.DetailPanels incident={incident} /> : null}
      <MessagesSection incident={incident} />
      <TimelineSection incident={incident} />
    </div>
  );
}

function WorkflowSection({ incident }: { incident: IncidentDetail }) {
  const me = useMe();
  const myId = me.data?.user.id ?? null;
  const ui = categoryUi(incident.category);
  const [dialog, setDialog] = useState<'assign' | 'unassign' | 'severity' | null>(null);
  // The transition is kept as chosen while its dialog is open: the refetch after the change
  // drops it from `allowedTransitions`, and deriving it would close the dialog before the
  // mutation settles, whose late close then shut the next transition's dialog.
  const [transition, setTransition] = useState<IncidentDetail['allowedTransitions'][number] | null>(
    null,
  );
  const [resolution, setResolution] = useState<ResolutionCode | ''>('');
  const [feedback, setFeedback] = useState<Record<string, unknown>>({});
  const [severity, setSeverity] = useState<IncidentSeverity>(incident.severity);
  const resolutionId = useId();
  const severityId = useId();
  const update = useApiMutation('IncidentsController_update_v1', {
    invalidates: INVALIDATES,
    successMessage: 'Incident updated',
  });
  const closed = incident.status === 'false_positive' || incident.status === 'resolved';
  const base = { expectedRowVersion: incident.rowVersion };
  const open = (to: string) => {
    const t = incident.allowedTransitions.find((x) => x.to === to);
    setResolution(t?.resolutionCodes.length === 1 ? t.resolutionCodes[0]! : '');
    setFeedback(to === 'false_positive' && ui?.initialFeedback ? ui.initialFeedback() : {});
    setTransition(t ?? null);
  };
  return (
    <Section
      title="Investigation"
      description={
        incident.canManage
          ? 'Move the incident through its states; every change is recorded with your note.'
          : 'You can read this incident; triage needs the category’s manage permission.'
      }
    >
      <DetailList
        items={[
          {
            label: 'Assignee',
            value: !incident.assigneeId
              ? 'Unassigned'
              : incident.assigneeId === myId
                ? 'You'
                : 'Another analyst',
          },
          { label: 'Confirmed', value: <DateTime value={incident.confirmedAt} emptyLabel="—" /> },
          { label: 'Mitigated', value: <DateTime value={incident.mitigatedAt} emptyLabel="—" /> },
          { label: 'Resolved', value: <DateTime value={incident.resolvedAt} emptyLabel="—" /> },
        ]}
      />
      {incident.canManage && !closed ? (
        <div className="grid gap-2">
          <div className="flex flex-wrap gap-2" aria-label="Status changes">
            {incident.allowedTransitions.map((t) => (
              <Button
                key={t.to}
                size="sm"
                variant={t.to === 'false_positive' ? 'outline' : 'default'}
                onClick={() => open(t.to)}
              >
                {TRANSITION_LABELS[t.to]}
              </Button>
            ))}
          </div>
          <div className="flex flex-wrap gap-2">
            {incident.assigneeId !== myId && myId ? (
              <Button size="sm" variant="outline" onClick={() => setDialog('assign')}>
                Assign to me
              </Button>
            ) : null}
            {incident.assigneeId ? (
              <Button size="sm" variant="ghost" onClick={() => setDialog('unassign')}>
                Unassign
              </Button>
            ) : null}
            <Button size="sm" variant="ghost" onClick={() => setDialog('severity')}>
              Change severity
            </Button>
          </div>
          <NoteForm incident={incident} />
        </div>
      ) : null}
      <AtoReasonDialog
        open={transition !== null}
        onOpenChange={(next) => !next && setTransition(null)}
        title={transition ? `${TRANSITION_LABELS[transition.to]}?` : ''}
        description={
          transition?.to === 'false_positive'
            ? 'The incident closes as a false positive. Its feedback is applied in the same change.'
            : transition?.to === 'resolved'
              ? 'The incident closes; new signals open a new incident.'
              : `The status becomes “${transition ? STATUS_LABELS[transition.to] : ''}”.`
        }
        confirmLabel={transition ? TRANSITION_LABELS[transition.to] : 'Confirm'}
        reasonLabel={transition?.resolutionCodes.length ? 'Resolution note' : 'Note'}
        required={Boolean(
          transition && (transition.noteRequired || transition.resolutionCodes.length > 0),
        )}
        minChars={transition?.resolutionCodes.length ? 10 : 1}
        maxChars={4000}
        disabled={Boolean(transition?.resolutionCodes.length) && !resolution}
        pending={update.isPending}
        extra={
          transition ? (
            <div className="grid gap-3">
              {transition.resolutionCodes.length > 0 ? (
                <div className="grid gap-1.5">
                  <Label htmlFor={resolutionId}>Resolution</Label>
                  <Select
                    value={resolution || undefined}
                    onValueChange={(v) => setResolution(v as ResolutionCode)}
                  >
                    <SelectTrigger id={resolutionId}>
                      <SelectValue placeholder="Choose a resolution" />
                    </SelectTrigger>
                    <SelectContent>
                      {transition.resolutionCodes.map((code) => (
                        <SelectItem key={code} value={code}>
                          {RESOLUTION_LABELS[code]}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              ) : null}
              {transition.to === 'false_positive' && ui?.FeedbackFields ? (
                <ui.FeedbackFields incident={incident} value={feedback} onChange={setFeedback} />
              ) : null}
            </div>
          ) : null
        }
        onSubmit={(note) => {
          if (!transition) return Promise.resolve({ ok: true });
          const resolving = transition.resolutionCodes.length > 0;
          return update.submit({
            path: { incidentId: incident.id },
            body: {
              ...base,
              status: transition.to,
              ...(resolving && resolution
                ? { resolution: { code: resolution, note: note ?? '' } }
                : {}),
              ...(!resolving && note ? { note } : {}),
              ...(transition.to === 'false_positive' && ui?.FeedbackFields
                ? { categoryFeedback: feedback }
                : {}),
            },
          });
        }}
        onRetry={update.retry}
      />
      <AtoReasonDialog
        open={dialog === 'assign' || dialog === 'unassign'}
        onOpenChange={(next) => !next && setDialog(null)}
        title={dialog === 'assign' ? 'Assign the incident to you?' : 'Unassign the incident?'}
        description="The assignment is recorded in the timeline."
        confirmLabel={dialog === 'assign' ? 'Assign to me' : 'Unassign'}
        reasonLabel="Note"
        required={false}
        minChars={1}
        maxChars={4000}
        pending={update.isPending}
        onSubmit={(note) =>
          update.submit({
            path: { incidentId: incident.id },
            body: {
              ...base,
              assigneeId: dialog === 'assign' ? myId : null,
              ...(note ? { note } : {}),
            },
          })
        }
        onRetry={update.retry}
      />
      <AtoReasonDialog
        open={dialog === 'severity'}
        onOpenChange={(next) => !next && setDialog(null)}
        title="Change the severity"
        description="Analysts may raise or lower the severity; detection only ever raises it."
        confirmLabel="Change severity"
        reasonLabel="Note"
        required={false}
        minChars={1}
        maxChars={4000}
        disabled={severity === incident.severity}
        pending={update.isPending}
        extra={
          <div className="grid gap-1.5">
            <Label htmlFor={severityId}>Severity</Label>
            <Select value={severity} onValueChange={(v) => setSeverity(v as IncidentSeverity)}>
              <SelectTrigger id={severityId}>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {INCIDENT_SEVERITIES.map((s) => (
                  <SelectItem key={s} value={s}>
                    {humanize(s)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        }
        onSubmit={(note) =>
          update.submit({
            path: { incidentId: incident.id },
            body: { ...base, severity, ...(note ? { note } : {}) },
          })
        }
        onRetry={update.retry}
      />
    </Section>
  );
}

function NoteForm({ incident }: { incident: IncidentDetail }) {
  const id = useId();
  const [note, setNote] = useState('');
  const add = useApiMutation('IncidentsController_addNote_v1', {
    invalidates: ['IncidentsController_timeline_v1', 'IncidentsController_get_v1'],
    successMessage: 'Note added',
  });
  const trimmed = note.trim();
  return (
    <form
      className="grid gap-1.5"
      onSubmit={(event) => {
        event.preventDefault();
        if (!trimmed) return;
        void add
          .submit({ path: { incidentId: incident.id }, body: { note: trimmed } })
          .then((outcome) => {
            if (outcome.ok) setNote('');
          });
      }}
    >
      <Label htmlFor={id}>Investigation note</Label>
      <Textarea
        id={id}
        rows={3}
        maxLength={4000}
        value={note}
        onChange={(e) => setNote(e.target.value)}
      />
      {add.error ? <AtoErrorSummary error={add.error} /> : null}
      <div className="flex gap-2">
        <Button
          type="submit"
          size="sm"
          disabled={!trimmed || add.isPending || add.retryAfterSeconds > 0}
        >
          Add note
        </Button>
        {add.error ? (
          <Button type="button" size="sm" variant="outline" onClick={() => void add.retry()}>
            Retry the same request
          </Button>
        ) : null}
      </div>
    </form>
  );
}

function MessagesSection({ incident }: { incident: IncidentDetail }) {
  const list = useCursorList(
    'IncidentsController_messages_v1',
    { sort: '-receivedAt' },
    { path: { incidentId: incident.id }, limit: 25 },
  );
  const columns: DataTableColumn<IncidentMessage>[] = [
    {
      id: 'message',
      header: 'Message',
      meta: { label: 'Message', hideable: false },
      cell: ({ row }) =>
        row.original.id ? (
          <Link
            href={`/messages/${row.original.id}`}
            className="font-mono text-xs text-primary underline-offset-2 hover:underline"
          >
            {`${row.original.id.slice(0, 8)}…`}
            <span className="sr-only">{` Open message ${row.original.id}`}</span>
          </Link>
        ) : (
          <span className="text-muted-foreground">Unavailable</span>
        ),
    },
    {
      id: 'received',
      header: 'Received',
      meta: { label: 'Received' },
      cell: ({ row }) => <DateTime value={row.original.receivedAt} />,
    },
    {
      id: 'direction',
      header: 'Direction',
      meta: { label: 'Direction' },
      cell: ({ row }) => humanize(row.original.direction),
    },
    {
      id: 'verdict',
      header: 'Verdict and action',
      meta: { label: 'Verdict and action' },
      cell: ({ row }) =>
        `${row.original.finalVerdict ? humanize(row.original.finalVerdict) : '—'} · ${row.original.finalAction ? humanize(row.original.finalAction) : '—'}`,
    },
    {
      id: 'recipients',
      header: 'Recipients',
      meta: { label: 'Recipients' },
      cell: ({ row }) =>
        `${row.original.recipientCount} (${row.original.externalDomainCount} external domains)`,
    },
    {
      id: 'findings',
      header: 'Findings',
      meta: { label: 'Findings' },
      cell: ({ row }) => (
        <span className="font-mono text-xs">{row.original.findingCodes.join(', ') || '—'}</span>
      ),
    },
  ];
  return (
    <Section
      title="Related messages"
      description="Messages linked as evidence. Subjects and recipient addresses are not shown here; open a message for its details (masked per your permissions)."
    >
      <DataTable
        tableId="incident-messages"
        caption="Messages linked to the incident"
        columns={columns}
        list={list}
        getRowId={(row) => `${row.id ?? 'none'}-${row.receivedAt}`}
        emptyState={<EmptyState title="No linked messages" />}
      />
    </Section>
  );
}

function TimelineSection({ incident }: { incident: IncidentDetail }) {
  const list = useCursorList(
    'IncidentsController_timeline_v1',
    { sort: 'at' },
    { path: { incidentId: incident.id }, limit: 50 },
  );
  const me = useMe();
  const rows = useMemo(() => list.rows, [list.rows]);
  return (
    <Section
      title="Timeline and notes"
      description="Every state, severity, assignment, note and response change, oldest first."
    >
      {list.query.isLoading ? (
        <LoadingState label="Loading the timeline" />
      ) : list.query.error ? (
        <ErrorState error={list.query.error} onRetry={() => void list.query.refetch()} compact />
      ) : rows.length === 0 ? (
        <EmptyState title="No timeline entries" />
      ) : (
        <ol className="grid gap-2" aria-label="Incident timeline">
          {rows.map((e) => (
            <li key={e.id} className="grid gap-0.5 rounded-md border p-2 text-sm">
              <span className="flex flex-wrap items-center gap-2">
                <span className="font-medium">{humanize(e.type.replace(/^ato\./, ''))}</span>
                <span className="text-xs text-muted-foreground">
                  <DateTime value={e.at} mode="absolute" /> ·{' '}
                  {e.actor.type === 'system'
                    ? 'System'
                    : e.actor.id && e.actor.id === me.data?.user.id
                      ? 'You'
                      : humanize(e.actor.type)}
                </span>
              </span>
              {e.fromStatus || e.toStatus ? (
                <span className="text-xs">
                  {e.fromStatus ? STATUS_LABELS[e.fromStatus] : '—'} →{' '}
                  {e.toStatus ? STATUS_LABELS[e.toStatus] : '—'}
                </span>
              ) : null}
              {e.fromSeverity || e.toSeverity ? (
                <span className="text-xs">
                  Severity {e.fromSeverity ? humanize(e.fromSeverity) : '—'} →{' '}
                  {e.toSeverity ? humanize(e.toSeverity) : '—'}
                </span>
              ) : null}
              {e.note ? <p className="text-sm whitespace-pre-wrap">{e.note}</p> : null}
            </li>
          ))}
        </ol>
      )}
      <CursorPager label="Timeline" state={pagerOf(list)} />
    </Section>
  );
}
