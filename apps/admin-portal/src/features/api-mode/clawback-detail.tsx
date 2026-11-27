'use client';

import { useQueryClient } from '@tanstack/react-query';
import { ArrowLeftIcon, ClockIcon, ShieldAlertIcon } from 'lucide-react';
import Link from 'next/link';
import { useId, useMemo, useState, type ReactNode } from 'react';
import { DataTable, type DataTableColumn } from '@/components/data-table';
import { VerdictBadge } from '@/components/domain/badges';
import { CopyableId } from '@/components/domain/copyable-id';
import { DateTime } from '@/components/domain/date-time';
import { UntrustedText } from '@/components/domain/untrusted-text';
import { EmptyState } from '@/components/states/empty-state';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import { Textarea } from '@/components/ui/textarea';
import { useApiMutation, useApiQuery, useCursorList } from '@/lib/api/hooks';
import { useCan, useMe } from '@/lib/auth/me';
import { formatNumber, humanize } from '@/lib/format';
import {
  DetailList,
  FilterSelect,
  FormDialog,
  LabelledSelect,
  MutationError,
  Section,
} from '@/features/domains/kit';
import { ReasonConfirm } from '@/features/quarantine/reason-confirm';
import {
  APPROVAL_REASON_TEXT,
  ApprovalBadge,
  CLAWBACK_POLL_MS,
  CLAWBACK_QUERIES,
  ClawbackProgress,
  ClawbackStatusBadge,
  MATCH_KEY_TEXT,
  POLLED_CLAWBACK_STATUSES,
  REASON_MAX_CHARS,
  RestoreStatusBadge,
  SIGNAL_KIND_TEXT,
  TARGET_STATUSES,
  TRIGGER_TEXT,
  TargetStatusBadge,
  clawbackErrorText,
  explainClawbackError,
  reportHref,
  targetReasonText,
  type ClawbackDetail,
  type ClawbackTarget,
  type SubmitClawbackBody,
} from './clawback-model';
import {
  HARD_DELETE_WARNING,
  RULE_LEVELS,
  RemediationStateBadge,
  actionLabel,
  detectionHref,
  historyHref,
  type RuleLevel,
} from './remediation-model';

const AUTOMATIC = new Set(['late_verdict', 'threat_intel']);
const SUBMIT_VERDICTS = ['malware', 'phishing', 'bec', 'suspicious', 'spam'] as const;
type SubmitVerdict = (typeof SUBMIT_VERDICTS)[number];
const EXPLICIT_ACTIONS = ['move_quarantine', 'move_junk', 'soft_delete'] as const;
type ExplicitAction = (typeof EXPLICIT_ACTIONS)[number];

/** Whether a submit of this clawback needs a second approver (C6; the api decides). */
export function approvalNeeded(
  clawback: Pick<ClawbackDetail, 'counts' | 'approval' | 'status'>,
  threshold: number | null,
): { needed: boolean; reasons: string[] } {
  const reasons: string[] = [];
  if (threshold !== null && clawback.counts.mailboxesEligible > threshold)
    reasons.push(APPROVAL_REASON_TEXT.mailbox_threshold);
  if (clawback.status === 'review_required' && clawback.approval.reasons.includes('auto_cap'))
    reasons.push(APPROVAL_REASON_TEXT.auto_cap);
  return { needed: reasons.length > 0, reasons };
}

function ApprovalPreview({
  clawback,
  threshold,
  hardDelete = false,
}: {
  clawback: ClawbackDetail;
  threshold: number | null;
  hardDelete?: boolean;
}) {
  const { needed, reasons } = approvalNeeded(clawback, threshold);
  const all = hardDelete ? [...reasons, APPROVAL_REASON_TEXT.hard_delete] : reasons;
  return (
    <div role="note" className="grid gap-1 rounded-md border bg-muted/40 px-3 py-2 text-sm">
      <span>
        <strong className="tabular-nums">
          {formatNumber(clawback.counts.mailboxesEligible)} eligible mailbox
          {clawback.counts.mailboxesEligible === 1 ? '' : 'es'}
        </strong>{' '}
        ({formatNumber(clawback.counts.targetsEligible)} messages)
        {threshold !== null ? (
          <>
            {' '}
            · approval threshold <span className="tabular-nums">
              {formatNumber(threshold)}
            </span>{' '}
            mailboxes
          </>
        ) : null}
      </span>
      {needed || hardDelete ? (
        <span className="font-medium">
          Needs a second approver ({all.join('; ')}): another person with the purge permission
          approves before anything changes in a mailbox.
        </span>
      ) : (
        <span>Below the threshold: the purge is queued right away.</span>
      )}
    </div>
  );
}

/** "Submit…" (C14 #5): the remediation policy with a chosen verdict, or an explicit action. */
export function SubmitDialog({
  clawback,
  threshold,
  open,
  onOpenChange,
}: {
  clawback: ClawbackDetail;
  threshold: number | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const base = useId();
  const queryClient = useQueryClient();
  const automatic = AUTOMATIC.has(clawback.trigger);
  const [mode, setMode] = useState<'policy' | 'explicit'>(automatic ? 'policy' : 'explicit');
  const signalVerdict = clawback.signal.verdict;
  const [verdict, setVerdict] = useState<SubmitVerdict>(
    (SUBMIT_VERDICTS as readonly string[]).includes(signalVerdict ?? '')
      ? (signalVerdict as SubmitVerdict)
      : 'phishing',
  );
  const [level, setLevel] = useState<RuleLevel>(clawback.signal.level ?? 'critical');
  const [action, setAction] = useState<ExplicitAction>('move_quarantine');
  const [reason, setReason] = useState('');
  const [hint, setHint] = useState<string | null>(null);
  const submit = useApiMutation('ApiModeClawbackController_submit_v1', {
    invalidates: CLAWBACK_QUERIES,
    successMessage: null,
  });
  const close = (next: boolean) => {
    if (!next) {
      setReason('');
      setHint(null);
      submit.reset();
    }
    onOpenChange(next);
  };
  const errorText = clawbackErrorText(submit.error);
  return (
    <FormDialog
      open={open}
      onOpenChange={close}
      wide
      title="Submit the purge"
      description="Choose how the hit list is remediated. Each message goes through the mailbox actions of API-mode remediation (budgets, audit, quarantine entries, restore)."
    >
      <form
        className="grid gap-4"
        aria-label="Submit the purge"
        onSubmit={(event) => {
          event.preventDefault();
          const text = reason.trim();
          if (!text) return setHint('Enter a reason.');
          setHint(null);
          const body: SubmitClawbackBody =
            mode === 'policy'
              ? automatic
                ? { mode, reason: text, expectedRowVersion: clawback.rowVersion }
                : { mode, verdict, level, reason: text, expectedRowVersion: clawback.rowVersion }
              : { mode, action, reason: text, expectedRowVersion: clawback.rowVersion };
          void submit.submit({ path: { clawbackId: clawback.id }, body }).then(async (outcome) => {
            if (outcome.ok) {
              close(false);
              return;
            }
            if (outcome.error.code === 'api_mode_clawback_state_conflict')
              await queryClient.invalidateQueries({
                queryKey: ['ApiModeClawbackController_detail_v1'],
              });
          });
        }}
      >
        <ApprovalPreview clawback={clawback} threshold={threshold} />
        <fieldset className="grid gap-2">
          <legend className="text-sm font-medium">Decision</legend>
          <RadioGroup
            value={mode}
            onValueChange={(value) => setMode(value as 'policy' | 'explicit')}
            className="grid gap-2"
          >
            <div className="flex items-center gap-2">
              <RadioGroupItem id={`${base}-policy`} value="policy" />
              <Label htmlFor={`${base}-policy`} className="font-normal">
                Remediation policy (each mailbox&apos;s policy decides the action)
              </Label>
            </div>
            <div className="flex items-center gap-2">
              <RadioGroupItem id={`${base}-explicit`} value="explicit" />
              <Label htmlFor={`${base}-explicit`} className="font-normal">
                Explicit action for every message
              </Label>
            </div>
          </RadioGroup>
        </fieldset>
        {mode === 'policy' ? (
          automatic ? (
            <p className="text-sm text-muted-foreground">
              The policy decides with the signal&apos;s verdict
              {clawback.signal.verdict ? ` (${humanize(clawback.signal.verdict)})` : ''} and level.
            </p>
          ) : (
            <div className="grid gap-3 sm:grid-cols-2">
              <LabelledSelect
                id={`${base}-verdict`}
                label="Verdict to decide on"
                value={verdict}
                onChange={(value) => setVerdict(value as SubmitVerdict)}
                options={SUBMIT_VERDICTS.map((value) => ({ value, label: humanize(value) }))}
              />
              <LabelledSelect
                id={`${base}-level`}
                label="Risk level"
                value={level}
                onChange={(value) => setLevel(value as RuleLevel)}
                options={RULE_LEVELS.map((value) => ({ value, label: humanize(value) }))}
              />
            </div>
          )
        ) : (
          <fieldset className="grid gap-2">
            <legend className="text-sm font-medium">Mailbox action</legend>
            <RadioGroup
              value={action}
              onValueChange={(value) => setAction(value as ExplicitAction)}
              className="grid gap-2"
            >
              {EXPLICIT_ACTIONS.map((value) => (
                <div key={value} className="flex items-center gap-2">
                  <RadioGroupItem id={`${base}-${value}`} value={value} />
                  <Label htmlFor={`${base}-${value}`} className="font-normal">
                    {actionLabel(value)}
                  </Label>
                </div>
              ))}
            </RadioGroup>
            <p className="text-xs text-muted-foreground">
              Each move creates a quarantine entry that can be restored. A clawback never weakens a
              stronger remediation already in place.
            </p>
          </fieldset>
        )}
        <div className="grid gap-2">
          <Label htmlFor={`${base}-reason`}>Reason (required)</Label>
          <Textarea
            id={`${base}-reason`}
            rows={2}
            maxLength={REASON_MAX_CHARS}
            value={reason}
            onChange={(event) => setReason(event.target.value)}
          />
        </div>
        {hint ? (
          <p role="alert" className="text-sm font-medium text-destructive">
            {hint}
          </p>
        ) : null}
        {submit.error ? (
          <div role="alert" className="grid gap-1">
            {errorText ? <p className="text-sm font-medium text-destructive">{errorText}</p> : null}
            <MutationError error={submit.error} />
          </div>
        ) : null}
        <div className="flex flex-wrap gap-2">
          <Button type="submit" size="sm" disabled={submit.isPending}>
            {submit.isPending ? 'Submitting …' : 'Submit purge'}
          </Button>
          <Button type="button" size="sm" variant="ghost" onClick={() => close(false)}>
            Cancel
          </Button>
        </div>
      </form>
    </FormDialog>
  );
}

function SignalCriteria({ c }: { c: ClawbackDetail }) {
  const k = c.criteria.keys;
  const keys: Array<{ label: string; value: ReactNode }> = [];
  const hashes = (values: readonly string[]) => (
    <ul className="grid gap-0.5 font-mono text-xs">
      {values.map((v) => (
        <li key={v}>{v}</li>
      ))}
    </ul>
  );
  if (k.messageIdHashes.length > 0)
    keys.push({ label: 'Message-ID (hash)', value: hashes(k.messageIdHashes) });
  if (k.attachmentSha256.length > 0)
    keys.push({ label: 'Attachment SHA-256', value: hashes(k.attachmentSha256) });
  if (k.urlSha256.length > 0) keys.push({ label: 'URL (hash)', value: hashes(k.urlSha256) });
  if (k.urlDomains.length > 0) keys.push({ label: 'URL domains', value: k.urlDomains.join(', ') });
  if (k.senders.length > 0)
    keys.push({
      label: 'Senders',
      value: (
        <span className="grid">
          {k.senders.map((s) => (
            <UntrustedText key={s} value={s} mono />
          ))}
        </span>
      ),
    });
  if (k.senderDomains.length > 0)
    keys.push({ label: 'Sender domains', value: k.senderDomains.join(', ') });
  if (k.senderSubject)
    keys.push({
      label: 'Sender and subject',
      value: (
        <span className="grid gap-0.5">
          <UntrustedText value={k.senderSubject.sender} mono />
          <span className="text-xs">
            Subject key: <UntrustedText value={k.senderSubject.subjectKey} maxLength={128} />
          </span>
        </span>
      ),
    });
  return (
    <Section
      title="Signal and criteria"
      description="What started the clawback and what the search matched on. Hashes are shown shortened; the subject key is normalized operator or message text."
    >
      <DetailList
        items={[
          {
            label: 'Signal',
            value: c.signal.kind
              ? (SIGNAL_KIND_TEXT[c.signal.kind] ?? humanize(c.signal.kind))
              : 'None',
          },
          {
            label: 'Signal verdict',
            value: c.signal.verdict ? (
              <span className="flex flex-wrap items-center gap-2">
                <VerdictBadge verdict={c.signal.verdict} />
                {c.signal.level ? <span className="text-xs">level {c.signal.level}</span> : null}
                {c.signal.hardBlocks.length > 0 ? (
                  <span className="font-mono text-xs">{c.signal.hardBlocks.join(', ')}</span>
                ) : null}
              </span>
            ) : (
              'Not set (chosen at submit)'
            ),
          },
          ...(c.signal.seedDetectionId
            ? [
                {
                  label: 'Seed detection',
                  value: (
                    <Link
                      href={detectionHref(c.signal.seedDetectionId)}
                      className="text-primary underline-offset-2 hover:underline"
                    >
                      Open the detection
                    </Link>
                  ),
                },
              ]
            : []),
          ...(c.reportId
            ? [
                {
                  label: 'Report',
                  value: (
                    <Link
                      href={reportHref(c.reportId)}
                      className="text-primary underline-offset-2 hover:underline"
                    >
                      Open the report
                    </Link>
                  ),
                },
              ]
            : []),
          {
            label: 'Window',
            value: (
              <span>
                <DateTime value={c.criteria.window.from} mode="absolute" /> to{' '}
                <DateTime value={c.criteria.window.to} mode="absolute" />
              </span>
            ),
          },
          {
            label: 'Directions',
            value: c.criteria.directions.map((d) => humanize(d)).join(', ') || 'None',
          },
          ...keys,
        ]}
      />
    </Section>
  );
}

function CountTile({ label, value, detail }: { label: string; value: number; detail?: string }) {
  return (
    <Card className="gap-1 px-4 py-3">
      <h4 className="text-xs font-medium text-muted-foreground">{label}</h4>
      <p className="text-lg font-semibold tabular-nums">{formatNumber(value)}</p>
      {detail ? <p className="text-xs text-muted-foreground">{detail}</p> : null}
    </Card>
  );
}

function Counts({ c }: { c: ClawbackDetail }) {
  const n = c.counts;
  return (
    <Section
      title="Counts"
      description={
        c.status === 'searching'
          ? 'The mailbox worker is searching the recorded copies; the counts appear when the hit list is ready.'
          : 'The hit list is frozen: what you preview is exactly what a purge acts on.'
      }
    >
      <ul className="grid gap-3 sm:grid-cols-3 xl:grid-cols-6" aria-label="Clawback counts">
        <li>
          <CountTile
            label="Messages found"
            value={n.targetsTotal}
            detail={`${formatNumber(n.mailboxesTotal)} mailboxes`}
          />
        </li>
        <li>
          <CountTile
            label="Eligible"
            value={n.targetsEligible}
            detail={`${formatNumber(n.mailboxesEligible)} mailboxes`}
          />
        </li>
        <li>
          <CountTile
            label="Skipped"
            value={n.skipped}
            detail={`${formatNumber(n.simulated)} simulated`}
          />
        </li>
        <li>
          <CountTile label="Queued" value={n.queued} />
        </li>
        <li>
          <CountTile label="Succeeded" value={n.succeeded} />
        </li>
        <li>
          <CountTile
            label="Failed"
            value={n.failed}
            detail={`${formatNumber(n.cancelled)} cancelled`}
          />
        </li>
      </ul>
      <ClawbackProgress counts={n} label="Purge progress" />
    </Section>
  );
}

function ApprovalBlock({
  c,
  onDecide,
}: {
  c: ClawbackDetail;
  onDecide: (decision: 'approve' | 'deny') => void;
}) {
  const me = useMe();
  const canPurge = useCan('ApiModeClawbackController_approve_v1');
  const myId = me.data?.user.id ?? null;
  const mine = myId !== null && (c.requestedBy.userId === myId || c.submittedBy === myId);
  const pending = c.approval.status === 'pending';
  const who = (id: string | null, type?: string) =>
    id ? <CopyableId value={id} label="user ID" max={40} /> : humanize(type ?? 'system');
  return (
    <Section
      title="Approval"
      description="Purges above the threshold, hard deletes and large automatic clawbacks need a second person with the purge permission (not the requester or submitter)."
      actions={<ApprovalBadge status={c.approval.status} />}
    >
      <DetailList
        items={[
          { label: 'Requested by', value: who(c.requestedBy.userId, c.requestedBy.type) },
          { label: 'Submitted by', value: c.submittedBy ? who(c.submittedBy) : 'Not submitted' },
          {
            label: 'Reasons',
            value:
              c.approval.reasons.length > 0
                ? c.approval.reasons.map((r) => APPROVAL_REASON_TEXT[r] ?? humanize(r)).join('; ')
                : 'None',
          },
          {
            label: 'Requested',
            value: <DateTime value={c.approval.requestedAt} mode="absolute" emptyLabel="Not yet" />,
          },
          {
            label: 'Expires',
            value: <DateTime value={c.approval.expiresAt} mode="absolute" emptyLabel="None" />,
          },
          {
            label: 'Decided',
            value: (
              <span className="grid gap-0.5">
                <DateTime value={c.approval.decidedAt} mode="absolute" emptyLabel="Not yet" />
                {c.approvalDecision.decidedBy ? (
                  <span className="text-xs">by {who(c.approvalDecision.decidedBy)}</span>
                ) : null}
                {c.approvalDecision.reason ? (
                  <span className="text-xs">
                    Reason: <UntrustedText value={c.approvalDecision.reason} maxLength={500} />
                  </span>
                ) : null}
              </span>
            ),
          },
        ]}
      />
      {pending && c.hints.canApprove ? (
        <div className="flex flex-wrap gap-2">
          <Button size="sm" onClick={() => onDecide('approve')}>
            Approve
          </Button>
          <Button size="sm" variant="outline" onClick={() => onDecide('deny')}>
            Deny
          </Button>
        </div>
      ) : pending ? (
        <p
          role="status"
          className="flex items-start gap-2 rounded-md bg-tone-purple px-3 py-2 text-sm text-tone-purple-foreground"
        >
          <ClockIcon className="mt-0.5 size-4 shrink-0" aria-hidden />
          <span>
            <strong>Waiting for approval.</strong>{' '}
            {mine
              ? 'You requested this purge, so another person with the purge permission must approve or deny it.'
              : canPurge
                ? 'You cannot decide this request.'
                : 'A person with the purge permission approves or denies it.'}
          </span>
        </p>
      ) : null}
    </Section>
  );
}

const RESTORE_STATUSES = ['none', 'queued', 'succeeded', 'failed', 'skipped'] as const;

function TargetsTable({ c }: { c: ClawbackDetail }) {
  const [status, setStatus] = useState<string | undefined>(undefined);
  const [restoreStatus, setRestoreStatus] = useState<string | undefined>(undefined);
  const filters = useMemo(
    () => ({ ...(status ? { status } : {}), ...(restoreStatus ? { restoreStatus } : {}) }),
    [status, restoreStatus],
  );
  const list = useCursorList('ApiModeClawbackController_targets_v1', filters, {
    path: { clawbackId: c.id },
    enabled: c.status !== 'searching',
    queryOptions: { refetchOnWindowFocus: false },
  });
  const showMessage = list.rows.some((r) => r.headerFrom !== null || r.subject !== null);
  const columns = useMemo<DataTableColumn<ClawbackTarget>[]>(
    () => [
      {
        id: 'mailbox',
        header: 'Mailbox',
        meta: { label: 'Mailbox' },
        cell: ({ row }) => (
          <UntrustedText value={row.original.mailbox.address} mono maxLength={60} />
        ),
      },
      {
        id: 'receivedAt',
        header: 'Received',
        meta: { label: 'Received', className: 'whitespace-nowrap' },
        cell: ({ row }) => <DateTime value={row.original.receivedAt} />,
      },
      ...(showMessage
        ? [
            {
              id: 'message',
              header: 'Sender and subject',
              meta: { label: 'Sender and subject' },
              cell: ({ row }: { row: { original: ClawbackTarget } }) => (
                <span className="grid gap-0.5">
                  <UntrustedText
                    value={row.original.headerFrom}
                    mono
                    maxLength={60}
                    emptyLabel="Unknown"
                  />
                  <UntrustedText
                    value={row.original.subject}
                    maxLength={80}
                    emptyLabel="No subject"
                  />
                </span>
              ),
            } satisfies DataTableColumn<ClawbackTarget>,
          ]
        : []),
      {
        id: 'matchKeys',
        header: 'Matched on',
        meta: { label: 'Matched on' },
        cell: ({ row }) =>
          row.original.matchKeys.map((k) => MATCH_KEY_TEXT[k] ?? humanize(k)).join(', '),
      },
      {
        id: 'copyState',
        header: 'Remediation',
        meta: { label: 'Remediation state' },
        cell: ({ row }) =>
          row.original.copyRemediationState ? (
            <RemediationStateBadge state={row.original.copyRemediationState} />
          ) : (
            <span className="text-xs text-muted-foreground">Copy expired</span>
          ),
      },
      {
        id: 'status',
        header: 'Target',
        meta: { label: 'Target status' },
        cell: ({ row }) => (
          <span className="grid justify-items-start gap-0.5">
            <TargetStatusBadge status={row.original.status} />
            {row.original.reasonCode ? (
              <span className="text-xs text-muted-foreground">
                {targetReasonText(row.original.reasonCode)}
              </span>
            ) : null}
          </span>
        ),
      },
      {
        id: 'plannedAction',
        header: 'Planned action',
        meta: { label: 'Planned action' },
        cell: ({ row }) =>
          row.original.plannedAction ? (
            actionLabel(row.original.plannedAction)
          ) : (
            <span className="text-xs text-muted-foreground">Decided at submit</span>
          ),
      },
      {
        id: 'restore',
        header: 'Restore',
        meta: { label: 'Restore result' },
        cell: ({ row }) => (
          <span className="grid justify-items-start gap-0.5">
            <RestoreStatusBadge status={row.original.restoreStatus} />
            {row.original.restoreReasonCode ? (
              <span className="text-xs text-muted-foreground">
                {targetReasonText(row.original.restoreReasonCode)}
              </span>
            ) : null}
          </span>
        ),
      },
      {
        id: 'links',
        header: 'Links',
        meta: { label: 'Links' },
        cell: ({ row }) => (
          <span className="grid text-xs">
            {row.original.detectionId ? (
              <Link
                href={detectionHref(row.original.detectionId)}
                className="text-primary hover:underline"
              >
                Detection
              </Link>
            ) : null}
            {row.original.remediationId ? (
              <Link
                href={historyHref({ remediationId: row.original.remediationId })}
                className="text-primary hover:underline"
              >
                Mailbox action
              </Link>
            ) : null}
          </span>
        ),
      },
    ],
    [showMessage],
  );
  if (c.status === 'searching') return null;
  return (
    <Section
      title="Hit list"
      description="Every recorded copy the search found, with its eligibility, the planned action and the result. Sender and subject are shown only to holders of the purge permission."
    >
      <DataTable
        tableId="api-mode-clawback-targets"
        caption="Messages found by the clawback"
        columns={columns}
        list={list}
        getRowId={(row) => `${row.mailbox.id}:${row.receivedAt}:${row.detectionId ?? ''}`}
        getRowLabel={(row) => `${row.mailbox.address} ${row.receivedAt}`}
        filters={
          <>
            <FilterSelect
              label="Target status"
              value={status}
              onChange={setStatus}
              options={TARGET_STATUSES.map((value) => ({ value, label: humanize(value) }))}
            />
            <FilterSelect
              label="Restore"
              value={restoreStatus}
              onChange={setRestoreStatus}
              options={RESTORE_STATUSES.map((value) => ({ value, label: humanize(value) }))}
            />
          </>
        }
        isFiltered={Boolean(status || restoreStatus)}
        onClearFilters={() => {
          setStatus(undefined);
          setRestoreStatus(undefined);
        }}
        emptyState={
          <EmptyState
            title="No messages"
            description={
              c.status === 'no_match'
                ? 'The search found no recorded copy in the window.'
                : c.status === 'too_broad'
                  ? 'The search matched more copies than one clawback may hold; narrow the criteria and search again.'
                  : 'No message matches these filters.'
            }
          />
        }
        mobileCard={(row) => (
          <div className="grid gap-1">
            <UntrustedText value={row.mailbox.address} mono maxLength={60} />
            <div className="flex flex-wrap items-center gap-2">
              <TargetStatusBadge status={row.status} />
              <DateTime value={row.receivedAt} />
            </div>
          </div>
        )}
      />
    </Section>
  );
}

/**
 * Detail view of one clawback (`?clawback=`; C14 #3/#4): signal and criteria, counts and
 * progress, the approval block, the hit list and the actions the api's hints allow — Submit,
 * Hard delete (platform setting), Approve/Deny, Cancel and Restore. Polls while searching, queued
 * or running.
 */
export function ClawbackDetailView({
  clawbackId,
  onBack,
}: {
  clawbackId: string;
  onBack: () => void;
  onOpen?: (clawbackId: string) => void;
}) {
  const detail = useApiQuery(
    'ApiModeClawbackController_detail_v1',
    { path: { clawbackId } },
    {
      refetchInterval: (query) =>
        query.state.data && POLLED_CLAWBACK_STATUSES.includes(query.state.data.status)
          ? CLAWBACK_POLL_MS
          : false,
    },
  );
  const settings = useApiQuery('ApiModeSettingsController_get_v1');
  const [dialog, setDialog] = useState<
    null | 'submit' | 'hardDelete' | 'approve' | 'deny' | 'cancel' | 'restore'
  >(null);
  const approve = useApiMutation('ApiModeClawbackController_approve_v1', {
    invalidates: CLAWBACK_QUERIES,
    successMessage: 'Approved: the purge is queued.',
  });
  const deny = useApiMutation('ApiModeClawbackController_deny_v1', {
    invalidates: CLAWBACK_QUERIES,
    successMessage: 'Denied: nothing changes in the mailboxes.',
  });
  const cancel = useApiMutation('ApiModeClawbackController_cancel_v1', {
    invalidates: CLAWBACK_QUERIES,
    successMessage: 'Cancel requested.',
  });
  const restore = useApiMutation('ApiModeClawbackController_restore_v1', {
    invalidates: CLAWBACK_QUERIES,
    successMessage:
      'Restore requested: the mailbox worker restores what the provider allows; per-message results appear in the hit list.',
  });
  const hardDelete = useApiMutation('ApiModeClawbackController_submitHardDelete_v1', {
    invalidates: CLAWBACK_QUERIES,
    successMessage: 'Hard delete requested: a second person must approve it.',
  });
  const back = (
    <Button size="sm" variant="ghost" className="justify-self-start" onClick={onBack}>
      <ArrowLeftIcon aria-hidden />
      All clawbacks
    </Button>
  );
  if (detail.isLoading)
    return (
      <div className="grid gap-4">
        {back}
        <LoadingState label="Loading the clawback" rows={6} />
      </div>
    );
  if (detail.error)
    return (
      <div className="grid gap-4">
        {back}
        <ErrorState error={detail.error} onRetry={() => void detail.refetch()} />
      </div>
    );
  const c = detail.data;
  if (!c) return null;
  const threshold = settings.data?.settings.purgeApprovalMailboxes ?? null;
  const hardDeleteAvailable = settings.data?.platform.hardDeleteAvailable === true;
  const version = c.rowVersion;
  return (
    <div className="grid min-w-0 gap-6 [&>*]:min-w-0" aria-label="Clawback">
      {back}
      <section aria-labelledby="clawback-heading" className="grid gap-2">
        <div className="flex flex-wrap items-center gap-3">
          <h2 id="clawback-heading" className="text-lg font-semibold">
            {TRIGGER_TEXT[c.trigger] ?? humanize(c.trigger)}
          </h2>
          <ClawbackStatusBadge status={c.status} />
          {c.cancelRequested && c.status !== 'cancelled' ? (
            <span className="text-xs text-muted-foreground">Cancel requested</span>
          ) : null}
          {c.action ? (
            <span className="text-sm">
              {actionLabel(c.action)}
              {c.action === 'hard_delete' ? (
                <ShieldAlertIcon className="ml-1 inline size-4 text-destructive" aria-hidden />
              ) : null}
            </span>
          ) : c.decisionMode === 'policy' ? (
            <span className="text-sm">Remediation policy</span>
          ) : null}
        </div>
        <p className="text-sm text-muted-foreground">
          Created <DateTime value={c.createdAt} />
          {c.submittedAt ? (
            <>
              {' '}
              · submitted <DateTime value={c.submittedAt} />
            </>
          ) : null}
          {c.completedAt ? (
            <>
              {' '}
              · finished <DateTime value={c.completedAt} />
            </>
          ) : null}
          {c.lastErrorCode ? <span className="font-mono"> · {c.lastErrorCode}</span> : null}
        </p>
        {c.requestReason ? (
          <p className="text-sm">
            Reason: <UntrustedText value={c.requestReason} maxLength={500} />
          </p>
        ) : null}
        <div className="flex flex-wrap gap-2">
          {c.hints.canSubmit ? (
            <Button size="sm" onClick={() => setDialog('submit')}>
              Submit…
            </Button>
          ) : null}
          {c.hints.canSubmit && hardDeleteAvailable ? (
            <Button size="sm" variant="destructive" onClick={() => setDialog('hardDelete')}>
              Hard delete…
            </Button>
          ) : null}
          {c.hints.canCancel ? (
            <Button size="sm" variant="outline" onClick={() => setDialog('cancel')}>
              Cancel clawback
            </Button>
          ) : null}
          {c.hints.canRestore ? (
            <Button size="sm" variant="outline" onClick={() => setDialog('restore')}>
              Restore…
            </Button>
          ) : null}
        </div>
        {POLLED_CLAWBACK_STATUSES.includes(c.status) ? (
          <p role="status" className="text-xs text-muted-foreground">
            Updating every few seconds while the mailbox worker{' '}
            {c.status === 'searching' ? 'searches' : 'runs the purge'}.
          </p>
        ) : null}
      </section>
      <Counts c={c} />
      {c.approval.required || c.approval.status !== null ? (
        <ApprovalBlock c={c} onDecide={(decision) => setDialog(decision)} />
      ) : null}
      {c.restore.status !== 'none' ? (
        <Section title="Restore" actions={<RestoreStatusBadge status={c.restore.status} />}>
          <p className="text-sm tabular-nums">
            {formatNumber(c.restore.succeeded)} restored · {formatNumber(c.restore.queued)} queued ·{' '}
            {formatNumber(c.restore.failed)} failed · {formatNumber(c.restore.skipped)} skipped
          </p>
          <p className="text-xs text-muted-foreground">
            Entries that need an approver are left for the Quarantine page; hard-deleted messages
            cannot be restored.
          </p>
        </Section>
      ) : null}
      <SignalCriteria c={c} />
      <TargetsTable c={c} />

      {dialog === 'submit' ? (
        <SubmitDialog
          clawback={c}
          threshold={threshold}
          open
          onOpenChange={(open) => !open && setDialog(null)}
        />
      ) : null}
      <ReasonConfirm
        open={dialog === 'hardDelete'}
        onOpenChange={(open) => !open && setDialog(null)}
        title="Hard delete every eligible message?"
        destructive
        description={
          <div className="grid gap-2">
            <p className="rounded-md bg-tone-danger px-3 py-2 text-sm text-tone-danger-foreground">
              <strong>Irreversible.</strong> {HARD_DELETE_WARNING}
            </p>
            <ApprovalPreview clawback={c} threshold={threshold} hardDelete />
          </div>
        }
        confirmLabel="Request hard delete"
        maxChars={REASON_MAX_CHARS}
        reasonHelp="Stored with the request and in the audit log"
        explainError={explainClawbackError}
        pending={hardDelete.isPending}
        onSubmit={(reason) =>
          hardDelete.submit({
            path: { clawbackId: c.id },
            body: { reason, expectedRowVersion: version },
          })
        }
        onRetry={() => hardDelete.retry()}
      />
      <ReasonConfirm
        open={dialog === 'approve'}
        onOpenChange={(open) => !open && setDialog(null)}
        title="Approve this purge?"
        description={
          <p>
            {formatNumber(c.counts.targetsEligible)} messages in{' '}
            {formatNumber(c.counts.mailboxesEligible)} mailboxes are remediated
            {c.action ? ` (${actionLabel(c.action)})` : ' by the remediation policy'}. Your decision
            is audited.
          </p>
        }
        confirmLabel="Approve"
        maxChars={REASON_MAX_CHARS}
        reasonHelp="Stored with the decision and in the audit log"
        explainError={explainClawbackError}
        pending={approve.isPending}
        onSubmit={(reason) =>
          approve.submit({
            path: { clawbackId: c.id },
            body: { reason, expectedRowVersion: version },
          })
        }
        onRetry={() => approve.retry()}
      />
      <ReasonConfirm
        open={dialog === 'deny'}
        onOpenChange={(open) => !open && setDialog(null)}
        title="Deny this purge?"
        description={<p>Nothing changes in the mailboxes. Your decision is audited.</p>}
        confirmLabel="Deny"
        destructive
        maxChars={REASON_MAX_CHARS}
        reasonHelp="Stored with the decision and in the audit log"
        explainError={explainClawbackError}
        pending={deny.isPending}
        onSubmit={(reason) =>
          deny.submit({ path: { clawbackId: c.id }, body: { reason, expectedRowVersion: version } })
        }
        onRetry={() => deny.retry()}
      />
      <ReasonConfirm
        open={dialog === 'cancel'}
        onOpenChange={(open) => !open && setDialog(null)}
        title="Cancel this clawback?"
        description={
          <p>
            Messages not yet acted on are left where they are; actions already running finish.
            Already removed messages stay removed (use Restore afterwards).
          </p>
        }
        confirmLabel="Cancel clawback"
        destructive
        maxChars={REASON_MAX_CHARS}
        reasonHelp="Stored in the audit log"
        explainError={explainClawbackError}
        pending={cancel.isPending}
        onSubmit={(reason) => cancel.submit({ path: { clawbackId: c.id }, body: { reason } })}
        onRetry={() => cancel.retry()}
      />
      <ReasonConfirm
        open={dialog === 'restore'}
        onOpenChange={(open) => !open && setDialog(null)}
        title="Restore the removed messages?"
        description={
          <p>
            Every message this clawback removed is moved back to the Inbox (tags removed) where the
            provider allows it, through the quarantine release rules: entries that need an approver
            are left for the Quarantine page; hard-deleted messages cannot be restored.
          </p>
        }
        confirmLabel="Restore"
        maxChars={REASON_MAX_CHARS}
        reasonHelp="Stored with the restore and in the audit log"
        explainError={explainClawbackError}
        pending={restore.isPending}
        onSubmit={(reason) => restore.submit({ path: { clawbackId: c.id }, body: { reason } })}
        onRetry={() => restore.retry()}
      />
    </div>
  );
}
