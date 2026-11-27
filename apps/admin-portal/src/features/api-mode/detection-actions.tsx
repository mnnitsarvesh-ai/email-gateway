'use client';

import { CheckCircle2Icon, ClockIcon } from 'lucide-react';
import Link from 'next/link';
import { useId, useState } from 'react';
import { VerdictBadge } from '@/components/domain/badges';
import { CopyableId } from '@/components/domain/copyable-id';
import { DateTime } from '@/components/domain/date-time';
import { UntrustedText } from '@/components/domain/untrusted-text';
import { ErrorState } from '@/components/states/error-state';
import { LoadingState } from '@/components/states/loading-state';
import { Button } from '@/components/ui/button';
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import type { ApiError } from '@/lib/api/errors';
import { useApiMutation, useApiQuery } from '@/lib/api/hooks';
import { useCan } from '@/lib/auth/me';
import { formatNumber, humanize } from '@/lib/format';
import { DetailList, LabelledSelect } from '@/features/domains/kit';
import { CodeList } from '@/features/messages/controls';
import { approvalHref, entryHref, releaseHref } from '@/features/quarantine/links';
import { ReasonConfirm } from '@/features/quarantine/reason-confirm';
import { REMEDIATION_QUERIES } from './history-tab';
import { clawbackHref } from './clawback-model';
import {
  DIRECTION_LABEL,
  SOURCE_LABEL,
  VerdictRevisionBadge,
  formatLagMs,
  type Detection,
} from './model';
import {
  MANUAL_ACTIONS,
  RemediationStateBadge,
  actionLabel,
  historyHref,
  remediationErrorText,
  type ManualAction,
  type RestoreResult,
} from './remediation-model';

/** The subset of a detection the actions need (list row or detail). */
export type DetectionRef = Pick<
  Detection,
  | 'id'
  | 'mailboxAddress'
  | 'status'
  | 'remediationState'
  | 'remediationAction'
  | 'remediationId'
  | 'quarantineEntryId'
>;

/** Queries a restore through the quarantine release makes stale as well. */
const RESTORE_QUERIES = [
  ...REMEDIATION_QUERIES,
  'QuarantineEntriesController_search_v1',
  'QuarantineEntriesController_detail_v1',
  'QuarantineApprovalsController_list_v1',
] as const;

const explain = (error: ApiError): string[] => {
  const text = remediationErrorText(error);
  return text ? [text] : error.messages;
};

/** Whether "Claw back similar…" may start a search from the detection (C2.4; the api decides). */
export function canBeClawedBack(d: Pick<DetectionRef, 'status'>): boolean {
  return d.status === 'scanned' || d.status === 'scan_failed';
}

/** Whether a manual remediation may be requested for the detection (R12; the api decides). */
export function canBeRemediated(d: DetectionRef): boolean {
  return (d.status === 'scanned' || d.status === 'scan_failed') && d.remediationState !== 'pending';
}

/** Whether a remediation is in effect that a restore can undo (R12; hard delete cannot). */
export function canBeRestored(d: DetectionRef): boolean {
  return d.remediationState === 'remediated' && d.remediationAction !== 'hard_delete';
}

/** "Remediate…" (R12): an action without hard delete, and a reason. */
export function RemediateDialog({
  detection,
  onOpenChange,
}: {
  detection: DetectionRef | null;
  onOpenChange: (open: boolean) => void;
}) {
  const selectId = useId();
  const [action, setAction] = useState<ManualAction>('move_quarantine');
  const remediate = useApiMutation('ApiModeRemediationController_remediate_v1', {
    invalidates: REMEDIATION_QUERIES,
    successMessage: 'Mailbox action queued: the mailbox worker runs it within seconds.',
  });
  return (
    <ReasonConfirm
      open={detection !== null}
      onOpenChange={(open) => {
        if (!open) setAction('move_quarantine');
        onOpenChange(open);
      }}
      title="Remediate this message?"
      description={
        <p>
          The action is applied to the message in{' '}
          <UntrustedText value={detection?.mailboxAddress ?? ''} mono /> through the provider API.
          Moves to the quarantine folder, Junk or deleted items create a quarantine entry that can
          be restored to the Inbox. Hard delete is never a manual action.
        </p>
      }
      confirmLabel="Remediate"
      maxChars={500}
      reasonHelp="Stored with the request and in the audit log"
      explainError={explain}
      pending={remediate.isPending}
      extra={
        <LabelledSelect
          id={selectId}
          label="Mailbox action"
          value={action}
          onChange={(value) => setAction(value as ManualAction)}
          options={MANUAL_ACTIONS.map((value) => ({ value, label: actionLabel(value) }))}
        />
      }
      onSubmit={(reason) =>
        remediate.submit({
          path: { detectionId: detection?.id ?? '' },
          body: { action, reason },
        })
      }
      onRetry={() => remediate.retry()}
    />
  );
}

/** "Restore" (R12): remove the tag, or release the mailbox quarantine entry (approvals apply). */
export function RestoreDialog({
  detection,
  onOpenChange,
  onResult,
}: {
  detection: DetectionRef | null;
  onOpenChange: (open: boolean) => void;
  onResult: (result: RestoreResult) => void;
}) {
  const restore = useApiMutation('ApiModeRemediationController_restore_v1', {
    invalidates: RESTORE_QUERIES,
    successMessage: null,
    onSuccess: (data) => onResult(data),
  });
  const tag = detection?.remediationAction === 'tag';
  return (
    <ReasonConfirm
      open={detection !== null}
      onOpenChange={onOpenChange}
      title={tag ? 'Remove the tag from this message?' : 'Restore this message to the Inbox?'}
      description={
        tag ? (
          <p>The gateway&apos;s tag is removed from the message; it stays in the Inbox.</p>
        ) : (
          <p>
            This releases the message&apos;s quarantine entry: the message is moved back to the
            Inbox of <UntrustedText value={detection?.mailboxAddress ?? ''} mono />. The quarantine
            release rules apply: a hard block or a failed scan needs an approver, and you also need
            the quarantine release permission.
          </p>
        )
      }
      confirmLabel={tag ? 'Remove tag' : 'Restore to inbox'}
      maxChars={500}
      reasonHelp="Stored with the request and in the audit log"
      explainError={explain}
      pending={restore.isPending}
      onSubmit={(reason) =>
        restore.submit({ path: { detectionId: detection?.id ?? '' }, body: { reason } })
      }
      onRetry={() => restore.retry()}
    />
  );
}

/** What a restore request led to (queued, approval requested, tag removal queued). */
export function RestoreResultNotice({ result }: { result: RestoreResult }) {
  if (result.via === 'mailbox_action') {
    return (
      <p className="flex items-start gap-2 rounded-md bg-tone-success px-3 py-2 text-sm text-tone-success-foreground">
        <CheckCircle2Icon className="mt-0.5 size-4 shrink-0" aria-hidden />
        <span>
          <strong>Tag removal queued.</strong> The mailbox worker removes the tag within seconds.{' '}
          {result.remediation ? (
            <Link
              href={historyHref({ remediationId: result.remediation.id })}
              className="font-medium underline"
            >
              Follow the action
            </Link>
          ) : null}
        </span>
      </p>
    );
  }
  const release = result.release;
  if (release?.outcome === 'approval_requested') {
    return (
      <p className="flex items-start gap-2 rounded-md bg-tone-purple px-3 py-2 text-sm text-tone-purple-foreground">
        <ClockIcon className="mt-0.5 size-4 shrink-0" aria-hidden />
        <span>
          <strong>Approval requested</strong>
          {release.approvalReasons.length > 0
            ? ` (${release.approvalReasons.map(humanize).join(', ')})`
            : ''}
          . An approver decides; the message is restored to the Inbox when approved.{' '}
          <Link href={approvalHref(release.approvalRequestId)} className="font-medium underline">
            Open the approval request
          </Link>
        </span>
      </p>
    );
  }
  return (
    <p className="flex items-start gap-2 rounded-md bg-tone-success px-3 py-2 text-sm text-tone-success-foreground">
      <CheckCircle2Icon className="mt-0.5 size-4 shrink-0" aria-hidden />
      <span>
        <strong>Restore queued.</strong> The mailbox worker moves the message back to the Inbox.{' '}
        {release ? (
          <>
            <Link href={entryHref(release.entryId)} className="font-medium underline">
              Open the quarantine entry
            </Link>{' '}
            ·{' '}
            <Link href={releaseHref(release.releaseId)} className="font-medium underline">
              Release status
            </Link>
          </>
        ) : null}
      </span>
    </p>
  );
}

/** Detail drawer of one detection (`?detection=`), the link target of entries and history. */
export function DetectionDrawer({
  detectionId,
  onClose,
  onRemediate,
  onRestore,
  onClawback,
}: {
  detectionId: string | undefined;
  onClose: () => void;
  onRemediate: (detection: DetectionRef) => void;
  onRestore: (detection: DetectionRef) => void;
  onClawback?: (detection: DetectionRef) => void;
}) {
  const canRemediate = useCan('ApiModeRemediationController_remediate_v1');
  const canClawback = useCan('ApiModeClawbackController_create_v1');
  const canClawbacks = useCan('ApiModeClawbackController_list_v1');
  const canRestore = useCan('ApiModeRemediationController_restore_v1');
  const canHistory = useCan('ApiModeRemediationController_list_v1');
  const detail = useApiQuery(
    'ApiModeController_getDetection_v1',
    { path: { detectionId: detectionId ?? '' } },
    { enabled: Boolean(detectionId) },
  );
  const d = detail.data;
  return (
    <Sheet open={Boolean(detectionId)} onOpenChange={(next) => (!next ? onClose() : undefined)}>
      <SheetContent side="right" className="w-full overflow-y-auto sm:max-w-lg">
        <SheetHeader>
          <SheetTitle>Detection</SheetTitle>
          <SheetDescription>
            {d ? `Copy in ${d.mailboxAddress}` : 'An API-mode copy and its verdict'}
          </SheetDescription>
        </SheetHeader>
        <div className="grid gap-4 px-4 pb-6">
          {detail.isLoading ? (
            <LoadingState label="Loading the detection" rows={6} />
          ) : detail.error ? (
            <ErrorState error={detail.error} onRetry={() => void detail.refetch()} compact />
          ) : d ? (
            <>
              <DetailList
                items={[
                  {
                    label: 'Mailbox',
                    value: <UntrustedText value={d.mailboxAddress} mono maxLength={80} />,
                  },
                  {
                    label: 'Verdict',
                    value: (
                      <span className="flex flex-wrap items-center gap-2">
                        <VerdictBadge verdict={d.verdict} />
                        <VerdictRevisionBadge revision={d.verdictRevision} />
                      </span>
                    ),
                  },
                  {
                    label: 'Direction',
                    value: DIRECTION_LABEL[d.direction] ?? humanize(d.direction),
                  },
                  {
                    label: 'Risk score',
                    value: d.riskScore === null ? '—' : formatNumber(d.riskScore),
                  },
                  { label: 'Status', value: humanize(d.status) },
                  {
                    label: 'Remediation',
                    value: (
                      <span className="flex flex-wrap items-center gap-2">
                        <RemediationStateBadge state={d.remediationState} />
                        {d.remediationAction ? (
                          <span className="text-xs">{actionLabel(d.remediationAction)}</span>
                        ) : null}
                      </span>
                    ),
                  },
                  {
                    label: 'Subject',
                    value:
                      d.subjectMasked || d.subject === null ? (
                        <span className="text-xs text-muted-foreground">Hidden (masked)</span>
                      ) : (
                        <UntrustedText value={String(d.subject)} maxLength={200} />
                      ),
                  },
                  {
                    label: 'Sender',
                    value: <UntrustedText value={d.headerFrom} mono emptyLabel="Unknown" />,
                  },
                  { label: 'Source', value: SOURCE_LABEL[d.source] },
                  {
                    label: 'Verdict authority',
                    value:
                      d.verdictAuthority === 'inline'
                        ? 'Inline gateway (Hybrid: never remediated automatically)'
                        : 'This copy',
                  },
                  { label: 'Received', value: <DateTime value={d.receivedAt} mode="absolute" /> },
                  { label: 'Lag', value: formatLagMs(d.lagMs) },
                  { label: 'Reason codes', value: <CodeList codes={d.reasonCodes} /> },
                  {
                    label: 'Detection ID',
                    value: <CopyableId value={d.id} label="detection ID" max={40} />,
                  },
                ]}
              />
              <nav aria-label="Related" className="flex flex-wrap gap-3 text-sm">
                {canHistory ? (
                  <Link
                    href={historyHref({ detectionId: d.id })}
                    className="text-primary underline-offset-2 hover:underline"
                  >
                    Mailbox actions of this detection
                  </Link>
                ) : null}
                {d.quarantineEntryId ? (
                  <Link
                    href={entryHref(d.quarantineEntryId)}
                    className="text-primary underline-offset-2 hover:underline"
                  >
                    Open the quarantine entry
                  </Link>
                ) : null}
                {canClawbacks
                  ? d.clawbacks.map((id, i) => (
                      <Link
                        key={id}
                        href={clawbackHref(id)}
                        className="text-primary underline-offset-2 hover:underline"
                      >
                        Clawback {d.clawbacks.length > 1 ? i + 1 : ''}
                        <span className="sr-only"> that targeted this copy</span>
                      </Link>
                    ))
                  : null}
              </nav>
              <div className="flex flex-wrap gap-2">
                {canRemediate ? (
                  <Button size="sm" disabled={!canBeRemediated(d)} onClick={() => onRemediate(d)}>
                    Remediate…
                  </Button>
                ) : null}
                {canRestore ? (
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={!canBeRestored(d)}
                    onClick={() => onRestore(d)}
                  >
                    Restore
                  </Button>
                ) : null}
                {canClawback && onClawback ? (
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={!canBeClawedBack(d)}
                    onClick={() => onClawback(d)}
                  >
                    Claw back similar…
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
