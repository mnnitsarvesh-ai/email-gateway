'use client';

import { useId, useState, type ReactNode } from 'react';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { FormErrorSummary } from '@/components/form';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { type ApiError } from '@/lib/api/errors';
import { formatUtc, humanize } from '@/lib/format';
import { REASON_MAX, reasonSchema } from './forms';

/** Human explanation of the coded quarantine errors (API guide, Quarantine "Error codes"). */
export function explainQuarantineError(error: ApiError): string[] {
  const d = error.details;
  const text = (value: unknown) => (typeof value === 'string' ? value : null);
  switch (error.code) {
    case 'quarantine_rescan_required':
      return [
        `The verdict is too old to release on${text(d.staleness) ? ` (${humanize(text(d.staleness) ?? '')})` : ''}: the message must be rescanned first. The rescan re-decides the recipients and replaces this entry.`,
      ];
    case 'quarantine_hard_block_release_disabled':
      return [
        'This entry has a hard block and the organization’s quarantine settings do not allow releasing hard-blocked mail.',
      ];
    case 'quarantine_version_conflict':
    case 'quarantine_state_conflict':
      return ['The entry changed since you opened it. Reload the page and try again.'];
    case 'quarantine_message_busy':
      return ['The message is being processed right now. Try again in a moment.'];
    case 'quarantine_legal_hold':
      return [
        `The message is under a legal hold${text(d.legalHoldId) ? ` (${text(d.legalHoldId)})` : ''} and cannot be deleted.`,
      ];
    case 'quarantine_retention_active':
      return [
        `The message is retained${text(d.retainUntil) ? ` until ${formatUtc(text(d.retainUntil) ?? '')}` : ''} and cannot be deleted yet.`,
      ];
    case 'quarantine_self_release_not_allowed':
      return [
        `You cannot release this message yourself${text(d.cause) ? ` (${humanize(text(d.cause) ?? '')})` : ''}. Request a release instead; an administrator decides.`,
      ];
    case 'quarantine_approval_forbidden':
      return [
        `Separation of duties: you cannot decide this request${text(d.reason) ? ` (${humanize(text(d.reason) ?? '')})` : ''}. The requester and the message's recipient may not approve or deny it; another approver must.`,
      ];
    case 'quarantine_approval_not_pending':
      return ['This request is no longer pending (it was decided, cancelled or expired).'];
    case 'quarantine_download_disabled':
      return [
        'Downloads are turned off for your organization (quarantine settings, “Allow downloads”).',
      ];
    case 'quarantine_download_blocked':
      return [
        `This content cannot be downloaded${text(d.reason) ? ` (${humanize(text(d.reason) ?? '')})` : ''}: hard blocks, malware or phishing verdicts and attachments that are not clean are never downloadable.`,
      ];
    case 'quarantine_reauth_failed':
      return [
        'The password or authenticator code is not correct. Repeated failures count toward the sign-in lockout.',
      ];
    case 'quarantine_bulk_limit':
      return [
        `Too many items for one bulk action${typeof d.maxItems === 'number' ? ` (at most ${d.maxItems})` : ''}.`,
      ];
    case 'quarantine_bulk_rate_limited':
      return [
        `The bulk action limit per minute was reached. Try again in ${error.retryAfterSeconds ?? 60} s.`,
      ];
    case 'quarantine_preview_not_allowed':
      return ['A preview is not available for this message (policy of your organization).'];
    case 'quarantine_content_purged':
      return ['The message content has been deleted; no preview or download is possible.'];
    case 'mfa_required':
      return ['This action needs a session signed in with MFA. Sign in again with MFA.'];
    default:
      return error.messages;
  }
}

/** Errors worth a manual retry of the same intent (same Idempotency-Key). */
export function isRetryable(error: ApiError | null): boolean {
  return Boolean(
    error &&
    (error.status === 0 ||
      error.status >= 500 ||
      error.code === 'idempotency_request_in_progress' ||
      error.code === 'quarantine_message_busy'),
  );
}

interface Outcome {
  readonly ok: boolean;
  readonly error?: ApiError;
}

/**
 * ConfirmDialog with a required reason (every quarantine mutation stores the operator's reason).
 * The reason field and the error summary go into the dialog's content slot. Confirm validates,
 * submits a new intent (new Idempotency-Key); "Retry" repeats the failed intent with the same key.
 */
export function ReasonConfirm({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel,
  destructive = false,
  maxChars = REASON_MAX,
  extra,
  onSubmit,
  onRetry,
  pending = false,
  reasonLabel = 'Reason',
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: ReactNode;
  confirmLabel: string;
  destructive?: boolean;
  maxChars?: number;
  extra?: ReactNode;
  onSubmit: (reason: string) => Promise<Outcome>;
  onRetry?: () => Promise<Outcome>;
  pending?: boolean;
  reasonLabel?: string;
}) {
  const id = useId();
  const [reason, setReason] = useState('');
  const [fieldError, setFieldError] = useState<string | null>(null);
  const [apiError, setApiError] = useState<ApiError | null>(null);
  const schema = reasonSchema(maxChars);

  const reset = () => {
    setReason('');
    setFieldError(null);
    setApiError(null);
  };

  const handle = (outcome: Outcome) => {
    if (outcome.ok) {
      reset();
      return true;
    }
    setApiError(outcome.error ?? null);
    return false;
  };

  const confirm = async () => {
    const parsed = schema.safeParse({ reason });
    if (!parsed.success) {
      setFieldError(parsed.error.issues[0]?.message ?? 'Enter a reason');
      return false;
    }
    setFieldError(null);
    setApiError(null);
    return handle(await onSubmit(parsed.data.reason));
  };

  const retry = async () => {
    if (!onRetry) return;
    const closed = handle(await onRetry());
    if (closed) onOpenChange(false);
  };

  return (
    <ConfirmDialog
      open={open}
      onOpenChange={(next) => {
        if (!next) reset();
        onOpenChange(next);
      }}
      title={title}
      description={description}
      confirmLabel={confirmLabel}
      destructive={destructive}
      pending={pending}
      onConfirm={confirm}
      error={
        <div className="grid gap-3">
          <div className="grid gap-1.5">
            <Label htmlFor={id}>{reasonLabel} (required)</Label>
            <Textarea
              id={id}
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              maxLength={maxChars}
              rows={3}
              aria-invalid={fieldError ? true : undefined}
              aria-describedby={`${id}-help${fieldError ? ` ${id}-error` : ''}`}
            />
            <p id={`${id}-help`} className="text-xs text-muted-foreground">
              Stored with the action and shown in the entry history (at most {maxChars} characters).
            </p>
            {fieldError ? (
              <p id={`${id}-error`} className="text-xs font-medium text-destructive">
                {fieldError}
              </p>
            ) : null}
          </div>
          {extra}
          {apiError ? (
            <div className="grid gap-2">
              <FormErrorSummary
                messages={[...explainQuarantineError(apiError), `Code: ${apiError.code}`]}
                requestId={apiError.requestId}
              />
              {onRetry && isRetryable(apiError) ? (
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  className="justify-self-start"
                  disabled={pending}
                  onClick={() => void retry()}
                >
                  Retry the same request
                </Button>
              ) : null}
            </div>
          ) : null}
        </div>
      }
    />
  );
}
