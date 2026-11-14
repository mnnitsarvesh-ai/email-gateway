'use client';

import { useQueryClient } from '@tanstack/react-query';
import { useId, useState } from 'react';
import { toast } from 'sonner';
import { z } from 'zod';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { FormErrorSummary } from '@/components/form';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import type { ApiError } from '@/lib/api/errors';
import { useApiMutation } from '@/lib/api/hooks';
import type { OperationId, RequestBody } from '@/lib/api/types';
import { humanize } from '@/lib/format';
import type { MessageDetailBody } from './summary-section';

/** The api bounds of the rescan reason (`reason: 10..500`). */
export const RESCAN_REASON_MIN = 10;
export const RESCAN_REASON_MAX = 500;

export const rescanSchema = z
  .object({
    reason: z
      .string()
      .trim()
      .min(
        RESCAN_REASON_MIN,
        `Enter at least ${RESCAN_REASON_MIN} characters (the reason is audited)`,
      )
      .max(RESCAN_REASON_MAX, `Use at most ${RESCAN_REASON_MAX} characters`),
  })
  .strict();

/** `POST /messages/{id}/rescan` body: the operator's reason and the version they saw. */
export function rescanBody(
  reason: string,
  expectedVersion: number,
): RequestBody<'MessageLifecycleController_rescan_v1'> {
  return { expectedVersion, reason };
}

/** Queries a rescan makes stale (new round, new state, superseded quarantine entries). */
const RESCAN_INVALIDATES: readonly OperationId[] = [
  'MessagesController_detail_v1',
  'MessageLifecycleController_lifecycle_v1',
  'MessageLifecycleController_history_v1',
  'MessageScansController_scansOf_v1',
  'PolicyMessagesController_evaluations_v1',
  'QuarantineEntriesController_search_v1',
];

function explainRescanError(error: ApiError): string[] {
  const state = typeof error.details.currentState === 'string' ? error.details.currentState : null;
  switch (error.code) {
    case 'message_version_conflict':
      return [
        'The message changed since you opened it. The page was reloaded: check the current state and confirm again.',
      ];
    case 'message_state_conflict':
      return [
        `The message cannot be rescanned in its current state${state ? ` (${humanize(state)})` : ''}.`,
      ];
    case 'quarantine_rescan_forbidden':
      return [
        'Rescanning a quarantined or held message re-decides its quarantine entries, so it also needs the quarantine:release permission.',
      ];
    default:
      return error.messages;
  }
}

function retryable(error: ApiError | null): boolean {
  return Boolean(
    error &&
    (error.status === 0 || error.status >= 500 || error.code === 'idempotency_request_in_progress'),
  );
}

/**
 * Rescan from the details header (§2 E11): reason of 10–500 characters, `expectedVersion` from
 * the detail, one Idempotency-Key per confirm (reused by "Retry the same request"); a `409`
 * version conflict reloads the detail.
 */
export function RescanDialog({
  message,
  open,
  onOpenChange,
}: {
  message: MessageDetailBody;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const id = useId();
  const queryClient = useQueryClient();
  const [reason, setReason] = useState('');
  const [fieldError, setFieldError] = useState<string | null>(null);
  const [apiError, setApiError] = useState<ApiError | null>(null);
  const rescan = useApiMutation('MessageLifecycleController_rescan_v1', {
    successMessage: null,
    invalidates: RESCAN_INVALIDATES,
    onSuccess: (data, { replayed }) => {
      if (!replayed) {
        toast.success(`Rescan started: round ${data.lifecycleRound} is being scanned.`);
      }
    },
  });

  const reset = () => {
    setReason('');
    setFieldError(null);
    setApiError(null);
  };

  const handle = async (outcome: Awaited<ReturnType<typeof rescan.submit>>) => {
    if (outcome.ok) {
      reset();
      return true;
    }
    setApiError(outcome.error);
    if (outcome.error.code === 'message_version_conflict') {
      await queryClient.invalidateQueries({ queryKey: ['MessagesController_detail_v1'] });
      await queryClient.invalidateQueries({
        queryKey: ['MessageLifecycleController_lifecycle_v1'],
      });
    }
    return false;
  };

  const confirm = async () => {
    const parsed = rescanSchema.safeParse({ reason });
    if (!parsed.success) {
      setFieldError(parsed.error.issues[0]?.message ?? 'Enter a reason');
      return false;
    }
    setFieldError(null);
    setApiError(null);
    return handle(
      await rescan.submit({
        path: { messageId: message.id },
        body: rescanBody(parsed.data.reason, message.version),
      }),
    );
  };

  const retry = async () => {
    const closed = await handle(await rescan.retry());
    if (closed) onOpenChange(false);
  };

  return (
    <ConfirmDialog
      open={open}
      onOpenChange={(next) => {
        if (!next) reset();
        onOpenChange(next);
      }}
      title="Rescan this message?"
      description={
        <p>
          Every scan engine scans the stored message again in a new lifecycle round (version{' '}
          {message.version}). Earlier rounds stay unchanged. A rescan of a quarantined or held
          message re-decides its quarantine entries.
        </p>
      }
      confirmLabel="Rescan"
      pending={rescan.isPending}
      onConfirm={confirm}
      error={
        <div className="grid gap-3">
          <div className="grid gap-1.5">
            <Label htmlFor={id}>Reason (required)</Label>
            <Textarea
              id={id}
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              maxLength={RESCAN_REASON_MAX}
              rows={3}
              aria-invalid={fieldError ? true : undefined}
              aria-describedby={`${id}-help${fieldError ? ` ${id}-error` : ''}`}
            />
            <p id={`${id}-help`} className="text-xs text-muted-foreground">
              {RESCAN_REASON_MIN}–{RESCAN_REASON_MAX} characters, recorded in the audit log.
            </p>
            {fieldError ? (
              <p id={`${id}-error`} className="text-xs font-medium text-destructive">
                {fieldError}
              </p>
            ) : null}
          </div>
          {apiError ? (
            <div className="grid gap-2">
              <FormErrorSummary
                messages={[...explainRescanError(apiError), `Code: ${apiError.code}`]}
                requestId={apiError.requestId}
              />
              {retryable(apiError) ? (
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  className="justify-self-start"
                  disabled={rescan.isPending}
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
