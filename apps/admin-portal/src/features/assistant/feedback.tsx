'use client';

import { useQueryClient } from '@tanstack/react-query';
import { ThumbsDownIcon, ThumbsUpIcon } from 'lucide-react';
import { useId, useState, type FormEvent } from 'react';
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
import { useApiMutation } from '@/lib/api/hooks';
import { cn } from '@/lib/utils';
import {
  FEEDBACK_REASONS,
  FEEDBACK_REASON_LABEL,
  type FeedbackReasonValue,
} from '@/features/assistant-admin/model';
import type { FeedbackRating, MessageFeedback, StoredMessage } from './types';

/**
 * Rating of an assistant answer (step AI-6 D2): thumbs up/down toggle buttons (`aria-pressed`)
 * on the assistant message of a completed turn, an optional reason and comment (≤ 500
 * characters) and the notice that administrators see them. Pressing the selected thumb again
 * removes the rating. The stored messages' `feedback` is the state; a saved rating updates the
 * cached messages in place (no refetch of the conversation).
 */

export const FEEDBACK_NOTICE =
  "Your rating and comment are visible to your organization's AI administrators.";
export const COMMENT_MAX = 500;
const NO_REASON = 'none';

type MessagesCache = { messages: StoredMessage[]; complete: boolean };

export function MessageFeedbackControls({
  conversationId,
  messageId,
  feedback,
}: {
  conversationId: string;
  messageId: string;
  feedback: MessageFeedback | null;
}) {
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState<string>(feedback?.reason ?? NO_REASON);
  const [comment, setComment] = useState(feedback?.comment ?? '');
  const [status, setStatus] = useState('');
  const [error, setError] = useState<string | null>(null);
  const id = useId();
  const rating = feedback?.rating ?? null;

  const store = (next: MessageFeedback | null) =>
    queryClient.setQueryData<MessagesCache>(
      ['AssistantMessagesController_list_v1', conversationId],
      (old) =>
        old && {
          ...old,
          messages: old.messages.map((message) =>
            message.id === messageId ? { ...message, feedback: next } : message,
          ),
        },
    );

  const put = useApiMutation('AssistantFeedbackController_set_v1', { successMessage: null });
  const remove = useApiMutation('AssistantFeedbackController_remove_v1', { successMessage: null });
  const busy = put.isPending || remove.isPending;

  const failed = (code: string, message: string) => {
    setError(
      code === 'assistant_feedback_not_allowed'
        ? 'Only a finished answer can be rated.'
        : code === 'assistant_message_not_found'
          ? 'This answer no longer exists.'
          : `The rating could not be saved: ${message}`,
    );
  };

  const save = async (next: FeedbackRating, details: { reason: string; comment: string }) => {
    setError(null);
    const text = details.comment.trim();
    const outcome = await put.submit({
      path: { messageId },
      body: {
        rating: next,
        ...(details.reason !== NO_REASON ? { reason: details.reason as FeedbackReasonValue } : {}),
        ...(text ? { comment: text.slice(0, COMMENT_MAX) } : {}),
      },
    });
    if (!outcome.ok) {
      failed(outcome.error.code, outcome.error.message);
      return false;
    }
    store({
      rating: outcome.data.rating,
      reason: outcome.data.reason,
      comment: outcome.data.comment,
    });
    return true;
  };

  const rate = async (next: FeedbackRating) => {
    if (busy) return;
    if (rating === next) {
      setError(null);
      const outcome = await remove.submit({ path: { messageId } });
      if (!outcome.ok) {
        failed(outcome.error.code, outcome.error.message);
        return;
      }
      store(null);
      setOpen(false);
      setReason(NO_REASON);
      setComment('');
      setStatus('Rating removed.');
      return;
    }
    if (await save(next, { reason, comment })) {
      setOpen(true);
      setStatus(next === 'up' ? 'Rated helpful.' : 'Rated not helpful.');
    }
  };

  const submitDetails = async (event: FormEvent) => {
    event.preventDefault();
    if (!rating) return;
    if (await save(rating, { reason, comment })) {
      setOpen(false);
      setStatus('Thank you for the details.');
    }
  };

  return (
    <div className="grid gap-2">
      <div className="flex flex-wrap items-center gap-1">
        <span id={`${id}-hint`} className="sr-only">
          {FEEDBACK_NOTICE}
        </span>
        <div
          role="group"
          aria-label="Rate this answer"
          aria-describedby={`${id}-hint`}
          className="flex items-center gap-1"
        >
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className={cn('size-7', rating === 'up' && 'bg-accent text-foreground')}
            aria-pressed={rating === 'up'}
            aria-label="Helpful"
            disabled={busy}
            onClick={() => void rate('up')}
          >
            <ThumbsUpIcon className={cn(rating === 'up' && 'fill-current')} aria-hidden />
          </Button>
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className={cn('size-7', rating === 'down' && 'bg-accent text-foreground')}
            aria-pressed={rating === 'down'}
            aria-label="Not helpful"
            disabled={busy}
            onClick={() => void rate('down')}
          >
            <ThumbsDownIcon className={cn(rating === 'down' && 'fill-current')} aria-hidden />
          </Button>
        </div>
        {rating && !open ? (
          <Button
            type="button"
            variant="link"
            size="sm"
            className="h-7 px-1 text-xs"
            onClick={() => {
              setReason(feedback?.reason ?? NO_REASON);
              setComment(feedback?.comment ?? '');
              setOpen(true);
            }}
          >
            {feedback?.reason || feedback?.comment ? 'Edit details' : 'Add details'}
          </Button>
        ) : null}
        <span className="sr-only" aria-live="polite">
          {status}
        </span>
      </div>
      {error ? (
        <p role="alert" className="text-xs text-destructive">
          {error}
        </p>
      ) : null}
      {open && rating ? (
        <form
          onSubmit={(event) => void submitDetails(event)}
          aria-label="Feedback details"
          className="grid max-w-md gap-2 rounded-md border bg-muted/30 p-3"
          noValidate
        >
          <p id={`${id}-notice`} className="text-xs text-muted-foreground">
            {FEEDBACK_NOTICE}
          </p>
          <div className="grid gap-1">
            <Label htmlFor={`${id}-reason`} className="text-xs">
              Reason (optional)
            </Label>
            <Select value={reason} onValueChange={setReason}>
              <SelectTrigger id={`${id}-reason`} size="sm" className="w-56">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={NO_REASON}>No reason</SelectItem>
                {FEEDBACK_REASONS.map((value) => (
                  <SelectItem key={value} value={value}>
                    {FEEDBACK_REASON_LABEL[value]}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="grid gap-1">
            <Label htmlFor={`${id}-comment`} className="text-xs">
              Comment (optional)
            </Label>
            <Textarea
              id={`${id}-comment`}
              value={comment}
              maxLength={COMMENT_MAX}
              rows={3}
              onChange={(event) => setComment(event.target.value)}
              aria-describedby={`${id}-notice ${id}-count`}
            />
            <span id={`${id}-count`} className="text-xs text-muted-foreground">
              {comment.length} / {COMMENT_MAX} characters
            </span>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button type="submit" size="sm" disabled={busy}>
              {put.isPending ? 'Saving …' : 'Send feedback'}
            </Button>
            <Button type="button" size="sm" variant="outline" onClick={() => setOpen(false)}>
              Close
            </Button>
          </div>
        </form>
      ) : null}
    </div>
  );
}
