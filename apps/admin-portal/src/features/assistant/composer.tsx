'use client';

import { SendHorizontalIcon, SquareIcon } from 'lucide-react';
import { forwardRef, useId, useState, type KeyboardEvent } from 'react';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { cn } from '@/lib/utils';

/** Default question length when `GET /assistant/status` has not answered (contracts §35). */
export const DEFAULT_MESSAGE_MAX_CHARS = 4000;

/**
 * The question box (step AI-1 D14): Enter sends, Shift+Enter adds a line, the length is capped at
 * the api's `limits.messageMaxChars`; while a turn runs sending is disabled and Stop cancels it.
 */
export const Composer = forwardRef<
  HTMLTextAreaElement,
  {
    onSend: (message: string) => void;
    onCancel?: () => void;
    running: boolean;
    disabled?: boolean;
    maxLength?: number;
    className?: string;
  }
>(function Composer(
  { onSend, onCancel, running, disabled = false, maxLength = DEFAULT_MESSAGE_MAX_CHARS, className },
  ref,
) {
  const [value, setValue] = useState('');
  const inputId = useId();
  const counterId = useId();
  const hintId = useId();
  const trimmed = value.trim();
  const tooLong = value.length > maxLength;
  const canSend = !running && !disabled && trimmed.length > 0 && !tooLong;

  const send = () => {
    if (!canSend) return;
    onSend(trimmed);
    setValue('');
  };

  const onKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key !== 'Enter' || event.shiftKey || event.nativeEvent.isComposing) return;
    event.preventDefault();
    send();
  };

  const nearLimit = value.length >= maxLength * 0.9;
  return (
    <form
      className={cn('grid gap-1.5', className)}
      onSubmit={(event) => {
        event.preventDefault();
        send();
      }}
      aria-label="Ask the AI assistant"
    >
      <label htmlFor={inputId} className="sr-only">
        Message to the AI assistant
      </label>
      <div className="flex items-end gap-2">
        <Textarea
          ref={ref}
          id={inputId}
          value={value}
          onChange={(event) => setValue(event.target.value.slice(0, maxLength))}
          onKeyDown={onKeyDown}
          maxLength={maxLength}
          rows={2}
          disabled={disabled}
          placeholder={
            disabled
              ? 'The assistant is not available'
              : 'Ask about policies, quarantine, reports …'
          }
          aria-describedby={`${hintId} ${counterId}`}
          className="max-h-48 min-h-14 resize-y"
        />
        {running ? (
          <Button
            type="button"
            variant="outline"
            onClick={onCancel}
            aria-label="Stop the answer"
            className="shrink-0"
          >
            <SquareIcon aria-hidden />
            <span className="hidden sm:inline">Stop</span>
          </Button>
        ) : (
          <Button type="submit" disabled={!canSend} aria-label="Send" className="shrink-0">
            <SendHorizontalIcon aria-hidden />
            <span className="hidden sm:inline">Send</span>
          </Button>
        )}
      </div>
      <div className="flex items-center justify-between gap-2 text-xs text-muted-foreground">
        <span id={hintId}>
          Enter to send, Shift+Enter for a new line. Answers use your permissions and can be wrong.
        </span>
        <span
          id={counterId}
          className={cn('shrink-0 tabular-nums', nearLimit && 'font-semibold text-foreground')}
        >
          {value.length} / {maxLength}
        </span>
      </div>
    </form>
  );
});
