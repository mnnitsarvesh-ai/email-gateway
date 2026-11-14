'use client';

import { EyeIcon, EyeOffIcon } from 'lucide-react';
import { DateTime } from '@/components/domain';
import { ErrorState } from '@/components/states/error-state';
import { Button } from '@/components/ui/button';
import { useRevealed } from './use-message-reveal';

/** The header's Reveal / Hide again button (only for `message:reveal` holders). */
export function RevealButton() {
  const reveal = useRevealed();
  if (reveal.values) {
    return (
      <Button variant="outline" size="sm" onClick={reveal.hide}>
        <EyeOffIcon aria-hidden />
        Hide again
      </Button>
    );
  }
  return (
    <Button
      variant="outline"
      size="sm"
      onClick={() => void reveal.reveal()}
      disabled={reveal.pending || reveal.retryAfterSeconds > 0}
    >
      <EyeIcon aria-hidden />
      {reveal.pending ? 'Revealing …' : 'Reveal'}
    </Button>
  );
}

function revealErrorText(status: number, code: string, retryAfter: number): string | null {
  if (status === 429) {
    return retryAfter > 0
      ? `Too many reveals in the last minute. Try again in ${retryAfter} s.`
      : 'Too many reveals in the last minute. You can try again now.';
  }
  if (status === 403) {
    return code === 'mfa_required'
      ? 'Revealing needs a session signed in with MFA.'
      : 'You do not have the message:reveal permission; values stay masked.';
  }
  if (status === 404) return 'The message no longer exists, or it is not visible to you.';
  return null;
}

/**
 * State of the page's reveal (§2 E11): the polite announcement (`aria-live`), the revealed-at
 * notice with "Hide again", and reveal errors (403, 429 with a countdown, 404, others with code
 * and requestId).
 */
export function RevealStatus() {
  const reveal = useRevealed();
  const error = reveal.error;
  const text = error ? revealErrorText(error.status, error.code, reveal.retryAfterSeconds) : null;
  return (
    <div className="grid gap-2">
      <p role="status" aria-live="polite" className="sr-only">
        {reveal.announcement}
      </p>
      {reveal.values ? (
        <p className="rounded-md border border-dashed bg-tone-info px-3 py-2 text-sm text-tone-info-foreground">
          Revealed values are shown for this page view only (revealed{' '}
          <DateTime value={reveal.values.revealedAt} />
          ). The reveal is recorded in the audit log; &ldquo;Hide again&rdquo; or leaving the page
          hides them.
        </p>
      ) : null}
      {error ? (
        text ? (
          <div role="alert" className="grid gap-1 rounded-md border px-3 py-2 text-sm">
            <span>{text}</span>
            <span className="text-xs text-muted-foreground">
              Code <span className="font-mono">{error.code}</span>
              {error.requestId ? (
                <>
                  {' '}
                  · Request ID <span className="font-mono">{error.requestId}</span>
                </>
              ) : null}
            </span>
          </div>
        ) : (
          <ErrorState error={error} onRetry={() => void reveal.reveal()} compact />
        )
      ) : null}
    </div>
  );
}
