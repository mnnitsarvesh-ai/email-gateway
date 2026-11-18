/**
 * Re-check schedules of the capture scheduler (A2, A7).
 *
 * - Waiting intents: 1, 2, 5, 15, 30 minutes after the previous check, then hourly.
 * - Captures of a final state: +1 h and +24 h after the later of the capture and the moment the
 *   message became final (late sandbox revisions), then the intent closes.
 * - Captures of a non-final state (quarantined, held for review): hourly until the message is
 *   final, bounded by `ARCHIVE_OUTCOME_WINDOW_DAYS` after the capture.
 */

const MINUTE_MS = 60_000;
const HOUR_MS = 3_600_000;
const DAY_MS = 86_400_000;

/** Minutes of the first waits; afterwards hourly. */
export const CAPTURE_WAIT_STEPS_MINUTES = Object.freeze([1, 2, 5, 15, 30]);
export const FINAL_OUTCOME_CHECK_OFFSETS_MS = Object.freeze([HOUR_MS, 24 * HOUR_MS]);

/** The next check of a waiting intent; `waitsSoFar` = waits already scheduled (0 = first). */
export function nextWaitCheckAt(now: Date, waitsSoFar: number): Date {
  const i = Math.max(0, Math.floor(waitsSoFar));
  const minutes = i < CAPTURE_WAIT_STEPS_MINUTES.length ? CAPTURE_WAIT_STEPS_MINUTES[i]! : 60;
  return new Date(now.getTime() + minutes * MINUTE_MS);
}

export interface OutcomeCheckInput {
  now: Date;
  capturedAt: Date;
  /** The message is in a final state now (delivered, rejected, expired). */
  final: boolean;
  /** When the message entered its current state (`email_messages.status_changed_at`). */
  finalSince?: Date | null;
  outcomeWindowDays: number;
}

/** The next outcome refresh of a `captured_open` intent, or null = close it now. */
export function nextOutcomeCheckAt(input: OutcomeCheckInput): Date | null {
  const now = input.now.getTime();
  const captured = input.capturedAt.getTime();
  const windowEnd = captured + Math.max(1, input.outcomeWindowDays) * DAY_MS;
  // The window bounds every refresh: after it the intent closes, final or not.
  if (now >= windowEnd) return null;
  if (input.final) {
    const base = Math.max(captured, input.finalSince?.getTime() ?? captured);
    const offset = FINAL_OUTCOME_CHECK_OFFSETS_MS.find((o) => now < base + o);
    return offset === undefined ? null : new Date(Math.min(base + offset, windowEnd));
  }
  return new Date(Math.min(now + HOUR_MS, windowEnd));
}
