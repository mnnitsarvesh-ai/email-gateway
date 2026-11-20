/**
 * Stream coverage and backfill replay windows (step 8.5 review fix, "backfill re-ingestion").
 *
 * A backfill re-reads provider history from `backfill_from` up to now. Events of that range that an
 * earlier ingestion of the same stream already processed must not be processed again: the Redis
 * seen-set (WP4-5) only remembers events for 6 hours, and the 8.4 pipeline would otherwise count a
 * re-read successful sign-in again on its aggregate row and apply its activity delta twice.
 *
 * - The api, when it starts a backfill (`POST /ato/providers/{id}/backfill`, or binding a removed
 *   connection again with `backfillDays`), stores the provider-time range the stream already
 *   ingested as `[replay_from, replay_until)` ({@link backfillReplay}).
 * - The ato-worker stream runner skips events inside it (result `replayed`, {@link isReplayed}) and,
 *   when the backfill completes, records the joined range start in `covered_from` and clears the
 *   window ({@link completedCoverage}).
 *
 * `replay_until` stops {@link REPLAY_MARGIN_MS} before the earlier watermark: the last hour may hold
 * late events the earlier ingestion had not read yet (window overlaps are at most one hour, D7.2);
 * those it had already processed are still in the seen-set unless the backfill takes longer than
 * about five hours to reach them.
 */

/** Distance kept between the earlier watermark and `replay_until` (the largest window overlap). */
export const REPLAY_MARGIN_MS = 3_600_000;

/** The coverage columns of a stream row (`ato_provider_streams`). */
export interface StreamCoverage {
  status: string;
  coveredFrom: Date | null;
  backfillFrom: Date | null;
  watermarkAt: Date | null;
  replayFrom: Date | null;
  replayUntil: Date | null;
  createdAt: Date;
}

export interface TimeRange {
  from: Date;
  until: Date;
}

const min = (a: Date, b: Date) => (a.getTime() <= b.getTime() ? a : b);

/**
 * The contiguous provider-time range a stream has processed (up to one margin before its
 * watermark), or `null` when it processed nothing reliable.
 */
export function ingestedRange(stream: StreamCoverage): TimeRange | null {
  if (!stream.watermarkAt) return null;
  const end = new Date(stream.watermarkAt.getTime() - REPLAY_MARGIN_MS);
  const backfilling = stream.status === 'backfilling' || stream.replayUntil !== null;
  if (backfilling && stream.backfillFrom) {
    // A backfill in progress (or interrupted by an unbind): [backfill_from, watermark] is done,
    // plus the earlier range it replays when the two meet.
    const earlier =
      stream.replayFrom && stream.replayUntil
        ? { from: stream.replayFrom, until: stream.replayUntil }
        : null;
    if (!earlier)
      return end > stream.backfillFrom ? { from: stream.backfillFrom, until: end } : null;
    if (stream.watermarkAt.getTime() >= earlier.from.getTime()) {
      const until = new Date(Math.max(earlier.until.getTime(), end.getTime()));
      return { from: min(stream.backfillFrom, earlier.from), until };
    }
    // Not joined yet: the earlier (live) range is kept; the partial backfill is read again.
    return earlier;
  }
  const from =
    stream.coveredFrom ??
    (stream.backfillFrom ? min(stream.backfillFrom, stream.createdAt) : stream.createdAt);
  return end > from ? { from, until: end } : null;
}

/** The replay window of a new backfill of a stream whose previous state is `previous`. */
export function backfillReplay(previous: StreamCoverage | null): {
  replayFrom: Date | null;
  replayUntil: Date | null;
} {
  const range = previous ? ingestedRange(previous) : null;
  return range
    ? { replayFrom: range.from, replayUntil: range.until }
    : { replayFrom: null, replayUntil: null };
}

/** `covered_from` once a backfill from `backfillFrom` completed (joined with what it replayed). */
export function completedCoverage(stream: {
  backfillFrom: Date | null;
  replayFrom: Date | null;
  coveredFrom: Date | null;
}): Date | null {
  if (!stream.backfillFrom) return stream.coveredFrom;
  return stream.replayFrom ? min(stream.backfillFrom, stream.replayFrom) : stream.backfillFrom;
}

/** Whether a backfill should skip this event (already processed by an earlier ingestion). */
export function isReplayed(
  stream: { replayFrom: Date | null; replayUntil: Date | null },
  event: { eventId: string; occurredAt: string },
): boolean {
  if (!stream.replayFrom || !stream.replayUntil) return false;
  // Snapshot events describe current mailbox state (cursor-confirmed, D8.3), never history.
  if (event.eventId.startsWith('snap:')) return false;
  const at = Date.parse(event.occurredAt);
  return at >= stream.replayFrom.getTime() && at < stream.replayUntil.getTime();
}
