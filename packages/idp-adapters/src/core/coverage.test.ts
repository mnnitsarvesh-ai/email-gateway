import { describe, expect, it } from 'vitest';
import {
  REPLAY_MARGIN_MS,
  backfillReplay,
  completedCoverage,
  ingestedRange,
  isReplayed,
  type StreamCoverage,
} from './coverage';

const at = (iso: string) => new Date(iso);
const minus = (d: Date, ms: number) => new Date(d.getTime() - ms);

const live: StreamCoverage = {
  status: 'active',
  coveredFrom: at('2026-11-10T00:00:00.000Z'),
  backfillFrom: null,
  watermarkAt: at('2026-11-20T00:00:00.000Z'),
  replayFrom: null,
  replayUntil: null,
  createdAt: at('2026-11-10T00:00:00.000Z'),
};

describe('stream coverage and backfill replay windows', () => {
  it('has no replay window for a stream that never ingested', () => {
    expect(backfillReplay(null)).toEqual({ replayFrom: null, replayUntil: null });
    expect(backfillReplay({ ...live, watermarkAt: null })).toEqual({
      replayFrom: null,
      replayUntil: null,
    });
    // Less than one margin ingested: nothing reliable to skip.
    expect(ingestedRange({ ...live, watermarkAt: at('2026-11-10T00:30:00.000Z') })).toBeNull();
  });

  it('replays a live stream from covered_from up to one margin before the watermark', () => {
    expect(backfillReplay(live)).toEqual({
      replayFrom: live.coveredFrom,
      replayUntil: minus(live.watermarkAt!, REPLAY_MARGIN_MS),
    });
  });

  it('falls back to backfill_from / created_at on rows without covered_from', () => {
    const old = { ...live, coveredFrom: null, backfillFrom: at('2026-11-05T00:00:00.000Z') };
    expect(ingestedRange(old)?.from).toEqual(at('2026-11-05T00:00:00.000Z'));
    expect(ingestedRange({ ...old, backfillFrom: null })?.from).toEqual(live.createdAt);
  });

  it('joins an interrupted backfill that reached the earlier range', () => {
    const interrupted: StreamCoverage = {
      ...live,
      status: 'backfilling',
      backfillFrom: at('2026-10-25T00:00:00.000Z'),
      watermarkAt: at('2026-11-12T00:00:00.000Z'),
      replayFrom: at('2026-11-10T00:00:00.000Z'),
      replayUntil: at('2026-11-19T23:00:00.000Z'),
    };
    expect(ingestedRange(interrupted)).toEqual({
      from: at('2026-10-25T00:00:00.000Z'),
      until: at('2026-11-19T23:00:00.000Z'),
    });
  });

  it('keeps only the earlier range when the interrupted backfill had not reached it', () => {
    const interrupted: StreamCoverage = {
      ...live,
      status: 'backfilling',
      backfillFrom: at('2026-10-25T00:00:00.000Z'),
      watermarkAt: at('2026-10-28T00:00:00.000Z'),
      replayFrom: at('2026-11-10T00:00:00.000Z'),
      replayUntil: at('2026-11-19T23:00:00.000Z'),
    };
    // The gap [10-28, 11-10] was never processed: it must not be skipped.
    expect(ingestedRange(interrupted)).toEqual({
      from: at('2026-11-10T00:00:00.000Z'),
      until: at('2026-11-19T23:00:00.000Z'),
    });
    // A backfill without an earlier range: what it processed so far.
    expect(ingestedRange({ ...interrupted, replayFrom: null, replayUntil: null })).toEqual({
      from: at('2026-10-25T00:00:00.000Z'),
      until: minus(at('2026-10-28T00:00:00.000Z'), REPLAY_MARGIN_MS),
    });
  });

  it('records the joined start as covered_from when a backfill completes', () => {
    const backfillFrom = at('2026-11-01T00:00:00.000Z');
    expect(
      completedCoverage({ backfillFrom, replayFrom: live.coveredFrom, coveredFrom: null }),
    ).toEqual(backfillFrom);
    const inside = at('2026-11-15T00:00:00.000Z');
    expect(
      completedCoverage({ backfillFrom: inside, replayFrom: live.coveredFrom, coveredFrom: null }),
    ).toEqual(live.coveredFrom);
    expect(
      completedCoverage({ backfillFrom: inside, replayFrom: null, coveredFrom: null }),
    ).toEqual(inside);
  });

  it('skips events inside the window, never snapshot events', () => {
    const stream = {
      replayFrom: at('2026-11-10T00:00:00.000Z'),
      replayUntil: at('2026-11-19T23:00:00.000Z'),
    };
    const event = (eventId: string, occurredAt: string) => ({ eventId, occurredAt });
    expect(isReplayed(stream, event('si:1', '2026-11-12T08:00:00.000Z'))).toBe(true);
    expect(isReplayed(stream, event('si:2', '2026-11-09T23:59:59.999Z'))).toBe(false);
    expect(isReplayed(stream, event('si:3', '2026-11-19T23:00:00.000Z'))).toBe(false);
    expect(isReplayed(stream, event('snap:x', '2026-11-12T08:00:00.000Z'))).toBe(false);
    expect(
      isReplayed(
        { replayFrom: null, replayUntil: null },
        event('si:1', '2026-11-12T08:00:00.000Z'),
      ),
    ).toBe(false);
  });
});
