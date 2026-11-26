import { describe, expect, it } from 'vitest';
import {
  journalDelivery,
  lagDelta,
  lagOf,
  mergeDelta,
  STATUS_OF_OUTCOME,
  storedVerdict,
} from './copy-plan';

describe('copy plan helpers (D7)', () => {
  const received = new Date('2026-11-10T12:00:00.000Z');

  it('maps every outcome to a copy status', () => {
    expect(STATUS_OF_OUTCOME).toEqual({
      scanned: 'scanned',
      scan_failed: 'scan_failed',
      parse_failed: 'parse_failed',
    });
  });

  it('takes the topmost Received date, else the ingest time', () => {
    const top = new Date('2026-11-10T11:58:00.000Z');
    expect(journalDelivery(top, received)).toEqual({ at: top, basis: 'received_header' });
    expect(journalDelivery(null, received)).toEqual({ at: received, basis: 'ingest' });
    expect(journalDelivery(new Date(Number.NaN), received).basis).toBe('ingest');
  });

  it('computes the lag of scanned copies only, never negative', () => {
    const verdict = new Date('2026-11-10T12:01:00.000Z');
    expect(lagOf('scanned', received, verdict)).toBe(60_000);
    expect(lagOf('scanned', new Date('2026-11-10T12:05:00.000Z'), verdict)).toBe(0);
    expect(lagOf('scan_failed', received, verdict)).toBeNull();
    expect(lagOf('parse_failed', received, verdict)).toBeNull();
    expect(lagOf('scanned', null, verdict)).toBeNull();
  });

  it('buckets lags and merges deltas (max for lag_max_ms)', () => {
    expect(lagDelta(30_000)).toEqual({
      lag_count: 1,
      lag_le_60s: 1,
      lag_sum_ms: 30_000,
      lag_max_ms: 30_000,
    });
    expect(lagDelta(4_000_000)).toMatchObject({ lag_gt_3600s: 1 });
    const merged = mergeDelta(mergeDelta({}, lagDelta(30_000)), lagDelta(600_000));
    expect(merged).toEqual({
      lag_count: 2,
      lag_le_60s: 1,
      lag_le_900s: 1,
      lag_sum_ms: 630_000,
      lag_max_ms: 600_000,
    });
  });

  it('lets a linked inline message carry the verdict authority (hybrid)', () => {
    expect(storedVerdict('phishing', null)).toEqual({ verdict: 'phishing', authority: 'copy' });
    expect(storedVerdict('phishing', { finalVerdict: 'clean' })).toEqual({
      verdict: 'clean',
      authority: 'inline',
    });
    expect(storedVerdict('spam', { finalVerdict: null })).toEqual({
      verdict: 'spam',
      authority: 'inline',
    });
  });
});
