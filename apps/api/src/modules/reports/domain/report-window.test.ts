import { BadRequestException } from '@nestjs/common';
import { describe, expect, it } from 'vitest';
import { bucketStarts, ceilTo, floorTo, maxRangeDays, resolveReportWindow } from './report-window';

const DAY = 86_400_000;
const now = new Date('2026-11-12T10:17:23.456Z');

describe('report windows (step 6.1 D12)', () => {
  it('floors and ceils to UTC hour and day boundaries', () => {
    expect(floorTo(now, 'hour').toISOString()).toBe('2026-11-12T10:00:00.000Z');
    expect(ceilTo(now, 'hour').toISOString()).toBe('2026-11-12T11:00:00.000Z');
    expect(floorTo(now, 'day').toISOString()).toBe('2026-11-12T00:00:00.000Z');
    expect(ceilTo(now, 'day').toISOString()).toBe('2026-11-13T00:00:00.000Z');
    // Already aligned instants stay.
    const midnight = new Date('2026-11-12T00:00:00.000Z');
    expect(ceilTo(midnight, 'day')).toEqual(midnight);
    expect(floorTo(midnight, 'hour')).toEqual(midnight);
  });

  it('defaults to the last 24 hours (hour) or 7 days (day), aligned', () => {
    const hour = resolveReportWindow({}, { granularity: 'hour', maxDays: 31, now });
    expect(hour.from.toISOString()).toBe('2026-11-11T10:00:00.000Z');
    expect(hour.to.toISOString()).toBe('2026-11-12T11:00:00.000Z');
    expect(bucketStarts(hour)).toHaveLength(25);
    const day = resolveReportWindow({}, { granularity: 'day', maxDays: 31, now });
    expect(day.from.toISOString()).toBe('2026-11-05T00:00:00.000Z');
    expect(day.to.toISOString()).toBe('2026-11-13T00:00:00.000Z');
    expect(bucketStarts(day).map((d) => d.toISOString())).toEqual([
      '2026-11-05T00:00:00.000Z',
      '2026-11-06T00:00:00.000Z',
      '2026-11-07T00:00:00.000Z',
      '2026-11-08T00:00:00.000Z',
      '2026-11-09T00:00:00.000Z',
      '2026-11-10T00:00:00.000Z',
      '2026-11-11T00:00:00.000Z',
      '2026-11-12T00:00:00.000Z',
    ]);
  });

  it('limits hour reports to 7 days and day reports to REPORTS_MAX_RANGE_DAYS', () => {
    expect(maxRangeDays('hour', 31)).toBe(7);
    expect(maxRangeDays('hour', 3)).toBe(3);
    expect(maxRangeDays('day', 31)).toBe(31);
    const to = now;
    const ok7 = new Date(to.getTime() - 7 * DAY);
    expect(() =>
      resolveReportWindow({ from: ok7, to }, { granularity: 'hour', maxDays: 7, now }),
    ).not.toThrow();
    expect(() =>
      resolveReportWindow(
        { from: new Date(ok7.getTime() - 1), to },
        { granularity: 'hour', maxDays: 7, now },
      ),
    ).toThrow(BadRequestException);
    expect(() =>
      resolveReportWindow(
        { from: new Date(to.getTime() - 32 * DAY), to },
        { granularity: 'day', maxDays: 31, now },
      ),
    ).toThrow(BadRequestException);
  });

  it('requires from < to', () => {
    expect(() =>
      resolveReportWindow({ from: now, to: now }, { granularity: 'day', maxDays: 31, now }),
    ).toThrow(BadRequestException);
  });

  it('gives the same window to requests inside the same bucket (cache sharing)', () => {
    const a = resolveReportWindow({}, { granularity: 'hour', maxDays: 7, now });
    const b = resolveReportWindow(
      {},
      { granularity: 'hour', maxDays: 7, now: new Date(now.getTime() + 20 * 60_000) },
    );
    expect(a).toEqual(b);
  });
});
