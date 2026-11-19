import { describe, expect, it } from 'vitest';
import { localDayStart, localParts, zonedMidnight } from './time';

describe('digest time arithmetic (D16)', () => {
  it('local midnight in zones east and west of UTC', () => {
    expect(zonedMidnight(2026, 11, 18, 'Asia/Kolkata').toISOString()).toBe(
      '2026-11-17T18:30:00.000Z',
    );
    expect(zonedMidnight(2026, 11, 18, 'America/New_York').toISOString()).toBe(
      '2026-11-18T05:00:00.000Z',
    );
    expect(zonedMidnight(2026, 7, 1, 'America/New_York').toISOString()).toBe(
      '2026-07-01T04:00:00.000Z',
    );
    expect(zonedMidnight(2026, 11, 18, 'UTC').toISOString()).toBe('2026-11-18T00:00:00.000Z');
  });

  it('previous local day and ISO weekday', () => {
    const at = new Date('2026-11-16T03:00:00.000Z'); // Monday 08:30 in Kolkata
    expect(localParts(at, 'Asia/Kolkata')).toMatchObject({ hour: 8, minute: 30, weekday: 1 });
    expect(localDayStart(at, 'Asia/Kolkata').toISOString()).toBe('2026-11-15T18:30:00.000Z');
    expect(localDayStart(at, 'Asia/Kolkata', -1).toISOString()).toBe('2026-11-14T18:30:00.000Z');
    expect(localDayStart(at, 'Asia/Kolkata', -7).toISOString()).toBe('2026-11-08T18:30:00.000Z');
  });

  it('an unknown zone falls back to UTC', () => {
    expect(localDayStart(new Date('2026-11-18T10:00:00Z'), 'Not/AZone').toISOString()).toBe(
      '2026-11-18T00:00:00.000Z',
    );
  });
});
