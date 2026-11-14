import { describe, expect, it } from 'vitest';
import {
  fromLocalInput,
  isMinuteIso,
  isValidCustomRange,
  resolveDateTimeRange,
  toLocalInput,
  validateCustomDateTimeRange,
} from './date-time-range';

const NOW = Date.parse('2026-11-14T10:20:30.000Z');
/** A local `datetime-local` value for a UTC instant (the test runs in any time zone). */
const local = (iso: string) => toLocalInput(iso);

describe('date-time ranges (step 7.2 §2 E10)', () => {
  it('presets end at the next whole minute and span their duration', () => {
    expect(resolveDateTimeRange({ kind: '1h' }, NOW)).toEqual({
      from: '2026-11-14T09:21:00.000Z',
      to: '2026-11-14T10:21:00.000Z',
      kind: '1h',
    });
    const month = resolveDateTimeRange({ kind: '30d' }, NOW);
    expect(Date.parse(month.to) - Date.parse(month.from)).toBe(30 * 86_400_000);
    // Exactly on a minute: that minute is the end.
    expect(resolveDateTimeRange({ kind: '24h' }, Date.parse('2026-11-14T10:20:00.000Z')).to).toBe(
      '2026-11-14T10:20:00.000Z',
    );
  });

  it('converts between the browser time zone and UTC at minute precision', () => {
    const iso = '2026-11-13T08:45:00.000Z';
    const input = local(iso);
    expect(input).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/);
    expect(fromLocalInput(input)).toBe(iso);
    expect(fromLocalInput(`${input}:59`)).toBe(iso);
    expect(fromLocalInput('2026-02-30T10:00')).toBeNull();
    expect(fromLocalInput('yesterday')).toBeNull();
    expect(toLocalInput('nope')).toBe('');
  });

  it('accepts a custom range of up to 31 days that starts in the past', () => {
    const result = validateCustomDateTimeRange(
      local('2026-10-14T10:00:00.000Z'),
      local('2026-11-14T10:00:00.000Z'),
      NOW,
    );
    expect(result).toEqual({
      ok: true,
      from: '2026-10-14T10:00:00.000Z',
      to: '2026-11-14T10:00:00.000Z',
    });
  });

  it('refuses missing, invalid, reversed, too long and future ranges with field messages', () => {
    const errors = (from: string, to: string) => {
      const result = validateCustomDateTimeRange(from, to, NOW);
      return result.ok ? [] : result.errors;
    };
    expect(errors('', '')).toEqual([
      { field: 'from', message: 'Enter the start date and time.' },
      { field: 'to', message: 'Enter the end date and time.' },
    ]);
    expect(errors('2026-02-30T10:00', local('2026-11-01T00:00:00.000Z'))[0]?.field).toBe('from');
    expect(errors(local('2026-11-02T00:00:00.000Z'), local('2026-11-01T00:00:00.000Z'))).toEqual([
      { field: 'to', message: 'The end must be after the start.' },
    ]);
    expect(errors(local('2026-10-01T00:00:00.000Z'), local('2026-11-01T00:01:00.000Z'))).toEqual([
      { field: 'range', message: 'Choose a range of at most 31 days.' },
    ]);
    expect(errors(local('2026-11-15T00:00:00.000Z'), local('2026-11-16T00:00:00.000Z'))).toEqual([
      { field: 'from', message: 'The start is in the future.' },
    ]);
  });

  it('checks URL bounds: whole-minute UTC ISO, ordered, at most 31 days', () => {
    expect(isMinuteIso('2026-11-13T08:00:00.000Z')).toBe(true);
    expect(isMinuteIso('2026-11-13T08:00Z')).toBe(true);
    expect(isMinuteIso('2026-11-13T08:00:30.000Z')).toBe(false);
    expect(isMinuteIso('2026-11-13T08:00:00+01:00')).toBe(false);
    expect(isValidCustomRange('2026-10-01T00:00:00.000Z', '2026-11-01T00:00:00.000Z')).toBe(true);
    expect(isValidCustomRange('2026-10-01T00:00:00.000Z', '2026-11-01T00:01:00.000Z')).toBe(false);
    expect(isValidCustomRange('2026-11-01T00:00:00.000Z', '2026-11-01T00:00:00.000Z')).toBe(false);
    expect(isValidCustomRange(undefined, '2026-11-01T00:00:00.000Z')).toBe(false);
  });
});
