import { describe, expect, it } from 'vitest';
import { REPORTS_MAX_RANGE_DAYS, resolvePreset, validateCustomRange } from './range';

const now = Date.parse('2026-11-13T10:20:00.000Z');

describe('report ranges (design P13)', () => {
  it('resolves presets to stable hour-aligned windows', () => {
    expect(resolvePreset('24h', now)).toMatchObject({
      from: '2026-11-12T11:00:00.000Z',
      to: '2026-11-13T11:00:00.000Z',
      granularity: 'hour',
    });
    expect(resolvePreset('7d', now)).toMatchObject({
      from: '2026-11-06T11:00:00.000Z',
      granularity: 'day',
    });
    expect(resolvePreset('30d', now + 10 * 60_000).to).toBe(resolvePreset('30d', now).to);
  });

  it('validates custom UTC-day ranges up to 31 days (to inclusive in the UI)', () => {
    const ok = validateCustomRange('2026-11-01', '2026-11-07', now);
    expect(ok).toMatchObject({
      ok: true,
      range: {
        from: '2026-11-01T00:00:00.000Z',
        to: '2026-11-08T00:00:00.000Z',
        granularity: 'day',
      },
    });
    expect(validateCustomRange('2026-10-01', '2026-10-31', now).ok).toBe(true);
    expect(validateCustomRange('2026-10-01', '2026-11-01', now)).toMatchObject({
      ok: false,
      error: 'too_long',
    });
    expect(REPORTS_MAX_RANGE_DAYS).toBe(31);
    expect(validateCustomRange('2026-11-07', '2026-11-01', now)).toMatchObject({
      ok: false,
      error: 'order',
    });
    expect(validateCustomRange('2026-12-01', '2026-12-02', now)).toMatchObject({
      ok: false,
      error: 'future',
    });
    expect(validateCustomRange('', '2026-12-02', now)).toMatchObject({
      ok: false,
      error: 'invalid',
    });
  });
});
