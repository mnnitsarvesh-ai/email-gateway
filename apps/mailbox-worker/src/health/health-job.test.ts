import { describe, expect, it } from 'vitest';
import { alertWindowOf } from './health-job';

describe('alert windows', () => {
  it('aligns the throttle window to its size', () => {
    const window = alertWindowOf(new Date('2026-11-10T17:30:00.000Z'), 24 * 60);
    expect(window.from.toISOString()).toBe('2026-11-10T00:00:00.000Z');
    expect(window.to.toISOString()).toBe('2026-11-11T00:00:00.000Z');
  });
});
