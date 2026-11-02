import { describe, expect, it } from 'vitest';
import {
  defaultJitter,
  JITTER_FRACTION,
  nextCheckAt,
  noJitter,
  type ScheduleConfig,
  type ScheduleInput,
} from './schedule';

const config: ScheduleConfig = {
  retryBaseSeconds: 60,
  retryMaxSeconds: 3600,
  recheckIncompleteSeconds: 1800,
  recheckIntervalSeconds: 86_400,
};
const now = new Date('2026-11-02T10:00:00.000Z');
const later = (seconds: number) => new Date(now.getTime() + seconds * 1000);

const input = (patch: Partial<ScheduleInput>): ScheduleInput => ({
  status: 'pending_verification',
  checkFailures: 0,
  attempts: 1,
  allRecordsValid: false,
  verificationExpiresAt: null,
  now,
  ...patch,
});

describe('nextCheckAt (D11)', () => {
  it('backs off pending verification exponentially: 1, 2, 4 … minutes, capped hourly', () => {
    const seq = [0, 1, 2, 3, 6, 7, 30].map((attempts) =>
      nextCheckAt(input({ attempts }), config, noJitter),
    );
    expect(seq).toEqual([
      later(60),
      later(120),
      later(240),
      later(480),
      later(3600),
      later(3600),
      later(3600),
    ]);
  });

  it('never schedules a pending domain after its verification expiry', () => {
    const expiresAt = later(90);
    expect(
      nextCheckAt(input({ attempts: 5, verificationExpiresAt: expiresAt }), config, noJitter),
    ).toEqual(expiresAt);
    // Already expired: check right away (now), never in the past.
    expect(nextCheckAt(input({ verificationExpiresAt: later(-10) }), config, noJitter)).toEqual(
      now,
    );
  });

  it('retries indeterminate checks with base × 2^(k−1) whatever the status', () => {
    for (const status of ['pending_verification', 'verified', 'active', 'suspended'] as const) {
      expect(
        nextCheckAt(input({ status, checkFailures: 1, attempts: 9 }), config, noJitter),
      ).toEqual(later(60));
      expect(nextCheckAt(input({ status, checkFailures: 3 }), config, noJitter)).toEqual(
        later(240),
      );
      expect(nextCheckAt(input({ status, checkFailures: 40 }), config, noJitter)).toEqual(
        later(3600),
      );
    }
  });

  it('caps an indeterminate retry of a pending domain at the expiry too', () => {
    expect(
      nextCheckAt(input({ checkFailures: 10, verificationExpiresAt: later(30) }), config, noJitter),
    ).toEqual(later(30));
  });

  it('rechecks owned domains: incomplete configuration often, healthy ones daily', () => {
    for (const status of ['verified', 'active', 'suspended'] as const) {
      expect(nextCheckAt(input({ status }), config, noJitter)).toEqual(later(1800));
      expect(nextCheckAt(input({ status, allRecordsValid: true }), config, noJitter)).toEqual(
        later(86_400),
      );
    }
  });

  it('stops checking failed, deleted and disabled domains', () => {
    for (const status of ['failed', 'deleted', 'disabled'] as const) {
      expect(nextCheckAt(input({ status, checkFailures: 2 }), config, noJitter)).toBeNull();
    }
  });

  it('applies the injected jitter to the delay', () => {
    expect(nextCheckAt(input({ attempts: 0 }), config, (s) => s * 1.1)).toEqual(later(66));
    expect(nextCheckAt(input({ attempts: 0 }), config, (s) => s * 0.9)).toEqual(later(54));
  });

  it('keeps the default jitter within ±10 %', () => {
    for (let i = 0; i < 1000; i++) {
      const value = defaultJitter(100);
      expect(value).toBeGreaterThanOrEqual(100 * (1 - JITTER_FRACTION));
      expect(value).toBeLessThanOrEqual(100 * (1 + JITTER_FRACTION));
    }
    const at = nextCheckAt(input({ status: 'active', allRecordsValid: true }), config)!;
    const delay = (at.getTime() - now.getTime()) / 1000;
    expect(delay).toBeGreaterThanOrEqual(86_400 * 0.9);
    expect(delay).toBeLessThanOrEqual(86_400 * 1.1);
  });

  it('never schedules sooner than one second ahead', () => {
    expect(nextCheckAt(input({ attempts: 0 }), config, () => 0)).toEqual(later(1));
  });
});
