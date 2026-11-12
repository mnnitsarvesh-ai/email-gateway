import { HttpStatus } from '@nestjs/common';
import { PARTITION_REGISTRY, retentionCutoff } from '@email-gateway/database';
import { describe, expect, it } from 'vitest';
import { CodedHttpException } from '../../../http/coded-exception';
import { EMAIL_MESSAGES_RETENTION, resolveBillingMonth } from './billing-month';

const now = new Date('2026-11-12T10:00:00.000Z');

function unavailable(fn: () => unknown): void {
  try {
    fn();
  } catch (err) {
    expect(err).toBeInstanceOf(CodedHttpException);
    expect((err as CodedHttpException).getStatus()).toBe(HttpStatus.BAD_REQUEST);
    expect((err as CodedHttpException).code).toBe('usage_period_unavailable');
    return;
  }
  expect.fail('expected 400 usage_period_unavailable');
}

describe('billing month resolution (step 6.1 D12)', () => {
  it('uses the email_messages retention of the partitioning registry (6 months)', () => {
    expect(EMAIL_MESSAGES_RETENTION).toBe(
      PARTITION_REGISTRY.find((s) => s.table === 'email_messages'),
    );
    expect(EMAIL_MESSAGES_RETENTION.retention).toBe(6);
    expect(retentionCutoff(EMAIL_MESSAGES_RETENTION, now)?.toISOString()).toBe(
      '2026-05-01T00:00:00.000Z',
    );
  });

  it('defaults to the current UTC month, counted up to now', () => {
    expect(resolveBillingMonth(undefined, now)).toEqual({
      month: '2026-11',
      from: new Date('2026-11-01T00:00:00.000Z'),
      end: new Date('2026-12-01T00:00:00.000Z'),
      to: now,
    });
  });

  it('resolves a past month to the whole calendar month', () => {
    expect(resolveBillingMonth('2026-08', now)).toEqual({
      month: '2026-08',
      from: new Date('2026-08-01T00:00:00.000Z'),
      end: new Date('2026-09-01T00:00:00.000Z'),
      to: new Date('2026-09-01T00:00:00.000Z'),
    });
  });

  it('accepts the oldest retained month and refuses older and future months', () => {
    // Retention: the current month plus 6 full months (May–November 2026).
    expect(resolveBillingMonth('2026-05', now).month).toBe('2026-05');
    unavailable(() => resolveBillingMonth('2026-04', now));
    unavailable(() => resolveBillingMonth('2025-11', now));
    unavailable(() => resolveBillingMonth('2026-12', now));
    unavailable(() => resolveBillingMonth('2027-01', now));
  });

  it('handles the year boundary and the first instant of a month', () => {
    const newYear = new Date('2027-01-01T00:00:00.000Z');
    expect(resolveBillingMonth(undefined, newYear).month).toBe('2027-01');
    expect(resolveBillingMonth('2026-07', newYear).month).toBe('2026-07');
    unavailable(() => resolveBillingMonth('2026-06', newYear));
  });

  it('refuses malformed months', () => {
    unavailable(() => resolveBillingMonth('2026-13', now));
    unavailable(() => resolveBillingMonth('2026-1', now));
  });
});
