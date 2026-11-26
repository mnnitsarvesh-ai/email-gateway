import { describe, expect, it } from 'vitest';
import { ProviderCallError } from '@email-gateway/idp-adapters';
import { MailboxApiError } from '@email-gateway/mailbox-api';
import { backoffMs, classifyFailure, pollIntervalMs, statusAfterFailure } from './schedule';

describe('feed scheduling (D10.6)', () => {
  it('backs off 30 s × 2^(n-1), capped at one hour', () => {
    expect([1, 2, 3, 4].map(backoffMs)).toEqual([30_000, 60_000, 120_000, 240_000]);
    expect(backoffMs(12)).toBe(3_600_000);
    expect(backoffMs(0)).toBe(30_000);
  });

  it('shows error from the third consecutive failure', () => {
    expect(statusAfterFailure(1, false)).toBe('pending');
    expect(statusAfterFailure(2, true)).toBe('active');
    expect(statusAfterFailure(3, true)).toBe('error');
  });

  it('polls safely with a subscription, normally without', () => {
    const cfg = { feedPollSeconds: 300, safetyPollSeconds: 3600 };
    expect(pollIntervalMs(true, cfg)).toBe(3_600_000);
    expect(pollIntervalMs(false, cfg)).toBe(300_000);
  });

  it('classifies throttling, budget, cursor expiry and failures by code', () => {
    expect(
      classifyFailure(new MailboxApiError('throttled', { retryAfterMs: 2000, status: 429 })),
    ).toEqual({
      kind: 'throttled',
      retryAfterMs: 2000,
    });
    expect(classifyFailure(new MailboxApiError('throttle_paused', { retryAfterMs: 500 }))).toEqual({
      kind: 'throttled',
      retryAfterMs: 1000,
    });
    expect(
      classifyFailure(
        new MailboxApiError('provider_unavailable', { status: 503, retryAfterMs: 5000 }),
      ),
    ).toEqual({ kind: 'throttled', retryAfterMs: 5000 });
    expect(classifyFailure(new MailboxApiError('provider_unavailable', { status: 503 }))).toEqual({
      kind: 'failure',
      code: 'provider_unavailable',
    });
    expect(classifyFailure(new MailboxApiError('rate_budget'))).toEqual({ kind: 'budget' });
    expect(classifyFailure(new MailboxApiError('cursor_expired'))).toEqual({
      kind: 'cursor_expired',
    });
    expect(classifyFailure(new ProviderCallError('missing_permission'))).toEqual({
      kind: 'failure',
      code: 'missing_permission',
    });
    const db = Object.assign(new Error('Server has closed the connection'), { code: 'P1017' });
    expect(classifyFailure(db)).toEqual({ kind: 'failure', code: 'P1017' });
  });
});
