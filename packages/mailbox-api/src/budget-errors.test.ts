import { ConnectionAccessError, ProviderCallError } from '@email-gateway/idp-adapters';
import { describe, expect, it } from 'vitest';
import {
  InMemoryThrottleGate,
  mailboxBudgetId,
  MAX_THROTTLE_PAUSE_MS,
  OPEN_THROTTLE_GATE,
  parseMailboxBudgetId,
} from './budget';
import {
  isGraphCursorExpired,
  MailboxApiError,
  toMailboxApiError,
  MAILBOX_API_ERROR_CODES,
} from './errors';

describe('budget ids and the in-memory throttle gate', () => {
  it('prefixes budget ids with mbx: and parses them back', () => {
    expect(mailboxBudgetId('0190dddd-0000-7000-8000-000000000001')).toBe(
      'mbx:0190dddd-0000-7000-8000-000000000001',
    );
    expect(parseMailboxBudgetId('mbx:abc')).toBe('abc');
    expect(parseMailboxBudgetId('mbx:')).toBeNull();
    expect(parseMailboxBudgetId('501')).toBeNull();
  });

  it('pauses per connection and family, keeps the longer pause and caps at 600 s', async () => {
    let now = 1_000_000;
    const gate = new InMemoryThrottleGate(() => now);
    const base = { apiConnectionPublicId: 'c1', status: 429, code: 'throttled' as const };
    await gate.pause({ ...base, family: 'graph', retryAfterMs: 10_000 });
    await gate.pause({ ...base, family: 'graph', retryAfterMs: 2_000 });
    expect(await gate.remainingMs('c1', 'graph')).toBe(10_000);
    expect(await gate.remainingMs('c1', 'gmail')).toBe(0);
    expect(await gate.remainingMs('c2', 'graph')).toBe(0);
    await gate.pause({ ...base, family: 'gmail', retryAfterMs: 86_400_000 });
    expect(await gate.remainingMs('c1', 'gmail')).toBe(MAX_THROTTLE_PAUSE_MS);
    now += 10_000;
    expect(await gate.remainingMs('c1', 'graph')).toBe(0);
    expect(await OPEN_THROTTLE_GATE.remainingMs('c1', 'graph')).toBe(0);
  });
});

describe('MailboxApiError', () => {
  it('normalizes provider, connection and unknown errors without their text', () => {
    const provider = toMailboxApiError(
      new ProviderCallError('throttled', { status: 429, retryAfterMs: 5000, providerCode: 'X1' }),
    );
    expect(provider).toMatchObject({
      code: 'throttled',
      retryable: true,
      retryAfterMs: 5000,
      status: 429,
      providerCode: 'X1',
    });
    expect(toMailboxApiError(new ConnectionAccessError('consent_missing')).code).toBe(
      'consent_missing',
    );
    expect(toMailboxApiError(new ConnectionAccessError('scope_not_granted')).code).toBe(
      'missing_permission',
    );
    const unknown = toMailboxApiError(new Error('secret EXAMPLE-token-in-message'));
    expect(unknown.code).toBe('provider_unavailable');
    expect(JSON.stringify(unknown)).not.toContain('EXAMPLE-token');
    expect(
      toMailboxApiError(
        new ProviderCallError('forbidden', { status: 403, providerCode: 'ErrorAccessDenied' }),
      ).code,
    ).toBe('missing_permission');
    const same = new MailboxApiError('cursor_expired');
    expect(toMailboxApiError(same)).toBe(same);
    expect(MAILBOX_API_ERROR_CODES).toContain('cursor_expired');
    expect(MAILBOX_API_ERROR_CODES).toContain('throttle_paused');
  });

  it('recognizes Graph cursor expiry by status 410 or sync-state codes', () => {
    expect(isGraphCursorExpired(new MailboxApiError('bad_request', { status: 410 }))).toBe(true);
    expect(
      isGraphCursorExpired(
        new MailboxApiError('bad_request', { status: 400, providerCode: 'SyncStateInvalid' }),
      ),
    ).toBe(true);
    expect(isGraphCursorExpired(new MailboxApiError('bad_request', { status: 400 }))).toBe(false);
  });
});
