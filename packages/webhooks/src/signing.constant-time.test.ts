import type * as NodeCrypto from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import { generateWebhookSecret, signatureHeader, verifyWebhookSignature } from './signing';

const calls = vi.hoisted(() => ({ count: 0 }));

vi.mock('node:crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof NodeCrypto>();
  return {
    ...actual,
    timingSafeEqual: (a: NodeJS.ArrayBufferView, b: NodeJS.ArrayBufferView) => {
      calls.count += 1;
      return actual.timingSafeEqual(a, b);
    },
  };
});

describe('verifyWebhookSignature: constant-time path', () => {
  it('compares every v1 against every secret with timingSafeEqual, without stopping at a match', () => {
    const a = generateWebhookSecret();
    const b = generateWebhookSecret();
    const c = generateWebhookSecret();
    const t = 1_794_560_000;
    const header = signatureHeader([a, b], t, 'body');
    calls.count = 0;
    // The first pair already matches; all 2 × 3 comparisons still run.
    expect(
      verifyWebhookSignature({ header, rawBody: 'body', secrets: [a, b, c], now: t * 1000 }),
    ).toEqual({ ok: true });
    expect(calls.count).toBe(6);
    calls.count = 0;
    expect(
      verifyWebhookSignature({ header, rawBody: 'other', secrets: [a, b, c], now: t * 1000 }),
    ).toEqual({ ok: false, reason: 'mismatch' });
    expect(calls.count).toBe(6);
    // Malformed and stale headers never reach a comparison.
    calls.count = 0;
    verifyWebhookSignature({ header: 'nonsense', rawBody: 'body', secrets: [a], now: t * 1000 });
    verifyWebhookSignature({ header, rawBody: 'body', secrets: [a], now: (t + 999) * 1000 });
    expect(calls.count).toBe(0);
  });
});
