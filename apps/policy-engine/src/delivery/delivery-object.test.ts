import { describe, expect, it, vi } from 'vitest';
import { InconsistentPolicyReadError } from '../evaluation/errors';
import { deliveryObject, isRewriteKeyOf } from './delivery-object';

/** Ported from the delivery-worker's development pass-through (step 4.3 U20 → step 5.2 P20). */
const RECEIVED = new Date('2026-11-03T11:00:00.000Z');
const REWRITE_KEY = 'org/7/rewrite/2026/11/03/100/r0-0190f0f0-0000-7000-8000-0000000000ff.eml';
const ORIGINAL = 'org/7/eml/2026/11/03/stored.eml';
const request = {
  messageId: 100n,
  receivedAt: RECEIVED,
  organizationId: 7n,
  round: 0,
  scanId: 900n,
  original: ORIGINAL,
};
const rewriteRow = (overrides: Record<string, unknown> = {}) => ({
  messageId: 100n,
  receivedAt: RECEIVED,
  organizationId: 7n,
  lifecycleRound: 0,
  scanId: 900n,
  status: 'rewritten',
  objectKey: REWRITE_KEY,
  ...overrides,
});
const fakeTx = (row: unknown) => ({ urlRewrite: { findFirst: vi.fn(() => Promise.resolve(row)) } });

describe('deliveryObject (P20, moved from the pass-through)', () => {
  it('delivers the rewritten object of the round, read for (message, org, round, scan, status)', async () => {
    const tx = fakeTx(rewriteRow());
    const sink = vi.fn();
    expect(await deliveryObject(tx as never, request, sink)).toEqual({
      key: REWRITE_KEY,
      object: 'rewritten',
    });
    expect(tx.urlRewrite.findFirst).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          messageId: 100n,
          receivedAt: RECEIVED,
          organizationId: 7n,
          lifecycleRound: 0,
          scanId: 900n,
          status: 'rewritten',
        },
      }),
    );
    expect(sink).not.toHaveBeenCalled();
  });

  it('delivers the original when the round has no rewritten copy (skipped or absent)', async () => {
    expect(await deliveryObject(fakeTx(null) as never, request, vi.fn())).toEqual({
      key: ORIGINAL,
      object: 'original',
    });
  });

  it.each([
    ['another organization prefix', 'org/8/rewrite/2026/11/03/100/r0-x.eml', 'key_prefix'],
    ['not a rewrite object', 'org/7/eml/2026/11/03/other.eml', 'key_prefix'],
    ['a dot-dot segment', 'org/7/rewrite/../eml/x.eml', 'key_prefix'],
    ['no key', null, 'missing_key'],
  ])('falls back to the original for %s', async (_label, objectKey, fallback) => {
    expect(
      await deliveryObject(fakeTx(rewriteRow({ objectKey })) as never, request, vi.fn()),
    ).toEqual({ key: ORIGINAL, object: 'original', fallback });
  });

  it.each([
    ['message', { messageId: 101n }],
    ['organization', { organizationId: 8n }],
    ['round', { lifecycleRound: 1 }],
    ['scan', { scanId: 901n }],
    ['receivedAt', { receivedAt: new Date(0) }],
    ['status', { status: 'skipped' }],
  ])('throws a retryable inconsistent read on a shifted row: %s', async (_label, overrides) => {
    const sink = vi.fn();
    await expect(
      deliveryObject(fakeTx(rewriteRow(overrides)) as never, request, sink),
    ).rejects.toBeInstanceOf(InconsistentPolicyReadError);
    expect(sink).toHaveBeenCalledWith('url_rewrite');
  });

  it('isRewriteKeyOf accepts only org/<org>/rewrite/ keys without dot or empty segments', () => {
    expect(isRewriteKeyOf(REWRITE_KEY, 7n)).toBe(true);
    expect(isRewriteKeyOf(REWRITE_KEY, 70n)).toBe(false);
    expect(isRewriteKeyOf('org/7/rewrite//x.eml', 7n)).toBe(false);
    expect(isRewriteKeyOf('org/7/rewriteX/x.eml', 7n)).toBe(false);
    expect(isRewriteKeyOf('org/7/rewrite/./x.eml', 7n)).toBe(false);
  });
});
