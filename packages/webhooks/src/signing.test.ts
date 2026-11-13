import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import {
  generateWebhookSecret,
  isWebhookSecret,
  parseSignatureHeader,
  signatureHeader,
  signPayload,
  verifyWebhookSignature,
  WEBHOOK_SECRET_LENGTH,
  WEBHOOK_SIGNATURE_HEADER,
  WEBHOOK_SIGNATURE_TOLERANCE_SECONDS,
} from './signing';

const SECRET = generateWebhookSecret();
const OTHER = generateWebhookSecret();
const BODY = '{"id":"0193a1b2-7c3d-8e4f-9a0b-1c2d3e4f5a6b","type":"email.received"}';
const T = 1_794_560_000; // 2026-11-13T…
const AT = T * 1000;

describe('secrets (W7)', () => {
  it('generates whsec_ + base64url(32 random bytes)', () => {
    expect(SECRET).toMatch(/^whsec_[A-Za-z0-9_-]{43}$/);
    expect(SECRET).toHaveLength(WEBHOOK_SECRET_LENGTH);
    expect(WEBHOOK_SECRET_LENGTH).toBe(49);
    expect(isWebhookSecret(SECRET)).toBe(true);
    expect(isWebhookSecret('whsec_short')).toBe(false);
    expect(SECRET).not.toBe(OTHER);
  });

  it('draws exactly 32 bytes from the entropy source', () => {
    const source = vi.fn((size: number) => Buffer.alloc(size, 0xab));
    expect(generateWebhookSecret(source)).toBe(
      `whsec_${Buffer.alloc(32, 0xab).toString('base64url')}`,
    );
    expect(source).toHaveBeenCalledWith(32);
    expect(() => generateWebhookSecret(() => Buffer.alloc(16))).toThrow();
  });
});

describe('signing (§4.2)', () => {
  it('is hex HMAC-SHA256 over "<t>.<raw body>" keyed with the whole secret string', () => {
    const expected = createHmac('sha256', Buffer.from(SECRET, 'utf8'))
      .update(`${T}.${BODY}`)
      .digest('hex');
    expect(signPayload(SECRET, T, BODY)).toBe(expected);
    expect(signPayload(SECRET, T, Buffer.from(BODY))).toBe(expected);
    expect(signatureHeader([SECRET], T, BODY)).toBe(`t=${T},v1=${expected}`);
    expect(WEBHOOK_SIGNATURE_HEADER).toBe('EG-Signature');
    expect(() => signPayload(SECRET, -1, BODY)).toThrow();
    expect(() => signatureHeader([], T, BODY)).toThrow();
  });

  it('round-trips and carries one v1 per secret, current first', () => {
    const header = signatureHeader([SECRET, OTHER], T, BODY);
    expect(parseSignatureHeader(header)).toEqual({
      timestamp: T,
      signatures: [signPayload(SECRET, T, BODY), signPayload(OTHER, T, BODY)],
    });
    expect(verifyWebhookSignature({ header, rawBody: BODY, secrets: [SECRET], now: AT })).toEqual({
      ok: true,
    });
  });

  it('rejects a tampered body', () => {
    const header = signatureHeader([SECRET], T, BODY);
    expect(
      verifyWebhookSignature({
        header,
        rawBody: BODY.replace('received', 'rejected'),
        secrets: [SECRET],
        now: AT,
      }),
    ).toEqual({ ok: false, reason: 'mismatch' });
    expect(
      verifyWebhookSignature({ header, rawBody: `${BODY} `, secrets: [SECRET], now: AT }),
    ).toEqual({ ok: false, reason: 'mismatch' });
  });

  it('rejects the wrong secret and a tampered timestamp', () => {
    const header = signatureHeader([SECRET], T, BODY);
    expect(verifyWebhookSignature({ header, rawBody: BODY, secrets: [OTHER], now: AT })).toEqual({
      ok: false,
      reason: 'mismatch',
    });
    const moved = header.replace(`t=${T}`, `t=${T + 1}`);
    expect(
      verifyWebhookSignature({ header: moved, rawBody: BODY, secrets: [SECRET], now: AT }),
    ).toEqual({
      ok: false,
      reason: 'mismatch',
    });
  });

  it('rejects a stale timestamp in the past and in the future, inside the tolerance it passes', () => {
    const header = signatureHeader([SECRET], T, BODY);
    const verifyAt = (now: number, toleranceSeconds?: number) =>
      verifyWebhookSignature({ header, rawBody: BODY, secrets: [SECRET], now, toleranceSeconds });
    expect(WEBHOOK_SIGNATURE_TOLERANCE_SECONDS).toBe(300);
    expect(verifyAt(AT + 300_000)).toEqual({ ok: true });
    expect(verifyAt(AT + 301_000)).toEqual({ ok: false, reason: 'stale' });
    // Future skew: the signer's clock is ahead of the receiver.
    expect(verifyAt(AT - 300_000)).toEqual({ ok: true });
    expect(verifyAt(AT - 301_000)).toEqual({ ok: false, reason: 'stale' });
    expect(verifyAt(AT + 30_000, 10)).toEqual({ ok: false, reason: 'stale' });
    expect(
      verifyWebhookSignature({ header, rawBody: BODY, secrets: [SECRET], now: new Date(AT) }),
    ).toEqual({ ok: true });
  });

  it('accepts either secret during a rotation overlap; after it only the new secret signs', () => {
    const NEW = generateWebhookSecret();
    const overlap = signatureHeader([NEW, SECRET], T, BODY);
    // A receiver that still has the old secret, and one that has the new one.
    expect(
      verifyWebhookSignature({ header: overlap, rawBody: BODY, secrets: [SECRET], now: AT }),
    ).toEqual({ ok: true });
    expect(
      verifyWebhookSignature({ header: overlap, rawBody: BODY, secrets: [NEW], now: AT }),
    ).toEqual({ ok: true });
    // After the overlap the platform signs with the new secret only: the old secret fails.
    const after = signatureHeader([NEW], T, BODY);
    expect(
      verifyWebhookSignature({ header: after, rawBody: BODY, secrets: [SECRET], now: AT }),
    ).toEqual({
      ok: false,
      reason: 'mismatch',
    });
    // A receiver that accepts both keeps working throughout.
    expect(
      verifyWebhookSignature({ header: after, rawBody: BODY, secrets: [SECRET, NEW], now: AT }),
    ).toEqual({ ok: true });
  });

  it.each([
    [undefined],
    [''],
    ['v1=abc'],
    [`t=${T}`],
    [`t=${T},v1=${'A'.repeat(64)}`],
    [`t=${T},v1=${'a'.repeat(63)}`],
    [`t=abc,v1=${'a'.repeat(64)}`],
    [`t=${T},t=${T},v1=${'a'.repeat(64)}`],
    [`t=${T},v1`],
    [`t=-1,v1=${'a'.repeat(64)}`],
    [`t=${T},${Array.from({ length: 9 }, () => `v1=${'a'.repeat(64)}`).join(',')}`],
    [`t=${T},v1=${'a'.repeat(64)},${'x'.repeat(1100)}=1`],
  ])('rejects the malformed header %j', (header) => {
    expect(verifyWebhookSignature({ header, rawBody: BODY, secrets: [SECRET], now: AT })).toEqual({
      ok: false,
      reason: 'malformed',
    });
  });

  it('ignores unknown schemes and whitespace around elements', () => {
    const sig = signPayload(SECRET, T, BODY);
    expect(
      verifyWebhookSignature({
        header: `t=${T}, v0=old, v1=${sig}`,
        rawBody: BODY,
        secrets: [SECRET],
        now: AT,
      }),
    ).toEqual({ ok: true });
  });
});

/**
 * The receiver snippet of the API guide (§4.2), written with node:crypto only and independent of
 * this package: it must accept what `signatureHeader` produces.
 */
function guideVerify(
  header: string,
  rawBody: Buffer,
  secrets: string[],
  nowSeconds: number,
): boolean {
  const parts = Object.fromEntries(
    header.split(',').map((p) => {
      const i = p.indexOf('=');
      return [p.slice(0, i).trim(), p.slice(i + 1)];
    }),
  );
  const t = Number(parts.t);
  if (!Number.isInteger(t) || Math.abs(nowSeconds - t) > 300) return false;
  const received = header
    .split(',')
    .map((p) => p.trim())
    .filter((p) => p.startsWith('v1='))
    .map((p) => Buffer.from(p.slice(3), 'hex'));
  return secrets.some((secret) => {
    const expected = createHmac('sha256', secret).update(`${t}.`).update(rawBody).digest();
    return received.some((sig) => sig.length === expected.length && timingSafeEqual(sig, expected));
  });
}

describe('API guide receiver snippet', () => {
  it('verifies the platform signature over the raw bytes', () => {
    const body = Buffer.concat([Buffer.from('{"x":"'), randomBytes(8), Buffer.from('"}')]);
    const header = signatureHeader([SECRET], T, body);
    expect(guideVerify(header, body, [SECRET], T + 5)).toBe(true);
    expect(guideVerify(header, Buffer.concat([body, Buffer.from(' ')]), [SECRET], T)).toBe(false);
    expect(guideVerify(header, body, [OTHER], T)).toBe(false);
    expect(guideVerify(header, body, [SECRET], T + 301)).toBe(false);
    expect(guideVerify(signatureHeader([OTHER, SECRET], T, body), body, [SECRET], T)).toBe(true);
  });
});
