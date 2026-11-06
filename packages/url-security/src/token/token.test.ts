import { createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  TOKEN_BYTES,
  TOKEN_LENGTH,
  continueNonce,
  parseTokenKey,
  signToken,
  tokenExpiry,
  validateTokenKeys,
  verifyContinueNonce,
  verifyToken,
  type TokenKey,
} from './token';

const current = parseTokenKey('11'.repeat(32), 7);
const previous = parseTokenKey('22'.repeat(32), 6);
const claims = {
  organizationId: 12345678901234n,
  messageId: 98765432109876n,
  receivedAtMs: Date.parse('2026-11-05T10:20:30.456Z'),
  urlSeq: 513,
  expiresAt: 2_000_000_000,
};
const NOW = 1_900_000_000;

describe('click token layout', () => {
  it('is 46 bytes / 62 base64url characters with the exact field layout', () => {
    const token = signToken(claims, current);
    expect(token).toHaveLength(TOKEN_LENGTH);
    expect(token).toMatch(/^[A-Za-z0-9_-]{62}$/);
    const bytes = Buffer.from(token, 'base64url');
    expect(bytes).toHaveLength(TOKEN_BYTES);
    expect(bytes[0]).toBe(1);
    expect(bytes[1]).toBe(7);
    expect(bytes.readBigUInt64BE(2)).toBe(claims.organizationId);
    expect(bytes.readBigUInt64BE(10)).toBe(claims.messageId);
    expect(bytes.readUIntBE(18, 6)).toBe(claims.receivedAtMs);
    expect(bytes.readUInt16BE(24)).toBe(513);
    expect(bytes.readUInt32BE(26)).toBe(2_000_000_000);
    const mac = createHmac('sha256', current.key)
      .update(Buffer.from('eg-url-token/v1\0', 'latin1'))
      .update(bytes.subarray(0, 30))
      .digest()
      .subarray(0, 16);
    expect(bytes.subarray(30).equals(mac)).toBe(true);
  });

  it('round-trips with the current key and with the previous key (rotation)', () => {
    expect(verifyToken(signToken(claims, current), { current }, NOW)).toEqual({
      outcome: 'ok',
      claims: { ...claims, keyId: 7 },
    });
    const old = signToken(claims, previous);
    expect(verifyToken(old, { current, previous }, NOW)).toMatchObject({
      outcome: 'ok',
      claims: { keyId: 6 },
    });
    expect(verifyToken(old, { current }, NOW)).toEqual({ outcome: 'unknown_kid' });
  });

  it('detects tampering of every single byte', () => {
    const token = signToken(claims, current);
    const bytes = Buffer.from(token, 'base64url');
    for (let i = 0; i < TOKEN_BYTES; i += 1) {
      const copy = Buffer.from(bytes);
      copy[i] = (copy[i] ?? 0) ^ 0x01;
      const outcome = verifyToken(copy.toString('base64url'), { current, previous }, NOW).outcome;
      if (i === 0) expect(outcome).toBe('bad_version');
      // Byte 1: kid 7 → 6 is the known previous key, so the MAC fails.
      else expect(outcome).toBe('bad_mac');
    }
    const kidToPrevious = Buffer.from(bytes);
    kidToPrevious[1] = 6;
    expect(
      verifyToken(kidToPrevious.toString('base64url'), { current, previous }, NOW).outcome,
    ).toBe('bad_mac');
    const unknownKid = Buffer.from(bytes);
    unknownKid[1] = 9;
    expect(verifyToken(unknownKid.toString('base64url'), { current, previous }, NOW).outcome).toBe(
      'unknown_kid',
    );
  });

  it('verifies in the documented order: malformed → version → kid → MAC → expiry', () => {
    expect(verifyToken('short', { current }, NOW).outcome).toBe('malformed');
    expect(verifyToken(`${signToken(claims, current)}A`, { current }, NOW).outcome).toBe(
      'malformed',
    );
    expect(
      verifyToken(signToken(claims, current).replace(/^./, '*'), { current }, NOW).outcome,
    ).toBe('malformed');
    // Non-canonical last character (unused low bits set).
    const token = signToken(claims, current);
    const last = token[61] as string;
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const tweaked =
      token.slice(0, 61) + (alphabet[(alphabet.indexOf(last) & ~0x0f) | 0x01] as string);
    expect(['malformed', 'bad_mac']).toContain(verifyToken(tweaked, { current }, NOW).outcome);
    const wrongKey = parseTokenKey('33'.repeat(32), 7);
    expect(verifyToken(token, { current: wrongKey }, NOW).outcome).toBe('bad_mac');
    // A wrong MAC on an expired token is bad_mac, not expired.
    const expired = signToken({ ...claims, expiresAt: NOW - 1 }, current);
    expect(verifyToken(expired, { current: wrongKey }, NOW).outcome).toBe('bad_mac');
  });

  it('expired is distinct and carries the claims; the boundary is exclusive', () => {
    const token = signToken({ ...claims, expiresAt: NOW }, current);
    expect(verifyToken(token, { current }, NOW)).toMatchObject({
      outcome: 'expired',
      claims: { organizationId: claims.organizationId },
    });
    expect(verifyToken(token, { current }, NOW - 1).outcome).toBe('ok');
  });

  it('refuses out-of-range claims and bad keys', () => {
    expect(() => signToken({ ...claims, organizationId: 0n }, current)).toThrow();
    expect(() => signToken({ ...claims, messageId: 1n << 64n }, current)).toThrow();
    expect(() => signToken({ ...claims, urlSeq: 65536 }, current)).toThrow();
    expect(() => signToken({ ...claims, receivedAtMs: 2 ** 48 }, current)).toThrow();
    expect(() => signToken({ ...claims, expiresAt: 2 ** 32 }, current)).toThrow();
    expect(() => parseTokenKey('ab', 1)).toThrow();
    expect(() => parseTokenKey('11'.repeat(32), 0)).toThrow();
    expect(() => parseTokenKey('11'.repeat(32), 256)).toThrow();
    expect(() => validateTokenKeys({ current, previous: { ...previous, id: 7 } })).toThrow();
    expect(() => validateTokenKeys({ current, previous: { id: 6, key: current.key } })).toThrow();
    expect(validateTokenKeys({ current, previous })).toBeTruthy();
  });

  it('computes expiry within the tenant bound', () => {
    const scan = new Date('2026-11-06T00:00:00Z');
    expect(tokenExpiry(scan, 30, 90)).toBe(Date.parse('2026-12-06T00:00:00Z') / 1000);
    expect(() => tokenExpiry(scan, 0, 90)).toThrow();
    expect(() => tokenExpiry(scan, 91, 90)).toThrow();
  });
});

describe('continue nonce', () => {
  const token = signToken(claims, current);
  const ttl = 600;
  it('is valid in the current and the previous window only', () => {
    const now = 1_900_000_123;
    const nonce = continueNonce(token, current, now, ttl);
    expect(nonce).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(verifyContinueNonce(token, nonce, current, now, ttl)).toBe(true);
    expect(verifyContinueNonce(token, nonce, current, now + ttl, ttl)).toBe(true);
    expect(verifyContinueNonce(token, nonce, current, now + 2 * ttl, ttl)).toBe(false);
  });
  it('is bound to the token and the key', () => {
    const now = 1_900_000_123;
    const nonce = continueNonce(token, current, now, ttl);
    const other = signToken({ ...claims, urlSeq: 1 }, current);
    expect(verifyContinueNonce(other, nonce, current, now, ttl)).toBe(false);
    const otherKey: TokenKey = parseTokenKey('44'.repeat(32), 7);
    expect(verifyContinueNonce(token, nonce, otherKey, now, ttl)).toBe(false);
    expect(verifyContinueNonce(token, 'garbage', current, now, ttl)).toBe(false);
  });
});
