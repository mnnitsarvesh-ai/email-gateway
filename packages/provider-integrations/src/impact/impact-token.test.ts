import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  canonicalJson,
  ImpactTokenKeyError,
  impactTokenKey,
  signImpactToken,
  verifyImpactToken,
  type ImpactTokenBody,
} from './impact-token';

const key = impactTokenKey(randomBytes(32).toString('hex'));
const now = new Date('2026-11-18T12:00:00Z');
const body: ImpactTokenBody = {
  orgId: 42n,
  connectionId: '01930000-0000-7000-8000-000000000001',
  rowVersion: 3,
  changeSet: {
    domains: [{ id: 'd1', next: [{ host: 'example-com.mail.protection.outlook.com', port: 25 }] }],
    kind: 'inbound',
  },
  userId: '01930000-0000-7000-8000-0000000000aa',
  expiresAt: new Date(now.getTime() + 15 * 60_000),
};

describe('impact tokens', () => {
  it('canonical JSON sorts keys at every depth and normalizes values', () => {
    expect(
      canonicalJson({ b: 1, a: { d: [3, { z: 1, y: 2 }], c: undefined }, e: 5n, f: new Date(0) }),
    ).toBe('{"a":{"d":[3,{"y":2,"z":1}]},"b":1,"e":"5","f":"1970-01-01T00:00:00.000Z"}');
    expect(() => canonicalJson({ n: Number.NaN })).toThrow(TypeError);
  });

  it('verifies the same body regardless of key order', () => {
    const token = signImpactToken(key, body);
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const reordered: ImpactTokenBody = {
      expiresAt: (body.expiresAt as Date).toISOString(),
      userId: body.userId,
      changeSet: {
        kind: 'inbound',
        domains: [
          { next: [{ port: 25, host: 'example-com.mail.protection.outlook.com' }], id: 'd1' },
        ],
      },
      rowVersion: 3,
      connectionId: body.connectionId,
      orgId: '42',
    };
    expect(verifyImpactToken(key, token, reordered, now)).toBe(true);
  });

  it('refuses tampering, other users, other organizations, stale rows and expiry', () => {
    const token = signImpactToken(key, body);
    expect(verifyImpactToken(key, token, { ...body, userId: 'other-user' }, now)).toBe(false);
    expect(verifyImpactToken(key, token, { ...body, orgId: 43n }, now)).toBe(false);
    expect(verifyImpactToken(key, token, { ...body, rowVersion: 4 }, now)).toBe(false);
    expect(
      verifyImpactToken(key, token, { ...body, changeSet: { kind: 'inbound', domains: [] } }, now),
    ).toBe(false);
    expect(verifyImpactToken(key, token, body, new Date((body.expiresAt as Date).getTime()))).toBe(
      false,
    );
    expect(
      verifyImpactToken(impactTokenKey(randomBytes(32).toString('hex')), token, body, now),
    ).toBe(false);
    const flipped = (token[0] === 'A' ? 'B' : 'A') + token.slice(1);
    expect(verifyImpactToken(key, flipped, body, now)).toBe(false);
    for (const bad of ['', 'short', `${token}x`, 42 as unknown as string]) {
      expect(verifyImpactToken(key, bad, body, now)).toBe(false);
    }
    expect(verifyImpactToken(key, token, { ...body, expiresAt: 'not a date' }, now)).toBe(false);
  });

  it('requires a 32-byte key', () => {
    expect(() => impactTokenKey('ab'.repeat(16))).toThrow(ImpactTokenKeyError);
    expect(() => impactTokenKey('zz'.repeat(32))).toThrow(ImpactTokenKeyError);
    expect(() => signImpactToken(Buffer.alloc(16), body)).toThrow(ImpactTokenKeyError);
  });
});
