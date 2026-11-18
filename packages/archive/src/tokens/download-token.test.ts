import { createHmac, randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { ArchiveKeyConfigError } from '../crypto/errors';
import {
  ARCHIVE_DOWNLOAD_TOKEN_DOMAIN,
  type ArchiveDownloadTokenPayload,
  parseDownloadTokenKey,
  signArchiveDownloadToken,
  verifyArchiveDownloadToken,
} from './download-token';

const key = randomBytes(32).toString('hex');
const now = new Date('2026-11-16T12:00:00.000Z');
const payload: ArchiveDownloadTokenPayload = {
  jti: '0190a5d0-0000-7000-8000-000000000001',
  org: '0190a5d0-0000-7000-8000-000000000002',
  usr: '0190a5d0-0000-7000-8000-000000000003',
  kind: 'message',
  tgt: '0190a5d0-0000-7000-8000-000000000004',
  exp: Math.floor(now.getTime() / 1000) + 60,
};

describe('archive download tokens', () => {
  it('signs v1.<payload>.<mac> and verifies with binding', () => {
    const token = signArchiveDownloadToken(payload, key);
    expect(token).toMatch(/^v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/);
    expect(JSON.parse(Buffer.from(token.split('.')[1]!, 'base64url').toString())).toEqual(payload);
    expect(
      Object.keys(JSON.parse(Buffer.from(token.split('.')[1]!, 'base64url').toString())),
    ).toEqual(['jti', 'org', 'usr', 'kind', 'tgt', 'exp']);
    expect(
      verifyArchiveDownloadToken(token, key, {
        now,
        expected: { org: payload.org, usr: payload.usr, kind: 'message', tgt: payload.tgt },
      }),
    ).toEqual({ ok: true, payload });
    expect(verifyArchiveDownloadToken(token, Buffer.from(key, 'hex'), { now }).ok).toBe(true);
  });

  it('expires at exp (clock injected)', () => {
    const token = signArchiveDownloadToken(payload, key);
    expect(
      verifyArchiveDownloadToken(token, key, { now: new Date(payload.exp * 1000 - 1) }).ok,
    ).toBe(true);
    expect(verifyArchiveDownloadToken(token, key, { now: new Date(payload.exp * 1000) })).toEqual({
      ok: false,
      reason: 'expired',
    });
  });

  it('refuses a binding to another organization, user, kind or target', () => {
    const token = signArchiveDownloadToken(payload, key);
    const other = '0190a5d0-0000-7000-8000-0000000000ff';
    for (const expected of [
      { org: other },
      { usr: other },
      { kind: 'export' as const },
      { tgt: other },
    ]) {
      expect(verifyArchiveDownloadToken(token, key, { now, expected })).toEqual({
        ok: false,
        reason: 'binding',
      });
    }
  });

  it('refuses tampering, another key and malformed tokens', () => {
    const token = signArchiveDownloadToken(payload, key);
    const [v, p, m] = token.split('.') as [string, string, string];
    const forged = Buffer.from(
      JSON.stringify({ ...payload, usr: '0190a5d0-0000-7000-8000-0000000000ff' }),
    ).toString('base64url');
    expect(verifyArchiveDownloadToken(`${v}.${forged}.${m}`, key, { now })).toEqual({
      ok: false,
      reason: 'bad_mac',
    });
    expect(verifyArchiveDownloadToken(token, randomBytes(32).toString('hex'), { now })).toEqual({
      ok: false,
      reason: 'bad_mac',
    });
    expect(verifyArchiveDownloadToken(`${v}.${p}.${m.slice(0, 8)}`, key, { now })).toEqual({
      ok: false,
      reason: 'bad_mac',
    });
    for (const bad of [
      '',
      'v1.a',
      `v2.${p}.${m}`,
      `${token}.x`,
      `v1.${p}=.${m}`,
      'x'.repeat(2000),
    ]) {
      expect(verifyArchiveDownloadToken(bad, key, { now })).toEqual({
        ok: false,
        reason: 'malformed',
      });
    }
  });

  it('refuses an authentic token with an invalid payload, and invalid payloads at signing', () => {
    const sign = (json: string) => {
      const bytes = Buffer.from(json, 'utf8');
      const mac = createHmac('sha256', Buffer.from(key, 'hex'))
        .update(ARCHIVE_DOWNLOAD_TOKEN_DOMAIN, 'utf8')
        .update(bytes)
        .digest();
      return `v1.${bytes.toString('base64url')}.${mac.toString('base64url')}`;
    };
    expect(verifyArchiveDownloadToken(sign('{not json'), key, { now })).toEqual({
      ok: false,
      reason: 'payload_invalid',
    });
    expect(
      verifyArchiveDownloadToken(sign(JSON.stringify({ ...payload, extra: 1 })), key, { now }),
    ).toEqual({
      ok: false,
      reason: 'payload_invalid',
    });
    expect(verifyArchiveDownloadToken(sign(JSON.stringify(payload)), key, { now }).ok).toBe(true);
    expect(() => signArchiveDownloadToken({ ...payload, kind: 'eml' as never }, key)).toThrow();
    expect(() => signArchiveDownloadToken({ ...payload, org: '42' }, key)).toThrow();
  });

  it('parses the key strictly and names it, never the value', () => {
    expect(parseDownloadTokenKey(key)).toHaveLength(32);
    for (const bad of [undefined, 'abc', 'z'.repeat(64), Buffer.alloc(16)]) {
      try {
        parseDownloadTokenKey(bad);
        expect.fail('expected ArchiveKeyConfigError');
      } catch (error) {
        expect(error).toBeInstanceOf(ArchiveKeyConfigError);
        expect((error as ArchiveKeyConfigError).keyName).toBe('ARCHIVE_DOWNLOAD_TOKEN_KEY');
      }
    }
    expect(() => verifyArchiveDownloadToken('v1.a.b', 'short', { now })).toThrow(
      ArchiveKeyConfigError,
    );
  });
});
