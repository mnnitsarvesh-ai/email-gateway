import { createHmac, randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  checkDownloadable,
  DOWNLOAD_TOKEN_DOMAIN,
  signDownloadToken,
  verifyDownloadToken,
  type DownloadableFacts,
  type DownloadTokenPayload,
} from './download';

const KEY = 'a1'.repeat(32);
const OTHER = 'b2'.repeat(32);
const NOW = new Date('2026-11-12T12:00:00.000Z');
const exp = Math.floor(NOW.getTime() / 1000) + 60;
const payload: DownloadTokenPayload = {
  v: 1,
  jti: '01930000-0000-7000-8000-0000000000aa',
  org: '7',
  usr: '01930000-0000-7000-8000-0000000000bb',
  ent: '01930000-0000-7000-8000-0000000000cc',
  obj: 'attachment',
  part: 3,
  exp,
};

describe('download tokens (Q12)', () => {
  const token = signDownloadToken(payload, KEY);
  it('has the qdl1 form with a domain-separated HMAC-SHA256 over the payload bytes', () => {
    const [prefix, body, mac] = token.split('.');
    expect(prefix).toBe('qdl1');
    const bytes = Buffer.from(body!, 'base64url');
    expect(JSON.parse(bytes.toString('utf8'))).toEqual(payload);
    const expected = createHmac('sha256', Buffer.from(KEY, 'hex'))
      .update(Buffer.concat([Buffer.from(DOWNLOAD_TOKEN_DOMAIN, 'utf8'), bytes]))
      .digest('base64url');
    expect(mac).toBe(expected);
    expect(DOWNLOAD_TOKEN_DOMAIN).toBe('eg-quarantine-download/v1\0');
    expect(signDownloadToken(payload, KEY)).toBe(token);
  });
  it('verifies with the right key before expiry and binding', () => {
    expect(
      verifyDownloadToken(token, KEY, { now: NOW, expected: { org: '7', usr: payload.usr } }),
    ).toEqual({
      ok: true,
      payload,
    });
    expect(verifyDownloadToken(token, Buffer.from(KEY, 'hex'), { now: NOW }).ok).toBe(true);
  });
  it('refuses a wrong key', () => {
    expect(verifyDownloadToken(token, OTHER, { now: NOW })).toEqual({
      ok: false,
      reason: 'bad_mac',
    });
  });
  it('refuses tampering with the payload or the MAC', () => {
    const [p, body, mac] = token.split('.');
    const forged = Buffer.from(
      JSON.stringify({ ...payload, usr: '01930000-0000-7000-8000-0000000000dd' }),
    ).toString('base64url');
    expect(verifyDownloadToken(`${p}.${forged}.${mac}`, KEY, { now: NOW }).ok).toBe(false);
    const flipped = mac!.slice(0, -2) + (mac!.endsWith('AA') ? 'AB' : 'AA');
    expect(verifyDownloadToken(`${p}.${body}.${flipped}`, KEY, { now: NOW })).toMatchObject({
      ok: false,
    });
    expect(verifyDownloadToken(`${p}.${body}.${mac!.slice(0, 20)}`, KEY, { now: NOW })).toEqual({
      ok: false,
      reason: 'bad_mac',
    });
    expect(verifyDownloadToken(`qdl2.${body}.${mac}`, KEY, { now: NOW })).toEqual({
      ok: false,
      reason: 'malformed',
    });
    expect(verifyDownloadToken(`${p}.${body}.${mac}.x`, KEY, { now: NOW })).toEqual({
      ok: false,
      reason: 'malformed',
    });
    expect(verifyDownloadToken(`${p}.${body}=.${mac}`, KEY, { now: NOW })).toEqual({
      ok: false,
      reason: 'malformed',
    });
    expect(verifyDownloadToken('x'.repeat(2000), KEY, { now: NOW })).toEqual({
      ok: false,
      reason: 'malformed',
    });
    expect(verifyDownloadToken('', KEY, { now: NOW })).toEqual({ ok: false, reason: 'malformed' });
  });
  it('a valid MAC over an invalid payload is payload_invalid (strict schema)', () => {
    const sign = (bytes: Buffer) =>
      `qdl1.${bytes.toString('base64url')}.${createHmac('sha256', Buffer.from(KEY, 'hex'))
        .update(DOWNLOAD_TOKEN_DOMAIN)
        .update(bytes)
        .digest('base64url')}`;
    for (const bad of [
      { ...payload, extra: 1 },
      { ...payload, v: 2 },
      { ...payload, obj: 'zip' },
      { ...payload, obj: 'eml', part: 3 },
      { ...payload, part: null },
      { ...payload, jti: 'not-a-uuid' },
    ]) {
      expect(
        verifyDownloadToken(sign(Buffer.from(JSON.stringify(bad))), KEY, { now: NOW }),
      ).toEqual({
        ok: false,
        reason: 'payload_invalid',
      });
    }
    expect(verifyDownloadToken(sign(Buffer.from('{not json')), KEY, { now: NOW })).toEqual({
      ok: false,
      reason: 'payload_invalid',
    });
  });
  it('expires at exp (injected clock)', () => {
    expect(verifyDownloadToken(token, KEY, { now: new Date(exp * 1000 - 1) }).ok).toBe(true);
    expect(verifyDownloadToken(token, KEY, { now: new Date(exp * 1000) })).toEqual({
      ok: false,
      reason: 'expired',
    });
  });
  it('binding: another organization, user or entry is refused', () => {
    for (const expected of [{ org: '8' }, { usr: payload.ent }, { ent: payload.usr }]) {
      expect(verifyDownloadToken(token, KEY, { now: NOW, expected })).toEqual({
        ok: false,
        reason: 'binding',
      });
    }
  });
  it('refuses short keys and invalid payloads at signing', () => {
    expect(() => signDownloadToken(payload, 'abcd')).toThrow(RangeError);
    expect(() => signDownloadToken({ ...payload, obj: 'eml' }, KEY)).toThrow();
    expect(() =>
      signDownloadToken({ ...payload, obj: 'eml', part: null }, randomBytes(32)),
    ).not.toThrow();
  });
});

describe('checkDownloadable (Q12.4 malware gating)', () => {
  const base: DownloadableFacts = {
    object: 'eml',
    entryHardBlocks: [],
    messageHardBlocks: [],
    latestVerdict: 'spam',
    attachments: [
      { partIndex: 2, verdict: 'clean', objectKey: 'org/1/part/a' },
      { partIndex: 3, verdict: 'clean', objectKey: 'org/1/part/b' },
    ],
    urls: [{ verdict: 'clean' }, { verdict: 'suspicious' }],
  };
  const c = (patch: Partial<DownloadableFacts>) => checkDownloadable({ ...base, ...patch });
  it('a clean EML and a clean attachment are downloadable', () => {
    expect(c({})).toEqual({ ok: true });
    expect(c({ object: 'attachment', partIndex: 3 })).toEqual({ ok: true });
  });
  it.each([
    ['entry hard block', { entryHardBlocks: ['hb.known_phishing'] }, 'hard_block'],
    ['message hard block', { messageHardBlocks: ['hb.malware_url'] }, 'hard_block'],
    ['malware verdict', { latestVerdict: 'malware' }, 'malware_verdict'],
    ['phishing verdict', { latestVerdict: 'phishing' }, 'phishing_verdict'],
    [
      'EML with a suspicious attachment',
      { attachments: [{ partIndex: 2, verdict: 'suspicious', objectKey: 'k' }] },
      'attachment_not_clean',
    ],
    [
      'EML with an unscanned attachment',
      { attachments: [{ partIndex: 2, verdict: null, objectKey: 'k' }] },
      'attachment_not_clean',
    ],
    ['EML with a malicious URL', { urls: [{ verdict: 'malicious' }] }, 'url_malicious'],
  ] as Array<[string, Partial<DownloadableFacts>, string]>)('EML: %s', (_n, patch, reason) => {
    expect(c(patch)).toEqual({ ok: false, code: 'quarantine_download_blocked', reason });
  });
  it.each([
    ['malicious', 'attachment_not_clean'],
    ['suspicious', 'attachment_not_clean'],
    ['error', 'attachment_not_clean'],
    ['skipped', 'attachment_not_clean'],
    ['unknown', 'attachment_not_clean'],
    [null, 'attachment_not_clean'],
  ])('attachment verdict %s refuses', (verdict, reason) => {
    expect(
      c({
        object: 'attachment',
        partIndex: 2,
        attachments: [{ partIndex: 2, verdict, objectKey: 'k' }],
      }),
    ).toMatchObject({ ok: false, reason });
  });
  it('attachment: missing row, missing part index or missing object refuses', () => {
    expect(c({ object: 'attachment', partIndex: 9 })).toMatchObject({
      reason: 'attachment_missing',
    });
    expect(c({ object: 'attachment' })).toMatchObject({ reason: 'attachment_missing' });
    expect(
      c({
        object: 'attachment',
        partIndex: 2,
        attachments: [{ partIndex: 2, verdict: 'clean', objectKey: null }],
      }),
    ).toMatchObject({ reason: 'attachment_object_missing' });
    // A suspicious sibling does not block a clean attachment; a malicious URL does not either.
    expect(
      c({
        object: 'attachment',
        partIndex: 3,
        attachments: [...base.attachments, { partIndex: 4, verdict: 'malicious', objectKey: 'k' }],
        urls: [{ verdict: 'malicious' }],
      }),
    ).toEqual({ ok: true });
  });
});
