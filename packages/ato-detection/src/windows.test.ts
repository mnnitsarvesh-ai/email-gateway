import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  accountChangeObservation,
  authObservation,
  InMemoryRedis,
  outboundObservation,
  submissionObservation,
  T0,
} from './testing';
import { AtoWindows, RECORD_SCRIPT, WINDOW_CAPS, WINDOW_TTLS } from './windows';

// Built at runtime: never a credential-shaped literal in the repository.
const HMAC = randomBytes(24).toString('hex');
const A = { organizationId: 7n, accountId: 11n };
const B = { organizationId: 8n, accountId: 12n };

function setup(start = T0.getTime()) {
  let now = start;
  const redis = new InMemoryRedis(() => now);
  const windows = new AtoWindows(redis, { hmacKey: HMAC });
  return {
    redis,
    windows,
    at: () => new Date(now),
    advance: (ms: number) => {
      now += ms;
    },
  };
}

const minute = Math.floor(T0.getTime() / 60_000);
const tenMinutes = Math.floor(T0.getTime() / 600_000);

describe('AtoWindows key patterns and TTLs (D8)', () => {
  it('uses the D8 key patterns', () => {
    const { windows } = setup();
    expect(windows.minuteKey(A, 'af', 5)).toBe('ato:w:7:11:af:m5');
    expect(windows.hourKey(A, 'msg', 5)).toBe('ato:w:7:11:msg:h5');
    expect(windows.setKey(A, 'fip', 5)).toBe('ato:s:7:11:fip:m5');
    expect(windows.attachmentKey(A, 'f'.repeat(64))).toBe(`ato:att:7:11:${'f'.repeat(64)}`);
    expect(windows.seenKey(A, 'countries')).toBe('ato:seen:7:11:cc');
    expect(windows.lastKey(A)).toBe('ato:last:7:11');
    expect(windows.ipFailureKey('192.0.2.1', 5)).toBe('ato:ip:192.0.2.1:f:m5');
    expect(windows.ipAccountsKey('192.0.2.1', 5)).toBe('ato:ip:192.0.2.1:a:m5');
    expect(windows.ipFlagKey('192.0.2.1')).toBe('ato:ipflag:192.0.2.1');
    expect(windows.submissionKey(7n, 'ABC123')).toBe('ato:sub:7:ABC123');
    expect(windows.dedupeKey('evt', 'a11')).toBe('ato:dd:evt:a11');
    expect(windows.signalKey(7n, 'd'.repeat(64))).toBe(`ato:sigdd:7:${'d'.repeat(64)}`);
  });

  it('refuses a short HMAC key', () => {
    expect(() => new AtoWindows(new InMemoryRedis(), { hmacKey: 'short' })).toThrow();
  });

  it('every key written by an outbound message carries the D8 TTL', async () => {
    const { redis, windows } = setup();
    await windows.record(
      'mail-1',
      A,
      outboundObservation({
        attachments: [{ sha256: 'c'.repeat(64), type: 'application/pdf' }],
        externalDomains: ['partner.example'],
      }),
      T0,
    );
    const keys = redis.keys();
    expect(keys.length).toBeGreaterThan(5);
    for (const key of keys) {
      const ttl = redis.ttl(key);
      if (key.includes(':h')) expect(ttl, key).toBe(WINDOW_TTLS.hour);
      else expect(ttl, key).toBe(WINDOW_TTLS.minute);
      expect(ttl, key).toBeGreaterThan(0);
    }
    expect(redis.evals).toContain(RECORD_SCRIPT);
  });
});

describe('AtoWindows.record is idempotent per source event', () => {
  it('a redelivered event never double counts; another account keeps its own marker', async () => {
    const { windows } = setup();
    const obs = authObservation({ outcome: 'failure', key: 'evt-1' });
    expect(await windows.record('evt-1', A, obs, T0)).toBe(true);
    expect(await windows.record('evt-1', A, obs, T0)).toBe(false);
    expect(await windows.record('evt-1', B, obs, T0)).toBe(true);
    const snap = await windows.snapshot(A, obs, T0);
    expect(snap.minutes.af[0]).toBe(1);
    expect(snap.distinctFailureIps30m).toBe(1);
  });

  it('counts failures, successes and MFA failures in minute buckets over 60 minutes', async () => {
    const { windows, advance, at } = setup();
    for (let i = 0; i < 12; i++) {
      await windows.record(
        `f${i}`,
        A,
        authObservation({ outcome: 'failure', ip: `192.0.2.${i}`, occurredAt: at() }),
        at(),
      );
      advance(60_000);
    }
    await windows.record('s1', A, authObservation({ outcome: 'success', occurredAt: at() }), at());
    await windows.record(
      'm1',
      A,
      authObservation({ outcome: 'mfa_failure', occurredAt: at() }),
      at(),
    );
    const snap = await windows.snapshot(A, authObservation(), at());
    expect(snap.minutes.af.reduce((s, n) => s + n, 0)).toBe(12);
    expect(snap.minutes.af[0]).toBe(0);
    expect(snap.minutes.af[1]).toBe(1);
    expect(snap.minutes.as[0]).toBe(1);
    expect(snap.minutes.mf[0]).toBe(1);
    expect(snap.distinctFailureIps30m).toBe(12);
    expect(snap.distinctSuccessPrefixes60m).toBe(1);
  });

  it('counts outbound volume, recipients, spam, replies without parent and identity mismatches', async () => {
    const { windows } = setup();
    for (let i = 0; i < 3; i++) {
      await windows.record(
        `m${i}`,
        A,
        outboundObservation({
          externalRecipients: 2,
          internalRecipients: 1,
          newDomainRecipients: 1,
          externalDomains: [`d${i}.example`, 'shared.example'],
          findings: { ...outboundObservation().findings, spam: i === 0 },
          replyWithoutParent: i < 2,
          headerFromMatches: i !== 2,
        }),
        T0,
      );
    }
    const snap = await windows.snapshot(A, outboundObservation(), T0);
    const sum = (xs: readonly number[]) => xs.reduce((s, n) => s + n, 0);
    expect(sum(snap.minutes.msg)).toBe(3);
    expect(sum(snap.minutes.rcpt)).toBe(9);
    expect(sum(snap.minutes.ext)).toBe(6);
    expect(sum(snap.minutes.newdom)).toBe(3);
    expect(sum(snap.minutes.spam)).toBe(1);
    expect(sum(snap.minutes.rnp)).toBe(2);
    expect(sum(snap.minutes.hfm)).toBe(1);
    expect(snap.hourlyMessages[0]).toBe(3);
    expect(snap.distinctExternalDomains60m).toBe(4);
    expect(snap.subjectMessages60m).toBe(3);
  });

  it('never keeps recipient domains or subject keys in clear', async () => {
    const { redis, windows } = setup();
    await windows.record(
      'm1',
      A,
      outboundObservation({ externalDomains: ['partner.example'], subjectKey: 'secret-subject' }),
      T0,
    );
    const values: unknown[] = [];
    for (const k of redis.keys()) {
      try {
        values.push([k, await redis.get(k)]);
      } catch {
        values.push([k, redis.members(k)]);
      }
    }
    const dump = JSON.stringify(values);
    expect(dump).not.toContain('partner.example');
    expect(dump).not.toContain('secret-subject');
  });

  it('tracks attachment spread per hash (recipients and distinct domains)', async () => {
    const { windows } = setup();
    const sha = 'e'.repeat(64);
    for (let i = 0; i < 6; i++) {
      await windows.record(
        `m${i}`,
        A,
        outboundObservation({
          externalRecipients: 4,
          externalDomains: [`d${i}.example`],
          attachments: [{ sha256: sha, type: 'application/zip' }],
        }),
        T0,
      );
    }
    const snap = await windows.snapshot(
      A,
      outboundObservation({ attachments: [{ sha256: sha, type: 'application/zip' }] }),
      T0,
    );
    expect(snap.attachmentSpread).toEqual({
      sha256: sha,
      type: 'application/zip',
      recipients: 24,
      domains: 6,
    });
  });

  it('caps sets at 200 members', async () => {
    const { windows } = setup();
    for (let i = 0; i < WINDOW_CAPS.set + 20; i++) {
      await windows.record(
        `f${i}`,
        A,
        authObservation({ outcome: 'failure', ip: `10.0.${Math.floor(i / 250)}.${i % 250}` }),
        T0,
      );
    }
    const snap = await windows.snapshot(A, authObservation(), T0);
    expect(snap.distinctFailureIps30m).toBe(WINDOW_CAPS.set);
    expect(snap.minutes.af[0]).toBe(WINDOW_CAPS.set + 20);
  });

  it('counts distinct senders of a connector and data-access account changes', async () => {
    const { windows } = setup();
    for (let i = 0; i < 4; i++) {
      await windows.record(`s${i}`, A, submissionObservation({ senderHash: `h${i % 3}` }), T0);
    }
    await windows.record('c1', A, accountChangeObservation({ action: 'message.revealed' }), T0);
    await windows.record('c2', A, accountChangeObservation({ action: 'auth.mfa_disabled' }), T0);
    expect((await windows.snapshot(A, submissionObservation(), T0)).distinctSenders60m).toBe(3);
    expect((await windows.snapshot(A, accountChangeObservation(), T0)).minutes.data[0]).toBe(1);
  });

  it('expires minute buckets after 2 hours (losing Redis loses only in-window counts)', async () => {
    const { redis, windows, advance } = setup();
    await windows.record('f1', A, authObservation({ outcome: 'failure' }), T0);
    advance(WINDOW_TTLS.minute * 1000 + 1);
    await expect(redis.get(windows.minuteKey(A, 'af', minute))).resolves.toBeNull();
    expect(redis.keys()).toEqual([]);
  });
});

describe('platform IP campaign windows (D8)', () => {
  const opts = { windowMinutes: 60, minAccounts: 3, flagHours: 24 };

  it('flags an IP after failures against N distinct accounts, holding no tenant identity', async () => {
    const { redis, windows } = setup();
    const ip = '203.0.113.9';
    const r1 = await windows.recordAuthFailure('e1', ip, 'acct-hmac-1', T0, opts);
    expect(r1).toEqual({ applied: true, distinctAccounts: 1, flagged: false, newlyFlagged: false });
    expect(await windows.recordAuthFailure('e1', ip, 'acct-hmac-1', T0, opts)).toMatchObject({
      applied: false,
      distinctAccounts: 1,
    });
    await windows.recordAuthFailure('e2', ip, 'acct-hmac-1', T0, opts);
    await windows.recordAuthFailure('e3', ip, 'acct-hmac-2', T0, opts);
    const r4 = await windows.recordAuthFailure('e4', ip, 'acct-hmac-3', T0, opts);
    expect(r4).toEqual({ applied: true, distinctAccounts: 3, flagged: true, newlyFlagged: true });
    const r5 = await windows.recordAuthFailure('e5', ip, 'acct-hmac-4', T0, opts);
    expect(r5).toMatchObject({ flagged: true, newlyFlagged: false, distinctAccounts: 4 });
    expect(await windows.ipFlag(ip)).toEqual({ flagged: true, distinctAccounts: 4 });
    expect(redis.ttl(windows.ipFlagKey(ip))).toBe(24 * 3600);
    await expect(redis.get(windows.ipFailureKey(ip, minute))).resolves.toBe('5');
    expect(redis.members(windows.ipAccountsKey(ip, tenMinutes)).sort()).toEqual([
      'acct-hmac-1',
      'acct-hmac-2',
      'acct-hmac-3',
      'acct-hmac-4',
    ]);
    for (const key of redis.keys()) {
      expect(key).toMatch(/^ato:(ip|ipflag|dd):/);
      expect(redis.ttl(key)).toBeGreaterThan(0);
    }
    expect(await windows.ipFlag('198.51.100.1')).toBeNull();
  });

  it('counts distinct accounts across the 10-minute buckets of the window only', async () => {
    const { windows, advance, at } = setup();
    const ip = '203.0.113.10';
    await windows.recordAuthFailure('e1', ip, 'h1', at(), opts);
    advance(30 * 60_000);
    await windows.recordAuthFailure('e2', ip, 'h2', at(), opts);
    advance(40 * 60_000);
    const r = await windows.recordAuthFailure('e3', ip, 'h3', at(), opts);
    expect(r.distinctAccounts).toBe(2);
    expect(r.flagged).toBe(false);
  });
});

describe('novelty, last success, attribution and the signal fast path', () => {
  it('rememberSeen is true once per value and kind, capped and TTL 48 h', async () => {
    const { redis, windows } = setup();
    expect(await windows.rememberSeen(A, 'countries', 'GB')).toBe(true);
    expect(await windows.rememberSeen(A, 'countries', 'GB')).toBe(false);
    expect(await windows.rememberSeen(A, 'prefixes', 'GB')).toBe(true);
    expect(redis.ttl(windows.seenKey(A, 'countries'))).toBe(WINDOW_TTLS.seen);
    const seen = await windows.seenToday(A);
    expect([...seen.countries]).toEqual(['GB']);
    expect([...seen.prefixes]).toEqual(['GB']);
    expect(seen.devices.size).toBe(0);
    for (let i = 0; i < WINDOW_CAPS.seen + 5; i++)
      await windows.rememberSeen(A, 'domains', `d${i}`);
    expect((await windows.seenToday(A)).domains.size).toBe(WINDOW_CAPS.seen);
  });

  it('stores the last successful location and submission attribution with TTLs', async () => {
    const { redis, windows } = setup();
    const last = {
      at: T0.toISOString(),
      country: 'IN',
      latitude: 19.076,
      longitude: 72.8777,
      accuracyKm: 20,
      anonymizerFlags: 0,
      trusted: false,
    };
    await windows.setLastSuccess(A, last);
    expect(await windows.lastSuccess(A)).toEqual(last);
    expect(await windows.lastSuccess(B)).toBeNull();
    expect(redis.ttl(windows.lastKey(A))).toBe(WINDOW_TTLS.last);
    const attribution = {
      connectorId: '42',
      clientIp: '198.51.100.7',
      helo: 'mx.example',
      tls: 'TLSv1.3',
    };
    await windows.setSubmissionAttribution(7n, 'Q1', attribution);
    expect(await windows.submissionAttribution(7n, 'Q1')).toEqual(attribution);
    expect(await windows.submissionAttribution(8n, 'Q1')).toBeNull();
    expect(redis.ttl(windows.submissionKey(7n, 'Q1'))).toBe(WINDOW_TTLS.submission);
  });

  it('markSignal is true once within the dedupe window and can be cleared', async () => {
    const { redis, windows } = setup();
    const key = 'f'.repeat(64);
    expect(await windows.markSignal(7n, key, 60)).toBe(true);
    expect(await windows.markSignal(7n, key, 60)).toBe(false);
    expect(await windows.markSignal(8n, key, 60)).toBe(true);
    expect(redis.ttl(windows.signalKey(7n, key))).toBe(3600);
    await windows.clearSignal(7n, key);
    expect(await windows.markSignal(7n, key, 60)).toBe(true);
  });
});
