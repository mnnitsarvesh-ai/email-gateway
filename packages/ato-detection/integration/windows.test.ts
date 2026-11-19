import { randomBytes, randomUUID } from 'node:crypto';
import Redis from 'ioredis';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  authObservation,
  InMemoryRedis,
  outboundObservation,
  submissionObservation,
  T0,
} from '../src/testing';
import { AtoWindows, WINDOW_TTLS, type RedisLike } from '../src/windows';
import { requireEnv } from './support/fixtures';

// Real Lua against the local Redis under a run-unique prefix (never the production `ato:` keys);
// every key of the prefix is removed afterwards.
const prefix = `it-ato-${randomUUID().slice(0, 8)}:`;
// Built at runtime: never a credential-shaped literal in the repository.
const HMAC = randomBytes(24).toString('hex');
let redis: Redis;

async function keysOf(): Promise<string[]> {
  const out: string[] = [];
  let cursor = '0';
  do {
    const [next, batch] = await redis.scan(cursor, 'MATCH', `${prefix}*`, 'COUNT', 500);
    cursor = next;
    out.push(...batch);
  } while (cursor !== '0');
  return out.sort();
}

beforeAll(() => {
  redis = new Redis(requireEnv('REDIS_URL'), { lazyConnect: false, maxRetriesPerRequest: 2 });
});

afterAll(async () => {
  const keys = await keysOf();
  if (keys.length > 0) await redis.del(...keys);
  await redis.quit();
});

const A = { organizationId: 9001n, accountId: 9101n };

/** One scenario of window updates; returns the snapshots it read. */
async function scenario(store: RedisLike, scope: string) {
  const w = new AtoWindows(store, { hmacKey: HMAC, prefix: `${prefix}${scope}:` });
  const at = (m: number) => new Date(T0.getTime() + m * 60_000);
  const applied: boolean[] = [];
  for (let i = 0; i < 8; i++) {
    const o = authObservation({ outcome: 'failure', ip: `192.0.2.${i % 5}`, occurredAt: at(i) });
    applied.push(await w.record(`f${i}`, A, o, at(i)));
    applied.push(await w.record(`f${i}`, A, o, at(i)));
  }
  applied.push(await w.record('s1', A, authObservation({ occurredAt: at(9) }), at(9)));
  const sha = 'd'.repeat(64);
  for (let i = 0; i < 4; i++) {
    await w.record(
      `m${i}`,
      A,
      outboundObservation({
        occurredAt: at(10),
        externalRecipients: 3,
        externalDomains: [`d${i}.example`, 'common.example'],
        attachments: [{ sha256: sha, type: 'application/zip' }],
        findings: { ...outboundObservation().findings, spam: i % 2 === 0 },
      }),
      at(10),
    );
  }
  for (let i = 0; i < 5; i++) {
    await w.record(
      `sub${i}`,
      A,
      submissionObservation({ senderHash: `s${i % 4}`, occurredAt: at(11) }),
      at(11),
    );
  }
  const ipOpts = { windowMinutes: 60, minAccounts: 3, flagHours: 24 };
  const ip = [] as unknown[];
  for (let i = 0; i < 4; i++) {
    ip.push(await w.recordAuthFailure(`ipe${i}`, '203.0.113.50', `acct-${i % 3}`, at(12), ipOpts));
  }
  ip.push(await w.recordAuthFailure('ipe0', '203.0.113.50', 'acct-0', at(12), ipOpts));
  const seen = [
    await w.rememberSeen(A, 'countries', 'GB'),
    await w.rememberSeen(A, 'countries', 'GB'),
    await w.rememberSeen(A, 'devices', '0123456789abcdef'),
  ];
  const seenToday = await w.seenToday(A);
  const now = at(12);
  return {
    windows: w,
    applied,
    ip,
    seen,
    seenToday: Object.fromEntries(Object.entries(seenToday).map(([k, v]) => [k, [...v].sort()])),
    flag: await w.ipFlag('203.0.113.50'),
    auth: await w.snapshot(A, authObservation(), now),
    mail: await w.snapshot(
      A,
      outboundObservation({ attachments: [{ sha256: sha, type: 'application/zip' }] }),
      now,
    ),
    submission: await w.snapshot(A, submissionObservation(), now),
  };
}

describe('AtoWindows Lua scripts against a real Redis (D8)', () => {
  it('produce exactly the results of the in-memory model (parity of the Lua and the test kit)', async () => {
    const real = await scenario(redis as unknown as RedisLike, 'real');
    let clock = T0.getTime() + 12 * 60_000;
    const memory = await scenario(new InMemoryRedis(() => clock), 'mem');
    clock += 1;
    const strip = (r: Awaited<ReturnType<typeof scenario>>) => {
      const { windows: _w, ...rest } = r;
      return rest;
    };
    expect(strip(real)).toEqual(strip(memory));
    expect(real.applied.filter((a, i) => i % 2 === 1 && i < 16)).toEqual(Array(8).fill(false));
    expect(real.auth.minutes.af.reduce((s, n) => s + n, 0)).toBe(8);
    expect(real.auth.distinctFailureIps30m).toBe(5);
    expect(real.mail.distinctExternalDomains60m).toBe(5);
    expect(real.mail.attachmentSpread).toMatchObject({ recipients: 12, domains: 5 });
    expect(real.submission.distinctSenders60m).toBe(4);
    expect(real.flag).toEqual({ flagged: true, distinctAccounts: 3 });
    expect(real.seen).toEqual([true, false, true]);
  });

  it('sets the D8 TTL on every key and never a key without TTL', async () => {
    const keys = (await keysOf()).filter((k) => k.startsWith(`${prefix}real:`));
    expect(keys.length).toBeGreaterThan(10);
    for (const key of keys) {
      const ttl = await redis.ttl(key);
      expect(ttl, key).toBeGreaterThan(0);
      const tail = key.slice(`${prefix}real:`.length);
      const expected = tail.startsWith('seen:')
        ? WINDOW_TTLS.seen
        : tail.startsWith('ipflag:')
          ? 24 * 3600
          : /^w:.*:h\d+$/.test(tail)
            ? WINDOW_TTLS.hour
            : WINDOW_TTLS.minute;
      expect(ttl, key).toBeLessThanOrEqual(expected);
      expect(ttl, key).toBeGreaterThan(expected - 120);
    }
  });

  it('keeps no tenant identifier in the platform IP keys', async () => {
    const keys = (await keysOf()).filter((k) => k.includes(':ip:') || k.includes(':ipflag:'));
    expect(keys.length).toBeGreaterThan(0);
    for (const key of keys) {
      expect(key).not.toContain(String(A.organizationId));
      expect(key).not.toContain(String(A.accountId));
    }
  });

  it('fast-path signal marker, last success and attribution round-trip with TTLs', async () => {
    const w = new AtoWindows(redis as unknown as RedisLike, {
      hmacKey: HMAC,
      prefix: `${prefix}rt:`,
    });
    expect(await w.markSignal(A.organizationId, 'a'.repeat(64), 30)).toBe(true);
    expect(await w.markSignal(A.organizationId, 'a'.repeat(64), 30)).toBe(false);
    const ttl = await redis.ttl(w.signalKey(A.organizationId, 'a'.repeat(64)));
    expect(ttl).toBeGreaterThan(1700);
    await w.clearSignal(A.organizationId, 'a'.repeat(64));
    expect(await w.markSignal(A.organizationId, 'a'.repeat(64), 30)).toBe(true);
    const last = {
      at: T0.toISOString(),
      country: 'GB',
      latitude: 51.5074,
      longitude: -0.1278,
      accuracyKm: 10,
      anonymizerFlags: 0,
      trusted: false,
    };
    await w.setLastSuccess(A, last);
    expect(await w.lastSuccess(A)).toEqual(last);
    expect(await redis.ttl(w.lastKey(A))).toBeGreaterThan(WINDOW_TTLS.last - 60);
    await w.setSubmissionAttribution(A.organizationId, 'QID1', {
      connectorId: '5',
      clientIp: null,
      helo: null,
      tls: null,
    });
    expect(await w.submissionAttribution(A.organizationId, 'QID1')).toMatchObject({
      connectorId: '5',
    });
  });
});
