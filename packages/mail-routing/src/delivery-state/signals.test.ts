import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  dsnSignalKey,
  logSignalKey,
  planSignalKey,
  rateLimitSignalKey,
  reconcileSignalKey,
  reinjectionSignalKey,
} from './signals';

const sha = (text: string) => createHash('sha256').update(text).digest('hex');

describe('signal keys', () => {
  it('hash the R9.1 key layouts', () => {
    expect(
      logSignalKey({
        sourceId: 'out.gateway.local',
        queueId: '4ZkQ2s1Hb7z9',
        address: 'User@Ext.Example',
        status: 'sent',
        logTimestamp: '2026-11-03T10:00:00.123456+00:00',
        dsn: '2.0.0',
      }),
    ).toBe(
      sha(
        'log|out.gateway.local|4ZkQ2s1Hb7z9|user@ext.example|sent|2026-11-03T10:00:00.123456+00:00|2.0.0',
      ),
    );
    expect(
      logSignalKey({
        sourceId: 's',
        queueId: 'Q',
        address: 'a@b',
        status: 'removed',
        logTimestamp: new Date('2026-11-03T10:00:00Z'),
        dsn: null,
      }),
    ).toBe(sha('log|s|Q|a@b|removed|2026-11-03T10:00:00.000Z|'));
    expect(
      dsnSignalKey({
        queueId: 'Q1',
        address: 'A@B.test',
        action: 'Failed',
        status: '5.1.1',
        arrivalDate: new Date('2026-11-03T10:00:00Z'),
      }),
    ).toBe(sha('dsn|Q1|a@b.test|failed|5.1.1|2026-11-03T10:00:00.000Z'));
    expect(
      reinjectionSignalKey({ reinjectionId: 12n, attempt: 2, address: 'A@b', outcome: 'queued' }),
    ).toBe(sha('reinject|12|2|a@b|queued'));
    expect(
      planSignalKey({ approvalEventId: '0190A0B0-1C2D-7E3F-8A4B-5C6D7E8F9A0B', recipientId: 5n }),
    ).toBe(sha('plan|0190a0b0-1c2d-7e3f-8a4b-5c6d7e8f9a0b|5'));
    expect(
      reconcileSignalKey({ deliveryId: '9', toStatus: 'unknown', reason: 'status_signal_missing' }),
    ).toBe(sha('reconcile|9|unknown|status_signal_missing'));
    expect(
      rateLimitSignalKey({ reinjectionId: 3n, windowStart: new Date('2026-11-03T10:01:00Z') }),
    ).toBe(sha('ratelimit|3|2026-11-03T10:01:00.000Z'));
  });

  it('differ between sources and inputs, and are 64 hex characters', () => {
    const keys = [
      planSignalKey({ approvalEventId: 'e', recipientId: 1n }),
      planSignalKey({ approvalEventId: 'e', recipientId: 2n }),
      reconcileSignalKey({ deliveryId: 1n, toStatus: 'unknown', reason: 'r' }),
      reinjectionSignalKey({ reinjectionId: 1n, attempt: 1, address: 'a@b', outcome: 'queued' }),
      reinjectionSignalKey({ reinjectionId: 1n, attempt: 2, address: 'a@b', outcome: 'queued' }),
      rateLimitSignalKey({ reinjectionId: 1n, windowStart: '2026-11-03T10:01:00.000Z' }),
    ];
    expect(new Set(keys).size).toBe(keys.length);
    for (const key of keys) expect(key).toMatch(/^[0-9a-f]{64}$/);
  });
});
