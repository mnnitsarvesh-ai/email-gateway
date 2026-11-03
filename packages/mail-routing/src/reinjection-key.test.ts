import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  parseReinjectionToken,
  recipientSetSha256,
  reinjectionIdempotencyKey,
  reinjectionToken,
} from './reinjection-key';

const sha = (text: string) => createHash('sha256').update(text).digest('hex');

describe('recipientSetSha256', () => {
  it('lower-cases, de-duplicates, sorts and LF-joins (the 2.2 ingest-key convention)', () => {
    expect(recipientSetSha256(['b@x.test', 'A@x.test', 'a@X.test'])).toBe(
      sha('a@x.test\nb@x.test'),
    );
    expect(recipientSetSha256(['a@x.test', 'b@x.test'])).toBe(
      recipientSetSha256(['B@X.TEST', 'a@x.test']),
    );
    expect(recipientSetSha256([])).toBe(sha(''));
    expect(recipientSetSha256(['a@x.test'])).not.toBe(recipientSetSha256(['a@x.test', 'c@x.test']));
  });
});

describe('reinjectionIdempotencyKey', () => {
  const set = recipientSetSha256(['a@x.test']);
  it('hashes v1|messageId|deliverySeq|listener|recipientSetSha256 deterministically', () => {
    const key = reinjectionIdempotencyKey({
      messageId: 42n,
      deliverySeq: 0,
      listener: 'reinject_inbound',
      recipientSetSha256: set,
    });
    expect(key).toBe(sha(`v1|42|0|reinject_inbound|${set}`));
    expect(key).toMatch(/^[0-9a-f]{64}$/);
    expect(
      reinjectionIdempotencyKey({
        messageId: '42',
        deliverySeq: 0,
        listener: 'reinject_inbound',
        recipientSetSha256: set,
      }),
    ).toBe(key);
    for (const changed of [
      { messageId: 43n },
      { deliverySeq: 1 },
      { listener: 'reinject_outbound' as const },
      { recipientSetSha256: recipientSetSha256(['b@x.test']) },
    ]) {
      expect(
        reinjectionIdempotencyKey({
          messageId: 42n,
          deliverySeq: 0,
          listener: 'reinject_inbound',
          recipientSetSha256: set,
          ...changed,
        }),
      ).not.toBe(key);
    }
  });

  it('refuses malformed inputs', () => {
    const base = {
      messageId: 42n,
      deliverySeq: 0,
      listener: 'reinject_inbound' as const,
      recipientSetSha256: set,
    };
    expect(() => reinjectionIdempotencyKey({ ...base, messageId: '042' })).toThrow();
    expect(() => reinjectionIdempotencyKey({ ...base, deliverySeq: -1 })).toThrow();
    expect(() => reinjectionIdempotencyKey({ ...base, deliverySeq: 70_000 })).toThrow();
    expect(() => reinjectionIdempotencyKey({ ...base, recipientSetSha256: 'ABC' })).toThrow();
    expect(() =>
      reinjectionIdempotencyKey({ ...base, listener: 'smtp' as 'reinject_inbound' }),
    ).toThrow();
  });
});

describe('reinjection tokens', () => {
  const publicId = '0190a0b0-1c2d-7e3f-8a4b-5c6d7e8f9a0b';
  it('derives dw1-<32 hex> from the public id and parses it back', () => {
    const token = reinjectionToken(publicId);
    expect(token).toBe('dw1-0190a0b01c2d7e3f8a4b5c6d7e8f9a0b');
    expect(token).toHaveLength(36);
    expect(reinjectionToken(publicId.toUpperCase())).toBe(token);
    expect(parseReinjectionToken(token)).toBe(publicId);
    expect(parseReinjectionToken(token.toUpperCase().replace('DW1', 'dw1'))).toBe(publicId);
  });

  it('refuses anything that is not a token', () => {
    expect(() => reinjectionToken('not-a-uuid')).toThrow();
    for (const token of [
      '',
      'dw1-',
      'dw2-0190a0b01c2d7e3f8a4b5c6d7e8f9a0b',
      'dw1-0190a0b01c2d7e3f8a4b5c6d7e8f9a0',
      'dw1-0190a0b01c2d7e3f8a4b5c6d7e8f9a0bb',
      'dw1-0190a0b0-1c2d-7e3f-8a4b-5c6d7e8f9a0b',
      'dw1-0190a0b01c2d7e3f8a4b5c6d7e8f9a0z',
      '4ZkQ2s1Hb7z9',
    ]) {
      expect(parseReinjectionToken(token), token).toBeNull();
    }
  });
});
