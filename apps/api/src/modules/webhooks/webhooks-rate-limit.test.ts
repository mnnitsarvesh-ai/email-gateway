import type { Request } from 'express';
import { describe, expect, it } from 'vitest';
import { webhookRate, webhookRateIdentifier } from './webhooks-rate-limit';

const req = (params: Record<string, string>, principal?: object) =>
  ({ params, principal }) as unknown as Request;
const user = { kind: 'user', organizationId: 4n, userPublicId: 'u' };

describe('webhook route limits (§6.1)', () => {
  it('reads the limits from the config', () => {
    const config = { WEBHOOK_TEST_REQUESTS_PER_MINUTE: 6, WEBHOOK_REPLAY_REQUESTS_PER_HOUR: 10 };
    expect(webhookRate('test', config)).toEqual({
      bucket: 'webhook-test',
      limit: 6,
      windowSeconds: 60,
    });
    expect(webhookRate('range_replay', config)).toEqual({
      bucket: 'webhook-range-replay',
      limit: 10,
      windowSeconds: 3600,
    });
  });

  it('counts tests per subscription and range replays per organization (from the principal)', () => {
    const id = '0193A2C4-5D6E-7F80-9A1B-2C3D4E5F6A7B';
    expect(webhookRateIdentifier('test', req({ webhookId: id }, user))).toBe(
      `org:4:sub:${id.toLowerCase()}`,
    );
    expect(webhookRateIdentifier('test', req({ webhookId: 'x' }, user))).toBe('org:4:sub:-');
    expect(webhookRateIdentifier('range_replay', req({ webhookId: id }, user))).toBe('org:4');
    expect(webhookRateIdentifier('test', req({ webhookId: id }))).toBeUndefined();
  });
});
