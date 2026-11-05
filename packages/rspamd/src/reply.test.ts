import { describe, expect, it } from 'vitest';
import { rspamdCheckReplySchema } from './reply';

describe('rspamdCheckReplySchema', () => {
  it('accepts a real Rspamd 3.12 reply and keeps unknown fields', () => {
    const parsed = rspamdCheckReplySchema.parse({
      is_skipped: false,
      score: 2.9,
      required_score: 15,
      action: 'no action',
      thresholds: { reject: 15 },
      symbols: {
        PHISHING: {
          name: 'PHISHING',
          score: 2,
          metric_score: 4,
          options: ['paypal.com->login.bad-url.scan.test'],
          description: 'Phished URL',
        },
      },
      messages: {},
      'message-id': 'confirm@clean.scan.test',
      time_real: 0.02,
      milter: { remove_headers: { 'X-Spam': 0 } },
      future_field: { nested: true },
    });
    expect(parsed.symbols?.PHISHING?.options).toEqual(['paypal.com->login.bad-url.scan.test']);
    expect((parsed as Record<string, unknown>).future_field).toEqual({ nested: true });
  });

  it('refuses replies without score, required_score or action, or with non-finite scores', () => {
    expect(rspamdCheckReplySchema.safeParse({ action: 'no action' }).success).toBe(false);
    expect(rspamdCheckReplySchema.safeParse({ score: 1, required_score: 15 }).success).toBe(false);
    expect(
      rspamdCheckReplySchema.safeParse({
        score: 1,
        required_score: 15,
        action: 'no action',
        symbols: { A: { name: 'A', score: 'x' } },
      }).success,
    ).toBe(false);
  });
});
