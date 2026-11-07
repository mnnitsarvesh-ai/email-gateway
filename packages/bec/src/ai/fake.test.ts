import { describe, expect, it } from 'vitest';
import { FakeBecLlmProvider } from './fake';
import type { AiInput } from './types';

const signal = new AbortController().signal;
const input = (features: Record<string, number>, text = ''): AiInput => ({
  features,
  excerpt: text
    ? {
        subject: null,
        text,
        segments: [],
        redactions: { email: 0, url: 0, number: 0, phone: 0, executive: 0, vendor: 0, org: 0 },
        truncated: false,
      }
    : null,
});

describe('FakeBecLlmProvider', () => {
  it('is refused in production', () => {
    expect(() => new FakeBecLlmProvider({ nodeEnv: 'production' })).toThrow(/refused/);
  });
  const fake = new FakeBecLlmProvider({ nodeEnv: 'test' });
  it('is deterministic and keyed by identity / intent features', async () => {
    const both = await fake.assess(input({ rule_x1: 1, lex_gift_card: 0.69 }), signal);
    expect(both).toMatchObject({
      status: 'ok',
      confidence: 0.95,
      modelId: 'fake',
      modelVersion: 'fake/1',
    });
    expect(both.labels[0]!.label).toBe('bec');
    expect(both.indicators).toEqual(['executive_impersonation', 'gift_card_request']);
    expect(await fake.assess(input({ rule_x1: 1, lex_gift_card: 0.69 }), signal)).toEqual(both);
    expect((await fake.assess(input({ lex_urgency: 0.69 }), signal)).confidence).toBe(0.85);
    expect((await fake.assess(input({ rule_l1: 1 }), signal)).labels[0]!.label).toBe('phishing');
    const benign = await fake.assess(input({}), signal);
    expect(benign).toMatchObject({ confidence: 0.9, indicators: ['benign_business'] });
    expect(benign.labels[0]!.label).toBe('benign');
  });
  it('honours the bec-fake-status-<status> test directive', async () => {
    expect(
      (await fake.assess(input({ rule_x1: 1 }, 'x bec-fake-status-timeout y'), signal)).status,
    ).toBe('timeout');
    expect((await fake.assess(input({}, 'bec-fake-status-refused'), signal)).status).toBe(
      'refused',
    );
    expect((await fake.assess(input({}, 'bec-fake-status-ok'), signal)).status).toBe('ok');
  });
});
