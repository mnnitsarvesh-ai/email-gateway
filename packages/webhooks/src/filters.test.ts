import { describe, expect, it } from 'vitest';
import {
  matchesSubscription,
  subscriptionEventTypesSchema,
  subscriptionFiltersSchema,
} from './filters';

const D1 = '0192f0c4-7d1e-7b6a-9c55-6f3e2a1d4b11';
const D2 = '0192f0c4-7d1e-7b6a-9c55-6f3e2a1d4b12';

describe('subscriptionFiltersSchema (§5.3)', () => {
  it('accepts every optional filter and the empty object', () => {
    expect(subscriptionFiltersSchema.safeParse({}).success).toBe(true);
    expect(
      subscriptionFiltersSchema.safeParse({
        directions: ['inbound', 'outbound', 'internal'],
        domainIds: [D1, D2],
        minSeverity: 'medium',
        verdicts: ['clean', 'spam', 'suspicious', 'malicious', 'unknown', 'timeout', 'error'],
      }).success,
    ).toBe(true);
  });

  it.each([
    [{ extra: true }],
    [{ directions: [] }],
    [{ directions: ['inbound', 'inbound'] }],
    [{ directions: ['sideways'] }],
    [{ domainIds: [] }],
    [{ domainIds: [D1, D1] }],
    [{ domainIds: ['acme.example'] }],
    [
      {
        domainIds: Array.from(
          { length: 21 },
          (_, i) => `${D1.slice(0, -2)}${String(i).padStart(2, '0')}`,
        ),
      },
    ],
    [{ minSeverity: 'critical' }],
    [{ verdicts: [] }],
    [{ verdicts: ['spam', 'spam'] }],
    [{ verdicts: ['phishing'] }],
  ])('refuses %o', (filters) => {
    expect(subscriptionFiltersSchema.safeParse(filters).success).toBe(false);
  });

  it('accepts 1..10 unique event types without wildcards or the ping', () => {
    expect(subscriptionEventTypesSchema.safeParse(['email.received']).success).toBe(true);
    expect(subscriptionEventTypesSchema.safeParse([]).success).toBe(false);
    expect(
      subscriptionEventTypesSchema.safeParse(['email.received', 'email.received']).success,
    ).toBe(false);
    expect(subscriptionEventTypesSchema.safeParse(['email.*']).success).toBe(false);
    expect(subscriptionEventTypesSchema.safeParse(['webhook.ping']).success).toBe(false);
  });
});

describe('matchesSubscription (W5)', () => {
  const message = {
    type: 'email.scanned' as const,
    severity: 'medium' as const,
    direction: 'inbound' as const,
    domainPublicId: D1,
    verdict: 'suspicious' as const,
  };
  const sub = (
    filters: object | null = null,
    eventTypes = ['email.scanned', 'domain.verified'],
  ) => ({
    eventTypes,
    filters,
  });

  it('requires the type and passes without filters', () => {
    expect(matchesSubscription(sub(), message)).toBe(true);
    expect(matchesSubscription(sub(null, ['email.received']), message)).toBe(false);
    expect(matchesSubscription({ eventTypes: ['email.scanned'] }, message)).toBe(true);
  });

  it('applies each filter to the attribute the event carries', () => {
    expect(matchesSubscription(sub({ directions: ['inbound'] }), message)).toBe(true);
    expect(matchesSubscription(sub({ directions: ['outbound'] }), message)).toBe(false);
    expect(matchesSubscription(sub({ domainIds: [D1] }), message)).toBe(true);
    expect(matchesSubscription(sub({ domainIds: [D2] }), message)).toBe(false);
    expect(matchesSubscription(sub({ verdicts: ['suspicious', 'malicious'] }), message)).toBe(true);
    expect(matchesSubscription(sub({ verdicts: ['malicious'] }), message)).toBe(false);
    for (const [min, expected] of [
      ['info', true],
      ['low', true],
      ['medium', true],
      ['high', false],
    ] as const) {
      expect(matchesSubscription(sub({ minSeverity: min }), message), min).toBe(expected);
    }
    // Every present filter must match.
    expect(matchesSubscription(sub({ directions: ['inbound'], domainIds: [D2] }), message)).toBe(
      false,
    );
  });

  it('passes filters for attributes an event type does not carry', () => {
    const domainEvent = {
      type: 'domain.verified' as const,
      severity: 'info' as const,
      domainPublicId: D1,
    };
    expect(
      matchesSubscription(
        sub({ directions: ['outbound'], verdicts: ['malicious'], domainIds: [D1] }),
        domainEvent,
      ),
    ).toBe(true);
    expect(matchesSubscription(sub({ domainIds: [D2] }), domainEvent)).toBe(false);
    expect(matchesSubscription(sub({ minSeverity: 'low' }), domainEvent)).toBe(false);
  });

  it('never matches a null domain against a domainIds filter', () => {
    const noDomain = { ...message, domainPublicId: null };
    expect(matchesSubscription(sub({ domainIds: [D1] }), noDomain)).toBe(false);
    expect(matchesSubscription(sub({ directions: ['inbound'] }), noDomain)).toBe(true);
  });
});
