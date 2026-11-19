import { describe, expect, it } from 'vitest';
import {
  assertEvidenceSafe,
  EXPLANATION_TEMPLATES,
  isEvidenceSafe,
  renderExplanation,
  renderScoreExplanation,
} from './explain';
import { ATO_RULES } from './rules/catalogue';
import { scoreAccount } from './scoring';
import { mergeAtoSettings } from './settings';
import { T0 } from './testing/builders';

describe('renderExplanation', () => {
  it('has a template for every rule code and renders without leftovers', () => {
    for (const r of ATO_RULES) {
      expect(EXPLANATION_TEMPLATES[r.code]).toBe(r.explanation);
      const text = renderExplanation(r.code, {});
      expect(text).not.toMatch(/\{[a-zA-Z]+\}/);
      expect(text.length).toBeGreaterThan(10);
    }
  });

  it('fills evidence values (the impossible-travel example of D10)', () => {
    expect(
      renderExplanation('ato.geo.impossible_travel', {
        fromCountry: 'IN',
        toCountry: 'GB',
        distanceKm: 7160,
        elapsedMinutes: 30,
        speedKmh: 14320,
      }),
    ).toBe('Sign-ins from IN and GB 7160 km apart within 30 minutes (about 14320 km/h)');
    expect(
      renderExplanation('ato.correlation.multi_category', {
        count: 3,
        categories: ['a', 'b', 'c'],
      }),
    ).toContain('a, b, c');
    expect(renderExplanation('ato.unknown', {})).toBe('ato.unknown');
  });
});

describe('assertEvidenceSafe (allow-list)', () => {
  it('accepts allow-listed flat evidence', () => {
    expect(() =>
      assertEvidenceSafe({
        ip: '192.0.2.1',
        ipPrefix: '192.0.2.0/24',
        count: 3,
        codes: ['a.b'],
        country: 'IN',
        domain: 'partner.example',
      }),
    ).not.toThrow();
    expect(isEvidenceSafe({ deviceLabel: 'Chrome 120 · Windows · desktop', distanceKm: 5 })).toBe(
      true,
    );
  });

  it('refuses unknown keys, addresses, URLs, tokens, nesting and oversize evidence', () => {
    expect(isEvidenceSafe({ subject: 'hello' })).toBe(false);
    expect(isEvidenceSafe({ domain: 'user@example.test' })).toBe(false);
    expect(isEvidenceSafe({ domain: 'https://example.test/x' })).toBe(false);
    expect(isEvidenceSafe({ codes: ['A'.repeat(48)] })).toBe(false);
    expect(isEvidenceSafe({ count: { nested: 1 } })).toBe(false);
    expect(isEvidenceSafe({ count: Number.POSITIVE_INFINITY })).toBe(false);
    expect(isEvidenceSafe({ asnOrg: 'x'.repeat(129) })).toBe(false);
    expect(isEvidenceSafe({ codes: Array.from({ length: 33 }, (_, i) => `c${i}`) })).toBe(false);
    expect(isEvidenceSafe([])).toBe(false);
    expect(isEvidenceSafe({ asnOrg: 'line\nbreak' })).toBe(false);
  });
});

describe('renderScoreExplanation', () => {
  it('summarizes contributions and gates', () => {
    const r = scoreAccount(
      [
        {
          code: 'ato.content.phishing_sent',
          category: 'outbound_content',
          strength: 'strong',
          weight: 45,
          status: 'active',
          lastOccurredAt: T0,
        },
      ],
      mergeAtoSettings({}),
      null,
      T0,
    );
    expect(renderScoreExplanation(r)).toBe(
      'Risk 60 (high): Phishing sent from the account +45; strong evidence: floor applied',
    );
    expect(renderScoreExplanation(scoreAccount([], mergeAtoSettings({}), null, T0))).toBe(
      'Risk 0 (low): no active signals',
    );
  });
});
