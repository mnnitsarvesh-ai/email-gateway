import { describe, expect, it } from 'vitest';
import {
  firstMatchingHold,
  holdToSearchCriteria,
  type LegalHoldFacts,
  legalHoldMatches,
  parseHoldCriteria,
} from './matcher';

const facts: LegalHoldFacts = {
  receivedAt: new Date('2026-03-15T10:00:00.000Z'),
  direction: 'inbound',
  recipientDirections: ['inbound'],
  senderAddresses: ['Sender@Example.org', 'boss@example.org'],
  recipientAddresses: ['alice@example.com', 'bcc-hidden@example.com'],
};
const V1 = { criteriaVersion: 'archive-hold/1' };

describe('legalHoldMatches: 5.3 semantics (legacy rows, criteria_version NULL)', () => {
  it.each([
    [{}, true],
    [{ custodians: [] }, true],
    [{ custodians: ['ALICE@example.com '] }, true],
    [{ custodians: ['sender@example.org'] }, true],
    [{ custodians: ['bcc-hidden@example.com'] }, true],
    [{ custodians: ['nobody@example.com'] }, false],
    [{ from: '2026-03-15' }, true],
    [{ from: '2026-03-16' }, false],
    [{ to: '2026-03-15' }, true],
    [{ to: '2026-03-14' }, false],
    [{ from: '2026-03-15T10:00:00Z', to: '2026-03-15T10:00:00Z' }, true],
    [{ from: '2026-03-15T10:00:00.001Z' }, false],
    [{ to: '2026-03-15T09:59:59.999Z' }, false],
    [{ from: '2026-03-15T12:00:00+02:00' }, true],
    [{ custodians: ['alice@example.com'], from: '2026-04-01' }, false],
  ])('%j → %s', (criteria, expected) => {
    expect(legalHoldMatches(criteria, facts)).toBe(expected);
    expect(legalHoldMatches(criteria, facts, { criteriaVersion: null })).toBe(expected);
  });

  it.each([
    [null],
    [undefined],
    ['text'],
    [42],
    [{ custodians: 'alice@example.com' }],
    [{ keywords: ['merger'] }],
    // A legacy row cannot carry directions: unparsable, so it holds everything.
    [{ directions: ['outbound'] }],
    [{ from: '2026-02-30' }],
  ])('unparsable legacy criteria %j match everything', (criteria) => {
    expect(legalHoldMatches(criteria, facts)).toBe(true);
    expect(
      legalHoldMatches(criteria, { ...facts, senderAddresses: [], recipientAddresses: [] }),
    ).toBe(true);
  });
});

describe('legalHoldMatches: archive-hold/1', () => {
  it('directions: the message direction or any recipient direction', () => {
    expect(legalHoldMatches({ directions: ['inbound'] }, facts, V1)).toBe(true);
    expect(legalHoldMatches({ directions: ['outbound'] }, facts, V1)).toBe(false);
    const mixed = {
      ...facts,
      direction: 'outbound' as const,
      recipientDirections: ['internal' as const],
    };
    expect(legalHoldMatches({ directions: ['internal'] }, mixed, V1)).toBe(true);
    // Unknown directions cannot exclude (fail-safe).
    expect(
      legalHoldMatches(
        { directions: ['outbound'] },
        { ...facts, direction: null, recipientDirections: [] },
        V1,
      ),
    ).toBe(true);
  });

  it('combines every criterion', () => {
    const c = {
      custodians: ['alice@example.com'],
      from: '2026-03-01',
      to: '2026-03-31',
      directions: ['inbound'],
    };
    expect(legalHoldMatches(c, facts, V1)).toBe(true);
    expect(legalHoldMatches({ ...c, to: '2026-03-14' }, facts, V1)).toBe(false);
    expect(legalHoldMatches({ ...c, custodians: ['x@y.z'] }, facts, V1)).toBe(false);
  });

  it('unknown keys or versions match everything', () => {
    expect(legalHoldMatches({ custodians: ['x@y.z'], keywords: ['a'] }, facts, V1)).toBe(true);
    expect(
      legalHoldMatches({ custodians: ['x@y.z'] }, facts, { criteriaVersion: 'archive-hold/9' }),
    ).toBe(true);
    expect(parseHoldCriteria({ custodians: ['x@y.z'] }, 'archive-hold/1')).toEqual({
      matchAll: false,
      criteria: { custodians: ['x@y.z'] },
    });
  });

  it('firstMatchingHold picks the first matching row with its own version', () => {
    const holds = [
      { id: 'a', criteria: { custodians: ['x@y.z'] }, criteriaVersion: null },
      { id: 'b', criteria: { directions: ['inbound'] }, criteriaVersion: 'archive-hold/1' },
    ];
    expect(firstMatchingHold(holds, facts)?.id).toBe('b');
    expect(firstMatchingHold([holds[0]!], facts)).toBeNull();
  });
});

describe('holdToSearchCriteria', () => {
  it('maps custodians (normalized), whole-day bounds and directions', () => {
    expect(
      holdToSearchCriteria(
        {
          custodians: ['Alice@Example.com', 'alice@example.com'],
          from: '2026-03-01',
          to: '2026-03-31',
          directions: ['inbound'],
        },
        'archive-hold/1',
      ),
    ).toEqual({
      matchAll: false,
      custodians: ['alice@example.com'],
      from: new Date('2026-03-01T00:00:00.000Z'),
      to: new Date('2026-03-31T23:59:59.999Z'),
      directions: ['inbound'],
    });
  });

  it('unparsable criteria cover everything', () => {
    expect(holdToSearchCriteria({ weird: 1 }, null)).toEqual({
      matchAll: true,
      custodians: [],
      from: null,
      to: null,
      directions: [],
    });
  });
});
