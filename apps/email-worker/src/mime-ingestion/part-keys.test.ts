import { describe, expect, it } from 'vitest';
import { assertOrganizationKey, isOrganizationKey, partKey } from './part-keys';

const target = {
  organizationId: 17n,
  messageId: 9_007_199_254_740_993n,
  // 23:59 local in UTC+5:30 is still the 3rd in UTC: the key uses the UTC date of received_at.
  receivedAt: new Date('2026-11-03T23:59:59.999Z'),
};

describe('part keys (design M11)', () => {
  it('builds org/{org}/part/{yyyy}/{mm}/{dd}/{messageId}/{partIndex}.{ext}', () => {
    expect(partKey(target, { partIndex: 2, kind: 'text' })).toBe(
      'org/17/part/2026/11/03/9007199254740993/2.text',
    );
    expect(partKey(target, { partIndex: 3, kind: 'html' })).toBe(
      'org/17/part/2026/11/03/9007199254740993/3.html',
    );
    expect(partKey(target, { partIndex: 10, kind: 'attachment' })).toBe(
      'org/17/part/2026/11/03/9007199254740993/10.att',
    );
  });

  it('uses the UTC date of received_at (stable across retry days) and pads it', () => {
    const early = { ...target, receivedAt: new Date('2027-01-05T00:00:00.000Z') };
    expect(partKey(early, { partIndex: 0, kind: 'attachment' })).toBe(
      'org/17/part/2027/01/05/9007199254740993/0.att',
    );
  });

  it('is deterministic for the same row and part', () => {
    const part = { partIndex: 4, kind: 'attachment' as const };
    expect(partKey({ ...target }, part)).toBe(partKey(target, part));
  });

  it('refuses invalid ids, indices and dates', () => {
    expect(() =>
      partKey({ ...target, organizationId: 0n }, { partIndex: 1, kind: 'text' }),
    ).toThrow();
    expect(() => partKey(target, { partIndex: -1, kind: 'text' })).toThrow();
    expect(() => partKey(target, { partIndex: 1.5, kind: 'text' })).toThrow();
    expect(() =>
      partKey({ ...target, receivedAt: new Date('nope') }, { partIndex: 1, kind: 'text' }),
    ).toThrow();
  });

  it('accepts only keys under the organization prefix', () => {
    expect(isOrganizationKey('org/17/eml/2026/11/03/a.eml', 17n)).toBe(true);
    expect(isOrganizationKey('org/170/eml/a.eml', 17n)).toBe(false);
    expect(isOrganizationKey('org/1/eml/a.eml', 17n)).toBe(false);
    expect(isOrganizationKey('org/17/', 17n)).toBe(false);
    expect(isOrganizationKey('org/17/../18/eml/a.eml', 17n)).toBe(false);
    expect(isOrganizationKey('xorg/17/eml/a.eml', 17n)).toBe(false);
    expect(() => assertOrganizationKey('org/18/x', 17n)).toThrow();
  });
});
