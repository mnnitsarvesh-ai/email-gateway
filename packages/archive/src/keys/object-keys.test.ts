import { describe, expect, it } from 'vitest';
import {
  ArchiveKeyError,
  archiveDayPrefixOf,
  archiveObjectKey,
  archivePrefixOf,
  assertKeyOfOrganization,
  exportObjectKey,
  isKeyOfOrganization,
} from './object-keys';

const MSG = '0190a5d0-0000-7000-8000-0000000000aa';
const CAP = '0190a5d0-0000-7000-8000-0000000000bb';
const EXP = '0190a5d0-0000-7000-8000-0000000000cc';
// 23:30 UTC on Nov 16 is already Nov 17 in many time zones: keys use the UTC date.
const RECEIVED = new Date('2026-11-16T23:30:00.000Z');

describe('archive object keys (§4.1)', () => {
  const ids = { organizationId: 42n, receivedAt: RECEIVED, messagePublicId: MSG, captureId: CAP };

  it('builds the record keys under the UTC date of received_at', () => {
    const prefix = `org/42/archive/2026/11/16/${MSG}/`;
    expect(archivePrefixOf(ids)).toBe(prefix);
    expect(archiveObjectKey({ ...ids, kind: 'eml' })).toBe(`${prefix}${CAP}/eml.bin`);
    expect(archiveObjectKey({ ...ids, kind: 'journal' })).toBe(`${prefix}${CAP}/journal.bin`);
    expect(archiveObjectKey({ ...ids, kind: 'scan', round: 2, revision: 1 })).toBe(
      `${prefix}${CAP}/scan-r2-v1.bin`,
    );
    expect(archiveDayPrefixOf(42, new Date('2026-01-05T00:00:00Z'))).toBe(
      'org/42/archive/2026/01/05/',
    );
  });

  it('builds export keys under the creation month', () => {
    expect(
      exportObjectKey({
        organizationId: '42',
        createdAt: new Date('2026-03-01T00:00:00Z'),
        exportPublicId: EXP,
      }),
    ).toBe(`org/42/exports/2026/03/${EXP}.bin`);
  });

  it('refuses invalid ids and parameters', () => {
    expect(() => archiveObjectKey({ ...ids, organizationId: 'acme', kind: 'eml' })).toThrow(
      ArchiveKeyError,
    );
    expect(() => archiveObjectKey({ ...ids, messagePublicId: '../x', kind: 'eml' })).toThrow(
      ArchiveKeyError,
    );
    expect(() => archiveObjectKey({ ...ids, captureId: CAP.toUpperCase(), kind: 'eml' })).toThrow(
      ArchiveKeyError,
    );
    expect(() => archiveObjectKey({ ...ids, kind: 'scan' })).toThrow(ArchiveKeyError);
    expect(() => archiveObjectKey({ ...ids, kind: 'scan', round: 1, revision: -1 })).toThrow(
      ArchiveKeyError,
    );
    expect(() => archiveObjectKey({ ...ids, kind: 'body' as never })).toThrow(ArchiveKeyError);
    expect(() =>
      archiveObjectKey({ ...ids, receivedAt: new Date(Number.NaN), kind: 'eml' }),
    ).toThrow(ArchiveKeyError);
  });
});

describe('assertKeyOfOrganization', () => {
  it('accepts keys of the organization and area', () => {
    const key = archiveObjectKey({
      organizationId: 42,
      receivedAt: RECEIVED,
      messagePublicId: MSG,
      captureId: CAP,
      kind: 'eml',
    });
    expect(assertKeyOfOrganization(key, 42, 'archive')).toBe(key);
    expect(assertKeyOfOrganization('org/42/eml/2026/11/16/x.eml', '42', 'eml')).toBeTruthy();
    expect(isKeyOfOrganization(key, 42n, 'archive')).toBe(true);
  });

  it.each([
    ['another organization', 'org/43/archive/a.bin'],
    ['a prefix collision', 'org/420/archive/a.bin'],
    ['another area', 'org/42/exports/a.bin'],
    ['the bare prefix', 'org/42/archive/'],
    ['an empty segment', 'org/42/archive//a.bin'],
    ['a dot segment', 'org/42/archive/./a.bin'],
    ['a dot-dot segment', 'org/42/archive/../../43/archive/a.bin'],
    ['a trailing slash', 'org/42/archive/a/'],
    ['a control character', 'org/42/archive/a\nb.bin'],
    ['a backslash', 'org/42/archive/a\\b.bin'],
    ['an empty key', ''],
  ])('refuses %s', (_name, key) => {
    expect(() => assertKeyOfOrganization(key, 42, 'archive')).toThrow(ArchiveKeyError);
    expect(isKeyOfOrganization(key, 42, 'archive')).toBe(false);
  });

  it('refuses invalid areas and organization ids; the error carries no key', () => {
    expect(() => assertKeyOfOrganization('org/42/archive/a', 42, '../x')).toThrow(ArchiveKeyError);
    expect(() => assertKeyOfOrganization('org/42/archive/a', 'x', 'archive')).toThrow(
      ArchiveKeyError,
    );
    try {
      assertKeyOfOrganization('org/43/archive/secret-name.bin', 42, 'archive');
    } catch (error) {
      expect((error as Error).message).not.toContain('secret-name');
    }
  });
});
