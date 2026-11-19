import {
  egressSetSha256,
  parseEgressCidr,
  PROVIDER_EGRESS_SNAPSHOT,
} from '@email-gateway/database';
import { describe, expect, it } from 'vitest';
import {
  canonicalizeCidr,
  diffEgressSets,
  EgressImportError,
  parseEgressImport,
} from './egress-import';

const errorOf = (fn: () => unknown): EgressImportError => {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(EgressImportError);
    return error as EgressImportError;
  }
  throw new Error('expected an EgressImportError');
};

describe('parseEgressImport', () => {
  it('canonicalizes, sorts, de-duplicates and hashes like the seed', () => {
    const parsed = parseEgressImport({
      schema: 'provider-egress-import/1',
      provider: 'microsoft_365',
      cidrs: ['2A01:111:F400:0000::/48', '104.47.0.0/17', '40.92.0.0/15', '40.92.0.0/15'],
    });
    expect(parsed.provider).toBe('microsoft_365');
    expect(parsed.cidrs).toEqual(['40.92.0.0/15', '104.47.0.0/17', '2a01:111:f400::/48']);
    expect(parsed.duplicatesRemoved).toBe(1);
    expect(parsed.sha256).toBe(egressSetSha256(parsed.cidrs.map(parseEgressCidr)));
  });

  it('the seed snapshot imports to the same hash', () => {
    for (const snapshot of PROVIDER_EGRESS_SNAPSHOT) {
      const parsed = parseEgressImport({ provider: snapshot.provider, cidrs: [...snapshot.cidrs] });
      expect(parsed.sha256).toBe(egressSetSha256(snapshot.cidrs.map(parseEgressCidr)));
    }
  });

  it.each([
    ['not a CIDR', '40.92.0.0', /not a CIDR/],
    ['garbage', 'abc/12', /not a valid/],
    ['prefix too long', '40.92.0.0/33', /out of range/],
    ['IPv4 prefix below /8', '40.0.0.0/7', /at least \/8/],
    ['IPv6 prefix below /16', '2a00::/15', /at least \/16/],
    ['host bits', '40.92.0.1/15', /host bits/],
    ['private', '10.0.0.0/8', /globally reachable/],
    ['loopback', '127.0.0.0/8', /globally reachable/],
    ['documentation', '192.0.2.0/24', /globally reachable/],
    ['unique local IPv6', 'fd00::/16', /globally reachable/],
    ['range reaching into special space', '100.0.0.0/8', /globally reachable/],
  ])('refuses %s (%s)', (_name, cidr, message) => {
    const error = errorOf(() =>
      parseEgressImport({ provider: 'google_workspace', cidrs: ['35.190.247.0/24', cidr] }),
    );
    expect(error.message).toMatch(message);
    expect(error.index).toBe(1);
  });

  it('refuses malformed documents and size limits', () => {
    expect(errorOf(() => parseEgressImport([])).message).toMatch(/JSON object/);
    expect(
      errorOf(() => parseEgressImport({ provider: 'aws', cidrs: ['35.190.247.0/24'] })).message,
    ).toMatch(/provider/);
    expect(
      errorOf(() => parseEgressImport({ provider: 'google_workspace', cidrs: [] })).message,
    ).toMatch(/empty/);
    expect(
      errorOf(() => parseEgressImport({ provider: 'google_workspace', cidrs: 'x' })).message,
    ).toMatch(/array/);
    expect(
      errorOf(() =>
        parseEgressImport({ provider: 'google_workspace', cidrs: ['35.190.247.0/24'], extra: 1 }),
      ).message,
    ).toMatch(/unknown fields/);
    expect(
      errorOf(() =>
        parseEgressImport({
          schema: 'v2',
          provider: 'google_workspace',
          cidrs: ['35.190.247.0/24'],
        }),
      ).message,
    ).toMatch(/schema/);
    const many = Array.from({ length: 5001 }, () => '35.190.247.0/24');
    expect(
      errorOf(() => parseEgressImport({ provider: 'google_workspace', cidrs: many })).message,
    ).toMatch(/5000/);
    expect(
      errorOf(() =>
        parseEgressImport(
          { provider: 'google_workspace', cidrs: ['35.190.247.0/24'] },
          { expectedProvider: 'microsoft_365' },
        ),
      ).message,
    ).toMatch(/not microsoft_365/);
    expect(errorOf(() => canonicalizeCidr(42 as unknown as string)).message).toMatch(
      /not a string/,
    );
  });

  it('diffs sets and requires --force above 50 % removal', () => {
    expect(diffEgressSets([], ['1.0.0.0/24'])).toMatchObject({
      removedFraction: 0,
      requiresForce: false,
      unchanged: false,
    });
    expect(diffEgressSets(['a', 'b'], ['a', 'b'])).toMatchObject({
      unchanged: true,
      requiresForce: false,
    });
    expect(diffEgressSets(['a', 'b', 'c', 'd'], ['a', 'b', 'e'])).toMatchObject({
      added: ['e'],
      removed: ['c', 'd'],
      removedFraction: 0.5,
      requiresForce: false,
    });
    expect(diffEgressSets(['a', 'b', 'c', 'd'], ['a', 'e'])).toMatchObject({ requiresForce: true });
  });
});
