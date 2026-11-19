import { describe, expect, it } from 'vitest';
import {
  base32Lower,
  deriveRouteToken,
  ROUTE_TOKEN_HEADER,
  ROUTE_TOKEN_PATTERN,
  routeTokenHeaderLine,
} from './route-token';

// A fixed, obviously synthetic example key (tests only; never a deployment value).
const EXAMPLE_KEY = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';
const CONNECTION = '0190a0a0-0000-7000-8000-000000000001';

describe('base32Lower', () => {
  it('encodes RFC 4648 base32 in lower case without padding', () => {
    // Vector computed independently (Python base64.b32encode, lower-cased, padding stripped).
    expect(base32Lower(Uint8Array.from({ length: 16 }, (_, i) => i))).toBe(
      'aaaqeayeaudaocajbifqydiob4',
    );
    expect(base32Lower(new Uint8Array())).toBe('');
    expect(base32Lower(Uint8Array.of(0xff))).toBe('74');
  });
});

describe('deriveRouteToken (D9)', () => {
  it('matches independently computed vectors', () => {
    expect(deriveRouteToken(EXAMPLE_KEY, CONNECTION, 1)).toBe('skagmgjhh6mni77sl7d2mmr4eppqaalr');
    expect(deriveRouteToken(EXAMPLE_KEY, CONNECTION, 2)).toBe('dcfld446wcq2egbi4gx5qsjip7nykooe');
    expect(deriveRouteToken(EXAMPLE_KEY, '0190a0a0-0000-7000-8000-000000000002', 1)).toBe(
      'ecmmkokb6wtloj2pme6wfd54susbuqfp',
    );
  });

  it('accepts an upper-case key and always yields 32 base32 characters', () => {
    const token = deriveRouteToken(EXAMPLE_KEY.toUpperCase(), CONNECTION, 1);
    expect(token).toBe('skagmgjhh6mni77sl7d2mmr4eppqaalr');
    expect(token).toMatch(ROUTE_TOKEN_PATTERN);
  });

  it('differs per key, connection and version', () => {
    const other = 'ff'.repeat(32);
    expect(deriveRouteToken(other, CONNECTION, 1)).not.toBe(
      deriveRouteToken(EXAMPLE_KEY, CONNECTION, 1),
    );
  });

  it.each([
    ['short key', 'ab'.repeat(31), CONNECTION, 1],
    ['non-hex key', 'zz'.repeat(32), CONNECTION, 1],
    ['upper-case id', EXAMPLE_KEY, CONNECTION.toUpperCase(), 1],
    ['not a uuid', EXAMPLE_KEY, 'connection', 1],
    ['version 0', EXAMPLE_KEY, CONNECTION, 0],
    ['version too large', EXAMPLE_KEY, CONNECTION, 65_536],
    ['fractional version', EXAMPLE_KEY, CONNECTION, 1.5],
  ])('refuses %s', (_, key, id, version) => {
    expect(() => deriveRouteToken(key, id, version)).toThrow();
  });
});

describe('routeTokenHeaderLine', () => {
  it('formats the header the delivery-worker prepends', () => {
    const token = deriveRouteToken(EXAMPLE_KEY, CONNECTION, 1);
    expect(ROUTE_TOKEN_HEADER).toBe('X-EG-Route-Token');
    expect(routeTokenHeaderLine(token)).toBe(`X-EG-Route-Token: ${token}`);
  });

  it('refuses anything that is not a token (no header injection)', () => {
    expect(() => routeTokenHeaderLine('abc\r\nBcc: x@example.test')).toThrow();
    expect(() => routeTokenHeaderLine('A'.repeat(32))).toThrow();
  });
});
