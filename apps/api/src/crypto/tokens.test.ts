import { describe, expect, it } from 'vitest';
import {
  generateApiKey,
  generateOpaqueToken,
  generateRecoveryCodes,
  isOpaqueToken,
  normalizeRecoveryCode,
  parseApiKey,
  safeEqualHex,
  sha256Hex,
  TokenHasher,
} from './tokens';

describe('opaque tokens', () => {
  it('are prefix_ + 32 random bytes in base64url', () => {
    const refresh = generateOpaqueToken('egr');
    const single = generateOpaqueToken('egt');
    expect(refresh).toMatch(/^egr_[A-Za-z0-9_-]{43}$/);
    expect(single).toMatch(/^egt_[A-Za-z0-9_-]{43}$/);
    expect(Buffer.from(refresh.slice(4), 'base64url')).toHaveLength(32);
    expect(generateOpaqueToken('egr')).not.toBe(refresh);
  });

  it('are checked strictly before lookup', () => {
    const token = generateOpaqueToken('egt');
    expect(isOpaqueToken(token, 'egt')).toBe(true);
    expect(isOpaqueToken(token, 'egr')).toBe(false);
    expect(isOpaqueToken(`${token}x`, 'egt')).toBe(false);
    expect(isOpaqueToken(42, 'egt')).toBe(false);
  });
});

describe('hashing', () => {
  it('sha256Hex matches the known vector', () => {
    expect(sha256Hex('abc')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });

  it('TokenHasher is an HMAC keyed by the pepper', () => {
    const a = new TokenHasher({ AUTH_TOKEN_PEPPER: 'p'.repeat(64) });
    const b = new TokenHasher({ AUTH_TOKEN_PEPPER: 'q'.repeat(64) });
    expect(a.hmacHex('value')).toMatch(/^[0-9a-f]{64}$/);
    expect(a.hmacHex('value')).toBe(a.hmacHex('value'));
    expect(a.hmacHex('value')).not.toBe(b.hmacHex('value'));
    expect(a.hmacHex('value')).not.toBe(sha256Hex('value'));
  });

  it('safeEqualHex compares digests', () => {
    const h = sha256Hex('x');
    expect(safeEqualHex(h, h)).toBe(true);
    expect(safeEqualHex(h, h.toUpperCase())).toBe(true);
    expect(safeEqualHex(h, sha256Hex('y'))).toBe(false);
    expect(safeEqualHex(h, h.slice(2))).toBe(false);
    expect(safeEqualHex('zz', 'zz')).toBe(false);
  });
});

describe('API keys', () => {
  it('have a 16-character egk_ prefix and a 32-byte secret', () => {
    const { key, prefix } = generateApiKey();
    expect(prefix).toMatch(/^egk_[0-9A-Za-z]{12}$/);
    expect(prefix).toHaveLength(16);
    expect(key.startsWith(`${prefix}_`)).toBe(true);
    expect(key).toHaveLength(16 + 1 + 43);
    expect(parseApiKey(key)).toEqual({ prefix });
  });

  it('are unique', () => {
    const prefixes = new Set(Array.from({ length: 200 }, () => generateApiKey().prefix));
    expect(prefixes.size).toBe(200);
  });

  it.each([
    ['empty', ''],
    ['wrong scheme', `egx_ABCDEFGHIJKL_${'a'.repeat(43)}`],
    ['short handle', `egk_ABCDEFGHIJK_${'a'.repeat(43)}`],
    ['non-base62 handle', `egk_ABCDEFGHIJ-L_${'a'.repeat(43)}`],
    ['short secret', `egk_ABCDEFGHIJKL_${'a'.repeat(42)}`],
    ['long secret', `egk_ABCDEFGHIJKL_${'a'.repeat(44)}`],
    ['bad secret chars', `egk_ABCDEFGHIJKL_${'a'.repeat(42)}+`],
    ['whitespace', ` egk_ABCDEFGHIJKL_${'a'.repeat(43)}`],
    ['missing separator', `egk_ABCDEFGHIJKL${'a'.repeat(44)}`],
  ])('parseApiKey rejects %s', (_case, key) => {
    expect(parseApiKey(key)).toBeNull();
  });

  it('parseApiKey rejects non-strings', () => {
    expect(parseApiKey(undefined)).toBeNull();
    expect(parseApiKey(['egk_'])).toBeNull();
  });
});

describe('recovery codes', () => {
  it('generates 10 distinct xxxxx-xxxxx base32 codes', () => {
    const codes = generateRecoveryCodes();
    expect(codes).toHaveLength(10);
    expect(new Set(codes).size).toBe(10);
    for (const code of codes) expect(code).toMatch(/^[a-z2-7]{5}-[a-z2-7]{5}$/);
  });

  it('honours n', () => {
    expect(generateRecoveryCodes(3)).toHaveLength(3);
  });

  it('normalizes user input to the canonical form', () => {
    expect(normalizeRecoveryCode('ABCDE-FGHIJ')).toBe('abcde-fghij');
    expect(normalizeRecoveryCode(' abcde fghij ')).toBe('abcde-fghij');
    expect(normalizeRecoveryCode('abcdefghij')).toBe('abcde-fghij');
  });

  it.each(['', 'abcde-fghi', 'abcde-fghij1', 'abcde-fgh0j', 'abcde_fghij', 'x'.repeat(40)])(
    'rejects %j',
    (input) => expect(normalizeRecoveryCode(input)).toBeNull(),
  );
});
