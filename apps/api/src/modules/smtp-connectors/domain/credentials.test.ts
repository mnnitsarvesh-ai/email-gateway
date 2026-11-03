import { describe, expect, it } from 'vitest';
import {
  generateSaslSecret,
  generateSaslUsername,
  normalizeFingerprint,
  SASL_USERNAME_PATTERN,
} from './credentials';

describe('generated SASL credentials (D10)', () => {
  it('usernames are egc- + 20 lower-case base32 characters, all different', () => {
    const names = Array.from({ length: 500 }, generateSaslUsername);
    for (const name of names) expect(name).toMatch(SASL_USERNAME_PATTERN);
    expect(new Set(names).size).toBe(names.length);
    // The random part uses the whole base32 alphabet (500 × 20 draws).
    const alphabet = new Set(names.map((name) => name.slice(4)).join(''));
    expect([...alphabet].sort().join('')).toBe('234567abcdefghijklmnopqrstuvwxyz');
  });

  it('secrets are 32 random bytes in base64url', () => {
    const secrets = Array.from({ length: 50 }, generateSaslSecret);
    for (const secret of secrets) {
      expect(secret).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(Buffer.from(secret, 'base64url')).toHaveLength(32);
    }
    expect(new Set(secrets).size).toBe(secrets.length);
  });
});

describe('normalizeFingerprint (D10)', () => {
  const lower = 'ab'.repeat(32);

  it.each([
    [lower, lower],
    ['AB'.repeat(32), lower],
    [` ${lower}\n`, lower],
    [Array.from({ length: 32 }, () => 'AB').join(':'), lower],
    [Array.from({ length: 32 }, () => 'ab').join(':'), lower],
  ])('accepts %j', (input, expected) => {
    expect(normalizeFingerprint(input)).toBe(expected);
  });

  it.each([
    'ab'.repeat(31),
    'ab'.repeat(33),
    'zz'.repeat(32),
    `${'ab:'.repeat(31)}a`,
    `${'ab:'.repeat(32)}`,
    `a${'b:ab'.repeat(16)}`,
    `sha256:${lower}`,
    '',
  ])('refuses %j', (input) => {
    expect(normalizeFingerprint(input)).toBeNull();
  });
});
