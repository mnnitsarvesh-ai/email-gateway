import { describe, expect, it } from 'vitest';
import { COMMON_PASSWORDS } from './common-passwords';
import { checkPasswordPolicy, PasswordSchema } from './password-policy';

describe('PasswordSchema', () => {
  it('accepts 12 to 128 characters and returns the NFKC form', () => {
    expect(PasswordSchema.parse('a'.repeat(12))).toBe('a'.repeat(12));
    expect(PasswordSchema.parse('x'.repeat(128))).toHaveLength(128);
    expect(PasswordSchema.parse('Ａ'.repeat(12))).toBe('A'.repeat(12));
  });

  it('counts code points, not UTF-16 units', () => {
    expect(PasswordSchema.safeParse('\u{1F512}'.repeat(12)).success).toBe(true);
    expect(PasswordSchema.safeParse('\u{1F512}'.repeat(11)).success).toBe(false);
  });

  it('rejects too short and too long passwords', () => {
    expect(PasswordSchema.safeParse('a'.repeat(11)).success).toBe(false);
    expect(PasswordSchema.safeParse('a'.repeat(129)).success).toBe(false);
    expect(PasswordSchema.safeParse(12345678901234).success).toBe(false);
  });
});

describe('checkPasswordPolicy', () => {
  const email = 'alice.smith@example.com';

  it('accepts a long, uncommon passphrase', () => {
    expect(checkPasswordPolicy('violet tractor sings at dawn', { email })).toEqual([]);
  });

  it('rejects passwords containing the email local part (case-insensitive)', () => {
    expect(checkPasswordPolicy('xx-Alice.Smith-2026', { email })).toEqual([
      'must not contain your email address',
    ]);
    expect(checkPasswordPolicy(email, { email })).toContain('must not contain your email address');
  });

  it('ignores very short local parts', () => {
    expect(checkPasswordPolicy('a violet tractor sings', { email: 'a@example.com' })).toEqual([]);
  });

  it('rejects common passwords case-insensitively', () => {
    expect(checkPasswordPolicy('Password1234', { email })).toEqual(['is too common']);
    expect(checkPasswordPolicy('QWERTYUIOPAS', { email })).toEqual(['is too common']);
  });

  it('rejects a single repeated character', () => {
    expect(checkPasswordPolicy('zzzzzzzzzzzzzz', { email })).toEqual([
      'must not be a single repeated character',
    ]);
  });

  it('never includes the password in a reason', () => {
    const password = 'alice.smith-unique-secret';
    expect(checkPasswordPolicy(password, { email }).join(' ')).not.toContain(password);
  });
});

describe('COMMON_PASSWORDS', () => {
  it('has at least 200 lower-case entries of 12+ characters without duplicates', () => {
    expect(COMMON_PASSWORDS.length).toBeGreaterThanOrEqual(200);
    expect(new Set(COMMON_PASSWORDS).size).toBe(COMMON_PASSWORDS.length);
    for (const entry of COMMON_PASSWORDS) {
      expect(entry.length).toBeGreaterThanOrEqual(12);
      expect(entry).toBe(entry.toLowerCase());
    }
  });
});
