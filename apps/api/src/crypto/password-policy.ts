import { z } from 'zod';
import { COMMON_PASSWORDS } from './common-passwords';
import { normalizePassword } from './password-hasher';

export const PASSWORD_MIN_LENGTH = 12;
export const PASSWORD_MAX_LENGTH = 128;

const COMMON = new Set(COMMON_PASSWORDS);
/** Shorter local parts (`a@…`) would reject too many good passwords to be useful. */
const MIN_LOCAL_PART_TO_CHECK = 3;

/** Length in code points, so one emoji or accented letter counts as one character. */
const length = (value: string): number => [...value].length;

/**
 * Length rule of the password policy (NIST SP 800-63B): 12–128 characters after NFKC
 * normalization. No composition rules. Its output is the normalized password.
 */
export const PasswordSchema = z
  .string()
  .transform(normalizePassword)
  .refine((v) => length(v) >= PASSWORD_MIN_LENGTH, {
    message: `must be at least ${PASSWORD_MIN_LENGTH} characters`,
  })
  .refine((v) => length(v) <= PASSWORD_MAX_LENGTH, {
    message: `must be at most ${PASSWORD_MAX_LENGTH} characters`,
  });

/**
 * Context-dependent rules (D4). Returns the reasons a password is rejected (empty = acceptable);
 * reasons never contain the password.
 */
export function checkPasswordPolicy(password: string, context: { email: string }): string[] {
  const normalized = normalizePassword(password).toLowerCase();
  const email = context.email.trim().toLowerCase();
  const localPart = email.split('@')[0] ?? '';
  const reasons: string[] = [];
  if (
    normalized === email ||
    (localPart.length >= MIN_LOCAL_PART_TO_CHECK && normalized.includes(localPart))
  ) {
    reasons.push('must not contain your email address');
  }
  if (COMMON.has(normalized)) {
    reasons.push('is too common');
  }
  const chars = [...normalized];
  if (chars.length > 0 && chars.every((c) => c === chars[0])) {
    reasons.push('must not be a single repeated character');
  }
  return reasons;
}
