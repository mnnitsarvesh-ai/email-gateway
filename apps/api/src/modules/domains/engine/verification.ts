import { randomBytes } from 'node:crypto';
import type { DnsResult } from '../../../dns/dns-resolver';
import type { DnsCheckOutcome } from './types';

export const VERIFICATION_VALUE_PREFIX = 'emailgateway-verification=';

/** 20 random bytes as 40 lower-case hex characters (D4). Not secret (published in DNS). */
export function generateVerificationToken(): string {
  return randomBytes(20).toString('hex');
}

/** The ownership TXT record: `<label>.<domain>` = `emailgateway-verification=<token>`. */
export function verificationRecord(
  domain: string,
  token: string,
  label: string,
): { host: string; value: string } {
  return { host: `${label}.${domain}`, value: `${VERIFICATION_VALUE_PREFIX}${token}` };
}

/** Surrounding whitespace and one pair of surrounding quotes are not part of a TXT value. */
export function normalizeTxtValue(value: string): string {
  const trimmed = value.trim();
  return trimmed.length >= 2 && trimmed.startsWith('"') && trimmed.endsWith('"')
    ? trimmed.slice(1, -1).trim()
    : trimmed;
}

/**
 * Ownership check (D4): any TXT string at the host equal to the expected value → valid; an
 * answer without it → invalid; NXDOMAIN/NODATA → missing; indeterminate stays indeterminate.
 */
export function evaluateVerification(
  result: DnsResult<string>,
  expectedValue: string,
): { outcome: DnsCheckOutcome; observedValue: string | null } {
  switch (result.outcome) {
    case 'answer':
      return {
        outcome: result.records.some((value) => normalizeTxtValue(value) === expectedValue)
          ? 'valid'
          : 'invalid',
        observedValue: result.records.join('\n'),
      };
    case 'nxdomain':
    case 'nodata':
      return { outcome: 'missing', observedValue: null };
    default:
      return { outcome: 'indeterminate', observedValue: null };
  }
}
