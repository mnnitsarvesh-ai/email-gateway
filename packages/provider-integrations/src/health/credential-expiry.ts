import type { CheckSeverity, CheckStatus } from '../types';

export const CREDENTIAL_EXPIRY_WARN_DAYS = 30;
export const CREDENTIAL_EXPIRY_CRITICAL_DAYS = 7;

/**
 * `credential.expiry` (D5): customer secrets with a declared expiry warn at 30 days and are
 * critical at 7 days (and after expiry). No declared expiry → `skipped`.
 */
export function evaluateCredentialExpiry(
  expiresAt: Date | null,
  now: Date,
): { status: CheckStatus; severity: CheckSeverity; daysLeft: number | null } {
  if (!expiresAt) return { status: 'skipped', severity: 'info', daysLeft: null };
  const daysLeft = Math.floor((expiresAt.getTime() - now.getTime()) / 86_400_000);
  if (daysLeft < CREDENTIAL_EXPIRY_CRITICAL_DAYS)
    return { status: 'fail', severity: 'critical', daysLeft };
  if (daysLeft < CREDENTIAL_EXPIRY_WARN_DAYS)
    return { status: 'warn', severity: 'warning', daysLeft };
  return { status: 'pass', severity: 'info', daysLeft };
}
