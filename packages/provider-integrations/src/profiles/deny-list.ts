import type { PermissionProfile } from './types';

/**
 * Deny list for `purpose: mail_flow` profiles (D1, I3): a mail-flow grant can never carry a
 * permission that writes to, or reads the content of, a customer tenant.
 */
export const MAIL_FLOW_DENIED_MICROSOFT_PATTERNS: readonly RegExp[] = Object.freeze([
  /ReadWrite/i,
  /^Mail\./i,
  /^MailboxSettings\./i,
  /^Exchange\.ManageAsApp$/i,
  /^full_access_as_app$/i,
  /^Directory\./i,
  /^User\./i,
  /^Policy\./i,
  /^Application\./i,
]);

const GOOGLE_SCOPE_PREFIX = 'https://www.googleapis.com/auth/';

/** Why a permission is refused for a mail-flow profile, or null when it is allowed. */
export function mailFlowDenyReason(
  provider: PermissionProfile['provider'],
  permission: string,
): string | null {
  if (provider === 'microsoft_365') {
    const hit = MAIL_FLOW_DENIED_MICROSOFT_PATTERNS.find((p) => p.test(permission));
    return hit ? `Microsoft permission ${permission} matches ${String(hit)}` : null;
  }
  if (
    permission === 'https://mail.google.com/' ||
    permission.startsWith('https://mail.google.com')
  ) {
    return `Google scope ${permission} grants full Gmail access`;
  }
  const short = permission.startsWith(GOOGLE_SCOPE_PREFIX)
    ? permission.slice(GOOGLE_SCOPE_PREFIX.length)
    : permission;
  if (/^gmail(\.|$)/i.test(short)) return `Google scope ${permission} is a Gmail scope`;
  if (!permission.endsWith('.readonly')) return `Google scope ${permission} is not read-only`;
  return null;
}

/**
 * Whether a permission writes (used for every profile that declares `readOnly: true`, whatever
 * its purpose): Microsoft `ReadWrite`/`Manage`/`full_access_as_app` permissions, Google scopes
 * that do not end in `.readonly`.
 */
export function isWritePermission(
  provider: PermissionProfile['provider'],
  permission: string,
): boolean {
  if (provider === 'microsoft_365') {
    return /ReadWrite|Manage|full_access_as_app|\.Send$|\.Write/i.test(permission);
  }
  return !permission.endsWith('.readonly');
}
