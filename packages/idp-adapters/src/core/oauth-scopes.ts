/**
 * OAuth scope codes (merge note M1, deviation WP3-2): 8.4's `providerEventSchema` carries scopes
 * as lower-case codes (`[a-z0-9][a-z0-9_.-]{0,63}`) and its rule Q1 treats `mail_read`,
 * `mail_send`, `full_access` and `offline_access` (`RISKY_OAUTH_SCOPES`) as risky. Provider
 * scope names (Graph `Mail.ReadWrite`, Google `https://www.googleapis.com/auth/gmail.modify`) are
 * mapped onto those four classes where they grant that access; every other scope becomes its
 * own bounded code (`user.read` → `user_read`, Google prefixes stripped).
 */
import type { IdentityProviderKind } from '../port/ato-port';
import { code64 } from './normalize';

const MICROSOFT_CLASSES: Readonly<Record<string, string>> = Object.freeze({
  'mail.read': 'mail_read',
  'mail.readbasic': 'mail_read',
  'mail.readbasic.all': 'mail_read',
  'mail.read.shared': 'mail_read',
  'mail.readwrite': 'mail_read',
  'mail.readwrite.shared': 'mail_read',
  'imap.accessasuser.all': 'mail_read',
  'pop.accessasuser.all': 'mail_read',
  'mail.send': 'mail_send',
  'mail.send.shared': 'mail_send',
  'smtp.send': 'mail_send',
  'ews.accessasuser.all': 'full_access',
  full_access_as_app: 'full_access',
  full_access_as_user: 'full_access',
  exchangemanageasapp: 'full_access',
  offline_access: 'offline_access',
});

const GOOGLE_PREFIX = 'https://www.googleapis.com/auth/';

const GOOGLE_CLASSES: Readonly<Record<string, string>> = Object.freeze({
  'https://mail.google.com/': 'full_access',
  'gmail.readonly': 'mail_read',
  'gmail.metadata': 'mail_read',
  'gmail.modify': 'mail_read',
  'gmail.send': 'mail_send',
  'gmail.compose': 'mail_send',
  'gmail.insert': 'mail_send',
});

/** The 8.4 scope code of one provider scope, or `undefined` when nothing usable remains. */
export function oauthScopeCode(provider: IdentityProviderKind, scope: string): string | undefined {
  const raw = scope.trim();
  if (!raw) return undefined;
  const lower = raw.toLowerCase();
  if (provider === 'google_workspace') {
    const direct = GOOGLE_CLASSES[lower];
    if (direct) return direct;
    const name = lower.startsWith(GOOGLE_PREFIX) ? lower.slice(GOOGLE_PREFIX.length) : lower;
    const classed = GOOGLE_CLASSES[name];
    if (classed) return classed;
    return code64(name.replace(/^https?:\/\//, '')) || undefined;
  }
  const classed = MICROSOFT_CLASSES[lower];
  if (classed) return classed;
  return code64(raw) || undefined;
}

/** Distinct scope codes in first-seen order, at most `max` (8.4 allows 64). */
export function oauthScopeCodes(
  provider: IdentityProviderKind,
  scopes: readonly string[],
  max = 50,
): string[] {
  const out = new Set<string>();
  for (const scope of scopes) {
    const value = oauthScopeCode(provider, scope);
    if (value) out.add(value);
    if (out.size >= max) break;
  }
  return [...out];
}
