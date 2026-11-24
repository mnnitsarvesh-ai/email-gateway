import { createHash } from 'node:crypto';

/**
 * The recipient rule of `report_send_email` (design D5 step 2, invariant I17): an address is
 * normalized (one plain ASCII address, no display name, no line breaks, the domain lower-cased)
 * and classified as the user's own address (`self`), an active user of the organization
 * (`member`) or an address in one of its verified domains (`domain`), in that order; anything
 * else is refused (`null`). Pure: the api supplies the directory lookups (users and domains of the
 * scope's organization, writer) and evaluates the rule at proposal and again at confirm.
 */

export const RECIPIENT_KINDS = ['self', 'member', 'domain'] as const;
export type RecipientKind = (typeof RECIPIENT_KINDS)[number];

export interface RecipientDirectory {
  /** The principal's own `users.email` (verified, not deleted), or null. */
  selfEmail: string | null;
  /**
   * An active user (status `active`, email verified, not deleted) of the organization has this
   * address. Receives the normalized address; the lookup compares case-insensitively.
   */
  isActiveMember(address: string): boolean;
  /** Names of the organization's domains with status `verified` or `active` (not deleted). */
  verifiedDomains: ReadonlySet<string>;
}

export const RECIPIENT_MAX_CHARS = 254;
const LOCAL_MAX = 64;
const DOMAIN_MAX = 253;
// RFC 5322 dot-atom characters (no quoted local parts, no comments).
const LOCAL = /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*$/;
const LABEL = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;

/**
 * One normalized address (`Local.Part@example.test`: the local part as typed, the domain
 * lower-cased) or null: not a string, empty, longer than 254 characters, non-ASCII (IDN refused;
 * punycode `xn--` labels are ASCII), whitespace or line breaks inside, a display name or angle
 * brackets, several addresses, a quoted local part, an IP literal or a single-label domain.
 */
export function normalizeRecipient(input: unknown): string | null {
  if (typeof input !== 'string') return null;
  const value = input.trim();
  if (value.length === 0 || value.length > RECIPIENT_MAX_CHARS) return null;
  if (!/^[\x21-\x7e]+$/.test(value)) return null; // printable ASCII only: no spaces, CR/LF, IDN
  const at = value.lastIndexOf('@');
  if (at <= 0 || at !== value.indexOf('@')) return null;
  const local = value.slice(0, at);
  const domain = value.slice(at + 1).toLowerCase();
  if (local.length > LOCAL_MAX || !LOCAL.test(local)) return null;
  if (domain.length === 0 || domain.length > DOMAIN_MAX) return null;
  const labels = domain.split('.');
  if (labels.length < 2 || !labels.every((label) => LABEL.test(label))) return null;
  if (/^[0-9]+$/.test(labels[labels.length - 1]!)) return null; // no IP-like hosts
  return `${local}@${domain}`;
}

/** The lower-cased domain of a normalized address. */
export function recipientDomainOf(address: string): string {
  return address.slice(address.lastIndexOf('@') + 1).toLowerCase();
}

/** SHA-256 hex of the lower-cased address (stored and audited instead of a refused address). */
export function recipientSha256(address: string): string {
  return createHash('sha256').update(address.trim().toLowerCase(), 'utf8').digest('hex');
}

/**
 * The recipient class, or null (refused): `self` (the user's own address), `member` (an active
 * user of the organization), `domain` (the address's domain equals, exactly, one of the
 * organization's verified domains; subdomains do not match). Case-insensitive.
 */
export function classifyRecipient(
  address: unknown,
  directory: RecipientDirectory,
): RecipientKind | null {
  const normalized = normalizeRecipient(address);
  if (!normalized) return null;
  const lower = normalized.toLowerCase();
  const self = directory.selfEmail ? normalizeRecipient(directory.selfEmail) : null;
  if (self && self.toLowerCase() === lower) return 'self';
  if (directory.isActiveMember(normalized)) return 'member';
  const domain = recipientDomainOf(normalized);
  for (const name of directory.verifiedDomains)
    if (typeof name === 'string' && name.trim().toLowerCase() === domain) return 'domain';
  return null;
}

/** The confirmation card's wording of a recipient class (design D5 step 5). */
export function recipientKindText(kind: RecipientKind, domain: string): string {
  switch (kind) {
    case 'self':
      return 'your own address';
    case 'member':
      return 'user of your organization';
    case 'domain':
      return `address in verified domain ${domain}`;
  }
}
